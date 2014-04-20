/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

#include <sys/debug.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <math.h>
#include <smbios.h>
#include <errno.h>
#include <sys/uuid.h>
#include <uuid/uuid.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <libintl.h>

#define	DEFAULT_SECRET_KEY_FILE	"/etc/challenge_response.key"
#define	POOL_LENGTH	4
#define	CHALLENGE_LENGTH	8
#define	SECRET_BYTE_LEN	64
#define	RESPONSE_LENGTH	6
#define	PROMPT_LENGTH	(30 + UUID_PRINTABLE_STRING_LENGTH + CHALLENGE_LENGTH)
#define	OFFSET_INDEX	19

/*
 * Fetch the system's UUID from BIOS and construct a string version of it in the
 * out argument uuidstr. This function returns 0 on success, 1 on failure.
 */
static int
get_system_uuid(char *uuidstr)
{
	int err;
	smbios_system_t sys;
	smbios_hdl_t *shp;

	if ((shp = smbios_open(NULL, SMB_VERSION, 0, &err)) == NULL) {
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: failed to load SMBIOS: %s",
		    smbios_errmsg(err));
		return (1);
	}
	if (smbios_info_system(shp, &sys) == SMB_ERR) {
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: failed to fetch SMBIOS info");
		return (1);
	}

	uuid_unparse((uchar_t *)sys.smbs_uuid, uuidstr);
	smbios_close(shp);
	return (0);
}

/*
 * Load this engine's secret key from the specified file into the out argument
 * key. On success, load_secret returns 0. On failure, 1 is returned.
 */
static int
load_secret(const char *secret_key_file, char *key)
{
	FILE *fp;
	int nread;

	if ((fp = fopen(secret_key_file, "r")) == NULL) {
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: error opening key file %s",
		    secret_key_file);
		return (1);
	}

	nread = fread(key, sizeof (char), SECRET_BYTE_LEN, fp);
	(void) fclose(fp);

	if (nread != SECRET_BYTE_LEN) {
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: error freading secret");
		return (1);
	} else {
		return (0);
	}
}

/*
 * This function is based on code from Apendix A of RFC 6287 OCRA: OATH
 * Challenge-Response Algorithm. It converts the first 4 bytes stored at str
 * into an unsigned integer with no more than the specified number of base-10
 * digits. This function assumes at least 4 bytes to a word, interprets the
 * integer value stored in str as big-endian, and masks the top-most bit in val
 * to "avoid confusion about signed vs. unsigned modulo computations."
 */
static unsigned int
toint_truncate(unsigned char *str, int digits)
{
	unsigned int val;
	ASSERT(digits < 9);

	val = (((str[0] & 0x7F) << 24) | ((str[1] & 0xFF) << 16) |
	    ((str[2] & 0xFF) << 8) | (str[3] & 0xFF));
	val = val % (int)pow(10, digits);
	return (val);
}

/*
 * Calculate the expected response string by calculating an HMAC of the
 * challenge, extracting an integer from that HMAC, and truncating that integer
 * to have no more than RESPONSE_LENGTH base-10 digits.
 */
static int
calculate_response(char *challenge, char *key,
    char response[RESPONSE_LENGTH + 1]) {
	int hmac_offset;
	unsigned int response_val;
	unsigned char hmac[EVP_MAX_MD_SIZE];

	if (HMAC(EVP_sha1(), key, SECRET_BYTE_LEN,
	    (unsigned char *)challenge, strlen(challenge),
	    hmac, NULL) == NULL) {
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: HMAC failure");
		return (1);
	}
	/*
	 * Calculate a random offset into hmac using the lower order 4 bits of
	 * hmac[OFFSET_INDEX]. The value of OFFSET_INDEX is defined
	 * differently in RFC 4226 (HOTP) and RFC 6287 (OCRA) and seems to have
	 * zero impact on the security of HOTP generation, but must be in-sync
	 * with the authentication portal for verification to succeed.
	 */
	hmac_offset = hmac[OFFSET_INDEX] & 0xF;
	response_val = toint_truncate(hmac + hmac_offset,
	    RESPONSE_LENGTH);
	(void) snprintf(response, sizeof (response), "%u", response_val);
	return (0);
}

/*
 * The challenge_response PAM module implements a subset of the authentication
 * protocol described in IETF RFC 6287: OATH Challenge-Response Algorithm (OCRA)
 * (http://tools.ietf.org/html/rfc6287).
 *
 * The authentication process occurs in three main steps: setup, challenge, and
 * response verification.
 *
 * Setup encapsulates:
 * 1. Loading from disk the shared secret to be used during authentication
 *    (load_secret).
 * 2. Fetching this engine's UUID from BIOS (get_system_uuid).
 * 3. Generating a set of random bits that will become the challenge presented
 *    to the authenticating user (RAND_bytes).
 *
 * The challenge phase constructs a 4-byte unsigned integer from the random bits
 * generated during setup. This uint is moduloed to be no more than D base-10
 * digits, where D is the maximum challenge length. The prompt to the user is
 * then generated from the stringified challenge and the UUID fetched in setup.
 * The prompt is presented to the user, and this PAM module waits for their
 * response.
 *
 * In the final step, response verification consists of reading back the
 * response entered, calculating the correct response using OpenSSL's HMAC
 * utilities, and comparing the char* representation of the two. If the entered
 * response is equal to the correct response, the PAM module returns PAM_SUCCESS
 * and the user is authenticated. If not, the process starts over with a new
 * challenge.
 *
 */
/*ARGSUSED*/
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int err;
	unsigned int challenge_val;
	char *user_response;
	char challenge_str[CHALLENGE_LENGTH + 1];
	char key[SECRET_BYTE_LEN];
	char uuidstr[UUID_PRINTABLE_STRING_LENGTH];
	char prompt[PROMPT_LENGTH + 1];
	char correct_response_val_str[RESPONSE_LENGTH + 1];
	unsigned char rand_pool[POOL_LENGTH];
	const char *secret_key_file = NULL;
	char err_str[256];

	if (argc) {
		secret_key_file = argv[0];
	} else {
		secret_key_file = DEFAULT_SECRET_KEY_FILE;
	}
	__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: fetching key from %s", secret_key_file);

	/* Load this engine's secret key from disk. */
	if (load_secret(secret_key_file, key)) {
		return (PAM_SYSTEM_ERR);
	}

	/* Fetch the UUID for this engine from BIOS. */
	if (get_system_uuid(uuidstr)) {
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: unable to fetch uuid");
		return (PAM_SYSTEM_ERR);
	}

	/* Fetch entropy from which to construct the challenge. */
	if (RAND_bytes(rand_pool, sizeof (rand_pool)) != 1) {
		(void) ERR_error_string_n(ERR_get_error(), err_str,
		    sizeof (err_str));
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: RAND_bytes failed: %s", err_str);
		return (PAM_SYSTEM_ERR);
	}

	/* Extract a 6-digit challenge. */
	challenge_val = toint_truncate(rand_pool, CHALLENGE_LENGTH);

	/* Generate the prompt to be presented to the user. */
	(void) snprintf(challenge_str, sizeof (challenge_str), "%u",
	    challenge_val);
	(void) snprintf(prompt, sizeof (prompt),
	    "Engine|Challenge: %s|%s\nResponse: ", uuidstr, challenge_str);

	/* Get the response back from the user using the prompt. */
	if ((err = __pam_get_authtok(pamh, PAM_PROMPT, PAM_AUTHTOK,
	    prompt, &user_response)) != PAM_SUCCESS) {
		return (err);
	}

	if (strlen(user_response) > RESPONSE_LENGTH) {
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_challenge_response: invalid response length");
		return (PAM_AUTH_ERR);
	}

	/* Calculate the correct response. */
	if (calculate_response(challenge_str, key, correct_response_val_str)) {
		return (PAM_SYSTEM_ERR);
	}

	/* Validate the calculated response against the entered response. */
	if (strncmp(user_response, correct_response_val_str,
	    strlen(correct_response_val_str)) == 0) {
		return (PAM_SUCCESS);
	} else {
		return (PAM_AUTH_ERR);
	}
}

/*ARGSUSED*/
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}
