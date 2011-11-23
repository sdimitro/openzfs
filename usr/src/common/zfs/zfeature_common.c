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
 * Copyright (c) 2011 by Delphix. All rights reserved.
 */

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <errno.h>
#include <string.h>
#endif
#include <sys/debug.h>
#include <sys/fs/zfs.h>
#include <sys/inttypes.h>
#include <sys/types.h>
#include "zfeature_common.h"

/*
 * Set to disable all feature checks while opening pools, allowing pools with
 * unsupported features to be opened. Set for testing only.
 */
boolean_t zfeature_checks_disable = B_FALSE;

zfeature_info_t spa_feature_table[SPA_FEATURES];

/*
 * Valid characters for feature names. This list is mainly for aesthetic
 * purposes and could be expanded in the future. There are different allowed
 * characters in the name's reverse dns portion (before the colon) and its
 * short name (after the colon).
 */
static int
valid_char(char c, boolean_t after_colon)
{
	return ((c >= 'a' && c <= 'z') ||
	    (c >= '0' && c <= '9') ||
	    c == (after_colon ? '_' : '.'));
}

/*
 * Every feature name must contain exactly one colon which separates a reverse
 * dns organization name from the feature's "short" name (e.g.
 * "com.company:feature_name").
 */
boolean_t
zfeature_is_valid_name(const char *name)
{
	int i;
	boolean_t has_colon = B_FALSE;

	i = 0;
	while (name[i] != '\0') {
		char c = name[i++];
		if (c == ':') {
			if (has_colon)
				return (B_FALSE);
			has_colon = B_TRUE;
			continue;
		}
		if (!valid_char(c, has_colon))
			return (B_FALSE);
	}

	return (has_colon);
}

boolean_t
zfeature_is_supported(const char *name, boolean_t allowshort)
{
	if (zfeature_checks_disable)
		return (B_TRUE);

	return (0 == zfeature_lookup(name, allowshort, NULL));
}

/*
 * If the allow_short option is given, the reverse DNS portion of the feature
 * name may be omitted. If this option is given and there are multiple features
 * with the same short name, this function returns EEXIST.
 */
int
zfeature_lookup(const char *name, boolean_t allowshort, zfeature_info_t **res)
{
	boolean_t found_short = B_FALSE;

	if (!allowshort && !zfeature_is_valid_name(name))
		return (EINVAL);

	for (int i = 0; i < SPA_FEATURES; i++) {
		zfeature_info_t *feature = &spa_feature_table[i];
		char *short_name;

		if (strcmp(name, feature->fi_name) == 0) {
			if (res != NULL)
				*res = feature;
			return (0);
		}

		if (!allowshort)
			continue;

		short_name = strchr(feature->fi_name, ':') + 1;
		ASSERT(short_name != NULL);
		if (strcmp(name, short_name) == 0) {
			if (found_short)
				return (EEXIST);

			if (res != NULL)
				*res = feature;
			found_short = B_TRUE;
		}
	}

	if (found_short)
		return (0);

	return (ENOENT);
}

static void
zfeature_register(int fid, const char *name, const char *desc,
    boolean_t readonly, boolean_t mos, zfeature_info_t **deps)
{
	zfeature_info_t *feature = &spa_feature_table[fid];
	static zfeature_info_t *nodeps[] = { NULL };

	ASSERT(name != NULL);
	ASSERT(desc != NULL);
	ASSERT(!readonly || !mos);
	ASSERT3U(fid, <, SPA_FEATURES);
	ASSERT(zfeature_is_valid_name(name));

	if (deps == NULL)
		deps = nodeps;

	feature->fi_name = name;
	feature->fi_desc = desc;
	feature->fi_can_readonly = readonly;
	feature->fi_mos = mos;
	feature->fi_depends = deps;
}

void
zpool_feature_init(void)
{
	zfeature_register(SPA_FEATURE_ASYNC_DESTROY,
	    "com.delphix:async_destroy", "Destroy filesystems asynchronously.",
	    B_TRUE, B_FALSE, NULL);
}
