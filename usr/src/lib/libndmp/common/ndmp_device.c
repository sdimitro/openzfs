/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Copyright (c) 2011 by Delphix. All rights reserved */

#include "ndmp_impl.h"

/*
 * NDMP device management.  This handles the discovery of SCSI devices on the
 * system.  This list is divded into tapes and SCSI changers.  This device list
 * is currently populated when the server is initialized and hence is static.
 * Eventually, this list should adapt to changes in device configuration.
 */

#define	SCSI_SERIAL_PAGE	0x80
#define	SCSI_DEVICE_IDENT_PAGE	0x83
#define	SCMD_READ_ELEMENT_STATUS	0xB8

typedef struct scsi_serial {
	int sr_flags;
	char sr_num[16];
} scsi_serial_t;

typedef struct {
#ifdef _BIG_ENDIAN
	uint8_t di_peripheral_qual	: 3,
		di_peripheral_dev_type	: 5;
	uint8_t di_page_code;
	uint16_t di_page_length;
#else
	uint8_t di_peripheral_dev_type	: 5,
		di_peripheral_qual	: 3;
	uint8_t di_page_code;
	uint16_t di_page_length;
#endif
} device_ident_header_t;

typedef struct {
#ifdef _BIG_ENDIAN
	uint8_t ni_proto_ident	: 4,
		ni_code_set	: 4;

	uint8_t ni_PIV		: 1,
		: 1,
		ni_assoi	: 2,
		ni_ident_type	: 4;

	uint8_t ni_reserved;
	uint8_t ni_ident_length;
#else
	uint8_t ni_code_set	: 4,
		ni_proto_ident	: 4;

	uint8_t ni_ident_type	: 4,
		ni_asso		: 2,
		: 1,
		ni_PIV		: 1;
	uint8_t ni_reserved;
	uint8_t ni_ident_length;
#endif
} name_ident_t;

#define	KILOBYTE	1024

#define	SCSI_CHANGER_DIR	"/dev/scsi/changer"
#define	SCSI_TAPE_DIR		"/dev/rmt"

#define	MAXIORETRY	20
/*
 * Generic routine to read a SCSI page from a SCSI device.
 */
int
read_scsi_page(scsi_device_t *sdp, union scsi_cdb *cdb,
    int command_size, caddr_t data, int size)
{
	struct uscsi_cmd uscsi_cmd = { 0 };
	int dev;

	/* Lun is in the 5th bit */
	cdb->scc_lun = sdp->sd_lun;
	uscsi_cmd.uscsi_flags |= USCSI_READ | USCSI_ISOLATE;
	uscsi_cmd.uscsi_bufaddr = data;
	uscsi_cmd.uscsi_buflen = size;
	uscsi_cmd.uscsi_timeout = 1000;
	uscsi_cmd.uscsi_cdb = (char *)cdb;

	if (cdb->scc_cmd == SCMD_READ_ELEMENT_STATUS) {
		uscsi_cmd.uscsi_flags |= USCSI_RQENABLE;
		uscsi_cmd.uscsi_rqbuf = data;
		uscsi_cmd.uscsi_rqlen = size;
	}
	uscsi_cmd.uscsi_cdblen = command_size;

	dev = open(sdp->sd_name, O_RDWR | O_NDELAY);
	if (dev == -1)
		return (errno);

	if (ioctl(dev, USCSICMD, &uscsi_cmd) < 0) {
		(void) close(dev);
		return (errno);
	}

	(void) close(dev);
	return (uscsi_cmd.uscsi_status);
}

/*
 * Read the Inquiry Page.
 */
static int
read_inquiry_page(scsi_device_t *sdp, struct scsi_inquiry *inq)
{
	union scsi_cdb cdb = { 0 };

	cdb.scc_cmd = SCMD_INQUIRY;
	cdb.g0_count0 = sizeof (struct scsi_inquiry);

	return (read_scsi_page(sdp, &cdb, CDB_GROUP0,
	    (caddr_t)inq, sizeof (*inq)) ? -1 : 0);
}

/*
 * Read the Product Data Page.
 */
static int
read_data_page(scsi_device_t *sdp, int pcode, char *snum, int size)
{
	char cmd[CDB_GROUP0];

	(void) memset(cmd, 0, sizeof (cmd));

	cmd[0] = SCMD_INQUIRY;
	cmd[1] = pcode ? 0x01 : 0x00;
	cmd[2] = pcode;
	cmd[4] = size;

	/* LINTED improper alignment */
	return (read_scsi_page(sdp, (union scsi_cdb *)&cmd, CDB_GROUP0,
	    (caddr_t)snum, size) == -1 ? -1 : 0);
}

/*
 * Read the Serial Number Page.
 */
static int
read_serial_num_page(scsi_device_t *sdp, char *snum, int size)
{
	scsi_serial_t serial;
	int rv;

	(void) memset(&serial, 0, sizeof (scsi_serial_t));
	rv = read_data_page(sdp, SCSI_SERIAL_PAGE, (caddr_t)&serial,
	    sizeof (scsi_serial_t));
	(void) strlcpy(snum, serial.sr_num, size);

	return (rv == -1 ? -1 : 0);
}

/*
 * Read the Device Name Page.
 */
static int
read_dev_name_page(scsi_device_t *sdp, device_ident_header_t *devp, int len)
{
	(void) memset(devp, 0, len);

	if (read_data_page(sdp, SCSI_DEVICE_IDENT_PAGE, (caddr_t)devp,
	    len) == -1)
		return (-1);

	if (devp->di_page_code != SCSI_DEVICE_IDENT_PAGE)
		return (-1);

	return (0);
}

/*
 * Formatted print of WWN
 */
static void
snprintf_wwn(char *buf, int size, uint8_t *wwn)
{
	if (wwn == NULL || buf == NULL)
		return;

	(void) snprintf(buf, size, "0x%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X",
	    wwn[0], wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);
}

/*
 * Extract and print the world wide name (WWN)
 */
int
read_device_wwn(scsi_device_t *sdp, char *wwnp, int wsize)
{
	device_ident_header_t *header;
	name_ident_t *ident;
	uint16_t page_len = sizeof (device_ident_header_t);
	uint16_t act_len;
	int accessed;
	uint8_t *designator_data;

	(void) memset(wwnp, 0, wsize);
resize:
	header = ndmp_malloc(NULL, page_len);
	if (header == NULL)
		return (-1);

	if (read_dev_name_page(sdp, header, page_len) == -1) {
		free(header);
		return (-1);
	}

	act_len = BE_16(header->di_page_length);
	if (act_len > page_len) {
		free(header);
		page_len = act_len;
		goto resize;
	}

	ident = (name_ident_t *)&header[1];
	accessed = sizeof (device_ident_header_t);

	while (accessed < act_len) {

		accessed += sizeof (name_ident_t);
		accessed += ident->ni_ident_length;
		designator_data = (uint8_t *)&ident[1];

		/*
		 * Looking for code set 1 (Binary) ident type NAA 64 bit
		 * address that is associated with the node (0).
		 */
		if ((ident->ni_code_set == 1) &&
		    (ident->ni_ident_type == 3)) {
			snprintf_wwn(wwnp, wsize, designator_data);
			/*
			 * If assc is zero (Node) this is the one we want.
			 * If we find that we're done.
			 */
			if (ident->ni_asso == 0)
				break;
		}

		/*
		 * If we find a EUI-64 we can use that also.
		 */
		if ((ident->ni_code_set == 2) &&
		    (ident->ni_ident_type == 1) &&
		    (ident->ni_asso == 0) &&
		    (isprint(wwnp[0] == 0))) { /* Don't overwrite */
			/*
			 * This isn't our first choice but we'll print it
			 * in case there is nothing else to use.
			 */
			(void) snprintf(wwnp, wsize, "%.*s",
			    ident->ni_ident_length, designator_data);
		}

		ident = (name_ident_t *)
		    &designator_data[ident->ni_ident_length];
	}

	free(header);

	/*
	 * See if we found something.
	 * Memset above would leave wwnp not printable.
	 */
	if (isprint(wwnp[0]))
		return (0);

	return (-1);
}

/*
 * Add this SCSI device.
 */
static int
scsi_add_device(ndmp_session_t *session, int sid, int lun, char *name, int type)
{
	scsi_device_t *sdp;

	sdp = ndmp_malloc(session, sizeof (scsi_device_t));
	if (sdp == NULL)
		return (-1);

	(void) snprintf(sdp->sd_name,
	    sizeof (sdp->sd_name), "%s/%s",
	    type == DTYPE_CHANGER ? SCSI_CHANGER_DIR : SCSI_TAPE_DIR,
	    name);

	sdp->sd_type = type;
	sdp->sd_lun = lun;
	sdp->sd_sid = sid;
	sdp->sd_requested_max_active = 1;

	/* Insert slink */
	sdp->sd_next = session->ns_server->ns_scsi_devices;
	session->ns_server->ns_scsi_devices = sdp;

	return (0);
}

/*
 * Go through the attached devices and detect the tape
 * and robot by checking the /dev entries
 */
static int
probe_scsi(ndmp_session_t *session)
{
	DIR *dirp;
	struct dirent *dp;
	char *p;
	int lun = 0;
	int sid = 0;
	const char *device_type;

	/* Scan for the changer */
	dirp = opendir(SCSI_CHANGER_DIR);
	if (dirp != NULL) {
		while ((dp = readdir(dirp)) != NULL) {
			if ((strcmp(dp->d_name, ".") == 0) ||
			    (strcmp(dp->d_name, "..") == 0))
				continue;

			if ((p = strchr(dp->d_name, 'd')) != NULL) {
				lun = atoi(++p);
				p = strchr(dp->d_name, 't');
				sid = atoi(++p);
			}
			else
				sid = atoi(dp->d_name);

			if (scsi_add_device(session, 0, lun, dp->d_name,
			    DTYPE_CHANGER) != 0)
				return (-1);
		}
		(void) closedir(dirp);
	}

	/* Scan for tape devices */
	dirp = opendir(SCSI_TAPE_DIR);
	if (dirp != NULL) {
		device_type = ndmp_get_prop(session, NDMP_DRIVE_TYPE);

		if ((strcasecmp(device_type, "sysv") != 0) &&
		    (strcasecmp(device_type, "bsd") != 0))
			return (-1);

		while ((dp = readdir(dirp)) != NULL) {
			if ((strcmp(dp->d_name, ".") == 0) ||
			    (strcmp(dp->d_name, "..") == 0))
				continue;

			/* Skip special modes */
			if (strpbrk(dp->d_name, "chlmu") != NULL)
				continue;

			/* Pick the non-rewind device */
			if (strchr(dp->d_name, 'n') == NULL)
				continue;

			if (strcasecmp(device_type, "sysv") == 0) {
				if (strchr(dp->d_name, 'b') != NULL)
					continue;
			} else if (strcasecmp(device_type, "bsd") == 0) {
				if (strchr(dp->d_name, 'b') == NULL)
					continue;
			}

			sid = atoi(dp->d_name);

			/*
			 * SCSI ID should match with the ID of the device
			 * (will be checked by SCSI get elements page later)
			 */
			if (scsi_add_device(session, sid, 0, dp->d_name,
			    DTYPE_SEQUENTIAL) != 0)
				return (-1);
		}
		(void) closedir(dirp);
	}

	return (0);
}

/*
 * Get the SCSI device type (tape, robot)
 */
/*ARGSUSED*/
int
scsi_get_devtype(ndmp_session_t *session, int sid, int lun)
{
	scsi_device_t *sdp;

	for (sdp = session->ns_server->ns_scsi_devices; sdp != NULL;
	    sdp = sdp->sd_next) {
		if (sdp->sd_sid == sid && sdp->sd_lun == lun)
			return (sdp->sd_type);
	}

	return (-1);
}

/*
 * Check if the SCSI device exists
 */
boolean_t
scsi_dev_exists(ndmp_session_t *session, int sid, int lun)
{
	scsi_device_t *sdp;

	for (sdp = session->ns_server->ns_scsi_devices; sdp != NULL;
	    sdp = sdp->sd_next) {
		if (sdp->sd_sid == sid && sdp->sd_lun == lun)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Initialize SCSI and tape library information.
 */
int
ndmp_device_init(ndmp_server_t *server)
{
	ndmp_session_t *session = &server->ns_global_session;
	scsi_device_t *sdp;
	struct scsi_inquiry scsi_data;

	/*
	 * Discover the set of available devices on the system.
	 */
	if (probe_scsi(session) < 0)
		return (-1);

	/*
	 * Fill in any device details from the SCSI info.
	 */
	for (sdp = server->ns_scsi_devices; sdp != NULL;
	    sdp = sdp->sd_next) {
		(void) memset(&scsi_data, 0, sizeof (struct scsi_inquiry));
		if (read_inquiry_page(sdp, &scsi_data) == -1)
			continue;

		(void) strlcpy(sdp->sd_vendor,
		    scsi_data.inq_vid, sizeof (sdp->sd_vendor));
		(void) strlcpy(sdp->sd_id,
		    scsi_data.inq_pid, sizeof (sdp->sd_id));
		(void) strlcpy(sdp->sd_rev,
		    scsi_data.inq_revision, sizeof (sdp->sd_rev));
		(void) read_serial_num_page(sdp, sdp->sd_serial,
		    sizeof (sdp->sd_serial));
		(void) read_device_wwn(sdp, sdp->sd_wwn,
		    sizeof (sdp->sd_wwn));
	}

	return (0);
}

void
ndmp_device_fini(ndmp_server_t *server)
{
	scsi_device_t *sdp;

	while (server->ns_scsi_devices != NULL) {
		sdp = server->ns_scsi_devices;
		server->ns_scsi_devices = sdp->sd_next;
		free(sdp);
	}
}
