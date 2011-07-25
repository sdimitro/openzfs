/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/* Copyright (c) 2011 by Delphix.   All rights reserved. */

#include "ndmp_impl.h"

static void tape_open_send_reply(ndmp_session_t *session, int err);
static boolean_t validmode(int mode);
static void common_tape_close(ndmp_session_t *session);

/*
 * Configurable delay & time when the tape is
 * busy during opening the tape.
 */
int ndmp_tape_open_retries = 5;
int ndmp_tape_open_delay = 1000;

/*
 * This handler closes the currently open tape device.
 */
/*ARGSUSED*/
void
ndmp_tape_close_v3(ndmp_session_t *session, void *body)
{
	ndmp_tape_close_reply reply = { 0 };

	if (session->ns_tape.td_fd == -1) {
		ndmp_log(session, LOG_ERR, "tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}
	common_tape_close(session);
}

/*
 * This handler handles tape_mtio requests.
 */
void
ndmp_tape_mtio_v3(ndmp_session_t *session, void *body)
{
	ndmp_tape_mtio_request *request = (ndmp_tape_mtio_request *) body;
	ndmp_tape_mtio_reply reply;

	struct mtop tapeop;
	struct mtget mtstatus;
	int retry = 0;
	int rc;

	reply.resid_count = 0;

	if (session->ns_tape.td_fd == -1) {
		ndmp_log(session, LOG_ERR, "tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	reply.error = NDMP_NO_ERR;
	switch (request->tape_op) {
	case NDMP_MTIO_FSF:
		tapeop.mt_op = MTFSF;
		break;
	case NDMP_MTIO_BSF:
		tapeop.mt_op = MTBSF;
		break;
	case NDMP_MTIO_FSR:
		tapeop.mt_op = MTFSR;
		break;
	case NDMP_MTIO_BSR:
		tapeop.mt_op = MTBSR;
		break;
	case NDMP_MTIO_REW:
		tapeop.mt_op = MTREW;
		break;
	case NDMP_MTIO_EOF:
		if (session->ns_tape.td_mode == NDMP_TAPE_READ_MODE)
			reply.error = NDMP_PERMISSION_ERR;
		tapeop.mt_op = MTWEOF;
		break;
	case NDMP_MTIO_OFF:
		tapeop.mt_op = MTOFFL;
		break;

	case NDMP_MTIO_TUR: /* test unit ready */

		if (is_tape_unit_ready(session,
		    session->ns_tape.td_adapter_name,
		    session->ns_tape.td_fd) == 0)
			/* tape not ready ? */
			reply.error = NDMP_NO_TAPE_LOADED_ERR;
		break;

	default:
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
	}

	if (reply.error == NDMP_NO_ERR && request->tape_op != NDMP_MTIO_TUR) {
		tapeop.mt_count = request->count;

		do {
			rc = ioctl(session->ns_tape.td_fd, MTIOCTOP, &tapeop);
			ndmp_debug(session, "ioctl MTIO rc:%d, cmd:%d, "
			    "retry:%d, error: %d", rc, tapeop.mt_op, retry,
			    errno);
		} while (rc < 0 && errno == EIO &&
		    retry++ < 5);

		/*
		 * Ignore I/O errors since these usually are the result of
		 * attempting to position past the beginning or end of the tape.
		 * The residual count will be returned and can be used to
		 * determine that the call was not completely successful.
		 */
		if (rc < 0) {
			ndmp_log(session, LOG_ERR,
			    "failed to send command to tape: %s",
			    strerror(errno));

			/* MTWEOF doesnt have residual count */
			if (tapeop.mt_op == MTWEOF)
				reply.error = NDMP_IO_ERR;
			else
				reply.error = NDMP_NO_ERR;
			reply.resid_count = tapeop.mt_count;
			ndmp_send_reply(session, &reply);
			return;
		}

		if (request->tape_op != NDMP_MTIO_REW &&
		    request->tape_op != NDMP_MTIO_OFF) {
			if (ioctl(session->ns_tape.td_fd, MTIOCGET,
			    &mtstatus) < 0) {
				ndmp_log(session, LOG_ERR,
				    "failed to send command to tape: %s",
				    strerror(errno));
				reply.error = NDMP_IO_ERR;
				ndmp_send_reply(session, &reply);
				return;
			}

			reply.resid_count = labs(mtstatus.mt_resid);
		}
	}

	ndmp_debug(session, "resid_count: %d", reply.resid_count);
	ndmp_send_reply(session, &reply);
}

/*
 * This handler handles tape_execute_cdb requests.
 */
void
ndmp_tape_execute_cdb_v3(ndmp_session_t *session, void *body)
{
	ndmp_tape_execute_cdb_request *request;
	ndmp_tape_execute_cdb_reply reply;

	request = (ndmp_tape_execute_cdb_request *) body;

	if (session->ns_tape.td_fd == -1) {
		(void) memset(&reply, 0, sizeof (reply));

		ndmp_log(session, LOG_ERR, "tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
	} else {
		session->ns_tape.td_eom_seen = B_FALSE;
		ndmp_execute_cdb(session, session->ns_tape.td_adapter_name,
		    session->ns_tape.td_sid, session->ns_tape.td_lun,
		    (ndmp_execute_cdb_request *)request);
	}
}

/*
 * This handler opens the specified tape device.
 */
void
ndmp_tape_open_v3(ndmp_session_t *session, void *body)
{
	ndmp_tape_open_request_v3 *request = (ndmp_tape_open_request_v3 *)body;
	char *devname = request->device;
	int ndmpmode = request->mode;
	char adptnm[SCSI_MAX_NAME];
	int err;
	int mode;
	int sid, lun;
	int devid;

	err = NDMP_NO_ERR;

	if (session->ns_tape.td_fd != -1 || session->ns_scsi.sd_is_open != -1) {
		ndmp_log(session, LOG_ERR,
		    "session already has a tape or scsi device open");
		err = NDMP_DEVICE_OPENED_ERR;
	} else if (!validmode(ndmpmode)) {
		err = NDMP_ILLEGAL_ARGS_ERR;
	}

	ndmp_debug(session, "Adapter device opened: %s", devname);
	(void) strlcpy(adptnm, devname, SCSI_MAX_NAME-2);
	adptnm[SCSI_MAX_NAME-1] = '\0';
	sid = lun = -1;

	scsi_find_sid_lun(session, devname, &sid, &lun);
	if (!ndmp_open_list_exists(devname, sid, lun)) {
		if ((devid = open(devname, O_RDWR | O_NDELAY)) < 0) {
			ndmp_log(session, LOG_ERR,
			    "failed to open device %s: %s", devname,
			    strerror(errno));
			err = NDMP_NO_DEVICE_ERR;
		} else {
			(void) close(devid);
		}
	}

	if (err != NDMP_NO_ERR) {
		tape_open_send_reply(session, err);
		return;
	}

	/*
	 * If tape is not opened in raw mode and tape is not loaded
	 * return error.
	 */
	if (ndmpmode != NDMP_TAPE_RAW1_MODE &&
	    ndmpmode != NDMP_TAPE_RAW2_MODE &&
	    !is_tape_unit_ready(session, adptnm, 0)) {
		tape_open_send_reply(session, NDMP_NO_TAPE_LOADED_ERR);
		return;
	}

	mode = (ndmpmode == NDMP_TAPE_READ_MODE) ? O_RDONLY : O_RDWR;
	mode |= O_NDELAY;
	session->ns_tape.td_fd = open(devname, mode);
	if (session->ns_version == NDMPV4 &&
	    session->ns_tape.td_fd < 0 &&
	    ndmpmode == NDMP_TAPE_RAW_MODE && errno == EACCES) {
		/*
		 * V4 suggests that if the tape is open in raw mode
		 * and could not be opened with write access, it should
		 * be opened read only instead.
		 */
		ndmpmode = NDMP_TAPE_READ_MODE;
		session->ns_tape.td_fd = open(devname, O_RDONLY);
	}

	if (session->ns_tape.td_fd < 0) {
		ndmp_log(session, LOG_ERR, "failed to open tape device %s: %s",
		    devname, strerror(errno));
		switch (errno) {
		case EACCES:
			err = NDMP_WRITE_PROTECT_ERR;
			break;
		case ENOENT:
			err = NDMP_NO_DEVICE_ERR;
			break;
		case EBUSY:
			err = NDMP_DEVICE_BUSY_ERR;
			break;
		case EPERM:
			err = NDMP_PERMISSION_ERR;
			break;
		default:
			err = NDMP_IO_ERR;
		}

		tape_open_send_reply(session, err);
		return;
	}

	switch (ndmp_open_list_add(session,
	    adptnm, sid, lun, session->ns_tape.td_fd)) {
	case 0:
		err = NDMP_NO_ERR;
		break;
	case EBUSY:
		err = NDMP_DEVICE_BUSY_ERR;
		break;
	case ENOMEM:
		err = NDMP_NO_MEM_ERR;
		break;
	default:
		err = NDMP_IO_ERR;
	}
	if (err != NDMP_NO_ERR) {
		tape_open_send_reply(session, err);
		return;
	}

	session->ns_tape.td_mode = ndmpmode;
	session->ns_tape.td_sid = sid;
	session->ns_tape.td_lun = lun;
	(void) strlcpy(session->ns_tape.td_adapter_name, adptnm, SCSI_MAX_NAME);
	session->ns_tape.td_record_count = 0;
	session->ns_tape.td_eom_seen = B_FALSE;

	ndmp_debug(session, "Tape is opened fd: %d", session->ns_tape.td_fd);

	tape_open_send_reply(session, NDMP_NO_ERR);
}

/*
 * This handler handles the ndmp_tape_get_state_request.  Status information
 * for the currently open tape device is returned.
 */
/*ARGSUSED*/
void
ndmp_tape_get_state_v3(ndmp_session_t *session, void *body)
{
	ndmp_tape_get_state_reply_v3 reply;
	struct mtdrivetype_request dtpr;
	struct mtdrivetype dtp;
	struct mtget mtstatus;

	if (session->ns_tape.td_fd == -1) {
		ndmp_log(session, LOG_ERR, "tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	if (ioctl(session->ns_tape.td_fd, MTIOCGET, &mtstatus) == -1) {
		ndmp_log(session, LOG_ERR, "failed to get status from tape: %s",
		    strerror(errno));

		reply.error = NDMP_IO_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	dtpr.size = sizeof (struct mtdrivetype);
	dtpr.mtdtp = &dtp;
	if (ioctl(session->ns_tape.td_fd, MTIOCGETDRIVETYPE, &dtpr) == -1) {
		ndmp_log(session, LOG_ERR,
		    "failed to get drive type information from tape: %s",
		    strerror(errno));

		reply.error = NDMP_IO_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	reply.flags = 0;

	reply.file_num = mtstatus.mt_fileno;
	reply.soft_errors = 0;
	reply.block_size = dtp.bsize;
	if (dtp.bsize == 0)
		reply.blockno = mtstatus.mt_blkno;
	else
		reply.blockno = mtstatus.mt_blkno *
		    (session->ns_mover.md_record_size / dtp.bsize);
	reply.total_space = long_long_to_quad(0); /* not supported */
	reply.space_remain = long_long_to_quad(0); /* not supported */
	reply.partition = 0; /* not supported */

	reply.soft_errors = 0;
	reply.total_space = long_long_to_quad(0LL);
	reply.space_remain = long_long_to_quad(0LL);

	reply.invalid = NDMP_TAPE_STATE_SOFT_ERRORS_INVALID |
	    NDMP_TAPE_STATE_TOTAL_SPACE_INVALID |
	    NDMP_TAPE_STATE_SPACE_REMAIN_INVALID |
	    NDMP_TAPE_STATE_PARTITION_INVALID;

	ndmp_debug(session, "f 0x%x, fnum %d, bsize %d, bno: %d",
	    reply.flags, reply.file_num, reply.block_size, reply.blockno);

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(session, &reply);
}

/*
 * This handler handles tape_write requests.  This interface is a non-buffered
 * interface. Each write request maps directly to a write to the tape device.
 * It is the responsibility of the NDMP client to pad the data to the desired
 * record size.  It is the responsibility of the NDMP client to ensure that the
 * length is a multiple of the tape block size if the tape device is in fixed
 * block mode.
 */
void
ndmp_tape_write_v3(ndmp_session_t *session, void *body)
{
	ndmp_tape_write_request *request = (ndmp_tape_write_request *) body;
	ndmp_tape_write_reply reply = { 0 };
	ssize_t n;

	reply.count = 0;

	if (session->ns_tape.td_fd == -1) {
		ndmp_log(session, LOG_ERR, "tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}
	if (session->ns_tape.td_mode == NDMP_TAPE_READ_MODE) {
		ndmp_log(session, LOG_ERR,
		    "tape device opened in read-only mode");
		reply.error = NDMP_PERMISSION_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}
	if (request->data_out.data_out_len == 0) {
		reply.error = NDMP_NO_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	/*
	 * V4 suggests that this should not be accepted
	 * when mover is in listen or active state
	 */
	if (session->ns_version == NDMPV4 &&
	    (session->ns_mover.md_state == NDMP_MOVER_STATE_LISTEN ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_ACTIVE)) {

		reply.error = NDMP_DEVICE_BUSY_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	/*
	 * Refer to the comment at the top of this file for
	 * Mammoth2 tape drives.
	 */
	if (session->ns_tape.td_eom_seen) {
		ndmp_debug(session, "eom_seen");
		ndmp_write_eom(session, session->ns_tape.td_fd);
		session->ns_tape.td_eom_seen = B_FALSE;
		reply.error = NDMP_EOM_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	n = write(session->ns_tape.td_fd, request->data_out.data_out_val,
	    request->data_out.data_out_len);

	session->ns_tape.td_eom_seen = B_FALSE;
	if (n >= 0) {
		session->ns_tape.td_write = 1;
	}
	if (n == 0) {
		ndmp_debug(session, "EOM detected");
		reply.error = NDMP_EOM_ERR;
		session->ns_tape.td_eom_seen = B_TRUE;
	} else if (n < 0) {
		ndmp_log(session, LOG_ERR, "tape write error: %s",
		    strerror(errno));
		reply.error = NDMP_IO_ERR;
	} else {
		reply.count = n;
		reply.error = NDMP_NO_ERR;
	}

	ndmp_send_reply(session, &reply);
}

/*
 * This handler handles tape_read requests.  This interface is a non-buffered
 * interface. Each read request maps directly to a read to the tape device. It
 * is the responsibility of the NDMP client to issue read requests with a
 * length that is at least as large as the record size used write the tape. The
 * tape driver always reads a full record. Data is discarded if the read
 * request is smaller than the record size.  It is the responsibility of the
 * NDMP client to ensure that the length is a multiple of the tape block size
 * if the tape device is in fixed block mode.
 */
void
ndmp_tape_read_v3(ndmp_session_t *session, void *body)
{
	ndmp_tape_read_request *request = body;
	ndmp_tape_read_reply reply;
	char *buf;
	int n, len;

	reply.data_in.data_in_len = 0;

	if (session->ns_tape.td_fd == -1) {
		ndmp_log(session, LOG_ERR, "tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}
	if (request->count == 0) {
		reply.error = NDMP_NO_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	/*
	 * V4 suggests that this should not be accepted when mover is in listen
	 * or active state
	 */
	if (session->ns_version == NDMPV4 &&
	    (session->ns_mover.md_state == NDMP_MOVER_STATE_LISTEN ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_ACTIVE)) {

		reply.error = NDMP_DEVICE_BUSY_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	if ((buf = ndmp_malloc(session, request->count)) == NULL) {
		reply.error = NDMP_NO_MEM_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}
	session->ns_tape.td_eom_seen = B_FALSE;

	n = read(session->ns_tape.td_fd, buf, request->count);
	if (n < 0) {
		/*
		 * This fix is for Symantec during importing of spanned data
		 * between the tapes.
		 */
		if (errno == ENOSPC) {
			reply.error = NDMP_EOF_ERR;
		} else {
			ndmp_log(session, LOG_ERR,
			    "tape read error: %s", strerror(errno));
			reply.error = NDMP_IO_ERR;
		}
	} else if (n == 0) {
		(void) ndmp_mtioctl(session, session->ns_tape.td_fd, MTFSF, 1);

		len = strlen(NDMP_EOM_MAGIC);
		(void) memset(buf, 0, len);
		n = read(session->ns_tape.td_fd, buf, len);
		buf[len] = '\0';

		ndmp_debug(session, "Checking EOM: nread %d [%s]", n, buf);

		if (strncmp(buf, NDMP_EOM_MAGIC, len) == 0) {
			reply.error = NDMP_EOM_ERR;
			ndmp_debug(session, "NDMP_EOM_ERR");
		} else {
			reply.error = NDMP_EOF_ERR;
			ndmp_debug(session, "NDMP_EOF_ERR");
		}
		if (n > 0)
			(void) ndmp_mtioctl(session, session->ns_tape.td_fd,
			    MTBSR, 1);
	} else {
		/*
		 * Symantec fix for import phase
		 *
		 * As import process from symantec skips filemarks
		 * they can come across to NDMP_EOM_MAGIC and treat
		 * it as data. This fix prevents the magic to be
		 * sent to the client and the read will return zero bytes
		 * and set the NDMP_EOM_ERR error. The tape should
		 * be positioned at the EOT side of the file mark.
		 */
		len = strlen(NDMP_EOM_MAGIC);
		if (n == len && strncmp(buf, NDMP_EOM_MAGIC, len) == 0) {
			reply.error = NDMP_EOM_ERR;
			(void) ndmp_mtioctl(session, session->ns_tape.td_fd,
			    MTFSF, 1);
			ndmp_debug(session, "NDMP_EOM_ERR");
		} else {
			session->ns_tape.td_pos += n;
			reply.data_in.data_in_len = n;
			reply.data_in.data_in_val = buf;
			reply.error = NDMP_NO_ERR;
		}
	}

	ndmp_send_reply(session, &reply);
	free(buf);
}

/*
 * This handler handles the ndmp_tape_get_state_request.  Status information
 * for the currently open tape device is returned.
 */
/*ARGSUSED*/
void
ndmp_tape_get_state_v4(ndmp_session_t *session, void *body)
{
	ndmp_tape_get_state_reply_v4 reply;
	struct mtget mtstatus;
	struct mtdrivetype_request dtpr;
	struct mtdrivetype dtp;

	if (session->ns_tape.td_fd == -1) {
		ndmp_log(session, LOG_ERR, "tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	/*
	 * Need code to detect NDMP_TAPE_STATE_NOREWIND
	 */

	if (ioctl(session->ns_tape.td_fd, MTIOCGET, &mtstatus) == -1) {
		ndmp_log(session, LOG_ERR,
		    "failed to get status information from tape: %s",
		    strerror(errno));

		reply.error = NDMP_IO_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	dtpr.size = sizeof (struct mtdrivetype);
	dtpr.mtdtp = &dtp;
	if (ioctl(session->ns_tape.td_fd, MTIOCGETDRIVETYPE, &dtpr) == -1) {
		ndmp_log(session, LOG_ERR,
		    "failed to get drive type information from tape: %s",
		    strerror(errno));

		reply.error = NDMP_IO_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	reply.flags = NDMP_TAPE_NOREWIND;

	reply.file_num = mtstatus.mt_fileno;
	reply.soft_errors = 0;
	reply.block_size = dtp.bsize;

	if (dtp.bsize == 0)
		reply.blockno = mtstatus.mt_blkno;
	else
		reply.blockno = mtstatus.mt_blkno *
		    (session->ns_mover.md_record_size / dtp.bsize);

	reply.total_space = long_long_to_quad(0); /* not supported */
	reply.space_remain = long_long_to_quad(0); /* not supported */

	reply.soft_errors = 0;
	reply.total_space = long_long_to_quad(0LL);
	reply.space_remain = long_long_to_quad(0LL);
	reply.unsupported = NDMP_TAPE_STATE_SOFT_ERRORS_INVALID |
	    NDMP_TAPE_STATE_TOTAL_SPACE_INVALID |
	    NDMP_TAPE_STATE_SPACE_REMAIN_INVALID |
	    NDMP_TAPE_STATE_PARTITION_INVALID;

	ndmp_debug(session, "f 0x%x, fnum %d, bsize %d, bno: %d",
	    reply.flags, reply.file_num, reply.block_size, reply.blockno);

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(session, &reply);
}

/*
 * This handler (v4) closes the currently open tape device.
 */
/*ARGSUSED*/
void
ndmp_tape_close_v4(ndmp_session_t *session, void *body)
{
	ndmp_tape_close_reply reply;

	if (session->ns_tape.td_fd == -1) {
		ndmp_log(session, LOG_ERR, "tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	/*
	 * V4 suggests that this should not be accepted
	 * when mover is in listen or active state
	 */
	if (session->ns_mover.md_state == NDMP_MOVER_STATE_LISTEN ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_ACTIVE) {
		reply.error = NDMP_DEVICE_BUSY_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}

	common_tape_close(session);
}

/*
 * Send a reply to the tape open message
 */
static void
tape_open_send_reply(ndmp_session_t *session, int err)
{
	ndmp_tape_open_reply reply;

	reply.error = err;
	ndmp_send_reply(session, &reply);
}

/*
 * Check the tape read mode is valid
 */
static boolean_t
validmode(int mode)
{
	boolean_t rv;

	switch (mode) {
	case NDMP_TAPE_READ_MODE:
	case NDMP_TAPE_WRITE_MODE:
	case NDMP_TAPE_RAW1_MODE:
	case NDMP_TAPE_RAW2_MODE:
		rv = B_TRUE;
		break;
	default:
		rv = B_FALSE;
	}

	return (rv);
}

/*
 * Generic function for closing the tape
 */
static void
common_tape_close(ndmp_session_t *session)
{
	ndmp_tape_close_reply reply;

	(void) ndmp_open_list_del(session->ns_tape.td_adapter_name,
	    session->ns_tape.td_sid, session->ns_tape.td_lun);
	(void) close(session->ns_tape.td_fd);
	session->ns_tape.td_fd = -1;
	session->ns_tape.td_sid = 0;
	session->ns_tape.td_lun = 0;
	session->ns_tape.td_write = 0;
	(void) memset(session->ns_tape.td_adapter_name, 0,
	    sizeof (session->ns_tape.td_adapter_name));
	session->ns_tape.td_record_count = 0;
	session->ns_tape.td_eom_seen = B_FALSE;

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(session, &reply);
}

/*
 * Will try to open the tape with the given flags and
 * path using the given retries and delay intervals
 */
int
tape_open(char *path, int flags)
{
	int fd, i;

	for (i = 0; i < ndmp_tape_open_retries; i++) {
		if ((fd = open(path, flags)) != -1)
			break;

		if (errno != EBUSY)
			break;

		(void) usleep(ndmp_tape_open_delay);
	}

	return (fd);
}
