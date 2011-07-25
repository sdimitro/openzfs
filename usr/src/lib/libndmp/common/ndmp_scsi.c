/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
/* Copyright (c) 2011 by Delphix.  All rights reserved. */

#include "ndmp_impl.h"

static void scsi_open_send_reply(ndmp_session_t *session, int err);
static void common_open(ndmp_session_t *session, char *devname);
static void common_set_target(ndmp_session_t *session, char *device,
    ushort_t controller, ushort_t sid, ushort_t lun);


/*
 * ************************************************************************
 * NDMP V2 HANDLERS
 * ************************************************************************
 */

/*
 * This handler opens the specified SCSI device.
 */
void
ndmp_scsi_open_v2(ndmp_session_t *session, void *body)
{
	ndmp_scsi_open_request_v2 *request = (ndmp_scsi_open_request_v2 *)body;

	common_open(session, request->device.name);
}

/*
 * This handler closes the currently open SCSI device.
 */
/*ARGSUSED*/
void
ndmp_scsi_close_v2(ndmp_session_t *session, void *body)
{
	ndmp_scsi_close_reply reply;

	if (session->ns_scsi.sd_is_open == -1) {
		ndmp_log(session, LOG_ERR, "SCSI device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		return;
	}
	(void) ndmp_open_list_del(session->ns_scsi.sd_adapter_name,
	    session->ns_scsi.sd_sid,
	    session->ns_scsi.sd_lun);
	(void) close(session->ns_scsi.sd_devid);

	session->ns_scsi.sd_is_open = -1;
	session->ns_scsi.sd_devid = -1;
	session->ns_scsi.sd_sid = 0;
	session->ns_scsi.sd_lun = 0;
	session->ns_scsi.sd_valid_target_set = B_FALSE;
	(void) memset(session->ns_scsi.sd_adapter_name, 0,
	    sizeof (session->ns_scsi.sd_adapter_name));

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(session, &reply);
}

/*
 * This handler returns state information for the currently open SCSI device.
 * Since the implementation only supports the opening of a specific SCSI
 * device, as opposed to a device that can talk to multiple SCSI targets,
 * this request is not supported. This request is only appropriate for
 * implementations that support device files that can target multiple
 * SCSI devices.
 */
/*ARGSUSED*/
void
ndmp_scsi_get_state_v2(ndmp_session_t *session, void *body)
{
	ndmp_scsi_get_state_reply reply;

	if (session->ns_scsi.sd_is_open == -1)
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
	else if (!session->ns_scsi.sd_valid_target_set) {
		reply.error = NDMP_NO_ERR;
		reply.target_controller = -1;
		reply.target_id = -1;
		reply.target_lun = -1;
	} else {
		reply.error = NDMP_NO_ERR;
		reply.target_controller = 0;
		reply.target_id = session->ns_scsi.sd_sid;
		reply.target_lun = session->ns_scsi.sd_lun;
	}

	ndmp_send_reply(session, &reply);
}

/*
 * This handler sets the SCSI target of the SCSI device.  It is only valid to
 * use this request if the opened SCSI device is capable of talking to multiple
 * SCSI targets.  Since the implementation only supports the opening of a
 * specific SCSI device, as opposed to a device that can talk to multiple SCSI
 * targets, this request is not supported. This request is only appropriate for
 * implementations that support device files that can target multiple
 * SCSI devices.
 */
void
ndmp_scsi_set_target_v2(ndmp_session_t *session, void *body)
{
	ndmp_scsi_set_target_request_v2 *request;

	request = (ndmp_scsi_set_target_request_v2 *) body;

	common_set_target(session, request->device.name,
	    request->target_controller, request->target_id,
	    request->target_lun);
}

/*
 * This handler resets the currently targeted SCSI device.
 */
/*ARGSUSED*/
void
ndmp_scsi_reset_device_v2(ndmp_session_t *session, void *body)
{
	ndmp_scsi_reset_device_reply reply;
	struct uscsi_cmd  cmd;

	if (session->ns_scsi.sd_devid == -1) {
		ndmp_log(session, LOG_ERR, "SCSI device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
	} else {
		reply.error = NDMP_NO_ERR;
		(void) memset((void*)&cmd, 0, sizeof (cmd));
		cmd.uscsi_flags |= USCSI_RESET;
		if (ioctl(session->ns_scsi.sd_devid, USCSICMD, &cmd) < 0) {
			ndmp_log(session, LOG_ERR, "reset command failed: %s",
			    strerror(errno));
			reply.error = NDMP_IO_ERR;
		}
	}

	ndmp_send_reply(session, &reply);
}

/*
 * This handler resets the currently targeted SCSI bus.
 */
/*ARGSUSED*/
void
ndmp_scsi_reset_bus_v2(ndmp_session_t *session, void *body)
{
	ndmp_scsi_reset_bus_reply reply;

	reply.error = NDMP_NOT_SUPPORTED_ERR;

	ndmp_send_reply(session, &reply);
}

/*
 * This handler sends the CDB to the currently targeted SCSI device.
 */
void
ndmp_scsi_execute_cdb_v2(ndmp_session_t *session, void *body)
{
	ndmp_execute_cdb_request *request = (ndmp_execute_cdb_request *) body;
	ndmp_execute_cdb_reply reply;

	if (session->ns_scsi.sd_is_open == -1 ||
	    !session->ns_scsi.sd_valid_target_set) {
		(void) memset(&reply, 0, sizeof (reply));

		ndmp_log(session, LOG_ERR, "SCSI device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
	} else {
		ndmp_execute_cdb(session, session->ns_scsi.sd_adapter_name,
		    session->ns_scsi.sd_sid, session->ns_scsi.sd_lun, request);
	}
}


/*
 * ************************************************************************
 * NDMP V3 HANDLERS
 * ************************************************************************
 */

/*
 * This handler opens the specified SCSI device.
 */
void
ndmp_scsi_open_v3(ndmp_session_t *session, void *body)
{
	ndmp_scsi_open_request_v3 *request = (ndmp_scsi_open_request_v3 *)body;

	common_open(session, request->device);
}


/*
 * This handler sets the SCSI target of the SCSI device.  It is only valid to
 * use this request if the opened SCSI device is capable of talking to multiple
 * SCSI targets.
 */
void
ndmp_scsi_set_target_v3(ndmp_session_t *session, void *body)
{
	ndmp_scsi_set_target_request_v3 *request;

	request = (ndmp_scsi_set_target_request_v3 *) body;

	common_set_target(session, request->device,
	    request->target_controller, request->target_id,
	    request->target_lun);
}


/*
 * ************************************************************************
 * NDMP V4 HANDLERS
 * ************************************************************************
 */

/*
 * ************************************************************************
 * LOCALS
 * ************************************************************************
 */

/*
 * Send a reply for SCSI open command
 */
static void
scsi_open_send_reply(ndmp_session_t *session, int err)
{
	ndmp_scsi_open_reply reply;

	reply.error = err;
	ndmp_send_reply(session, &reply);
}

/*
 * Common SCSI open function for all NDMP versions
 */
static void
common_open(ndmp_session_t *session, char *devname)
{
	char adptnm[SCSI_MAX_NAME];
	int sid, lun;
	int err;
	int devid;

	err = NDMP_NO_ERR;

	if (session->ns_tape.td_fd != -1 || session->ns_scsi.sd_is_open != -1) {
		ndmp_log(session, LOG_ERR,
		    "session already has a tape or SCSI device open");
		err = NDMP_DEVICE_OPENED_ERR;
	} else {
		ndmp_debug(session, "Adapter device found: %s", devname);
		(void) strlcpy(adptnm, devname, SCSI_MAX_NAME-2);
		adptnm[SCSI_MAX_NAME-1] = '\0';
		sid = lun = -1;

		scsi_find_sid_lun(session, devname, &sid, &lun);
		if (!ndmp_open_list_exists(devname, sid, lun) &&
		    (devid = open(devname, O_RDWR | O_NDELAY)) < 0) {
			ndmp_log(session, LOG_ERR,
			    "failed to open device %s: %s",
			    devname, strerror(errno));
			err = NDMP_NO_DEVICE_ERR;
		}
	}

	if (err != NDMP_NO_ERR) {
		scsi_open_send_reply(session, err);
		return;
	}

	switch (ndmp_open_list_add(session, adptnm, sid, lun, devid)) {
	case 0:
		/* OK */
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
		scsi_open_send_reply(session, err);
		return;
	}

	(void) strlcpy(session->ns_scsi.sd_adapter_name, adptnm, SCSI_MAX_NAME);
	session->ns_scsi.sd_is_open = 1;
	session->ns_scsi.sd_devid = devid;
	if (sid != -1) {
		session->ns_scsi.sd_sid = sid;
		session->ns_scsi.sd_lun = lun;
		session->ns_scsi.sd_valid_target_set = B_TRUE;
	} else {
		session->ns_scsi.sd_sid = session->ns_scsi.sd_lun = -1;
		session->ns_scsi.sd_valid_target_set = B_FALSE;
	}

	scsi_open_send_reply(session, err);
}

/*
 * Set the SCSI target (SCSI number, LUN number, controller number)
 */
/*ARGSUSED*/
static void
common_set_target(ndmp_session_t *session, char *device,
    ushort_t controller, ushort_t sid, ushort_t lun)
{
	ndmp_scsi_set_target_reply reply;
	int type;

	reply.error = NDMP_NO_ERR;

	if (session->ns_scsi.sd_is_open == -1) {
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
	} else if (!scsi_dev_exists(session, sid, lun)) {
		ndmp_log(session, LOG_ERR,
		    "no such SCSI device: target %d, LUN %d", sid, lun);
		reply.error = NDMP_NO_DEVICE_ERR;
	} else {
		type = scsi_get_devtype(session, sid, lun);
		if (type != DTYPE_SEQUENTIAL && type != DTYPE_CHANGER) {
			ndmp_log(session, LOG_ERR,
			    "not a tape or robot device: target %d, LUN %d.",
			    sid, lun);
			reply.error = NDMP_ILLEGAL_ARGS_ERR;
		}
	}

	if (reply.error != NDMP_NO_ERR) {
		ndmp_send_reply(session, &reply);
		return;
	}

	/*
	 * The open_list must be updated if the SID or LUN are going to be
	 * changed.  Close uses the same SID & LUN for removing the entry
	 * from the open_list.
	 */
	if (sid != session->ns_scsi.sd_sid || lun != session->ns_scsi.sd_lun) {
		switch (ndmp_open_list_add(session,
		    session->ns_scsi.sd_adapter_name, sid, lun, 0)) {
		case 0:
			(void) ndmp_open_list_del(session->
			    ns_scsi.sd_adapter_name, session->ns_scsi.sd_sid,
			    session->ns_scsi.sd_lun);
			break;
		case EBUSY:
			reply.error = NDMP_DEVICE_BUSY_ERR;
			break;
		case ENOMEM:
			reply.error = NDMP_NO_MEM_ERR;
			break;
		default:
			reply.error = NDMP_IO_ERR;
		}
	}

	if (reply.error == NDMP_NO_ERR) {
		ndmp_debug(session, "Updated sid %d lun %d", sid, lun);
		session->ns_scsi.sd_sid = sid;
		session->ns_scsi.sd_lun = lun;
		session->ns_scsi.sd_valid_target_set = B_TRUE;
	}

	ndmp_send_reply(session, &reply);
}

/*
 * gets the adapter, and returns the sid and lun number
 */
void
scsi_find_sid_lun(ndmp_session_t *session, char *devname, int *sid, int *lun)
{
	scsi_device_t *sdp;

	for (sdp = session->ns_server->ns_scsi_devices; sdp != NULL;
	    sdp = sdp->sd_next) {
		if (strcmp(devname, sdp->sd_name) == 0) {
			*sid = sdp->sd_sid;
			*lun = sdp->sd_lun;
			return;
		}
	}

	*sid = -1;
	*lun = -1;
}
