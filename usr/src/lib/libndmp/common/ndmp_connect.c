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

/*
 * NDMP connect handlers.
 */

/*
 * Handle the connect open request.  This is used to handle version negotiation
 * in the event the client refuses the version specified in the initial
 * NOTIFY_CONNECTION_STATUS request.
 */
void
ndmp_connect_open_v3(ndmp_session_t *session, void *body)
{
	ndmp_connect_open_request *request = (ndmp_connect_open_request *)body;
	ndmp_connect_open_reply reply;

	reply.error = NDMP_NO_ERR;

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE ||
	    session->ns_data.dd_state != NDMP_DATA_STATE_IDLE) {
		ndmp_log(session, LOG_ERR, "invalid state for command");
		reply.error = NDMP_ILLEGAL_STATE_ERR;
	} else if (request->protocol_version > ndmp_get_prop_int(session,
	    NDMP_MAX_VERSION) ||
	    request->protocol_version < ndmp_get_prop_int(session,
	    NDMP_MIN_VERSION)) {
		/*
		 * We don't log an error here as this is part of the version
		 * negotiation protocol.
		 */
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
	}

	ndmp_send_reply(session, &reply);

	/*
	 * Set the protocol version.  Must wait until after sending the reply
	 * since the reply must be sent using the same protocol version that
	 * was used to process the request.
	 */
	if (reply.error == NDMP_NO_ERR) {
		ndmp_debug(session, "negotiated version %d",
		    request->protocol_version);
		session->ns_version = request->protocol_version;
	}
}

/*
 * This handler authorizes the NDMP client to the server.
 */
void
ndmp_connect_client_auth_v3(ndmp_session_t *session, void *body)
{
	ndmp_connect_client_auth_request_v3 *request;
	ndmp_connect_client_auth_reply_v3 reply;
	ndmp_auth_text_v3 *auth;
	ndmp_server_conf_t *conf = session->ns_server->ns_conf;
	ndmp_auth_md5_v3 *md5;

	request = (ndmp_connect_client_auth_request_v3 *)body;
	ndmp_debug(session, "authentication request type=%s",
	    request->auth_data.auth_type == NDMP_AUTH_NONE ? "None" :
	    request->auth_data.auth_type == NDMP_AUTH_TEXT ? "Text" :
	    request->auth_data.auth_type == NDMP_AUTH_MD5 ? "MD5" : "Invalid");

	reply.error = NDMP_NO_ERR;

	switch (request->auth_data.auth_type) {
	case NDMP_AUTH_NONE:
		ndmp_log(session, LOG_ERR, "invalid authorization type, "
		    "must be MD5 or cleartext");
		reply.error = NDMP_NOT_SUPPORTED_ERR;
		break;

	case NDMP_AUTH_TEXT:
		auth = &request->auth_data.ndmp_auth_data_v3_u.auth_text;
		reply.error = conf->ns_auth_text(session, auth->auth_id,
		    auth->auth_password);
		break;

	case NDMP_AUTH_MD5:
		md5 = &request->auth_data.ndmp_auth_data_v3_u.auth_md5;
		reply.error = conf->ns_auth_md5(session, md5->auth_id,
		    md5->auth_digest, session->ns_challenge);
		break;

	default:
		ndmp_log(session, LOG_ERR, "invalid authorization type, "
		    "must be MD5 or cleartext");
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
	}

	session->ns_authorized = (reply.error == NDMP_NO_ERR);

	ndmp_send_reply(session, &reply);
}

/*
 * Close the session.
 */
/*ARGSUSED*/
void
ndmp_connect_close_v3(ndmp_session_t *session, void *body)
{
	ndmp_notify_connected_request req;

	/* Send the SHUTDOWN message before closing the session. */
	req.reason = NDMP_SHUTDOWN;
	req.protocol_version = session->ns_version;
	req.text_reason = "Connection closed by server.";

	if (ndmp_send_request(session, NDMP_NOTIFY_CONNECTION_STATUS,
	    &req, NULL) < 0) {
		return;
	}

	ndmp_session_close(session);
}
