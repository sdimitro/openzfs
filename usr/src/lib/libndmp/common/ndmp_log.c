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
 * Copyright (c) 2011 by Delphix.  All rights reserved
 */

#include "ndmp_impl.h"

/*
 * Client-side log handlers.  For clients, consumers can provide two log
 * callbacks: a local logging callback and a remote one.  These handlers invoke
 * the remote logging callback to indicate the message is coming from the
 * remove server.
 */

void
ndmp_log_log_v2(ndmp_session_t *session, void *body)
{
	ndmp_log_log_request *request = body;
	ndmp_client_conf_t *conf = session->ns_client->nc_conf;

	conf->nc_log_remote(session, LOG_INFO, request->entry);
}

void
ndmp_log_debug_v2(ndmp_session_t *session, void *body)
{
	ndmp_log_debug_request *request = body;
	ndmp_client_conf_t *conf = session->ns_client->nc_conf;

	conf->nc_log_remote(session, LOG_DEBUG, request->message);
}

void
ndmp_log_file_v2(ndmp_session_t *session, void *body)
{
	ndmp_log_file_request *request = body;
	ndmp_client_conf_t *conf = session->ns_client->nc_conf;
	char *msg;

	switch (request->error) {
	case NDMP_NO_ERR:
		NDMP_ASPRINTF(&msg,
		    "file '%s' successfully recovered", request->name);
		conf->nc_log_remote(session, LOG_INFO, msg);
		break;

	case NDMP_PERMISSION_ERR:
		NDMP_ASPRINTF(&msg,
		    "failed to recover file '%s': permission denied",
		    request->name);
		conf->nc_log_remote(session, LOG_ERR, msg);
		break;

	case NDMP_FILE_NOT_FOUND_ERR:
		NDMP_ASPRINTF(&msg,
		    "failed to recover file '%s': no such file or directory",
		    request->name);
		conf->nc_log_remote(session, LOG_ERR, msg);
		break;

	default:
		NDMP_ASPRINTF(&msg, "failed to recover file '%s'",
		    request->name);
		conf->nc_log_remote(session, LOG_ERR, msg);
		break;
	}
}

/*
 * Convert from a NDMP log level into a syslog level.
 */
static int
ndmp_convert_log_type(int type)
{
	switch (type) {
	case NDMP_LOG_NORMAL:
		return (LOG_INFO);

	case NDMP_LOG_DEBUG:
		return (LOG_DEBUG);

	case NDMP_LOG_WARNING:
		return (LOG_WARNING);

	case NDMP_LOG_ERROR:
	default:
		return (LOG_ERR);
	}
}

void
ndmp_log_message_v3(ndmp_session_t *session, void *body)
{
	ndmp_log_message_request_v3 *request = body;
	ndmp_client_conf_t *conf = session->ns_client->nc_conf;

	conf->nc_log_remote(session, ndmp_convert_log_type(request->log_type),
	    request->entry);
}

void
ndmp_log_message_v4(ndmp_session_t *session, void *body)
{
	ndmp_log_message_request_v4 *request = body;
	ndmp_client_conf_t *conf = session->ns_client->nc_conf;

	conf->nc_log_remote(session, ndmp_convert_log_type(request->log_type),
	    request->entry);
}
