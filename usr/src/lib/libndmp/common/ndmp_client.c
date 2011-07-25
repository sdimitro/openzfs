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

#include "ndmp_impl.h"

/*
 * Client-side support.  The client implementation in libndmp shares a lot of
 * the base message code with the server, so we support client (DMA) mode as
 * well server mode from the same base.  Apart from sharing connection and
 * message attributes, the interfaces are quite different.  Unlike the server
 * side, all session manipulation is driven from the consumer.
 *
 * The set of interfaces exported by the client is designed to support basic
 * testing of the server, including sending raw messages and coordinating 3-way
 * backup and restore.  It is not designed to be a general purpose DMA
 * implementation.  Features should be added to the client as necessary to
 * achieve the goals of consumers.
 */

/*
 * Instantiate a new client instance.  A single client instance can have
 * multiple active sessions; the client exists simply to provide a nexus for
 * the client-side configuration.
 */
ndmp_client_t *
ndmp_client_create(ndmp_client_conf_t *conf)
{
	ndmp_client_t *client;
	ndmp_session_t *session;

	if ((client = calloc(sizeof (ndmp_client_t), 1)) == NULL) {
		conf->nc_common.nc_log(NULL, LOG_ERR, "out of memory");
		return (NULL);
	}

	client->nc_conf = conf;
	session = &client->nc_global_session;
	session->ns_client = client;
	session->ns_conf = &conf->nc_common;
	session->ns_global = B_TRUE;
	session->ns_sock = -1;

	ndmp_debug(session, "NDMP client initialized");

	if (ndmp_load_prop(session) != 0) {
		free(client);
		return (NULL);
	}

	return (client);
}

/*
 * Destroy a client instance.  This will destroy any active sessions.  Because
 * client sessions are driven by consumers, it is important that consumers
 * ensure that no active session references exist prior to calling this
 * function.
 */
void
ndmp_client_destroy(ndmp_client_t *client)
{
	client->nc_shutdown = B_TRUE;
	ndmp_session_list_teardown(&client->nc_session_list);
	free(client);
}

/*
 * Connect to a remote host, establishing a new client session.
 */
ndmp_session_t *
ndmp_client_connect(ndmp_client_t *client, const char *host, int port)
{
	return (ndmp_connect(client, host, port));
}

/*
 * Disconnect from a remote host.  This does a hard close of the socket.
 * Consumers wishing to shutdown the connection to the server should call
 * ndmp_client_close() first.
 */
void
ndmp_client_disconnect(ndmp_session_t *session)
{
	ndmp_session_close(session);
}

/*
 * Raw mechanism to send a message.  Consumers should use messages and request
 * bodies from ndmp.h.  The result is manippulated with the ndmp_client_msg_*()
 * functions, and must be explicitly freed.
 */
ndmp_msg_t *
ndmp_client_send(ndmp_session_t *session, ndmp_message message, void *body)
{
	ndmp_msg_t *reply;
	int ret;

	if ((reply = ndmp_malloc(session, sizeof (ndmp_msg_t))) == NULL)
		return (NULL);

	ret = ndmp_send_request(session, message, body, reply);
	if (ret < 0) {
		free(reply);
		return (NULL);
	}

	return (reply);
}

/*
 * Return the error associated with the message.  This is the message-level
 * error, which is independent from any error that may be specified as part of
 * the message body.
 */
int
ndmp_client_msg_error(ndmp_msg_t *msg)
{
	return (msg->mi_hdr.error);
}

/*
 * Return the body of the message.  The contents of the message must be
 * interpreted according to the message type of the original request.
 */
void *
ndmp_client_msg_body(ndmp_msg_t *msg)
{
	return (msg->mi_body);
}

/*
 * Free memory associated with a reply.
 */
void
ndmp_client_msg_free(ndmp_session_t *session, ndmp_msg_t *msg)
{
	ndmp_free_message(session, msg);
	free(msg);
}

/*
 * Open an NDMP connection to the target.  This must be the first function
 * called after establishing the connection.  We first wait for the NOTIFY
 * CONNECTION STATUS request, which will contain the version the client
 * prefers.  If this is an acceptable value, then we have nothing to do here.
 * Otherwise, we need to issue a CONNECT OPEN request for each supported
 * version until we negotiate an acceptable version.
 */
int
ndmp_client_open(ndmp_session_t *session)
{
	ndmp_connect_open_request request;
	ndmp_connect_open_reply *reply = NULL;
	ndmp_msg_t msg;
	ndmp_notification_t *notification;
	char *reason;
	int max_vers, min_vers;
	int err;

	/*
	 * Wait for the NOTIFY STATUS message to be received.  This should be
	 * the first message sent, so we have a very short timeout.
	 */
	notification = ndmp_notify_wait(session, 1000, &err);
	if (notification == NULL) {
		if (err == ETIME)
			ndmp_log(session, LOG_ERR,
			    "timed out waiting for open notification");
		return (-1);
	}

	if (notification->nn_message != NDMP_NOTIFY_CONNECTION_STATUS) {
		ndmp_log(session, LOG_ERR,
		    "unxpected notification message 0x%x received before "
		    "connection status", notification->nn_message);
		ndmp_client_notify_free(session, notification);
		return (-1);
	}

	if (notification->nn_text != NULL)
		NDMP_ASPRINTF(&reason, ": %s", notification->nn_text);
	else
		reason = "";

	if (notification->nn_reason == NDMP_REFUSED) {
		ndmp_log(session, LOG_ERR, "connection refused%s", reason);
		ndmp_client_notify_free(session, notification);
		return (-1);
	} else if (notification->nn_reason == NDMP_SHUTDOWN) {
		ndmp_log(session, LOG_ERR, "connection shutdown unexpectedly%s",
		    reason);
		ndmp_client_notify_free(session, notification);
		return (-1);
	}

	ndmp_client_notify_free(session, notification);

	if (session->ns_version_known)
		return (0);

	/*
	 * We got the version number from the client but it wasn't acceptable,
	 * so now we try to negotiate the version via the CONNECT OPEN request.
	 */
	max_vers = ndmp_get_prop_int(&session->ns_client->nc_global_session,
	    NDMP_MAX_VERSION);
	min_vers = ndmp_get_prop_int(&session->ns_client->nc_global_session,
	    NDMP_MIN_VERSION);

	err = -1;
	for (request.protocol_version = max_vers;
	    request.protocol_version >= min_vers;
	    request.protocol_version--) {
		if ((err = ndmp_send_request(session, NDMP_CONNECT_OPEN,
		    &request, &msg)) < 0) {
			return (-1);
		}

		reply = msg.mi_body;
		if (err == 0)
			err = reply->error;

		ndmp_free_message(session, &msg);

		if (err == NDMP_NO_ERR)
			break;

		if (err != NDMP_ILLEGAL_ARGS_ERR) {
			ndmp_log(session, LOG_ERR,
			    "unexpected response 0x%x to connect open request",
			    err);
			return (-1);
		}
	}

	if (err != 0) {
		ndmp_log(session, LOG_ERR,
		    "unable to negotiate NDMP version");
		return (-1);
	}

	session->ns_version = request.protocol_version;
	session->ns_version_known = B_TRUE;

	return (0);
}

/*
 * Wait for the next server notification request to be received.  The result
 * must be freed with ndmp_client_notify_free().
 */
ndmp_notification_t *
ndmp_client_wait_notify(ndmp_session_t *session, uint_t timeout_ms,
    int *err)
{
	return (ndmp_notify_wait(session, timeout_ms, err));
}

/*
 * Free a notification structure returned by ndmp_client_wait_notify().
 */
/*ARGSUSED*/
void
ndmp_client_notify_free(ndmp_session_t *session,
    ndmp_notification_t *notification)
{
	free(notification->nn_text);
	free(notification);
}

/*
 * Graceful close of an NDMP connection.  We send the CONNECT CLOSE attempt and
 * (briefly) wait for a response before giving up.  This doesn't actually close
 * the connection socket; that is handled by the ndmp_client_terminate() call,
 * which can be invoked at any time if the consumer doesn't want to attempt a
 * graceful close.
 */
int
ndmp_client_close(ndmp_session_t *session)
{
	ndmp_notification_t *notification;
	int ret = -1;

	if (ndmp_send_request(session, NDMP_CONNECT_CLOSE, NULL, NULL) != 0)
		return (-1);

	/*
	 * This should be a quick operation, so we only wait a brief period for
	 * the resulting NOTIFY CONNECTION STATUS request.  We don't want a
	 * misbehaving server to keep us from shutting down the connection
	 * entirely.
	 */
	while ((notification = ndmp_notify_wait(session, 1000, NULL)) != NULL) {
		if (notification->nn_message == NDMP_NOTIFY_CONNECTION_STATUS &&
		    notification->nn_reason == NDMP_SHUTDOWN) {
			ndmp_client_notify_free(session, notification);
			ret = 0;
			break;
		}

		ndmp_client_notify_free(session, notification);
	}

	return (ret);
}

/*
 * Authenticate the client using MD5 authentication.  This method will return
 * -1 on failure, 1 if it's not supported (in which case we should fall back to
 * AUTH_TEXT), or 0 on success.
 */
static int
ndmp_client_auth_md5(ndmp_session_t *session, const char *user,
    const char *password)
{
	ndmp_config_get_auth_attr_request attr_request = { 0 };
	ndmp_config_get_auth_attr_reply *attr_reply;
	ndmp_connect_client_auth_request_v3 request;
	ndmp_auth_md5_v3 *auth_md5;
	ndmp_msg_t msg;
	ndmp_connect_client_auth_reply *reply;
	int err;

	/* Request the challenge from the server */
	attr_request.auth_type = NDMP_AUTH_MD5;
	if ((err = ndmp_send_request(session, NDMP_CONFIG_GET_AUTH_ATTR,
	    &attr_request, &msg)) < 0)
		return (-1);

	attr_reply = msg.mi_body;
	if (err == NDMP_NO_ERR)
		err = attr_reply->error;

	if (err == NDMP_ILLEGAL_ARGS_ERR ||
	    err == NDMP_NOT_SUPPORTED_ERR) {
		ndmp_free_message(session, &msg);
		return (1);
	} else if (err != NDMP_NO_ERR) {
		ndmp_free_message(session, &msg);
		return (-1);
	}

	/* generate the digest using the server challenge */
	request.auth_data.auth_type = NDMP_AUTH_MD5;
	auth_md5 = &request.auth_data.ndmp_auth_data_v3_u.auth_md5;
	auth_md5->auth_id = (char *)user;
	ndmp_create_md5_digest((unsigned char *)auth_md5->auth_digest,
	    password, (unsigned char *)
	    attr_reply->server_attr.ndmp_auth_attr_u.challenge);

	ndmp_free_message(session, &msg);

	/* now send the request */
	if ((err = ndmp_send_request(session, NDMP_CONNECT_CLIENT_AUTH,
	    &request, &msg)) < 0)
		return (-1);

	reply = msg.mi_body;
	if (err == NDMP_NO_ERR)
		err = reply->error;

	if (err == NDMP_ILLEGAL_ARGS_ERR ||
	    err == NDMP_NOT_SUPPORTED_ERR) {
		ndmp_free_message(session, &msg);
		return (1);
	}

	if (err != NDMP_NO_ERR) {
		ndmp_free_message(session, &msg);
		return (-1);
	}

	ndmp_free_message(session, &msg);
	return (0);
}

/*
 * Authenticate the client using text authentication.
 */
static int
ndmp_client_auth_text(ndmp_session_t *session, const char *user,
    const char *password)
{
	ndmp_connect_client_auth_request_v3 request;
	ndmp_auth_text_v3 *auth_text;
	ndmp_connect_client_auth_reply *reply;
	ndmp_msg_t msg;
	int ret;

	request.auth_data.auth_type = NDMP_AUTH_TEXT;
	auth_text = &request.auth_data.ndmp_auth_data_v3_u.auth_text;
	auth_text->auth_id = (char *)user;
	auth_text->auth_password = (char *)password;

	if ((ret = ndmp_send_request(session, NDMP_CONNECT_CLIENT_AUTH,
	    &request, &msg)) < 0)
		return (-1);

	reply = msg.mi_body;
	if (ret == NDMP_NO_ERR)
		ret = reply->error;

	ndmp_free_message(session, &msg);

	return (ret != NDMP_NO_ERR ? -1 : 0);
}

/*
 * Authenticate to a remote client.  If the auth type is specified, then only
 * that authentication type is attempted.  By default (type=0), we use MD5
 * and fall back to plaintext if it's not supported.
 */
int
ndmp_client_authenticate(ndmp_session_t *session, const char *user,
    const char *password, ndmp_auth_type type)
{
	int ret;

	if (type != NDMP_AUTH_TEXT) {
		ret = ndmp_client_auth_md5(session, user, password);
		if (ret <= 0)
			return (ret);
	}

	if (type == NDMP_AUTH_MD5) {
		ndmp_log(session, LOG_ERR,
		    "remote client doesn't supported required authentication "
		    "mode");
		return (-1);
	}

	if (ndmp_client_auth_text(session, user, password) != 0) {
		ndmp_log(session, LOG_ERR, "authentication failed");
		return (-1);
	}

	ndmp_debug(session, "successfully authenticated as user '%s'", user);

	return (0);
}

/*
 * Utility function to print out a ndmp_addr structure depending on the current
 * protocol version.
 */
static void
dump_addr(ndmp_session_t *session, const char *desc, void *raw)
{
	ulong_t addr;
	ushort_t port;

	if (session->ns_version == NDMPV3) {
		ndmp_addr_v3 *v3addr = raw;
		addr = v3addr->tcp_ip_v3;
		port = v3addr->tcp_port_v3;
	} else {
		ndmp_addr_v4 *v4addr = raw;
		addr = v4addr->tcp_ip_v4(0);
		port = v4addr->tcp_port_v4(0);
	}

	ndmp_debug(session, "%s = %s:%d", desc, inet_ntoa(IN_ADDR(addr)),
	    ntohs(port));
}

/*
 * Send an NDMP DATA LISTEN request to the server.  We only support TCP
 * requests, returning the address as an opaque type to the caller.  This can
 * later be used in ndmp_client_data_connect() to connect another NDMP server
 * to the returned port.
 */
ndmp_addr_t *
ndmp_client_data_listen(ndmp_session_t *session)
{
	ndmp_data_listen_request_v3 request;
	ndmp_data_listen_reply_v3 *reply_v3;
	ndmp_data_listen_reply_v4 *reply_v4;
	ndmp_msg_t msg;
	void *ret;
	int err;

	request.addr_type = NDMP_ADDR_TCP;

	if ((err = ndmp_send_request(session, NDMP_DATA_LISTEN, &request,
	    &msg)) < 0)
		return (NULL);

	reply_v3 = msg.mi_body;
	reply_v4 = msg.mi_body;

	/* the error is still the same for both requests */
	if (err == NDMP_NO_ERR)
		err = reply_v3->error;

	if (err != NDMP_NO_ERR) {
		ndmp_free_message(session, &msg);
		ndmp_log(session, LOG_ERR, "data listen request failed");
		return (NULL);
	}

	if (session->ns_version == NDMPV3) {
		if ((ret = ndmp_malloc(session,
		    sizeof (ndmp_addr_v3))) == NULL) {
			ndmp_free_message(session, &msg);
			return (NULL);
		}

		ndmp_copy_addr_v3(ret, &reply_v3->data_connection_addr);
	} else {
		if ((ret = ndmp_malloc(session,
		    sizeof (ndmp_addr_v4))) == NULL) {
			ndmp_free_message(session, &msg);
			return (NULL);
		}

		if (ndmp_copy_addr_v4(session, ret,
		    &reply_v4->connect_addr) != 0) {
			free(ret);
			ndmp_free_message(session, &msg);
			return (NULL);
		}
	}

	dump_addr(session, "remote data address", ret);

	ndmp_free_message(session, &msg);

	return (ret);
}

/*
 * Send a DATA CONNECT request to the server.  We only support TCP addresses,
 * and the address and port must be in network byte order.
 */
int
ndmp_client_data_connect(ndmp_session_t *session, ndmp_addr_t *addr)
{
	ndmp_data_connect_request_v3 request_v3 = { 0 };
	ndmp_data_connect_request_v4 request_v4 = { 0 };
	ndmp_data_connect_reply_v3 *reply;
	void *request;
	ndmp_msg_t msg;
	int err;

	if (session->ns_version == NDMPV3) {
		ndmp_copy_addr_v3(&request_v3.addr, addr);
		request = &request_v3;
	} else {
		if (ndmp_copy_addr_v4(session, &request_v4.addr, addr) != 0)
			return (-1);
		request = &request_v4;
	}

	if ((err = ndmp_send_request(session, NDMP_DATA_CONNECT, request,
	    &msg)) < 0) {
		return (-1);
	}

	reply = msg.mi_body;
	if (err == NDMP_NO_ERR)
		err = reply->error;

	if (err != NDMP_NO_ERR) {
		ndmp_free_message(session, &msg);
		free(request_v4.addr.tcp_addr_v4);
		ndmp_log(session, LOG_ERR, "failed to setup data connection");
		return (-1);
	}

	dump_addr(session, "data connection address", addr);

	ndmp_free_message(session, &msg);

	return (0);
}

/*
 * Free the memory associated with a response from ndmp_client_data_listen().
 */
void
ndmp_client_addr_free(ndmp_session_t *session, ndmp_addr_t *addr)
{
	if (session->ns_version == NDMPV4) {
		ndmp_addr_v4 *v4addr = addr;
		free(v4addr->tcp_addr_v4);
	}

	free(addr);
}

/*
 * Return the set of backup types supported by the server.  This is returned as
 * as a raw message, which is later accessed by ndmp_client_butype_info().
 * This allows clients to explicitly free the message once they are done with
 * it.
 */
ndmp_msg_t *
ndmp_client_butypes_get(ndmp_session_t *session)
{
	ndmp_config_get_butype_info_reply_v3 *reply;
	ndmp_msg_t *msg;
	int err;

	if ((msg = ndmp_malloc(session, sizeof (ndmp_msg_t))) == NULL)
		return (NULL);

	if ((err = ndmp_send_request(session, NDMP_CONFIG_GET_BUTYPE_INFO, NULL,
	    msg)) < 0) {
		free(msg);
		return (NULL);
	}

	reply = msg->mi_body;
	if (err == NDMP_NO_ERR)
		err = reply->error;

	if (err != NDMP_NO_ERR) {
		ndmp_log(session, LOG_ERR, "failed to get backup type info");
		ndmp_client_msg_free(session, msg);
		return (NULL);
	}

	return (msg);
}

/*
 * Return information about a particular backup type returned by
 * ndmp_client_butypes_get().  If the index exceeds the set of available backup
 * types, NULL is returned.
 */
/*ARGSUSED*/
ndmp_butype_info *
ndmp_client_butypes_info(ndmp_session_t *session, ndmp_msg_t *msg,
    int idx)
{
	ndmp_config_get_butype_info_reply_v3 *reply = msg->mi_body;

	if (idx >= reply->butype_info.butype_info_len)
		return (NULL);

	return (&reply->butype_info.butype_info_val[idx]);
}

/*
 * Start a backup on the remote server, using the given environment.  This
 * currently only supports V3 or higher.
 */
int
ndmp_client_start_backup(ndmp_session_t *session, const char *butype,
    int envsize, ndmp_pval *env)
{
	ndmp_data_start_backup_request_v3 request = { 0 };
	ndmp_data_start_backup_reply *reply;
	int err;
	ndmp_msg_t msg;

	request.bu_type = (char *)butype;
	request.env.env_len = envsize;
	request.env.env_val = env;

	if ((err = ndmp_send_request(session, NDMP_DATA_START_BACKUP,
	    &request, &msg)) < 0) {
		return (-1);
	}

	reply = msg.mi_body;
	if (err == NDMP_NO_ERR)
		err = reply->error;

	ndmp_free_message(session, &msg);

	if (err != NDMP_NO_ERR) {
		ndmp_log(session, LOG_ERR, "start backup request failed");
		return (-1);
	}

	return (0);
}

/*
 * Start a recover on the remote server, using the given environment and name
 * list.  This currently only support V3 or higher.
 */
int
ndmp_client_start_recover(ndmp_session_t *session, const char *butype,
    int envsize, ndmp_pval *env, int nsize, ndmp_name_v3 *nlist)
{
	ndmp_data_start_recover_request_v3 request = { 0 };
	ndmp_data_start_recover_reply *reply;
	int err;
	ndmp_msg_t msg;

	request.bu_type = (char *)butype;
	request.env.env_len = envsize;
	request.env.env_val = env;
	request.nlist.nlist_len = nsize;
	request.nlist.nlist_val = nlist;

	if ((err = ndmp_send_request(session, NDMP_DATA_START_RECOVER,
	    &request, &msg)) < 0) {
		return (-1);
	}

	reply = msg.mi_body;
	if (err == NDMP_NO_ERR)
		err = reply->error;

	ndmp_free_message(session, &msg);

	if (err != NDMP_NO_ERR) {
		ndmp_log(session, LOG_ERR, "start restore request failed");
		return (-1);
	}

	return (0);
}

/*
 * Get a list of available filesystems from the remote server.
 */
ndmp_msg_t *
ndmp_client_fs_list(ndmp_session_t *session)
{
	ndmp_config_get_fs_info_reply_v3 *reply;
	ndmp_msg_t *msg;
	int err;

	if ((msg = ndmp_malloc(session, sizeof (ndmp_msg_t))) == NULL)
		return (NULL);

	if ((err = ndmp_send_request(session, NDMP_CONFIG_GET_FS_INFO, NULL,
	    msg)) < 0) {
		free(msg);
		return (NULL);
	}

	reply = msg->mi_body;
	if (err == NDMP_NO_ERR)
		err = reply->error;

	if (err != NDMP_NO_ERR) {
		ndmp_log(session, LOG_ERR, "failed to get filesystem info");
		ndmp_client_msg_free(session, msg);
		return (NULL);
	}

	return (msg);

}

/*ARGSUSED*/
ndmp_fs_info_v3 *
ndmp_client_fs_info(ndmp_session_t *session, ndmp_msg_t *msg, int idx)
{
	ndmp_config_get_fs_info_reply_v3 *reply = msg->mi_body;

	if (idx >= reply->fs_info.fs_info_len)
		return (NULL);

	return (&reply->fs_info.fs_info_val[idx]);
}
