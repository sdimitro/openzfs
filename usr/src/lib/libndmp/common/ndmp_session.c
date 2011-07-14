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
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/* Copyright (c) 2011 by Delphix.  All rights reserved. */

/*
 * Sessions, clients, and servers.
 *
 * The libndmp library supports running both as a server and as a client (DMA).
 * Both instances use a session to represent an active connection to a remote
 * host, either due to accepting a new connection or by making an explicit
 * connection to a remote host.
 *
 * Every session has a thread that is asynchronously waiting for requests, and
 * every session is placed on the session list for the client or server
 * instance of which it is a part.  Destroying a server or client will poke all
 * active sessions to exit, and then wait for the connection list to be drained
 * before returning.
 *
 * There is also a special 'global' session for both the client and the server.
 * This is not a session in the traditional sense, but is used in contexts
 * where we need to access the consumer-provided callbacks but we don't yet
 * have a session.
 *
 *
 * Threads, suspending, and aborting sessions.
 *
 * For server side sessions, there are potentially several async threads in
 * progress at any given time.  We have:
 *
 *	session handler		Main thread, processing message requests.
 *
 *	mover writer		Thread buffering output to a socket or tape.
 *
 *	mover reader		Thread buffering output from a socket or tape.
 *
 *	data thread		Thread owned by the consumer and created in
 *      			response to a backup/recover request.
 *
 * Of these, the session handler thread exists for the life of the session,
 * while the remaining are only active during a data operation.  Since there
 * can be multiple data operations within one session (even if one is aborted),
 * we need a way to signal that the current data operation is complete without
 * desttroying the entire session.  It is up to the consumers to provide an
 * abort operation, but the expectation is that will work by signalling the
 * thread, as it could be stuck in a read() or cv_wait().
 *
 * Once the consumer thread is done, we then stop the async reader/writer
 * threads by closing any file descriptors they may be using and waiting for
 * htem to exit.
 *
 * We keep the following state variables per session:
 *
 *	ns_eof		A fatal error has occurred on the connection.  This
 *			could be due to a connection level event, or due to
 *			some other internal error.
 *
 *	ns_conn_error	For connection-level events, records the error
 *			associated with the event.  This can be EIO or
 *			ECONNRESET.
 *
 *	dd_abort	Indicates that an explicit request was made
 *			to abort the data operation.  This is set both when an
 *			explicit request was made, or when we get EINTR in a
 *			blocking call.  This is reset after each data
 *			operation.
 *
 *	ns_shutdown	Indicates that the entire server is to be shutdown.
 *			This will abort any active data operation as well as
 *			stop the main message processing thread.
 *
 * These are hidden behind the following functions:
 *
 *	ndmp_session_error()	Returns the session error.  This could be
 *				ns_conn_error, or ESHUTDOWN or EINTR for
 *				shutdown and abort, respectively.
 *
 *	ndmp_session_data_stop() Abort the current data session.
 */

#include "ndmp_impl.h"

/*
 * Add a session to the session list.
 */
static void
ndmp_session_list_add(ndmp_session_list_t *list, ndmp_session_t *session)
{
	(void) mutex_lock(&list->nsl_lock);
	session->ns_next = list->nsl_head;
	list->nsl_head = session;
	list->nsl_count++;
	(void) mutex_unlock(&list->nsl_lock);
}

/*
 * Remove a session from the session list.  If this is the last session to be
 * removed, signal any ndmp_session_list_destroy() waiters.
 */
static void
ndmp_session_list_remove(ndmp_session_list_t *list, ndmp_session_t *session)
{
	ndmp_session_t **search;

	(void) mutex_lock(&list->nsl_lock);
	for (search = &list->nsl_head; *search != NULL;
	    search = &(*search)->ns_next) {
		if (*search == session)
			break;
	}
	assert(*search != NULL);
	*search = (*search)->ns_next;
	list->nsl_count--;

	if (list->nsl_count == 0)
		(void) cond_signal(&list->nsl_cv);
	(void) mutex_unlock(&list->nsl_lock);
}

/*
 * Mark a given session as inactive.  This is used in the client when we're
 * done processing messages, so we know when it's save to teardown the client
 * even if the sessions aren't explicitly destroyed.
 */
static void
ndmp_session_list_inactive(ndmp_session_list_t *list)
{
	(void) mutex_lock(&list->nsl_lock);
	list->nsl_count--;
	if (list->nsl_count == 0)
		(void) cond_signal(&list->nsl_cv);
	(void) mutex_unlock(&list->nsl_lock);
}

/*
 * Tear down the resources associated with a session, remove it from the client
 * or server list, and free memory.  This is called when the connection handler
 * is complete, and when destroying the session on error during creation.
 */
static void
ndmp_session_destroy(ndmp_session_t *session)
{
	ndmp_session_close(session);

	if (session->ns_scsi.sd_is_open != -1) {
		(void) ndmp_open_list_del(session->ns_scsi.sd_adapter_name,
		    session->ns_scsi.sd_sid, session->ns_scsi.sd_lun);
	}
	if (session->ns_tape.td_fd != -1) {
		(void) close(session->ns_tape.td_fd);
		(void) ndmp_open_list_del(session->ns_tape.td_adapter_name,
		    session->ns_tape.td_sid, session->ns_tape.td_lun);
	}

	if (session->ns_server != NULL) {
		ndmp_mover_shut_down(session);
		ndmp_data_cleanup(session);
		ndmp_mover_cleanup(session);
	}

	xdr_destroy(&session->ns_xdrs);

	if (session->ns_server != NULL) {
		ndmp_session_list_remove(&session->ns_server->ns_session_list,
		    session);
	} else {
		ndmp_session_list_remove(&session->ns_client->nc_session_list,
		    session);
	}

	free(session);
}

/*
 * Teardown all sessions in the given session list.  This will close all
 * sessions and then wait for the processing threads to exit (by virtue of the
 * session being removed from the list).
 */
void
ndmp_session_list_teardown(ndmp_session_list_t *list)
{
	ndmp_session_t *session;

	(void) mutex_lock(&list->nsl_lock);

	/* First go through and close all sessions */
	for (session = list->nsl_head; session != NULL;
	    session = session->ns_next) {
		ndmp_session_close(session);
	}

	/* And wait for them to exit */
	while (list->nsl_count != 0)
		(void) cond_wait(&list->nsl_cv, &list->nsl_lock);

	(void) mutex_unlock(&list->nsl_lock);

	/*
	 * Teardown any client-side sessions.  We need to do this outside the
	 * lock, and because we know no one else is modifying the list we can
	 * do this safely.
	 */
	while (list->nsl_head != NULL)
		ndmp_session_destroy(list->nsl_head);
}

/*
 * Close a session.  This simply closes the socket and notes that the
 * session is closed.  This will cause the async session handler to exit.
 */
void
ndmp_session_close(ndmp_session_t *session)
{
	ndmp_session_failed(session, ESHUTDOWN);
	if (session->ns_sock != -1) {
		(void) close(session->ns_sock);
		session->ns_sock = -1;
	}
}

/*
 * Session file handler function.  Called by ndmp_select when data is available
 * to be read on the connection.  This simply processes the requests and notes
 * the connection as closed if anything fails.
 */
/*ARGSUSED*/
static void
session_file_handler(ndmp_session_t *session, int fd, ulong_t mode)
{
	fd_set fds;
	struct timeval timeout;

	(void) mutex_lock(&session->ns_lock);

	/*
	 * We need to check if there is data to be read after we grab the lock.
	 * Otherwise, another thread may have processed the data while waiting
	 * for a response after we noticed data was available but before we got
	 * a chance to read requests.  Without this check, we'd end up sleeping
	 * waiting for non-existent data with the lock held, which will prevent
	 * other threads from making forward progress.
	 */
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	if (select(FD_SETSIZE, &fds, NULL, NULL, &timeout) == 0) {
		(void) mutex_unlock(&session->ns_lock);
		return;
	}

	if (ndmp_process_requests(session, B_FALSE) < 0)
		ndmp_session_failed(session, 0);

	(void) mutex_unlock(&session->ns_lock);
}


/*
 * Session worker.  This thread is kicked off asynchronously as part of creating
 * a session.  This thread is very simple, as most of the work is done setting
 * up the session in synchronous context.
 */
static void *
ndmp_session_worker(void *param)
{
	ndmp_session_t *session = param;
	ndmp_notify_connected_request req = { 0 };
	int sock;

	/*
	 * If this is a server session, send the NOTIFY CONNECTION STATUS
	 * request to the client.
	 */
	if (session->ns_server != NULL) {
		req.reason = NDMP_CONNECTED;
		req.protocol_version = session->ns_version;
		req.text_reason = "";

		if (ndmp_send_request(session, NDMP_NOTIFY_CONNECTION_STATUS,
		    &req, NULL) < 0) {
			/*
			 * If we can't send the notify request, then don't wait
			 * for a response as the client may be blocked waiting
			 * for us.
			 */
			ndmp_session_failed(session, 0);
		}
	}

	/* Remember the session socket as it may be closed on us */
	sock = session->ns_sock;
	if (ndmp_add_file_handler(session, session, sock,
	    NDMPD_SELECT_MODE_READ, HC_CLIENT, session_file_handler) != 0) {
		ndmp_session_failed(session, 0);
	}

	while (!session->ns_eof)
		(void) ndmp_select(session, B_TRUE, HC_ALL);

	ndmp_debug(session, "session with %s terminated",
	    session->ns_remoteaddr);

	(void) ndmp_remove_file_handler(session, sock);

	/*
	 * Only server sessions are destroyed in this context, as we've
	 * notified consumers via unregister() above, guaranteeing that it's no
	 * longer referenced by outside code.  We can't make the same
	 * assumption about client sessions, as we may have been disconnected
	 * while waiting for a response.  For client sessions, we instead just
	 * mark the session as inactive, so that we can safely teardown the
	 * client while there are outstanding connections.
	 */
	if (session->ns_server != NULL) {
		if (session->ns_server->ns_running) {
			session->ns_server->ns_conf->ns_abort(session);
			session->ns_server->ns_running = B_FALSE;
		}

		session->ns_server->ns_conf->ns_session_unregister(session);

		ndmp_session_destroy(session);
	} else {
		ndmp_session_list_inactive(
		    &session->ns_client->nc_session_list);
	}

	return (NULL);
}

/*
 * Low level read routine called by the xdrrec library.  Returns the number of
 * bytes read, or -1 on error.
 */
static int
ndmp_readit(void *session_handle, caddr_t buf, int len)
{
	ndmp_session_t *session = session_handle;

	len = read(session->ns_sock, buf, len);
	if (len <= 0) {
		ndmp_session_failed(session, errno);
		return (-1);
	}

	return (len);
}

/*
 * Low level write routine called by the xdrrec library.  Returns the number of
 * bytes read, or -1 on error.
 */
static int
ndmp_writeit(void *session_handle, caddr_t buf, int len)
{
	ndmp_session_t *session = session_handle;
	int n, cnt;

	for (cnt = len; cnt > 0; cnt -= n, buf += n) {
		if ((n = write(session->ns_sock, buf, cnt)) < 0) {
			ndmp_session_failed(session, errno);
			return (-1);
		}
	}

	return (len);
}

/*
 * Create a new session.  This will initialize all the necessary fields, and
 * start the async processing thread.  This works for both client and server
 * sessions, and takes a global session pointer as the frame of reference.  We
 * try to do as much as possible in synchronous context (as opposed to worker
 * context) to simplify the failure modes.
 */
ndmp_session_t *
ndmp_session_create(ndmp_session_t *global_session, int socket)
{
	ndmp_session_t *session;
	ndmp_session_list_t *session_list;
	pthread_attr_t tattr;
	struct sockaddr_in sin;
	int slen;

	/* allocate the new session structure */
	session = ndmp_malloc(global_session, sizeof (ndmp_session_t));
	if (session == NULL) {
		(void) close(socket);
		return (NULL);
	}

	/* hook into the global session */
	session->ns_server = global_session->ns_server;
	session->ns_client = global_session->ns_client;
	if (session->ns_server != NULL) {
		session->ns_conf = &session->ns_server->ns_conf->ns_common;
		session_list = &session->ns_server->ns_session_list;
	} else {
		session->ns_conf = &session->ns_client->nc_conf->nc_common;
		session_list = &session->ns_client->nc_session_list;
		/*
		 * When connecting to a remote client, we are implicitly
		 * allowing that client to send us requests back (such as
		 * logging).
		 */
		session->ns_authorized = B_TRUE;
	}
	ndmp_session_list_add(session_list, session);

	/* setup basic settings */
	session->ns_sock = socket;
	session->ns_version =
	    ndmp_get_prop_int(global_session, NDMP_MAX_VERSION);
	session->ns_scsi.sd_is_open = -1;
	session->ns_scsi.sd_devid = -1;
	session->ns_tape.td_fd = -1;

	randomize(session->ns_challenge, MD5_CHALLENGE_SIZE);

	/*
	 * This lock is recursive because we grab it when sending data over
	 * ns_sock.  This can be asynchronous from another thread, or while
	 * handling a response (where the lock is already held).
	 */
	(void) mutex_init(&session->ns_lock, LOCK_RECURSIVE, NULL);

	/*
	 * While it may seem like this should be handled by mover_init(), this
	 * is persisted across data operations, and the init methods are called
	 * in between data operations.
	 */
	session->ns_mover.md_record_size = MAX_RECORD_SIZE;

	/*
	 * Get the remote address and log a message recording the new
	 * connection.
	 */
	slen = sizeof (sin);
	if (getpeername(socket, (struct sockaddr *)&sin, &slen) != 0 ||
	    inet_ntop(sin.sin_family, &sin.sin_addr,
	    session->ns_remoteaddr,
	    sizeof (session->ns_remoteaddr)) == NULL) {
		(void) strlcpy(session->ns_remoteaddr,
		    "unknown", sizeof (session->ns_remoteaddr));
	} else {
		slen = strlen(session->ns_remoteaddr);
		(void) snprintf(session->ns_remoteaddr + slen,
		    sizeof (session->ns_remoteaddr) - slen,
		    ":%d", sin.sin_port);
	}

	ndmp_debug(global_session, "session established with %s",
	    session->ns_remoteaddr);

	/* Register with the consumer if in server mode */
	if (session->ns_server != NULL &&
	    session->ns_server->ns_conf->ns_session_register(session) != 0) {
		ndmp_log(global_session, LOG_DEBUG,
		    "failed to register session handler");
		goto error;
	}

	/* Initialize XDR and subsystem-specific data */
	xdrrec_create(&session->ns_xdrs, 0, 0, (caddr_t)session,
	    ndmp_readit, ndmp_writeit);

	if (session->ns_xdrs.x_ops == NULL) {
		ndmp_log(session, LOG_ERR, "out of memory");
		goto error;
	}

	/*
	 * We only need the data and mover configuration when in server mode.
	 * The local backup params are needed in both contexts.
	 */
	if (session->ns_server != NULL) {
		ndmp_data_init(session);
		if (ndmp_mover_init(session) != 0)
			goto error;
	}

	/* create async handler thread */
	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr,
	    PTHREAD_CREATE_DETACHED);
	if (pthread_create(NULL, &tattr, ndmp_session_worker,
	    session) != 0) {
		(void) pthread_attr_destroy(&tattr);
		ndmp_log(session, LOG_ERR,
		    "failed to create processing thread: %s",
		    strerror(errno));
		goto error;
	}
	(void) pthread_attr_destroy(&tattr);

	return (session);

error:
	ndmp_session_destroy(session);
	return (NULL);
}

/*
 * Called when a session is closed or is no longer usable.  This could be due
 * to internal failure, explicit request, or connection-level failure.  For
 * connection-level failures, we keep track of the error so that consumers can
 * distinguish between failure modes (connection lost, interrupt, internal
 * error, etc).
 */
void
ndmp_session_failed(ndmp_session_t *session, int err)
{
	ndmp_debug(session, "session failed with error %d", err);

	/*
	 * We should only ever receive EINTR in the case that we're aborting an
	 * active data connection.  Normally this is set through
	 * ndmp_session_data_stop(), but we also handle the case where the
	 * client self-initiates an abort, in which case we notice the
	 * interruption and mark the session as aborted.
	 */
	if (err == EINTR) {
		session->ns_data.dd_abort = B_TRUE;
		return;
	}

	(void) mutex_lock(&session->ns_lock);
	session->ns_eof = B_TRUE;
	if (session->ns_conn_error == 0)
		session->ns_conn_error = err;
	(void) cond_broadcast(&session->ns_notify.ns_cv);
	(void) mutex_unlock(&session->ns_lock);
}

/*
 * Called when we want to stop any in-progress data operation.  If we have a
 * data operation running, this will invoke the consumer-supplied abort
 * mechanism.
 */
void
ndmp_session_data_stop(ndmp_session_t *session)
{
	if (session->ns_server == NULL)
		return;

	session->ns_data.dd_abort = B_TRUE;
	if (session->ns_server->ns_running) {
		session->ns_server->ns_conf->ns_abort(session);
		session->ns_server->ns_running = B_FALSE;
	}
}

/*
 * Return the connection-level error associated with the session, if any.  This
 * should be used by clients to distinguish between environmental (connection)
 * errors and programmatic (protocol) errors.  For any client function that
 * fails, this function can be called afterwards to determine the underlying
 * root cause.  The following are possible error values:
 *
 *	EINTR		Data operation aborted
 *
 *	ECONNRESET	Connection lost
 *	EIO
 *
 *	ESHUTDOWN	Connection closed due to ndmp_client_destroy() called
 */
int
ndmp_session_error(ndmp_session_t *session)
{
	if (session->ns_data.dd_abort)
		return (EINTR);

	return (session->ns_conn_error);
}
