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
 * Copyright (c) 2011 by Delphix. All rights reserved
 */

#include "ndmp_impl.h"

/*
 * Client-side notification handling.  As part of the NDMP prototocl, servers
 * can send DMA clients asynchronous notifications.  The main message
 * processing for clients consists of taking these notifications and converting
 * them into a queue that can easily be manipulated by consumers.
 *
 * All notifications are converted into a ndmp_notification_t, which covers all
 * possible payloads for any notification.  Most of the time this is just a
 * message code and a reason, but some notifications have other properties,
 * such as offset and length.
 */

/*
 * Main consumer method.  This will wait for the given timeout (or forever if
 * the timeout is 0) for the next notification.  It will return NULL on error,
 * and place the reason for the error in 'error' if supplied.  This allows
 * consumers to distinguish between, say, timeouts, interrupts, and internal
 * errors.
 */
ndmp_notification_t *
ndmp_notify_wait(ndmp_session_t *session, uint_t mswait, int *error)
{
	ndmp_session_notify_state_t *notify = &session->ns_notify;
	timestruc_t ts;
	int err;
	ndmp_notification_t *ret;

	(void) mutex_lock(&notify->ns_lock);
	ts.tv_sec = mswait / 1000;
	ts.tv_nsec = (mswait % 1000) * 1000 * 1000;
	while (!session->ns_eof && !notify->ns_failed &&
	    notify->ns_list == NULL) {
		if (mswait != 0) {
			err = cond_reltimedwait(&notify->ns_cv,
			    &notify->ns_lock, &ts);
		} else {
			err = cond_wait(&notify->ns_cv,
			    &notify->ns_lock);
		}
		if (err != 0) {
			(void) mutex_unlock(&notify->ns_lock);
			if (error != NULL)
				*error = err;
			/*
			 * We preserve session-wide EINTR semantics here even
			 * though it's not strictly connection related (we
			 * didn't interrupt the connection handler thread
			 * itself).  If we ever need to disinguish these cases
			 * we'll have to come up with an alternate mechanism.
			 */
			if (err == EINTR)
				ndmp_session_failed(session, EINTR);
			ndmp_debug(session, "notify listen failed: %s",
			    strerror(errno));
			return (NULL);
		}
	}

	if (notify->ns_failed || session->ns_eof) {
		ret = NULL;
		if (notify->ns_failed)
			ndmp_debug(session, "failed to post notification");
	} else {
		ret = notify->ns_list;
		assert(ret != NULL);
		if (ret->nn_next == ret) {
			notify->ns_list = NULL;
		} else {
			ret->nn_prev->nn_next = ret->nn_next;
			ret->nn_next->nn_prev = ret->nn_prev;
			notify->ns_list = ret->nn_next;
		}
	}
	(void) mutex_unlock(&notify->ns_lock);
	if (error != NULL)
		*error = 0;

	return (ret);
}

/*
 * Common notification helper function.  Adds the notification to the list and
 * notifies any consumers.
 */
static void
ndmp_send_notification(ndmp_session_t *session, ndmp_message message,
    int reason, const char *text, u_longlong_t offset, u_longlong_t length)
{
	ndmp_session_notify_state_t *notify = &session->ns_notify;
	ndmp_notification_t *notification;

	ndmp_debug(session, "received notification 0x%x, reason 0x%x",
	    message, reason);

	if ((notification = ndmp_malloc(session,
	    sizeof (ndmp_notification_t))) == NULL)
		goto error;

	if (text != NULL && (notification->nn_text = ndmp_strdup(session,
	    text)) == NULL) {
		free(notification);
		goto error;
	}

	notification->nn_message = message;
	notification->nn_reason = reason;
	notification->nn_offset = offset;
	notification->nn_length = length;

	(void) mutex_lock(&notify->ns_lock);
	notification->nn_next = notify->ns_list;
	if (notify->ns_list != NULL) {
		notify->ns_list->nn_prev->nn_next = notification;
		notification->nn_prev = notify->ns_list->nn_prev;
		notify->ns_list->nn_prev = notification;
	} else {
		notification->nn_prev = notification->nn_next = notification;
		notify->ns_list = notification;
	}
	(void) cond_signal(&notify->ns_cv);
	(void) mutex_unlock(&notify->ns_lock);

	return;

error:
	notify->ns_failed = B_TRUE;
	(void) cond_broadcast(&notify->ns_cv);
}

/*
 * Notification-specific handlers.
 */
void
ndmp_notify_data_halted_v3(ndmp_session_t *session, void *body)
{
	ndmp_notify_data_halted_request *request = body;

	ndmp_send_notification(session, NDMP_NOTIFY_DATA_HALTED,
	    request->reason, request->text_reason, 0, 0);
}

void
ndmp_notify_connection_status_v3(ndmp_session_t *session, void *body)
{
	ndmp_notify_connected_request *request = body;

	/*
	 * If this is the first connection status notification, then check the
	 * version and see if it's acceptable.
	 */
	if (!session->ns_version_known) {
		if (request->protocol_version <=
		    session->ns_version) {
			session->ns_version =
			    request->protocol_version;
			session->ns_version_known = B_TRUE;
		}
	};

	/*
	 * Close the session on shutdown requests.
	 */
	if (request->reason == NDMP_SHUTDOWN)
		ndmp_session_close(session);

	ndmp_send_notification(session, NDMP_NOTIFY_CONNECTION_STATUS,
	    request->reason, request->text_reason, 0, 0);
}

void
ndmp_notify_mover_halted_v3(ndmp_session_t *session, void *body)
{
	ndmp_notify_mover_halted_request *request = body;

	ndmp_send_notification(session, NDMP_NOTIFY_MOVER_HALTED,
	    request->reason, request->text_reason, 0, 0);
}

void
ndmp_notify_mover_paused_v3(ndmp_session_t *session, void *body)
{
	ndmp_notify_mover_paused_request *request = body;

	ndmp_send_notification(session, NDMP_NOTIFY_MOVER_PAUSED,
	    request->reason, NULL, quad_to_long_long(request->seek_position),
	    0);
}

void
ndmp_notify_data_read_v3(ndmp_session_t *session, void *body)
{
	ndmp_notify_data_read_request *request = body;

	ndmp_send_notification(session, NDMP_NOTIFY_DATA_READ,
	    0, NULL, quad_to_long_long(request->offset),
	    quad_to_long_long(request->length));
}

void
ndmp_notify_data_halted_v4(ndmp_session_t *session, void *body)
{
	ndmp_notify_data_halted_request_v4 *request = body;

	ndmp_send_notification(session, NDMP_NOTIFY_DATA_HALTED,
	    request->reason, NULL, 0, 0);
}

void
ndmp_notify_mover_halted_v4(ndmp_session_t *session, void *body)
{
	ndmp_notify_data_halted_request_v4 *request = body;

	ndmp_send_notification(session, NDMP_NOTIFY_MOVER_HALTED,
	    request->reason, NULL, 0, 0);
}
