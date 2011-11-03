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

#include "ndmp_impl.h"

/*
 * Patchable socket buffer sizes in kilobytes.
 * ssb: send buffer size.
 * rsb: receive buffer size.
 */
int ndmp_sbs = 60;
int ndmp_rbs = 60;

/*
 * Keeps track of the open SCSI (including tape and robot) devices.
 * When a SCSI device is opened its name must be added to this list and
 * when it's closed its name must be removed from this list.  The main
 * purpose of this list is the robot device.  If the robot devices are not
 * attached in SASD layer, Local Backup won't see them. If they are
 * attached and we open the robot devices, then wrong commands are sent
 * to robot by SASD since it assumes that the robot is a tape (sequential
 * access) device.
 */
struct open_list {
	LIST_ENTRY(open_list) ol_q;
	int ol_nref;
	char *ol_devnm;
	int ol_sid;
	int ol_lun;
	int ol_fd;
	ndmp_session_t *cl_session;
};
LIST_HEAD(ol_head, open_list);

/*
 * Head of the opened SCSI devices list.
 */
static struct ol_head ol_head;

mutex_t ol_mutex = DEFAULTMUTEX;

static struct open_list *ndmp_open_list_find(char *, int, int);

static int scsi_test_unit_ready(ndmp_session_t *, int dev_id);

/*
 * Adds a file handler to the file handler list.  The file handler list is used
 * by ndmp_api_dispatch.
 */
int
ndmp_add_file_handler(ndmp_session_t *session, void *cookie, int fd,
    ulong_t mode, ulong_t class, ndmp_file_handler_func_t *func)
{
	ndmp_file_handler_t *new;

	new = ndmp_malloc(session, sizeof (ndmp_file_handler_t));
	if (new == 0)
		return (-1);

	new->fh_cookie = cookie;
	new->fh_fd = fd;
	new->fh_mode = mode;
	new->fh_class = class;
	new->fh_func = func;
	new->fh_next = session->ns_file_handler_list;
	session->ns_file_handler_list = new;
	return (0);
}

/*
 * Removes a file handler from the file handler list.
 */
int
ndmp_remove_file_handler(ndmp_session_t *session, int fd)
{
	ndmp_file_handler_t **last;
	ndmp_file_handler_t *handler;

	last = &session->ns_file_handler_list;
	while (*last != 0) {
		handler = *last;

		if (handler->fh_fd == fd) {
			*last = handler->fh_next;
			(void) free(handler);
			return (1);
		}
		last = &handler->fh_next;
	}

	return (0);
}

/*
 * If the session closed or not.
 */
int
ndmp_session_closed(int fd)
{
	fd_set fds;
	int closed, ret;
	struct timeval timeout;

	if (fd < 0) /* We are not using the mover */
		return (-1);

	timeout.tv_sec = 0;
	timeout.tv_usec = 1000;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	ret = select(FD_SETSIZE, &fds, NULL, NULL, &timeout);

	closed = (ret == -1 && errno == EBADF);

	return (closed);
}

/*
 * Checks the mover session status and sends an appropriate NDMP message to
 * client based on that.
 */
void
ndmp_check_mover_state(ndmp_session_t *session)
{
	int moverfd;

	/*
	 * NDMPV3 Spec (Three-way restore):
	 * Once all of the files have been recovered, NDMP DATA Server closes
	 * the session to the mover on the NDMP TAPE Server. THEN
	 * The NDMP client should receive an NDMP_NOTIFY_MOVER_HALTED message
	 * with an NDMP_MOVER_CONNECT_CLOSED reason from the NDMP TAPE Server
	 */
	moverfd = session->ns_mover.md_sock;
	/* If session is closed by the peer */
	if (moverfd >= 0 &&
	    session->ns_mover.md_mode == NDMP_MOVER_MODE_WRITE) {
		int closed, reason;

		closed = ndmp_session_closed(moverfd);
		if (closed) {
			/* Connection closed or internal error */
			if (closed > 0) {
				ndmp_log(session, LOG_INFO,
				    "mover session closed by peer");
				reason = NDMP_MOVER_HALT_CONNECT_CLOSED;
			} else {
				ndmp_log(session, LOG_ERR,
				    "internal error checking mover state");
				reason = NDMP_MOVER_HALT_INTERNAL_ERROR;
			}
			ndmp_mover_error(session, reason);
		}
	}
}

/*
 * Calls select on the the set of file descriptors from the file handler list
 * masked by the fd_class argument.  Calls the file handler function for each
 * file descriptor that is ready for I/O.
 */
int
ndmp_select(ndmp_session_t *session, boolean_t block, ulong_t class_mask)
{
	fd_set rfds;
	fd_set wfds;
	fd_set efds;
	int n;
	ndmp_file_handler_t *handler;
	struct timeval timeout;
	boolean_t error;

	if (session->ns_file_handler_list == NULL)
		return (0);

	/*
	 * If select should be blocked, then we poll every ten seconds.
	 * The reason is in case of three-way restore we should be able
	 * to detect if the other end closed the session or not.
	 * NDMP client(DMA) does not send any information about the session
	 * that was closed in the other end.
	 */
	if (block)
		timeout.tv_sec = 10;
	else
		timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	do {
		/* Create the fd_sets for select. */
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);

		for (handler = session->ns_file_handler_list; handler != 0;
		    handler = handler->fh_next) {
			if ((handler->fh_class & class_mask) == 0)
				continue;

			if (handler->fh_mode & NDMPD_SELECT_MODE_READ)
				FD_SET(handler->fh_fd, &rfds);
			if (handler->fh_mode & NDMPD_SELECT_MODE_WRITE)
				FD_SET(handler->fh_fd, &wfds);
			if (handler->fh_mode & NDMPD_SELECT_MODE_EXCEPTION)
				FD_SET(handler->fh_fd, &efds);
		}
		ndmp_check_mover_state(session);
		n = select(FD_SETSIZE, &rfds, &wfds, &efds, &timeout);
	} while (n == 0 && block);

	if (n < 0) {
		int session_fd = session->ns_sock;

		if (errno == EINTR) {
			if (session->ns_conn_error == 0)
				session->ns_conn_error = EINTR;
			return (-1);
		}

		ndmp_debug(session, "error on select: %s", strerror(errno));

		for (handler = session->ns_file_handler_list; handler != 0;
		    handler = handler->fh_next) {
			if ((handler->fh_class & class_mask) == 0)
				continue;

			error = B_FALSE;
			if (handler->fh_mode & NDMPD_SELECT_MODE_READ) {
				if (FD_ISSET(handler->fh_fd, &rfds) &&
				    session_fd == handler->fh_fd) {
					error = B_TRUE;
				}
			}
			if (handler->fh_mode & NDMPD_SELECT_MODE_WRITE) {
				if (FD_ISSET(handler->fh_fd, &wfds) &&
				    session_fd == handler->fh_fd) {
					error = B_TRUE;
				}
			}
			if (handler->fh_mode & NDMPD_SELECT_MODE_EXCEPTION) {
				if (FD_ISSET(handler->fh_fd, &efds) &&
				    session_fd == handler->fh_fd) {
					error = B_TRUE;
				}
			}

			if (error)
				ndmp_session_failed(session, EIO);
		}

		return (-1);
	}

	if (n == 0)
		return (0);

	handler = session->ns_file_handler_list;
	while (handler != NULL) {
		ulong_t mode = 0;

		if ((handler->fh_class & class_mask) == 0) {
			handler = handler->fh_next;
			continue;
		}
		if (handler->fh_mode & NDMPD_SELECT_MODE_READ) {
			if (FD_ISSET(handler->fh_fd, &rfds)) {
				mode |= NDMPD_SELECT_MODE_READ;
				FD_CLR(handler->fh_fd, &rfds);
			}
		}
		if (handler->fh_mode & NDMPD_SELECT_MODE_WRITE) {
			if (FD_ISSET(handler->fh_fd, &wfds)) {
				mode |= NDMPD_SELECT_MODE_WRITE;
				FD_CLR(handler->fh_fd, &wfds);
			}
		}
		if (handler->fh_mode & NDMPD_SELECT_MODE_EXCEPTION) {
			if (FD_ISSET(handler->fh_fd, &efds)) {
				mode |= NDMPD_SELECT_MODE_EXCEPTION;
				FD_CLR(handler->fh_fd, &efds);
			}
		}
		if (mode) {
			(*handler->fh_func)(handler->fh_cookie,
			    handler->fh_fd, mode);

			/*
			 * The list can be modified during the execution of
			 * handler->fh_func. Therefore, handler will start from
			 * the beginning of the handler list after each
			 * execution.
			 */
			handler = session->ns_file_handler_list;
		} else {
			handler = handler->fh_next;
		}

	}

	return (1);
}

/*
 * Saves a copy of the environment variable list from the data_start_backup
 * request or data_start_recover request.
 */
ndmp_error
ndmp_save_env(ndmp_session_t *session, ndmp_pval *env, ulong_t envlen)
{
	ulong_t i;
	char *namebuf;
	char *valbuf;

	session->ns_data.dd_env_len = 0;

	if (envlen == 0)
		return (NDMP_NO_ERR);

	session->ns_data.dd_env = ndmp_malloc(session,
	    sizeof (ndmp_pval) * envlen);
	if (session->ns_data.dd_env == NULL)
		return (NDMP_NO_MEM_ERR);

	for (i = 0; i < envlen; i++) {
		namebuf = ndmp_strdup(session, env[i].name);
		if (namebuf == NULL)
			return (NDMP_NO_MEM_ERR);

		valbuf = ndmp_strdup(session, env[i].value);
		if (valbuf == NULL) {
			free(namebuf);
			return (NDMP_NO_MEM_ERR);
		}

		ndmp_debug(session, "env(%s): \"%s\"",
		    namebuf, valbuf);

		(void) mutex_lock(&session->ns_lock);
		session->ns_data.dd_env[i].name = namebuf;
		session->ns_data.dd_env[i].value = valbuf;
		session->ns_data.dd_env_len++;
		(void) mutex_unlock(&session->ns_lock);
	}

	return (NDMP_NO_ERR);
}

/*
 * Free the previously saved environment variable array.
 */
void
ndmp_free_env(ndmp_session_t *session)
{
	ulong_t i;
	int count = session->ns_data.dd_env_len;

	(void) mutex_lock(&session->ns_lock);
	session->ns_data.dd_env_len = 0;
	for (i = 0; i < count; i++) {
		free(session->ns_data.dd_env[i].name);
		free(session->ns_data.dd_env[i].value);
	}

	free((char *)session->ns_data.dd_env);
	session->ns_data.dd_env = 0;
	(void) mutex_unlock(&session->ns_lock);
}

/*
 * Free a list created by ndmp_save_nlist_v3.
 */
void
ndmp_free_nlist_v3(ndmp_session_t *session)
{
	ulong_t i;
	mem_ndmp_name_v3_t *tp; /* destination entry */

	tp = session->ns_data.dd_nlist_v3;
	for (i = 0; i < session->ns_data.dd_nlist_len; tp++, i++) {
		NDMP_FREE(tp->nm3_opath);
		NDMP_FREE(tp->nm3_dpath);
		NDMP_FREE(tp->nm3_newnm);
	}

	NDMP_FREE(session->ns_data.dd_nlist_v3);
	session->ns_data.dd_nlist_len = 0;
}

/*
 * Save a copy of list of file names to be restored.
 */
ndmp_error
ndmp_save_nlist_v3(ndmp_session_t *session, ndmp_name_v3 *nlist,
    ulong_t nlistlen)
{
	ulong_t i;
	ndmp_error rv;
	ndmp_name_v3 *sp; /* source entry */
	mem_ndmp_name_v3_t *tp; /* destination entry */

	if (nlistlen == 0)
		return (NDMP_ILLEGAL_ARGS_ERR);

	session->ns_data.dd_nlist_len = 0;
	tp = session->ns_data.dd_nlist_v3 =
	    ndmp_malloc(session, sizeof (mem_ndmp_name_v3_t) * nlistlen);
	if (session->ns_data.dd_nlist_v3 == NULL)
		return (NDMP_NO_MEM_ERR);

	rv = NDMP_NO_ERR;
	sp = nlist;
	for (i = 0; i < nlistlen; tp++, sp++, i++) {
		tp->nm3_opath = ndmp_strdup(session, sp->original_path);
		if (tp->nm3_opath == NULL) {
			rv = NDMP_NO_MEM_ERR;
			break;
		}
		if (!*sp->destination_dir) {
			tp->nm3_dpath = NULL;
			/* In V4 destination dir cannot be NULL */
			if (session->ns_version == NDMPV4) {
				rv = NDMP_ILLEGAL_ARGS_ERR;
				break;
			}
		} else if ((tp->nm3_dpath = ndmp_strdup(session,
		    sp->destination_dir)) == NULL) {
			rv = NDMP_NO_MEM_ERR;
			break;
		}

		if (!*sp->new_name) {
			tp->nm3_newnm = NULL;
		} else if (!(tp->nm3_newnm = ndmp_strdup(session,
		    sp->new_name))) {
			rv = NDMP_NO_MEM_ERR;
			break;
		}

		tp->nm3_node = quad_to_long_long(sp->node);
		tp->nm3_fh_info = quad_to_long_long(sp->fh_info);
		tp->nm3_err = NDMP_NO_ERR;
		session->ns_data.dd_nlist_len++;

		ndmp_debug(session, "orig \"%s\"", tp->nm3_opath);
		ndmp_debug(session, "dest \"%s\"", NDMP_SVAL(tp->nm3_dpath));
		ndmp_debug(session, "name \"%s\"", NDMP_SVAL(tp->nm3_newnm));
		ndmp_debug(session, "node %lld", tp->nm3_node);
		ndmp_debug(session, "fh_info %lld", tp->nm3_fh_info);
	}

	if (rv != NDMP_NO_ERR)
		ndmp_free_nlist_v3(session);

	return (rv);
}

/*
 * Free the recovery list based on the version
 */
void
ndmp_free_nlist(ndmp_session_t *session)
{
	ndmp_free_nlist_v3(session);
}

/*
 * Comparison function used in sorting the Nlist based on their
 * file history info (offset of the entry on the tape)
 */
static int
fh_cmpv3(const void *p, const void *q)
{
#define	FH_INFOV3(p)	(((mem_ndmp_name_v3_t *)p)->nm3_fh_info)

	if (FH_INFOV3(p) < FH_INFOV3(q))
		return (-1);
	else if (FH_INFOV3(p) == FH_INFOV3(q))
		return (0);
	else
		return (1);

#undef FH_INFOV3
}

/*
 * Sort the recovery list based on their offset on the tape
 */
void
ndmp_sort_nlist_v3(ndmp_session_t *session)
{
	if (session->ns_data.dd_nlist_len == 0 ||
	    !session->ns_data.dd_nlist_v3)
		return;

	(void) qsort(session->ns_data.dd_nlist_v3,
	    session->ns_data.dd_nlist_len,
	    sizeof (mem_ndmp_name_v3_t), fh_cmpv3);
}

/*
 * Send the reply, check for error and print the msg if any error
 * occured when sending the reply.
 */
void
ndmp_send_reply(ndmp_session_t *session, void *reply)
{
	(void) ndmp_send_response(session, NDMP_NO_ERR, reply);
}

/*
 * Performs numerous filemark operations.
 */
int
ndmp_mtioctl(ndmp_session_t *session, int fd, int cmd, int count)
{
	struct mtop mp;

	mp.mt_op = cmd;
	mp.mt_count = count;
	if (ioctl(fd, MTIOCTOP, &mp) < 0) {

		ndmp_log(session, LOG_ERR,
		    "failed to send command to tape: %s",
		    strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Convert type quad to longlong_t
 */
u_longlong_t
quad_to_long_long(ndmp_u_quad q)
{
	u_longlong_t ull;

	ull = ((u_longlong_t)q.high << 32) + q.low;
	return (ull);
}

/*
 * Convert long long to quad type
 */
ndmp_u_quad
long_long_to_quad(u_longlong_t ull)
{
	ndmp_u_quad q;

	q.high = (ulong_t)(ull >> 32);
	q.low = (ulong_t)ull;
	return (q);
}

/*
 * Set the TCP socket option to nodelay mode
 */
void
ndmp_set_socket_nodelay(int sock)
{
	int flag = 1;

	(void) setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof (flag));
}

/*
 * Set the socket send buffer size
 */
void
ndmp_set_socket_snd_buf(ndmp_session_t *session, int sock, int size)
{
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof (size)) < 0)
		ndmp_debug(session, "failed to set SO_SNDBUF: %s",
		    strerror(errno));
}

/*
 * ndmp_set_socket_rcv_buf
 *
 * Set the socket receive buffer size
 */
void
ndmp_set_socket_rcv_buf(ndmp_session_t *session, int sock, int size)
{
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof (size)) < 0)
		ndmp_debug(session, "failed to set SO_RCVBUF: %s",
		    strerror(errno));
}

/*
 * Run a sanity check on the buffer
 */
boolean_t
is_buffer_erroneous(ndmp_session_t *session, ndmp_buffer_t *buf)
{
	boolean_t rv;

	rv = (buf == NULL || buf->nb_eot || buf->nb_eof ||
	    buf->nb_errno != 0);
	if (rv) {
		if (buf == NULL) {
			ndmp_debug(session, "erroneous buffer: NULL");
		} else {
			ndmp_debug(session, "erroneous buffer: "
			    "eot: %u, eof: %u, errno: %d",
			    buf->nb_eot, buf->nb_eof, buf->nb_errno);
		}
	}

	return (rv);
}

/*
 * Main SCSI CDB execution program, this is used by message handler for the
 * NDMP tape/SCSI execute CDB requests. This function uses USCSI interface to
 * run the CDB command and sets all the CDB parameters in the SCSI query before
 * calling the USCSI ioctl. The result of the CDB is returned in two places:
 *
 *    cmd.uscsi_status		The status of CDB execution
 *    cmd.uscsi_rqstatus	The status of sense requests
 *    reply.error		The general errno (ioctl)
 */
/*ARGSUSED*/
void
ndmp_execute_cdb(ndmp_session_t *session, char *adapter_name, int sid, int lun,
    ndmp_execute_cdb_request *request)
{
	ndmp_execute_cdb_reply reply = { 0 };
	struct uscsi_cmd cmd = { 0 };
	int fd;
	struct open_list *olp;
	char rq_buf[255];

	(void) memset(rq_buf, 0, sizeof (rq_buf));

	if (request->flags == NDMP_SCSI_DATA_IN) {
		cmd.uscsi_flags = USCSI_READ | USCSI_RQENABLE;
		if ((cmd.uscsi_bufaddr =
		    ndmp_malloc(session, request->datain_len)) == 0) {
			reply.error = NDMP_NO_MEM_ERR;
			(void) ndmp_send_response(session,
			    NDMP_NO_ERR, &reply);
			return;
		}

		cmd.uscsi_buflen = request->datain_len;
	} else if (request->flags == NDMP_SCSI_DATA_OUT) {
		cmd.uscsi_flags = USCSI_WRITE | USCSI_RQENABLE;
		cmd.uscsi_bufaddr = request->dataout.dataout_val;
		cmd.uscsi_buflen = request->dataout.dataout_len;
	} else {
		cmd.uscsi_flags = USCSI_RQENABLE;
		cmd.uscsi_bufaddr = 0;
		cmd.uscsi_buflen = 0;
	}
	cmd.uscsi_rqlen = sizeof (rq_buf);
	cmd.uscsi_rqbuf = rq_buf;

	cmd.uscsi_timeout = (request->timeout < 1000) ?
	    1 : (request->timeout / 1000);

	cmd.uscsi_cdb = (caddr_t)request->cdb.cdb_val;
	cmd.uscsi_cdblen = request->cdb.cdb_len;

	ndmp_debug(session, "cmd: 0x%x, len: %d, flags: %d, datain_len: %d",
	    request->cdb.cdb_val[0] & 0xff, request->cdb.cdb_len,
	    request->flags, request->datain_len);
	ndmp_debug(session, "dataout_len: %d, timeout: %d",
	    request->dataout.dataout_len, request->timeout);

	if (request->cdb.cdb_len > 12) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		ndmp_send_reply(session, &reply);
		if (request->flags == NDMP_SCSI_DATA_IN)
			free(cmd.uscsi_bufaddr);
		return;
	}

	reply.error = NDMP_NO_ERR;

	(void) mutex_lock(&ol_mutex);
	if ((olp = ndmp_open_list_find(adapter_name, sid, lun)) != NULL) {
		fd = olp->ol_fd;
	} else {
		(void) mutex_unlock(&ol_mutex);
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(session, &reply);
		if (request->flags == NDMP_SCSI_DATA_IN)
			free(cmd.uscsi_bufaddr);
		return;
	}
	(void) mutex_unlock(&ol_mutex);

	if (ioctl(fd, USCSICMD, &cmd) < 0) {
		if (errno != EIO && errno != 0)
			ndmp_log(session, LOG_ERR,
			    "failed to send command to device: %s",
			    strerror(errno));
		if (cmd.uscsi_status == 0)
			reply.error = NDMP_IO_ERR;
	}

	reply.status = cmd.uscsi_status;

	if (request->flags == NDMP_SCSI_DATA_IN) {
		reply.datain.datain_len = cmd.uscsi_buflen;
		reply.datain.datain_val = cmd.uscsi_bufaddr;
	} else {
		reply.dataout_len = request->dataout.dataout_len;
	}

	reply.ext_sense.ext_sense_len = cmd.uscsi_rqlen - cmd.uscsi_rqresid;
	reply.ext_sense.ext_sense_val = rq_buf;

	(void) ndmp_send_response(session, NDMP_NO_ERR, &reply);

	if (request->flags == NDMP_SCSI_DATA_IN)
		free(cmd.uscsi_bufaddr);
}

/*
 * Find a specific device in the open list.
 */
static struct open_list *
ndmp_open_list_find(char *dev, int sid, int lun)
{
	struct ol_head *olhp;
	struct open_list *olp;

	assert(dev != NULL);
	assert(*dev != '\0');

	olhp = &ol_head;
	for (olp = LIST_FIRST(olhp); olp != NULL; olp = LIST_NEXT(olp, ol_q)) {
		if (strcmp(olp->ol_devnm, dev) == 0 && olp->ol_sid == sid &&
		    olp->ol_lun == lun) {
			return (olp);
		}
	}

	return (NULL);
}

boolean_t
ndmp_open_list_exists(char *dev, int sid, int lun)
{
	struct open_list *olp;

	(void) mutex_lock(&ol_mutex);
	olp = ndmp_open_list_find(dev, sid, lun);
	(void) mutex_unlock(&ol_mutex);

	return (olp != NULL);
}

/*
 * Add a specific device to the open list
 */
int
ndmp_open_list_add(ndmp_session_t *session, char *dev, int sid, int lun, int fd)
{
	int err;
	struct ol_head *olhp;
	struct open_list *olp;

	assert(dev != NULL);
	assert(*dev != '\0');

	err = 0;
	olhp = &ol_head;

	(void) mutex_lock(&ol_mutex);
	if ((olp = ndmp_open_list_find(dev, sid, lun)) != NULL) {
		/*
		 * The adapter handle can be opened many times by the clients.
		 * Only when the target is set, we must check and reject the
		 * open request if the device is already being used by another
		 * session.
		 */
		if (sid == -1) {
			olp->ol_nref++;
		} else {
			err = EBUSY;
			ndmp_log(session, LOG_ERR,
			    "device already opened in another session");
		}
	} else if ((olp = ndmp_malloc(session,
	    sizeof (struct open_list))) == NULL) {
		err = ENOMEM;
	} else if ((olp->ol_devnm = ndmp_strdup(session, dev)) == NULL) {
		free(olp);
		err = ENOMEM;
	} else {
		olp->cl_session = session;
		olp->ol_nref = 1;
		olp->ol_sid = sid;
		olp->ol_lun = lun;
		if (fd > 0)
			olp->ol_fd = fd;
		else
			olp->ol_fd = -1;
		LIST_INSERT_HEAD(olhp, olp, ol_q);
	}
	(void) mutex_unlock(&ol_mutex);

	return (err);
}

/*
 * Delete a specific device from the open list
 */
int
ndmp_open_list_del(char *dev, int sid, int lun)
{
	struct open_list *olp;

	assert(dev != NULL);
	assert(*dev != '\0');

	(void) mutex_lock(&ol_mutex);
	if ((olp = ndmp_open_list_find(dev, sid, lun)) == NULL) {
		(void) mutex_unlock(&ol_mutex);
		return (-1);
	}

	if (--olp->ol_nref <= 0) {
		LIST_REMOVE(olp, ol_q);
		free(olp->ol_devnm);
		free(olp);
	}
	(void) mutex_unlock(&ol_mutex);

	return (0);
}

/*
 * Close all the resources belonging to this session.
 */
void
ndmp_open_list_release(ndmp_session_t *session)
{
	struct ol_head *olhp = &ol_head;
	struct open_list *olp;
	struct open_list *next;

	(void) mutex_lock(&ol_mutex);
	olp = LIST_FIRST(olhp);
	while (olp != NULL) {
		next = LIST_NEXT(olp, ol_q);
		if (olp->cl_session == session) {
			LIST_REMOVE(olp, ol_q);
			if (olp->ol_fd > 0)
				(void) close(olp->ol_fd);
			free(olp->ol_devnm);
			free(olp);
		}
		olp = next;
	}
	(void) mutex_unlock(&ol_mutex);
}

/*
 * Convert the address type to a string
 */
char *
ndmp_addr2str_v3(ndmp_addr_type type)
{
	char *rv;

	switch (type) {
	case NDMP_ADDR_LOCAL:
		rv = "Local";
		break;
	case NDMP_ADDR_TCP:
		rv = "TCP";
		break;
	case NDMP_ADDR_FC:
		rv = "FC";
		break;
	case NDMP_ADDR_IPC:
		rv = "IPC";
		break;
	default:
		rv = "Unknown";
	}

	return (rv);
}

/*
 * Make sure that the NDMP address is from any of the valid types
 */
boolean_t
ndmp_valid_v3addr_type(ndmp_addr_type type)
{
	boolean_t rv;

	switch (type) {
	case NDMP_ADDR_LOCAL:
	case NDMP_ADDR_TCP:
	case NDMP_ADDR_FC:
	case NDMP_ADDR_IPC:
		rv = B_TRUE;
		break;
	default:
		rv = B_FALSE;
	}

	return (rv);
}

/*
 * Copy NDMP address from source to destination (V3 only)
 */
void
ndmp_copy_addr_v3(ndmp_addr_v3 *dst, ndmp_addr_v3 *src)
{
	dst->addr_type = src->addr_type;
	switch (src->addr_type) {
	case NDMP_ADDR_LOCAL:
		/* nothing */
		break;
	case NDMP_ADDR_TCP:
		dst->tcp_ip_v3 = src->tcp_ip_v3;
		dst->tcp_port_v3 = src->tcp_port_v3;
		break;
	case NDMP_ADDR_FC:
	case NDMP_ADDR_IPC:
	default:
		break;
	}
}

/*
 * Copy NDMP address from source to destination. V4 has a extra environment
 * list inside the address too which needs to be copied.
 */
int
ndmp_copy_addr_v4(ndmp_session_t *session, ndmp_addr_v4 *dst, ndmp_addr_v4 *src)
{
	int i;

	dst->addr_type = src->addr_type;
	dst->tcp_len_v4 = src->tcp_len_v4;
	switch (src->addr_type) {
	case NDMP_ADDR_LOCAL:
		/* nothing */
		break;
	case NDMP_ADDR_TCP:
		dst->tcp_addr_v4 = ndmp_malloc(session,
		    sizeof (ndmp_tcp_addr_v4) * src->tcp_len_v4);
		if (dst->tcp_addr_v4 == NULL)
			return (-1);

		for (i = 0; i < src->tcp_len_v4; i++) {
			dst->tcp_ip_v4(i) = src->tcp_ip_v4(i);
			dst->tcp_port_v4(i) = src->tcp_port_v4(i);
			dst->tcp_env_v4(i).addr_env_len = 0;
			dst->tcp_env_v4(i).addr_env_val = 0;
		}
		break;
	case NDMP_ADDR_FC:
	case NDMP_ADDR_IPC:
	default:
		break;
	}

	return (0);
}

/*
 * Creates a socket and connects to the specified address/port.  The address
 * and port should already be in network byte order, as these fields come
 * straight from the network packets.
 */
int
ndmp_connect_sock_v3(ndmp_session_t *session, ulong_t addr, ushort_t port)
{
	int sock;
	struct sockaddr_in sin;
	int flag = 1;

	ndmp_debug(session, "connecting to %s:%d", inet_ntoa(IN_ADDR(addr)),
	    ntohs(port));

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		ndmp_log(session, LOG_ERR,
		    "failed to create socket: %s", strerror(errno));
		return (-1);
	}

	(void) memset(&sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	sin.sin_port = port;
	if (connect(sock, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		ndmp_log(session, LOG_ERR,
		    "failed to connect to remote host: %s", strerror(errno));
		(void) close(sock);
		sock = -1;
	} else {
		if (ndmp_sbs > 0) {
			ndmp_set_socket_snd_buf(session, sock,
			    ndmp_sbs * KILOBYTE);
		}
		if (ndmp_rbs > 0) {
			ndmp_set_socket_rcv_buf(session, sock,
			    ndmp_rbs * KILOBYTE);
		}

		ndmp_set_socket_nodelay(sock);
		(void) setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flag,
		    sizeof (flag));
	}

	return (sock);
}

/*
 * Creates a socket for listening for accepting data sessions.  The address and
 * port are returned in network bytes order.
 */
int
ndmp_create_socket(ndmp_session_t *session, ulong_t *addr, ushort_t *port)
{
	int length;
	int sd;
	struct sockaddr_in sin;

	/* Use the same address as the management request */
	length = sizeof (sin);
	if (getsockname(session->ns_sock,
	    (struct sockaddr *)&sin, &length) != 0) {
		ndmp_log(session, LOG_ERR,
		    "failed to get socket address: %s",
		    strerror(errno));
		return (-1);
	}

	*addr = sin.sin_addr.s_addr;

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		ndmp_log(session, LOG_ERR,
		    "failed to create listening socket: %s",
		    strerror(errno));
		return (-1);
	}
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = 0;
	length = sizeof (sin);

	if (bind(sd, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		ndmp_log(session, LOG_ERR,
		    "failed to bind listening socket: %s",
		    strerror(errno));
		(void) close(sd);
		sd = -1;
	} else if (getsockname(sd, (struct sockaddr *)&sin, &length) < 0) {
		ndmp_log(session, LOG_ERR,
		    "failed to get socket info: %s",
		    strerror(errno));
		(void) close(sd);
		sd = -1;
	} else if (listen(sd, 5) < 0) {
		ndmp_log(session, LOG_ERR, "failed to listen on socket: %s",
		    strerror(errno));
		(void) close(sd);
		sd = -1;
	} else {
		*port = sin.sin_port;
	}

	return (sd);
}

/*
 * Check if the tape device is ready or not
 */
boolean_t
is_tape_unit_ready(ndmp_session_t *session, char *adptnm, int dev_id)
{
	int try;
	int fd = 0;

	try = TUR_MAX_TRY;
	if (dev_id <= 0) {
		if ((fd = open(adptnm, O_RDONLY | O_NDELAY)) < 0)
			return (B_FALSE);
	} else {
		fd = dev_id;
	}

	do {
		if (scsi_test_unit_ready(session, fd) >= 0) {
			ndmp_debug(session, "tape unit is ready");

			if (dev_id <= 0)
				(void) close(fd);

			return (B_TRUE);
		}

		ndmp_debug(session, "tape unit is not ready");
		(void) usleep(TUR_WAIT);

	} while (--try > 0);

	if (dev_id <= 0)
		(void) close(fd);

	ndmp_debug(session, "test unit ready failed");
	return (B_FALSE);
}

/*
 * This is for Test Unit Read, without this function, the only impact is
 * getting EBUSY's before each operation which we have busy waiting loops
 * checking EBUSY error code.
 */
static int
scsi_test_unit_ready(ndmp_session_t *session, int dev_id)
{
	struct uscsi_cmd ucmd;
	union scsi_cdb cdb;
	int retval;

	(void) memset(&ucmd, 0, sizeof (struct uscsi_cmd));
	(void) memset(&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_TEST_UNIT_READY;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_flags |= USCSI_SILENT;
	ucmd.uscsi_timeout = 60;	/* Allow maximum 1 min */

	retval = ioctl(dev_id, USCSICMD, &ucmd);

	if (retval != 0 && errno != EIO) {
		ndmp_debug(session,
		    "failed to send inquiry request to device: %s",
		    strerror(errno));
		retval = -errno;
	} else {
		retval = -(ucmd.uscsi_status);
	}

	return (retval);
}

/*
 * Randomize the contents of a buffer
 */
void
randomize(unsigned char *buffer, int size)
{
	int fd = open("/dev/urandom", O_RDONLY);

	assert(fd != -1);
	(void) read(fd, buffer, size);

	(void) close(fd);
}

/*
 * Converts the mode to the NDMP file type
 */
void
ndmp_get_file_entry_type(int mode, ndmp_file_type *ftype)
{
	switch (mode & S_IFMT) {
	case S_IFIFO:
		*ftype = NDMP_FILE_FIFO;
		break;
	case S_IFCHR:
		*ftype = NDMP_FILE_CSPEC;
		break;
	case S_IFDIR:
		*ftype = NDMP_FILE_DIR;
		break;
	case S_IFBLK:
		*ftype = NDMP_FILE_BSPEC;
		break;
	case S_IFREG:
		*ftype = NDMP_FILE_REG;
		break;
	case S_IFLNK:
		*ftype = NDMP_FILE_SLINK;
		break;
	default:
		*ftype = NDMP_FILE_SOCK;
		break;
	}
}

/*
 * Log to to the local debug file.
 */
void
ndmp_debug(ndmp_session_t *session, const char *fmt, ...)
{
	va_list ap;
	char *buf;

	va_start(ap, fmt);
	NDMP_VASPRINTF(&buf, fmt, ap);

	session->ns_conf->nc_log(session->ns_global ? NULL : session, LOG_DEBUG,
	    buf);
}

void
ndmp_log(ndmp_session_t *session, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;

	va_start(ap, fmt);

	NDMP_VASPRINTF(&buf, fmt, ap);

	session->ns_conf->nc_log(session->ns_global ? NULL : session,
	    level, buf);

	if (session->ns_server != NULL)
		ndmp_server_log(session, level, buf);
}

void
ndmp_log_local(ndmp_session_t *session, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;

	va_start(ap, fmt);

	NDMP_VASPRINTF(&buf, fmt, ap);

	session->ns_conf->nc_log(session->ns_global ? NULL : session,
	    level, buf);
}

void *
ndmp_malloc(ndmp_session_t *session, size_t size)
{
	void *data;

	if ((data = calloc(1, size)) == NULL) {
		ndmp_log(session, LOG_ERR, "out of memory");
	}

	return (data);
}

char *
ndmp_strdup(ndmp_session_t *session, const char *str)
{
	void *data;

	if ((data = strdup(str)) == NULL) {
		ndmp_log(session, LOG_ERR, "out of memory");
	}

	return (data);
}

void *
ndmp_realloc(ndmp_session_t *session, void *orig, size_t size)
{
	void *data;

	if ((data = realloc(orig, size)) == NULL) {
		ndmp_log(session, LOG_ERR, "out of memory");
	}

	return (data);
}

/*
 * This function uses the MD5 message-digest algorithm described in RFC1321 to
 * authenticate the client using a shared secret (password).  The message used
 * to compute the MD5 digest is a concatenation of password, null padding, the
 * 64 byte fixed length challenge and a repeat of the password. The length of
 * the null padding is chosen to result in a 128 byte fixed length message. The
 * lengh of the padding can be computed as 64 - 2*(length of the password). The
 * client digest is computed using the server challenge from the
 * NDMP_CONFIG_GET_AUTH_ATTR reply.
 */
void
ndmp_create_md5_digest(unsigned char *digest, const char *passwd,
    unsigned char *challenge)
{
	char buf[130];
	char *p = &buf[0];
	int len, i;
	MD5_CTX md;

	*p = 0;
	if ((len = strlen(passwd)) > MD5_PASS_LIMIT)
		len = MD5_PASS_LIMIT;
	(void) memcpy(p, passwd, len);
	p += len;

	for (i = 0; i < MD5_CHALLENGE_SIZE - 2 * len; i++)
		*p++ = 0;

	(void) memcpy(p, challenge, MD5_CHALLENGE_SIZE);
	p += MD5_CHALLENGE_SIZE;
	(void) strlcpy(p, passwd, MD5_PASS_LIMIT);

	MD5Init(&md);
	MD5Update(&md, buf, 128);
	MD5Final(digest, &md);
}

void
ndmp_asprintf(char *buf, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	(void) vsprintf(buf, fmt, ap);
}

void
ndmp_vasprintf(char *buf, const char *fmt, va_list ap)
{
	(void) vsprintf(buf, fmt, ap);
}
