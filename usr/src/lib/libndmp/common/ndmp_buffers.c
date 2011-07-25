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

/*
 * Copyright (c) 2011 by Delphix.  All rights reserved.
 */

#include "ndmp_impl.h"

#define	RECORDSIZE	512

/*
 * ndmp_allocate_buffers
 *
 * build a set of buffers
 */
ndmp_buffers_t *
ndmp_allocate_buffers(ndmp_session_t *session, boolean_t write, long xfer_size)
{
	ndmp_buffers_t *buffers = ndmp_malloc(session, sizeof (ndmp_buffers_t));
	int	buf;

	if (buffers == NULL)
		return (NULL);

	for (buf = 0; buf < NDMP_TAPE_BUFFERS; buf++) {
		buffers->nbs_buffer[buf].nb_buffer_data =
		    ndmp_malloc(session, xfer_size);
		if (buffers->nbs_buffer[buf].nb_buffer_data == 0) {
			int	i;

			/* Memory allocation failed. Give everything back */
			for (i = 0; i < buf; i++)
				free(buffers->nbs_buffer[i].nb_buffer_data);

			free(buffers);
			return (NULL);
		} else {
			buffers->nbs_buffer[buf].nb_buffer_size = (write)
			    ? xfer_size : 0;
			buffers->nbs_buffer[buf].nb_full = FALSE;
			buffers->nbs_buffer[buf].nb_eof = FALSE;
			buffers->nbs_buffer[buf].nb_eot = FALSE;
			buffers->nbs_buffer[buf].nb_errno = 0;
			buffers->nbs_buffer[buf].nb_buffer_spot = 0;
		}

	}

	(void) mutex_init(&buffers->nbs_mtx, 0, NULL);
	(void) cond_init(&buffers->nbs_in_cv, 0, NULL);
	(void) cond_init(&buffers->nbs_out_cv, 0, NULL);

	buffers->nbs_data_transfer_size = xfer_size;
	buffers->nbs_ref = 1;
	return (buffers);
}

/*
 * ndmp_release_buffers
 *
 * give all memory back to the OS
 */
void
ndmp_release_buffers(ndmp_buffers_t *buffers)
{
	int i;

	if (buffers != NULL) {
		ndmp_buffer_release_in_buf(buffers);
		ndmp_buffer_release_out_buf(buffers);

		(void) mutex_lock(&buffers->nbs_mtx);

		if (--buffers->nbs_ref <= 0) {
			for (i = 0; i < NDMP_TAPE_BUFFERS; i++)
				free(buffers->nbs_buffer[i].nb_buffer_data);

		}

		(void) cond_destroy(&buffers->nbs_in_cv);
		(void) cond_destroy(&buffers->nbs_out_cv);
		(void) mutex_unlock(&buffers->nbs_mtx);
		(void) mutex_destroy(&buffers->nbs_mtx);
		free(buffers);
	}
}

/*
 * ndmp_buffer_mark_empty
 *
 * Mark a buffer empty and clear its flags. No lock is take here:
 * the buffer should be marked empty before it is released for use
 * by another thread.
 */
void
ndmp_buffer_mark_empty(ndmp_buffer_t *buf)
{
	if (buf == NULL)
		return;

	buf->nb_full = buf->nb_eof = buf->nb_eot = FALSE;
	buf->nb_errno = 0;
}


/*
 * ndmp_buffer_advance_in_idx
 *
 * Advance the input index of the buffers(round-robin) and return pointer
 * to the next buffer in the buffer pool.
 */
ndmp_buffer_t *
ndmp_buffer_advance_in_idx(ndmp_buffers_t *bufs)
{
	if (bufs == NULL)
		return (NULL);

	(void) mutex_lock(&bufs->nbs_mtx);
	if (++bufs->nbs_buffer_in >= NDMP_TAPE_BUFFERS)
		bufs->nbs_buffer_in = 0;

	(void) mutex_unlock(&bufs->nbs_mtx);
	return (&bufs->nbs_buffer[bufs->nbs_buffer_in]);
}


/*
 * ndmp_buffer_advance_out_idx
 *
 * Advance the output index of the buffers(round-robin) and return pointer
 * to the next buffer in the buffer pool.
 */
ndmp_buffer_t *
ndmp_buffer_advance_out_idx(ndmp_buffers_t *bufs)
{
	if (bufs == NULL)
		return (NULL);

	(void) mutex_lock(&bufs->nbs_mtx);
	if (++bufs->nbs_buffer_out >= NDMP_TAPE_BUFFERS)
		bufs->nbs_buffer_out = 0;

	(void) mutex_unlock(&bufs->nbs_mtx);
	return (&bufs->nbs_buffer[bufs->nbs_buffer_out]);
}


/*
 * ndmp_buffer_in_buf
 *
 * Return pointer to the next buffer in the buffer pool.
 */
ndmp_buffer_t *
ndmp_buffer_in_buf(ndmp_buffers_t *bufs, int *idx)
{
	ndmp_buffer_t *ret;

	if (bufs == NULL)
		return (NULL);

	(void) mutex_lock(&bufs->nbs_mtx);
	ret = &bufs->nbs_buffer[bufs->nbs_buffer_in];
	if (idx)
		*idx = bufs->nbs_buffer_in;
	(void) mutex_unlock(&bufs->nbs_mtx);
	return (ret);
}


/*
 * ndmp_buffer_out_buf
 *
 * Return pointer to the next buffer in the buffer pool.
 */
ndmp_buffer_t *
ndmp_buffer_out_buf(ndmp_buffers_t *bufs, int *idx)
{
	ndmp_buffer_t *ret;

	if (bufs == NULL)
		return (NULL);

	(void) mutex_lock(&bufs->nbs_mtx);
	ret = &bufs->nbs_buffer[bufs->nbs_buffer_out];
	if (idx)
		*idx = bufs->nbs_buffer_out;
	(void) mutex_unlock(&bufs->nbs_mtx);
	return (ret);
}


/*
 * ndmp_buffer_release_in_buf
 *
 * Another buffer is filled. Wake up the consumer if it's waiting for it.
 */
void
ndmp_buffer_release_in_buf(ndmp_buffers_t *bufs)
{
	(void) mutex_lock(&bufs->nbs_mtx);
	bufs->nbs_flags |= NDMP_BUF_IN_READY;
	(void) cond_signal(&bufs->nbs_in_cv);
	(void) mutex_unlock(&bufs->nbs_mtx);
}


/*
 * ndmp_buffer_release_out_buf
 *
 * A buffer is used. Wake up the producer to re-fill a buffer if it's waiting
 * for the buffer to be used.
 */
void
ndmp_buffer_release_out_buf(ndmp_buffers_t *bufs)
{
	(void) mutex_lock(&bufs->nbs_mtx);
	bufs->nbs_flags |= NDMP_BUF_OUT_READY;
	(void) cond_signal(&bufs->nbs_out_cv);
	(void) mutex_unlock(&bufs->nbs_mtx);
}

/*
 * ndmp_buffer_in_buf_wait
 *
 * Wait for the input buffer to get available.
 */
void
ndmp_buffer_in_buf_wait(ndmp_buffers_t *bufs)

{
	(void) mutex_lock(&bufs->nbs_mtx);

	while ((bufs->nbs_flags & NDMP_BUF_IN_READY) == 0)
		(void) cond_wait(&bufs->nbs_in_cv, &bufs->nbs_mtx);

	bufs->nbs_flags &= ~NDMP_BUF_IN_READY;

	(void) mutex_unlock(&bufs->nbs_mtx);
}

/*
 * ndmp_buffer_setup_timer
 *
 * Set up the time out value.
 */
static inline void
ndmp_buffer_setup_timer(timestruc_t *timo, unsigned milli_timo)
{
	if (milli_timo == 0)
		milli_timo = 1;

	if (milli_timo / 1000)
		timo->tv_sec = (milli_timo / 1000);
	else
		timo->tv_sec = 0;
	timo->tv_nsec = (milli_timo % 1000) * 1000000L;
}


/*
 * ndmp_buffer_in_buf_timed_wait
 *
 * Wait for the input buffer to get ready with a time out.
 */
void
ndmp_buffer_in_buf_timed_wait(ndmp_buffers_t *bufs, unsigned int milli_timo)

{
	timestruc_t timo;

	ndmp_buffer_setup_timer(&timo, milli_timo);

	(void) mutex_lock(&bufs->nbs_mtx);

	(void) cond_reltimedwait(&bufs->nbs_in_cv, &bufs->nbs_mtx, &timo);

	/*
	 * NDMP_BUF_IN_READY doesn't matter for timedwait but clear
	 * it here so that cond_wait doesn't get the wrong result.
	 */
	bufs->nbs_flags &= ~NDMP_BUF_IN_READY;

	(void) mutex_unlock(&bufs->nbs_mtx);
}


/*
 * ndmp_buffer_out_buf_timed_wait
 *
 * Wait for the output buffer to get ready with a time out.
 */
void
ndmp_buffer_out_buf_timed_wait(ndmp_buffers_t *bufs, unsigned int milli_timo)
{
	timestruc_t timo;

	ndmp_buffer_setup_timer(&timo, milli_timo);

	(void) mutex_lock(&bufs->nbs_mtx);

	(void) cond_reltimedwait(&bufs->nbs_out_cv, &bufs->nbs_mtx, &timo);

	/*
	 * NDMP_BUF_OUT_READY doesn't matter for timedwait but clear
	 * it here so that cond_wait doesn't get the wrong result.
	 */
	bufs->nbs_flags &= ~NDMP_BUF_OUT_READY;

	(void) mutex_unlock(&bufs->nbs_mtx);
}


/*
 * ndmp_cmd_wait
 *
 * Buffer command synchronization typically use by command
 * parent threads to wait for launched threads to initialize.
 */
void
ndmp_cmd_wait(ndmp_cmd_t *cmd, uint32_t event_type)
{
	(void) mutex_lock(&cmd->tc_mtx);

	while ((cmd->tc_flags & event_type) == 0)
		(void) cond_wait(&cmd->tc_cv, &cmd->tc_mtx);

	cmd->tc_flags &= ~event_type;
	(void) mutex_unlock(&cmd->tc_mtx);
}


/*
 * ndmp_cmd_signal
 *
 * Buffer command synchronization typically use by launched threads
 * to unleash the parent thread.
 */
void
ndmp_cmd_signal(ndmp_cmd_t *cmd, uint32_t event_type)
{
	(void) mutex_lock(&cmd->tc_mtx);

	cmd->tc_flags |= event_type;
	(void) cond_signal(&cmd->tc_cv);

	(void) mutex_unlock(&cmd->tc_mtx);
}

/*
 * get the next tape buffer from the drive's pool of buffers
 */
/*ARGSUSED*/
char *
ndmp_get_write_buffer(long want, long *actual_size,
    ndmp_buffers_t *buffers, int zero)
{
	int	buf = buffers->nbs_buffer_in;
	ndmp_buffer_t *buffer = &buffers->nbs_buffer[buf];
	int	align_size = RECORDSIZE - 1;
	char	*rec;

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	want += align_size;
	want &= ~align_size;

	*actual_size = buffer->nb_buffer_size - buffer->nb_buffer_spot;
	if (*actual_size <= 0) {
		/*
		 * no room, send this one
		 * and wait for a free one
		 */
		if (!buffer->nb_full) {
			/*
			 * we are now ready to send a full buffer
			 * instead of trying to get a new buffer
			 *
			 * do not send if we failed to get a buffer
			 * on the previous call
			 */
			buffer->nb_full = TRUE;

			/*
			 * tell the writer that a buffer is available
			 */
			ndmp_buffer_release_in_buf(buffers);

			buffer = ndmp_buffer_advance_in_idx(buffers);
		}

		buffer = ndmp_buffer_in_buf(buffers, NULL);

		if (buffer->nb_full) {
			/*
			 * wait for the writer to free up a buffer
			 */
			ndmp_buffer_out_buf_timed_wait(buffers, 500);
		}

		buffer = ndmp_buffer_in_buf(buffers, NULL);
		if (buffer->nb_full) {
			/*
			 * the next buffer is still full
			 * of data from previous activity
			 *
			 * nothing has changed.
			 */
			return (0);
		}

		buffer->nb_buffer_spot = 0;
		*actual_size = buffer->nb_buffer_size - buffer->nb_buffer_spot;
	}

	*actual_size = MIN(want, *actual_size);
	rec = &buffer->nb_buffer_data[buffer->nb_buffer_spot];
	buffer->nb_buffer_spot += *actual_size;
	buffers->nbs_offset += *actual_size;
	if (zero) {
		(void) memset(rec, 0, *actual_size);
	}
	return (rec);
}

/*
 * get a read record from the tape buffer,
 * and read a tape block if necessary
 */
/*ARGSUSED*/
char *
ndmp_get_read_buffer(int want, int *error,
    ndmp_buffers_t *buffers, int *actual_size)
{
	ndmp_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;
	char	*rec;

	buf = buffers->nbs_buffer_out;
	buffer = &buffers->nbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	want += align_size;
	want &= ~align_size;

	current_size = buffer->nb_buffer_size - buffer->nb_buffer_spot;
	if (buffer->nb_full && current_size <= 0) {
		/*
		 * no more data, release this
		 * one and go get another
		 */

		/*
		 * tell the reader that a buffer is available
		 */
		buffer->nb_full = FALSE;
		ndmp_buffer_release_out_buf(buffers);

		buffer = ndmp_buffer_advance_out_idx(buffers);
		current_size = buffer->nb_buffer_size - buffer->nb_buffer_spot;
	}

	if (!buffer->nb_full) {
		/*
		 * next buffer is not full yet.
		 * wait for the reader.
		 */
		ndmp_buffer_in_buf_timed_wait(buffers, 500);

		buffer = ndmp_buffer_out_buf(buffers, NULL);
		if (!buffer->nb_full) {
			/*
			 * we do not have anything from the tape yet
			 */
			return (0);
		}

		current_size = buffer->nb_buffer_size - buffer->nb_buffer_spot;
	}

	/* Make sure we got something */
	if (current_size <= 0)
		return (NULL);

	current_size = MIN(want, current_size);
	rec = &buffer->nb_buffer_data[buffer->nb_buffer_spot];
	buffer->nb_buffer_spot += current_size;
	*actual_size = current_size;

	/*
	 * the error flag is only sent back one time,
	 * since the flag refers to a previous read
	 * attempt, not the data in this buffer.
	 */
	*error = buffer->nb_errno;

	return (rec);
}

/*
 * unread a previously read buffer back to the tape buffer
 */
void
ndmp_unget_read_buffer(ndmp_buffers_t *buffers, int size)
{
	ndmp_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;

	buf = buffers->nbs_buffer_out;
	buffer = &buffers->nbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	size += align_size;
	size &= ~align_size;

	current_size = MIN(size, buffer->nb_buffer_spot);
	buffer->nb_buffer_spot -= current_size;
}

/*
 * unwrite a previously written buffer
 */
void
ndmp_unget_write_buffer(ndmp_buffers_t *buffers, int size)
{
	ndmp_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;

	buf = buffers->nbs_buffer_in;
	buffer = &buffers->nbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	size += align_size;
	size &= ~align_size;

	current_size = MIN(size, buffer->nb_buffer_spot);
	buffer->nb_buffer_spot -= current_size;
}

/*
 * create the IPC area between the reader and writer
 */
ndmp_cmd_t *
ndmp_create_reader_writer_ipc(ndmp_session_t *session, boolean_t write,
    long data_transfer_size)
{
	ndmp_cmd_t *cmd;

	cmd = ndmp_malloc(session, sizeof (ndmp_cmd_t));
	if (cmd == NULL)
		return (NULL);

	cmd->tc_reader = NDMP_BACKUP_RUN;
	cmd->tc_writer = NDMP_BACKUP_RUN;
	cmd->tc_ref = 1;

	cmd->tc_buffers = ndmp_allocate_buffers(session, write,
	    data_transfer_size);
	if (cmd->tc_buffers == NULL) {
		free(cmd);
		return (NULL);
	}

	(void) mutex_init(&cmd->tc_mtx, 0, NULL);
	(void) cond_init(&cmd->tc_cv, 0, NULL);

	return (cmd);
}

/*
 * release(destroy) the IPC between the reader and writer
 */
void
ndmp_release_reader_writer_ipc(ndmp_cmd_t *cmd)
{
	if (--cmd->tc_ref <= 0) {
		(void) mutex_lock(&cmd->tc_mtx);
		ndmp_release_buffers(cmd->tc_buffers);
		(void) cond_destroy(&cmd->tc_cv);
		(void) mutex_unlock(&cmd->tc_mtx);
		(void) mutex_destroy(&cmd->tc_mtx);
		free(cmd);
	}
}
