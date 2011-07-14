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

/* Copyright (c) 2011 by Delphix.  All rights reserved. */

#include "ndmp_impl.h"

/*
 * get the next tape buffer from the drive's pool of buffers
 */
/*ARGSUSED*/
char *
tlm_get_write_buffer(long want, long *actual_size,
    tlm_buffers_t *buffers, int zero)
{
	int	buf = buffers->tbs_buffer_in;
	tlm_buffer_t *buffer = &buffers->tbs_buffer[buf];
	int	align_size = RECORDSIZE - 1;
	char	*rec;

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	want += align_size;
	want &= ~align_size;

	*actual_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	if (*actual_size <= 0) {
		/*
		 * no room, send this one
		 * and wait for a free one
		 */
		if (!buffer->tb_full) {
			/*
			 * we are now ready to send a full buffer
			 * instead of trying to get a new buffer
			 *
			 * do not send if we failed to get a buffer
			 * on the previous call
			 */
			buffer->tb_full = TRUE;

			/*
			 * tell the writer that a buffer is available
			 */
			tlm_buffer_release_in_buf(buffers);

			buffer = tlm_buffer_advance_in_idx(buffers);
		}

		buffer = tlm_buffer_in_buf(buffers, NULL);

		if (buffer->tb_full) {
			/*
			 * wait for the writer to free up a buffer
			 */
			tlm_buffer_out_buf_timed_wait(buffers, 500);
		}

		buffer = tlm_buffer_in_buf(buffers, NULL);
		if (buffer->tb_full) {
			/*
			 * the next buffer is still full
			 * of data from previous activity
			 *
			 * nothing has changed.
			 */
			return (0);
		}

		buffer->tb_buffer_spot = 0;
		*actual_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	}

	*actual_size = MIN(want, *actual_size);
	rec = &buffer->tb_buffer_data[buffer->tb_buffer_spot];
	buffer->tb_buffer_spot += *actual_size;
	buffers->tbs_offset += *actual_size;
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
tlm_get_read_buffer(int want, int *error,
    tlm_buffers_t *buffers, int *actual_size)
{
	tlm_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;
	char	*rec;

	buf = buffers->tbs_buffer_out;
	buffer = &buffers->tbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	want += align_size;
	want &= ~align_size;

	current_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	if (buffer->tb_full && current_size <= 0) {
		/*
		 * no more data, release this
		 * one and go get another
		 */

		/*
		 * tell the reader that a buffer is available
		 */
		buffer->tb_full = FALSE;
		tlm_buffer_release_out_buf(buffers);

		buffer = tlm_buffer_advance_out_idx(buffers);
		current_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	}

	if (!buffer->tb_full) {
		/*
		 * next buffer is not full yet.
		 * wait for the reader.
		 */
		tlm_buffer_in_buf_timed_wait(buffers, 500);

		buffer = tlm_buffer_out_buf(buffers, NULL);
		if (!buffer->tb_full) {
			/*
			 * we do not have anything from the tape yet
			 */
			return (0);
		}

		current_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	}

	/* Make sure we got something */
	if (current_size <= 0)
		return (NULL);

	current_size = MIN(want, current_size);
	rec = &buffer->tb_buffer_data[buffer->tb_buffer_spot];
	buffer->tb_buffer_spot += current_size;
	*actual_size = current_size;

	/*
	 * the error flag is only sent back one time,
	 * since the flag refers to a previous read
	 * attempt, not the data in this buffer.
	 */
	*error = buffer->tb_errno;

	return (rec);
}

/*
 * unread a previously read buffer back to the tape buffer
 */
void
tlm_unget_read_buffer(tlm_buffers_t *buffers, int size)
{
	tlm_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;

	buf = buffers->tbs_buffer_out;
	buffer = &buffers->tbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	size += align_size;
	size &= ~align_size;

	current_size = MIN(size, buffer->tb_buffer_spot);
	buffer->tb_buffer_spot -= current_size;
}

/*
 * unwrite a previously written buffer
 */
void
tlm_unget_write_buffer(tlm_buffers_t *buffers, int size)
{
	tlm_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;

	buf = buffers->tbs_buffer_in;
	buffer = &buffers->tbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	size += align_size;
	size &= ~align_size;

	current_size = MIN(size, buffer->tb_buffer_spot);
	buffer->tb_buffer_spot -= current_size;
}

/*
 * get internal scsi_sasd entry for this tape drive
 */
int
tlm_get_scsi_sasd_entry(int lib, int drv)
{
	int entry;
	int i, n;
	scsi_link_t *sl;
	tlm_drive_t *dp;

	entry = -1;
	dp = tlm_drive(lib, drv);
	if (dp != NULL && dp->td_slink != NULL && dp->td_slink->sl_sa != NULL) {
		/* search through the SASD table */
		n = sasd_dev_count();
		for (i = 0; i < n; i++) {
			sl = sasd_dev_slink(i);
			if (!sl)
				continue;

			if (dp->td_slink->sl_sa == sl->sl_sa &&
			    dp->td_scsi_id == sl->sl_sid &&
			    dp->td_lun == sl->sl_lun) {
				/* all 3 variables match */
				entry = i;
				break;
			}
		}
	}

	return (entry);
}

/*
 * get the OS device name for this tape
 */
char *
tlm_get_tape_name(int lib, int drv)
{
	int entry;

	entry = tlm_get_scsi_sasd_entry(lib, drv);
	if (entry >= 0) {
		sasd_drive_t *sd;

		if ((sd = sasd_drive(entry)) != 0)
			return (sd->sd_name);
	}

	return ("");
}

/*
 * create the IPC area between the reader and writer
 */
tlm_cmd_t *
tlm_create_reader_writer_ipc(ndmp_session_t *session, boolean_t write,
    long data_transfer_size)
{
	tlm_cmd_t *cmd;

	cmd = ndmp_malloc(session, sizeof (tlm_cmd_t));
	if (cmd == NULL)
		return (NULL);

	cmd->tc_reader = TLM_BACKUP_RUN;
	cmd->tc_writer = TLM_BACKUP_RUN;
	cmd->tc_ref = 1;

	cmd->tc_buffers = tlm_allocate_buffers(session, write,
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
tlm_release_reader_writer_ipc(tlm_cmd_t *cmd)
{
	if (--cmd->tc_ref <= 0) {
		(void) mutex_lock(&cmd->tc_mtx);
		tlm_release_buffers(cmd->tc_buffers);
		(void) cond_destroy(&cmd->tc_cv);
		(void) mutex_unlock(&cmd->tc_mtx);
		(void) mutex_destroy(&cmd->tc_mtx);
		free(cmd);
	}
}

/*
 * Enable the barcode capability on the library
 */
void
tlm_enable_barcode(int l)
{
	tlm_library_t *lp = tlm_library(l);

	if (lp != NULL)
		lp->tl_capability_barcodes = TRUE;
}

/*
 * SASD SCSI support
 */
static scsi_adapter_t my_sa;
static int sasd_drive_count = 0;
static scsi_sasd_drive_t *scsi_sasd_drives[128];

/*
 * Count of SCSI devices
 */
int
sasd_dev_count(void)
{
	return (sasd_drive_count);
}

/*
 * Return the SCSI device name
 */
char *
sasd_slink_name(scsi_link_t *slink)
{
	int i;

	for (i = 0; i < sasd_drive_count; i++) {
		if (&scsi_sasd_drives[i]->ss_slink == slink)
			return (scsi_sasd_drives[i]->ss_sd.sd_name);
	}
	return (NULL);
}

/*
 * Return the SCSI drive structure
 */
sasd_drive_t *
sasd_slink_drive(scsi_link_t *slink)
{
	int i;

	for (i = 0; i < sasd_drive_count; i++) {
		if (&scsi_sasd_drives[i]->ss_slink == slink)
			return (&scsi_sasd_drives[i]->ss_sd);
	}
	return (NULL);
}

/*
 * Return the SCSI link pointer for the given index
 */
scsi_link_t *
sasd_dev_slink(int entry)
{
	scsi_link_t *rv;

	if (entry >= 0 && entry < sasd_drive_count)
		rv = &scsi_sasd_drives[entry]->ss_slink;
	else
		rv = NULL;

	return (rv);
}

/*
 * Return the SCSI drive for the given index
 */
sasd_drive_t *
sasd_drive(int entry)
{
	sasd_drive_t *rv;

	if (entry >= 0 && entry < sasd_drive_count)
		rv = &scsi_sasd_drives[entry]->ss_sd;
	else
		rv = NULL;

	return (rv);
}

/*
 * Attach the SCSI device by updating the structures
 */
void
scsi_sasd_attach(ndmp_session_t *session, scsi_adapter_t *sa, int sid, int lun,
    char *name, int type)
{
	scsi_link_t *sl, *next;
	scsi_sasd_drive_t *ssd;

	ssd = ndmp_malloc(session, sizeof (scsi_sasd_drive_t));
	if (ssd == NULL)
		return;

	scsi_sasd_drives[sasd_drive_count++] = ssd;

	switch (type) {
	case DTYPE_CHANGER:
		(void) snprintf(ssd->ss_sd.sd_name,
		    sizeof (ssd->ss_sd.sd_name), "%s/%s", SCSI_CHANGER_DIR,
		    name);
		break;
	case DTYPE_SEQUENTIAL:
		(void) snprintf(ssd->ss_sd.sd_name,
		    sizeof (ssd->ss_sd.sd_name), "%s/%s", SCSI_TAPE_DIR, name);
		break;
	}

	sl = &ssd->ss_slink;
	sl->sl_type = type;
	sl->sl_sa = sa;
	sl->sl_lun = lun;
	sl->sl_sid = sid;
	sl->sl_requested_max_active = 1;

	/* Insert slink */
	next = sa->sa_link_head.sl_next;
	sa->sa_link_head.sl_next = sl;
	sl->sl_next = next;
}

/*
 * Go through the attached devices and detect the tape
 * and robot by checking the /dev entries
 */
int
probe_scsi(ndmp_session_t *session)
{
	DIR *dirp;
	struct dirent *dp;
	scsi_adapter_t *sa = &my_sa;
	char *p;
	int lun = 0;
	int sid = 0;
	const char *drive_type;

	/* Initialize the scsi adapter link */
	sa->sa_link_head.sl_next = &sa->sa_link_head;

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

			scsi_sasd_attach(session, sa, 0, lun, dp->d_name,
			    DTYPE_CHANGER);
		}
		(void) closedir(dirp);
	}

	/* Scan for tape drives */
	dirp = opendir(SCSI_TAPE_DIR);
	if (dirp != NULL) {
		drive_type = ndmp_get_prop(session, NDMP_DRIVE_TYPE);

		if ((strcasecmp(drive_type, "sysv") != 0) &&
		    (strcasecmp(drive_type, "bsd") != 0))
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

			if (strcasecmp(drive_type, "sysv") == 0) {
				if (strchr(dp->d_name, 'b') != NULL)
					continue;
			} else if (strcasecmp(drive_type, "bsd") == 0) {
				if (strchr(dp->d_name, 'b') == NULL)
					continue;
			}

			sid = atoi(dp->d_name);

			/*
			 * SCSI ID should match with the ID of the device
			 * (will be checked by SCSI get elements page later)
			 */
			scsi_sasd_attach(session, sa, sid, 0, dp->d_name,
			    DTYPE_SEQUENTIAL);
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
scsi_get_devtype(char *adapter, int sid, int lun)
{
	int rv;
	scsi_adapter_t *sa = &my_sa;
	scsi_link_t *sl, *sh;

	rv = -1;
	sh = &sa->sa_link_head;
	for (sl = sh->sl_next; sl != sh; sl = sl->sl_next)
		if (sl->sl_sid == sid && sl->sl_lun == lun)
			rv = sl->sl_type;

	return (rv);
}


/*
 * Check if the SCSI device exists
 */
/*ARGSUSED*/
int
scsi_dev_exists(char *adapter, int sid, int lun)
{
	scsi_adapter_t *sa = &my_sa;
	scsi_link_t *sl, *sh;

	sh = &sa->sa_link_head;
	for (sl = sh->sl_next; sl != sh; sl = sl->sl_next)
		if (sl->sl_sid == sid && sl->sl_lun == lun)
			return (1);
	return (0);
}


/*
 * Count of SCSI adapters
 */
int
scsi_get_adapter_count(void)
{
	/* Currently support one adapter only */
	return (1);
}

/*
 * Return the SCSI adapter structure
 */
/*ARGSUSED*/
scsi_adapter_t *
scsi_get_adapter(int adapter)
{
	return (&my_sa);
}

/*
 * IOCTL wrapper with retries
 */
int
tlm_ioctl(int fd, int cmd, void *data)
{
	int retries = 0;

	if (fd == 0 || data == NULL)
		return (EINVAL);

	do {
		if (ioctl(fd, cmd, data) == 0)
			break;

		if (errno != EIO && errno != 0)
			return (errno);

		(void) sleep(1);
	} while (retries++ < MAXIORETRY);

	return (0);
}
