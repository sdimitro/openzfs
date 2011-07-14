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

/* Copyright (c) 2011 by Delphix. All rights reserved. */

#ifndef	_TLM_H_
#define	_TLM_H_

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <strings.h>
#include <synch.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define	IS_SET(f, m)	(((f) & (m)) != 0)

#define	TLM_MAX_BACKUP_JOB_NAME	32	/* max size of a job's name */
#define	TLM_TAPE_BUFFERS	10	/* number of rotating tape buffers */
#define	TLM_LINE_SIZE		128	/* size of text messages */

#define	TLM_BACKUP_RUN		0x00000001
#define	TLM_RESTORE_RUN		0x00000002
#define	TLM_STOP		0x00000009	/* graceful stop */
#define	TLM_ABORT		0x99999999	/* abandon the run */

#define	TLM_EXTRA_SPACE		64
#define	TLM_MAX_PATH_NAME	(PATH_MAX + TLM_EXTRA_SPACE)

/* operation flags */
#define	TLM_OP_CHOOSE_ARCHIVE	0x00000001	/* look for archive bit */

/*
 * Synchronization flags used when launching the TLM threads.
 */
#define	TLM_TAPE_READER		0x00000001
#define	TLM_TAPE_WRITER		0x00000002
#define	TLM_SOCK_READER		0x00000004
#define	TLM_SOCK_WRITER		0x00000008
#define	TLM_BUF_READER		0x00000010
#define	TLM_BUF_WRITER		0x00000020
#define	TLM_TAR_READER		0x00000040
#define	TLM_TAR_WRITER		0x00000080

#define	SCSI_SERIAL_PAGE	0x80
#define	SCSI_DEVICE_IDENT_PAGE	0x83
#define	SCMD_READ_ELEMENT_STATUS	0xB8

#define	OCTAL7CHAR	07777777
#define	SYSATTR_RDONLY	"SUNWattr_ro"
#define	SYSATTR_RW	"SUNWattr_rw"

typedef	int (*func_t)();

typedef struct scsi_serial {
	int sr_flags;
	char sr_num[16];
} scsi_serial_t;

typedef struct fs_fhandle {
	int fh_fid;
	char *fh_fpath;
} fs_fhandle_t;

typedef struct scsi_link {
	struct scsi_link 	*sl_next;
	struct scsi_link 	*sl_prev;
	struct scsi_adapter 	*sl_sa;
	unsigned int		sl_sid;
	unsigned int		sl_lun;
	unsigned int		sl_requested_max_active;
	unsigned int		sl_granted_max_active;
	unsigned int		sl_n_active;
	unsigned int		sl_type; /* SCSI device type */
} scsi_link_t;

typedef struct scsi_adapter {
	struct scsi_adapter	*sa_next;
	char			sa_name[16];
	struct scsi_link	sa_link_head;
} scsi_adapter_t;

typedef struct sasd_drive {
	char		sd_name[256];
	char		sd_vendor[8 + 1];
	char		sd_id[16 + 1];
	char		sd_rev[4 + 1];
	char		sd_serial[16 + 1];
	char		sd_wwn[32 + 1];
} sasd_drive_t;

typedef struct scsi_sasd_drive {
	sasd_drive_t	ss_sd;
	scsi_link_t	ss_slink;
} scsi_sasd_drive_t;


#define	DEFAULT_SLINK_MAX_XFER	(64*1024)

typedef struct	tlm_info {
	int			ti_init_done;	/* initialization done ? */
	int			ti_library_count; /* number of libraries */
	struct tlm_library	*ti_library;	/* first in chain */
} tlm_info_t;

typedef struct	tlm_chain_link {
	struct tlm_chain_link	*tc_next;	/* next blob of statistics */
	struct tlm_chain_link	*tc_prev;	/* previous blob in the chain */
	int	tc_ref_count;			/* number of routines */
	void	*tc_data;			/* the data blob */
} tlm_chain_link_t;

typedef struct	tlm_robot {
	struct tlm_robot	*tr_next;
	struct tlm_library	*tr_library;
	int	tr_number;
} tlm_robot_t;

typedef struct	tlm_drive {
	struct tlm_drive	*td_next;
	struct tlm_library	*td_library;
	char	td_job_name[TLM_MAX_BACKUP_JOB_NAME];
	int	td_number;		/* number of this tape drive */
	int	td_element;		/* the library's number for the drive */
	struct	scsi_link *td_slink;	/* because the drive may be connected */
					/* to a different SCSI card than the */
					/* library */
	short	td_scsi_id;
	short	td_lun;
	short	td_volume_number;	/* for current job */
					/*  an index into the tape set */
	int	td_fd;			/* I/O file descriptor */
	int	td_errno;		/* system error number */
	long	td_exists	: 1;

} tlm_drive_t;

typedef struct	tlm_slot {
	struct tlm_slot		*ts_next;
	struct tlm_library	*ts_library;
	int	ts_number;		/* number of this slot */
	int	ts_element;
	short	ts_use_count;		/* number of times used since loaded */
	long	ts_status_full		: 1;
} tlm_slot_t;

typedef struct	tlm_library {
	struct tlm_library	*tl_next;
	int	tl_number;		/* number of this tape library */
	long	tl_capability_robot	: 1,
		tl_capability_door	: 1,
		tl_capability_lock	: 1,
		tl_capability_slots	: 1,
		tl_capability_export	: 1,
		tl_capability_drives	: 1,
		tl_capability_barcodes	: 1,
		tl_ghost_drives		: 1;
		/*
		 * "ghost_drives" is used to make sure that
		 * all drives claimed by the library really
		 * exist ... libraries have been known to lie.
		 */
	struct	scsi_link *tl_slink;

	int		tl_robot_count;
	tlm_robot_t	*tl_robot;
	int		tl_drive_count;
	tlm_drive_t	*tl_drive;
	int		tl_slot_count;
	tlm_slot_t	*tl_slot;
} tlm_library_t;

typedef struct {
#ifdef _BIG_ENDIAN
	uint8_t	di_peripheral_qual	: 3,
		di_peripheral_dev_type	: 5;
	uint8_t	di_page_code;
	uint16_t	di_page_length;
#else
	uint8_t	di_peripheral_dev_type	: 5,
		di_peripheral_qual	: 3;
	uint8_t	di_page_code;
	uint16_t	di_page_length;
#endif
} device_ident_header_t;

typedef struct {
#ifdef _BIG_ENDIAN
	uint8_t	ni_proto_ident	: 4,
		ni_code_set	: 4;

	uint8_t	ni_PIV		: 1,
				: 1,
		ni_asso		: 2,
		ni_ident_type	: 4;

	uint8_t	ni_reserved;
	uint8_t	ni_ident_length;
#else
	uint8_t	ni_code_set	: 4,
		ni_proto_ident	: 4;

	uint8_t	ni_ident_type	: 4,
		ni_asso		: 2,
				: 1,
		ni_PIV		: 1;
	uint8_t	ni_reserved;
	uint8_t	ni_ident_length;
#endif
} name_ident_t;

#define	TLM_NO_ERRORS			0x00000000
#define	TLM_ERROR_BUSY			0x00000001
#define	TLM_ERROR_INTERNAL		0x00000002
#define	TLM_ERROR_NO_ROBOTS		0x00000003
#define	TLM_TIMEOUT			0x00000004
#define	TLM_ERROR_RANGE			0x00000005
#define	TLM_EMPTY			0x00000006
#define	TLM_DRIVE_NOT_ASSIGNED		0x00000007
#define	TLM_NO_TAPE_NAME		0x00000008
#define	TLM_NO_BACKUP_DIR		0x00000009
#define	TLM_NO_BACKUP_HARDWARE		0x0000000a
#define	TLM_NO_SOURCE_FILE		0x0000000b
#define	TLM_NO_FREE_TAPES		0x0000000c
#define	TLM_EOT				0x0000000d
#define	TLM_SERIAL_NOT_FOUND		0x0000000e
#define	TLM_SMALL_READ			0x0000000f
#define	TLM_NO_RESTORE_FILE		0x00000010
#define	TLM_EOF				0x00000011
#define	TLM_NO_DIRECTORY		0x00000012
#define	TLM_NO_MEMORY			0x00000013
#define	TLM_WRITE_ERROR			0x00000014
#define	TLM_NO_SCRATCH_SPACE		0x00000015
#define	TLM_INVALID			0x00000016
#define	TLM_MOVE			0x00000017
#define	TLM_SKIP			0x00000018
#define	TLM_OPEN_ERR			0x00000019

#define	TLM_MAX_TAPE_DRIVES	16
#define	TLM_NAME_SIZE		100
#define	TLM_MAX_TAR_IMAGE	017777777770

#define	TLM_VOLNAME_MAX_LENGTH	255
#define	NAME_MAX		255

#define	TLM_MAGIC		"ustar  "
#define	TLM_SNAPSHOT_PREFIX	".zfs"
#define	TLM_SNAPSHOT_DIR	".zfs/snapshot"

#define	RECORDSIZE	512

#define	KILOBYTE	1024

#define	SCSI_CHANGER_DIR	"/dev/scsi/changer"
#define	SCSI_TAPE_DIR		"/dev/rmt"

#define	MAXIORETRY	20

/* tlm buffers */

#define	NDMP_MAX_SELECTIONS	64

typedef struct	tlm_buffer {
	char	*tb_buffer_data;	/* area to be used for I/O */
	long	tb_buffer_size;	/* number of valid bytes in the buffer */
	long	tb_buffer_spot;	/* current location in the I/O buffer */
	longlong_t tb_seek_spot;	/* for BACKUP */
				/* where in the file this buffer stops. */
				/* this is used for the Multi Volume */
				/* Header record. */
	longlong_t tb_file_size;	/* for BACKUP */
					/* how much of the file is left. */
	int	tb_full	: 1,
		tb_eot	: 1,
		tb_eof	: 1;
	int	tb_errno;	/* I/O error values */
} tlm_buffer_t;

/*
 * Flags for tlm_buffers.
 */
#define	TLM_BUF_IN_READY	0x00000001
#define	TLM_BUF_OUT_READY	0x00000002

typedef struct	tlm_buffers {
	int	tbs_ref;	/* number of threads using this */
	short	tbs_buffer_in;	/* buffer to be filled */
	short	tbs_buffer_out;	/* buffer to be emptied */
				/* these are indexes into tlm_buffers */
	mutex_t	tbs_mtx;
	cond_t	tbs_in_cv;
	cond_t	tbs_out_cv;
	uint32_t	tbs_flags;
	long	tbs_data_transfer_size;	/* max size of read/write buffer */
	longlong_t tbs_offset;
	tlm_buffer_t tbs_buffer[TLM_TAPE_BUFFERS];
} tlm_buffers_t;

typedef struct	tlm_cmd {
	int	tc_ref;			/* number of threads using this */
	mutex_t	tc_mtx;
	cond_t	tc_cv;
	uint32_t	tc_flags;
	int	tc_reader;		/* writer to reader */
	int	tc_writer;		/* reader to writer */
	char	tc_file_name[TLM_MAX_PATH_NAME]; /* name of last file */
						/* for restore */
	tlm_buffers_t *tc_buffers; /* reader-writer speedup buffers */
} tlm_cmd_t;

typedef struct	tlm_commands {
	int	tcs_reader;	/* commands to all readers */
	int	tcs_writer;	/* commands to all writers */
	int	tcs_reader_count;	/* number of active readers */
	int	tcs_writer_count;	/* number of active writers */
	int	tcs_error;	/* worker errors */
	char	tcs_message[TLM_LINE_SIZE]; /* worker message back to user */
	tlm_cmd_t *tcs_command;	/* IPC area between read-write */
} tlm_commands_t;

struct full_dir_info {
	fs_fhandle_t fd_dir_fh;
	char fd_dir_name[TLM_MAX_PATH_NAME];
};

typedef struct bk_selector {
	void *bs_cookie;
	int bs_level;
	int bs_ldate;
	boolean_t (*bs_fn)(struct bk_selector *bks, struct stat64 *s);
} bk_selector_t;


/*
 *  RSFLG_OVR_*: overwriting policies.  Refer to LBR FSD for more info.
 *  RSFLG_MATCH_WCARD: should wildcards be supported in the selection list.
 *  RSFLG_IGNORE_CASE: should the compare be case-insensetive.  NDMP needs
 * 	case-sensetive name comparison.
 */
#define	RSFLG_OVR_ALWAYS	0x00000001
#define	RSFLG_OVR_NEVER		0x00000002
#define	RSFLG_OVR_UPDATE	0x00000004
#define	RSFLG_MATCH_WCARD	0x00000008
#define	RSFLG_IGNORE_CASE	0x00000010


/*
 * Different cases where two paths can match with each other.
 * Parent means that the current path, is parent of an entry in
 * the selection list.
 * Child means that the current path, is child of an entry in the
 * selection list.
 */
#define	PM_NONE		0
#define	PM_EXACT	1
#define	PM_PARENT	2
#define	PM_CHILD	3

struct ndmp_session;

extern boolean_t tlm_is_excluded(char *, char *, char **);
extern char *tlm_remove_checkpoint(char *, char *);
extern tlm_buffers_t *tlm_allocate_buffers(struct ndmp_session *session,
    boolean_t, long);
extern tlm_buffer_t *tlm_buffer_advance_in_idx(tlm_buffers_t *);
extern tlm_buffer_t *tlm_buffer_advance_out_idx(tlm_buffers_t *);
extern tlm_buffer_t *tlm_buffer_in_buf(tlm_buffers_t *, int *);
extern tlm_buffer_t *tlm_buffer_out_buf(tlm_buffers_t *, int *);
extern void tlm_buffer_mark_empty(tlm_buffer_t *);
extern void tlm_buffer_release_in_buf(tlm_buffers_t *);
extern void tlm_buffer_release_out_buf(tlm_buffers_t *);
extern void tlm_buffer_in_buf_wait(tlm_buffers_t *);
extern void tlm_buffer_out_buf_wait(tlm_buffers_t *);
extern void tlm_buffer_in_buf_timed_wait(tlm_buffers_t *, unsigned);
extern void tlm_buffer_out_buf_timed_wait(tlm_buffers_t *, unsigned);
extern char *tlm_get_write_buffer(long, long *, tlm_buffers_t *, int);
extern char *tlm_get_read_buffer(int, int *, tlm_buffers_t *, int *);
extern void tlm_unget_read_buffer(tlm_buffers_t *, int);
extern void tlm_unget_write_buffer(tlm_buffers_t *, int);
extern void tlm_release_buffers(tlm_buffers_t *);
extern tlm_cmd_t *tlm_create_reader_writer_ipc(struct ndmp_session *,
    boolean_t, long);
extern void tlm_release_reader_writer_ipc(tlm_cmd_t *);

extern void tlm_cmd_wait(tlm_cmd_t *, uint32_t);
extern void tlm_cmd_signal(tlm_cmd_t *, uint32_t);

typedef struct {
	tlm_commands_t *ba_commands;
	tlm_cmd_t *ba_cmd;
	char *ba_job;
	char *ba_dir;
	char *ba_sels[NDMP_MAX_SELECTIONS];
	pthread_barrier_t ba_barrier;
} tlm_backup_restore_arg_t;

struct ndmp_session;

/* external prototypes */
extern tlm_drive_t *tlm_drive(int, int);
extern tlm_library_t *tlm_library(int);
extern tlm_slot_t *tlm_slot(int, int);

extern sasd_drive_t *sasd_slink_drive(scsi_link_t *);
extern scsi_link_t *sasd_dev_slink(int);
extern sasd_drive_t *sasd_drive(int);
extern scsi_adapter_t *scsi_get_adapter(int);
extern int scsi_get_adapter_count(void);

extern char *sasd_slink_name(scsi_link_t *);
extern int sasd_dev_count(void);
extern int tlm_ioctl(int, int, void *);
extern int probe_scsi(struct ndmp_session *);

extern void tlm_enable_barcode(int);
extern int tlm_insert_new_library(struct ndmp_session *, scsi_link_t *);
extern int tlm_insert_new_drive(struct ndmp_session *, int);
extern int tlm_insert_new_slot(struct ndmp_session *, int);

extern char *tlm_get_tape_name(int, int);
extern int tlm_library_count(void);

#endif	/* !_TLM_H_ */
