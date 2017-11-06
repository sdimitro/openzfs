/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_kb.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_ctf.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define	divideup(x, y)	(((x) + ((y) - 1)) / (y))
#define	round(x, y)	(((x) / (y)) * (y))

#define	DUMP_PARTITION_SIGNATURE	"diskdump"
#define	SIG_LEN (sizeof (DUMP_PARTITION_SIGNATURE) - 1)
#define	DISK_DUMP_SIGNATURE		"DISKDUMP"
#define	KDUMP_SIGNATURE			"KDUMP   "

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct disk_dump_header {
	char			signature[SIG_LEN];
	int			header_version;
	struct new_utsname	utsname;
	struct timeval		timestamp;
	unsigned int		status;
	int			block_size;
	int			sub_hdr_size;
	unsigned int		bitmap_blocks;
	unsigned int		max_mapnr;
	unsigned int		total_ram_blocks;
	unsigned int		device_blocks;
	unsigned int		written_blocks;
	unsigned int		current_cpu;
	int			nr_cpus;
	struct task_struct	*tasks[0];
};

struct kdump_sub_header {
	unsigned long	phys_base;
	int		dump_level;
	int		split;
	unsigned long	start_pfn;
	unsigned long	end_pfn;
	off_t		offset_vmcoreinfo;
	unsigned long	size_vmcoreinfo;
	off_t		offset_note;
	unsigned long	size_note;
	off_t		offset_eraseinfo;
	unsigned long	size_eraseinfo;
	unsigned long long start_pfn_64;
	unsigned long long end_pfn_64;
	unsigned long long max_mapnr_64;
};

typedef struct kdump_header {
	struct disk_dump_header	kh_main_header;
	struct kdump_sub_header	kh_sub_header;
	void			*kh_first_bitmap;
	void			*kh_second_bitmap;
	size_t			kh_bitmap_size;
} kdump_header_t;

typedef struct kdump_data {
	int			kd_fd;
	kdump_header_t		kd_hdr;
	size_t			kd_hdr_bitmap_size;
	unsigned long long	kd_max_mapnr;
	off_t			kd_data_offset;
} kdump_data_t;

static inline int
kdump_is_partial(kdump_data_t *kdump)
{
	struct disk_dump_header	*hdr = &kdump->kd_hdr.kh_main_header;

	return hdr->bitmap_blocks >=
	    divideup(divideup(kdump->kd_max_mapnr, 8), hdr->block_size) * 2;
}

kdump_data_t *
kdump_alloc(void)
{
	kdump_data_t *kdump = mdb_zalloc(sizeof (*kdump), UM_SLEEP);
	return (kdump);
}

static void
kdump_free(kdump_data_t *kdump)
{
	if (kdump->kd_fd != -1) {
		(void) close(kdump->kd_fd);
	}

	if (kdump->kd_hdr.kh_first_bitmap != NULL) {
		mdb_free(kdump->kd_hdr.kh_first_bitmap,
		    kdump->kd_hdr.kh_bitmap_size);
	}

	if (kdump->kd_hdr.kh_second_bitmap != NULL) {
		mdb_free(kdump->kd_hdr.kh_second_bitmap,
		    kdump->kd_hdr.kh_bitmap_size);
	}

	mdb_free(kdump, sizeof (*kdump));
}

int
kdump_identify(const char *file, int *longmode)
{
	char	signature[SIG_LEN];
	int	fd;

	if ((fd = open(file, O_RDONLY)) == -1) {
		mdb_warn("Failed to open file '%s'\n", file);
		return (-1);
	}

	if (read(fd, signature, sizeof (signature)) != sizeof (signature)) {
		mdb_warn("Failed to read kdump signature\n");
		return (-1);
	}

	if (!memcmp(signature, KDUMP_SIGNATURE, sizeof (signature))) {
		(void) close(fd);
		*longmode = 1;
		return (1);
	}

	(void) close(fd);
	return (-1);
}

static void *
kdump_open(const char *symfile, const char *corefile, const char *swapfile,
    int flags, const char *err)
{
	kdump_data_t		*kdump = NULL;
	struct disk_dump_header	*main_hdr = NULL;
	struct kdump_sub_header	*sub_hdr = NULL;
	void			*first_bitmap = NULL;
	void			*second_bitmap = NULL;

	kdump = kdump_alloc();

	kdump->kd_fd = open(corefile, O_RDONLY);
	if (kdump->kd_fd == -1) {
		mdb_warn("Failed to open file '%s'\n", corefile);
		goto error;
	}

	main_hdr = &kdump->kd_hdr.kh_main_header;

	if (lseek(kdump->kd_fd, 0, SEEK_SET) == -1) {
		mdb_warn("Failed to seek to kdump main header\n");
		goto error;
	}

	if (read(kdump->kd_fd, main_hdr, sizeof (*main_hdr)) !=
	    sizeof (*main_hdr)) {
		mdb_warn("Failed to read kdump main header\n");
		goto error;
	}

	int blksz = main_hdr->block_size;
	sub_hdr = &kdump->kd_hdr.kh_sub_header;

	if (lseek(kdump->kd_fd, blksz, SEEK_SET) == -1) {
		mdb_warn("Failed to seek to kdump sub header\n");
		goto error;
	}

	if (read(kdump->kd_fd, sub_hdr, sizeof (*sub_hdr)) !=
	    sizeof (*sub_hdr)) {
		mdb_warn("Failed to read kdump sub header\n");
		goto error;
	}

	if (main_hdr->header_version >= 6)
		kdump->kd_max_mapnr = sub_hdr->max_mapnr_64;
	else
		kdump->kd_max_mapnr = main_hdr->max_mapnr;

	/*
	 * TODO: What is the format used to store these bitmaps? The
	 * logic below was mostly cribbed from the "crash" sources.
	 * Looking at the documentation for the dump file's format, it
	 * doesn't appear to be consistent with what I see done by
	 * "crash" when reading in the bitmaps. This confusion needs to
	 * be cleared up, but for now, we simply do what "crash" does.
	 */

	off_t bitmap_offset = (1 + main_hdr->sub_hdr_size) * blksz;
	size_t bitmap_size = main_hdr->bitmap_blocks * blksz;
	first_bitmap = mdb_alloc(bitmap_size, UM_SLEEP);
	kdump->kd_hdr.kh_bitmap_size = bitmap_size;
	kdump->kd_hdr.kh_first_bitmap = first_bitmap;

	if (lseek(kdump->kd_fd, bitmap_offset, SEEK_SET) == -1) {
		mdb_warn("Failed to seek to kdump first bitmap\n");
		goto error;
	}

	if (read(kdump->kd_fd, first_bitmap, bitmap_size) != bitmap_size) {
		mdb_warn("Failed to read kdump first bitmap\n");
		goto error;
	}

	second_bitmap = mdb_alloc(bitmap_size, UM_SLEEP);
	kdump->kd_hdr.kh_second_bitmap = second_bitmap;

	if (kdump_is_partial(kdump)) {
		memcpy(second_bitmap, first_bitmap + (bitmap_size / 2),
		    bitmap_size / 2);
	} else {
		memcpy(second_bitmap, first_bitmap, bitmap_size);
	}

	kdump->kd_data_offset =
	    (1 + main_hdr->sub_hdr_size + main_hdr->bitmap_blocks) * blksz;

	return (kdump);

error:
	kdump_free(kdump);
	return (NULL);
}

static int
kdump_close(void *data)
{
	kdump_free(data);
	return (0);
}

static mdb_io_t *
kdump_sym_io(void *data, const char *symfile)
{
	return (NULL);
}

static mdb_kb_ops_t kdump_kb_ops = {
	.kb_open	= kdump_open,
	.kb_close	= kdump_close,
	.kb_sym_io	= kdump_sym_io,
	.kb_kread	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_kwrite	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_aread	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_awrite	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_pread	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_pwrite	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_vtop	= (uint64_t (*)())mdb_tgt_notsup,
	.kb_getmregs	= (int (*)())mdb_tgt_notsup,
};

mdb_kb_ops_t *
mdb_kdump_ops(void)
{
	return (&kdump_kb_ops);
}

static const mdb_dcmd_t dcmds[] = {
	NULL
};

static const mdb_walker_t walkers[] = {
	NULL
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION,
	dcmds,
	walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

void
_mdb_fini(void)
{
}
