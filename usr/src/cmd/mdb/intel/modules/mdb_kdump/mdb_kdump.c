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
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_ctf.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <zlib.h>
#include <stdlib.h>

#define	DEBUG_PRINTF	0

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

#define	DUMP_DH_COMPRESSED_ZLIB		0x1
#define	DUMP_DH_COMPRESSED_LZO		0x2
#define	DUMP_DH_COMPRESSED_SNAPPY	0x4
#define	DUMP_DH_COMPRESSED_INCOMPLETE	0x8
#define	DUMP_DH_EXCLUDED_VMEMMAP	0x10

typedef struct page_desc {
	off_t			offset;
	unsigned int		size;
	unsigned int		flags;
	unsigned long long	page_flags;
} page_desc_t;

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
	unsigned long		*kd_valid_pages;
	size_t			kd_valid_pages_size;
	char			*kd_vmcoreinfo;
	size_t			kd_vmcoreinfo_size;
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

	if (kdump->kd_valid_pages != NULL) {
		mdb_free(kdump->kd_valid_pages, kdump->kd_valid_pages_size);
	}

	if (kdump->kd_vmcoreinfo != NULL) {
		mdb_free(kdump->kd_vmcoreinfo, kdump->kd_vmcoreinfo_size);
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

static boolean_t
kdump_page_is_dumpable(kdump_data_t *kdump, unsigned long nr)
{
	char *bitmap = kdump->kd_hdr.kh_second_bitmap;
	return (bitmap[nr >> 3] & (1 << (nr & 7)));
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


	off_t vmcoreinfo_offset = kdump->kd_hdr.kh_sub_header.offset_vmcoreinfo;
	kdump->kd_vmcoreinfo_size =
	    kdump->kd_hdr.kh_sub_header.size_vmcoreinfo + 1;

	if (lseek(kdump->kd_fd, vmcoreinfo_offset, SEEK_SET) == -1) {
		mdb_warn("Failed to seek to vmcoreinfo\n");
		goto error;
	}

	kdump->kd_vmcoreinfo = mdb_alloc(kdump->kd_vmcoreinfo_size, UM_SLEEP);

	if (read(kdump->kd_fd, kdump->kd_vmcoreinfo,
	    kdump->kd_vmcoreinfo_size - 1) != kdump->kd_vmcoreinfo_size -1) {
		mdb_warn("Failed to read vmcoreinfo\n");
		goto error;
	}

	kdump->kd_vmcoreinfo[kdump->kd_vmcoreinfo_size] = '\0';

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
	first_bitmap = mdb_zalloc(bitmap_size, UM_SLEEP);
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

	second_bitmap = mdb_zalloc(bitmap_size, UM_SLEEP);
	kdump->kd_hdr.kh_second_bitmap = second_bitmap;

	if (kdump_is_partial(kdump)) {
		memcpy(second_bitmap, first_bitmap + (bitmap_size / 2),
		    bitmap_size / 2);
	} else {
		memcpy(second_bitmap, first_bitmap, bitmap_size);
	}

	kdump->kd_data_offset =
	    (1 + main_hdr->sub_hdr_size + main_hdr->bitmap_blocks) * blksz;

	unsigned long pfn = 0;
	unsigned long max_sect_len = divideup(kdump->kd_max_mapnr, blksz);
	kdump->kd_valid_pages_size = sizeof (unsigned long) * max_sect_len;
	kdump->kd_valid_pages =
	    mdb_zalloc(kdump->kd_valid_pages_size, UM_SLEEP);

#if DEBUG_PRINTF
	printf("%s: max_sect_len: %lx\n", __FUNCTION__, max_sect_len);
	printf("%s: kd_valid_pages_size: %lx\n", __FUNCTION__,
	    kdump->kd_valid_pages_size);
#endif

	for (unsigned int i = 1; i < max_sect_len + 1; i++) {
		kdump->kd_valid_pages[i] = kdump->kd_valid_pages[i - 1];
		for (unsigned int j = 0; j < blksz; j++, pfn++) {
			if (kdump_page_is_dumpable(kdump, pfn))
				kdump->kd_valid_pages[i]++;
		}
	}

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

static char *
kdump_vmcoreinfo_lookup(kdump_data_t *kdump, const char *key, size_t *size)
{
	size_t keylen = strlen(key);
	char *lookup = NULL;
	char *value = NULL;
	char *p1, *p2;

	lookup = mdb_alloc(keylen + 2, UM_SLEEP);
	snprintf(lookup, keylen + 2, "%s=", key);
	lookup[keylen + 2] = '\0';

	if ((p1 = strstr(kdump->kd_vmcoreinfo, lookup)) != NULL) {
		p2 = p1 + strlen(lookup);
		p1 = strstr(p2, "\n");

		*size = p1 - p2;
		value = mdb_alloc(*size, UM_SLEEP);
		strncpy(value, p2, *size);
		value[*size] = '\0';
	}

	mdb_free(lookup, keylen + 2);
	return (value);
}

static mdb_io_t *
kdump_sym_io(void *data, const char *symfile)
{
	kdump_data_t *kdump = data;
	mdb_io_t *io = NULL;
	char *kerneloffset;
	size_t size;

	kerneloffset = kdump_vmcoreinfo_lookup(kdump, "KERNELOFFSET", &size);
	if (kerneloffset == NULL) {
		mdb_warn("Failed to lookup KERNELOFFSET\n");
		return (NULL);
	}

	if ((io = mdb_fdio_create_path(NULL, symfile, O_RDONLY, 0)) == NULL) {
		mdb_warn("Failed to open '%s'\n", symfile);
		mdb_free(kerneloffset, size);
		return (NULL);
	}

	io->io_kerneloffset = strtoull(kerneloffset, NULL, 16);

#if DEBUG_PRINTF
	printf("kerneloffset string: %s\n", kerneloffset);
	printf("kerneloffset number: %lx\n", io->io_kerneloffset);
#endif

	mdb_free(kerneloffset, size);

	return (io);
}

static unsigned long
kdump_paddr_to_pfn(kdump_data_t *kdump, uintptr_t addr)
{
	return (addr >> (ffs(kdump->kd_hdr.kh_main_header.block_size) - 1));
}

static unsigned long
kdump_pfn_to_pdi(kdump_data_t *kdump, unsigned long pfn)
{
	unsigned long p1 = pfn;
	unsigned long p2 = round(pfn, kdump->kd_hdr.kh_main_header.block_size);
	unsigned long valid =
	    kdump->kd_valid_pages[p1 / kdump->kd_hdr.kh_main_header.block_size];
	unsigned long pdi = valid;

#if DEBUG_PRINTF
	printf("%s: p1: %lx\n", __FUNCTION__, p1);
	printf("%s: p2: %lx\n", __FUNCTION__, p2);
	printf("%s: valid: %lx\n", __FUNCTION__, valid);
	printf("%s: pdi: %lx\n", __FUNCTION__, pdi);
#endif

	for (int j = p2; j <= pfn; j++) {
		if (kdump_page_is_dumpable(kdump, j))
			pdi++;
	}

	return (pdi);
}

static ssize_t
kdump_pread(void *data, uintptr_t addr, void *buf, size_t size)
{
	kdump_data_t *kdump = data;
	unsigned long block_size = kdump->kd_hdr.kh_main_header.block_size;
	uintptr_t page_addr = addr & ~(block_size - 1);
	unsigned long page_offset = addr & (block_size - 1);
	unsigned long pfn = kdump_paddr_to_pfn(kdump, page_addr);
	unsigned long pdi = kdump_pfn_to_pdi(kdump, pfn);
	off_t offset = kdump->kd_data_offset +
	    ((off_t)(pdi - 1) * sizeof (page_desc_t));
	page_desc_t pd;

#if DEBUG_PRINTF
	printf("%s: addr: %lx\n", __FUNCTION__, addr);
	printf("%s: page addr: %lx\n", __FUNCTION__, page_addr);
	printf("%s: page offset: %lx\n", __FUNCTION__, page_offset);
	printf("%s: size: %lx\n", __FUNCTION__, size);
	printf("%s: pfn: %lx\n", __FUNCTION__, pfn);
	printf("%s: pdi: %lx\n", __FUNCTION__, pdi);
	printf("%s: offset: %lx\n", __FUNCTION__, offset);
	printf("%s: data: %lx\n", __FUNCTION__, kdump->kd_data_offset);
#endif

	if (lseek(kdump->kd_fd, offset, SEEK_SET) == -1) {
		mdb_warn("Failed to seek to page descriptor\n");
		return (-1);
	}

	if (read(kdump->kd_fd, &pd, sizeof (pd)) != sizeof (pd)) {
		mdb_warn("Failed to read page descriptor\n");
		return (-1);
	}

#if DEBUG_PRINTF
	printf("%s: pd offset: %lx\n", __FUNCTION__, pd.offset);
	printf("%s: pd size: %lx\n", __FUNCTION__, pd.size);
	printf("%s: pd flags: %lx\n", __FUNCTION__, pd.flags);
	printf("%s: pd page flags: %lx\n", __FUNCTION__, pd.page_flags);
#endif

	if (pd.size > block_size) {
		mdb_warn("Failed to read page descriptor (incorrect size)\n");
		return (-1);
	}

	if (lseek(kdump->kd_fd, pd.offset, SEEK_SET) == -1) {
		mdb_warn("Failed to seek to compressed page\n");
		return (-1);
	}

	void *cpage = mdb_zalloc(pd.size, UM_SLEEP);
	void *upage = mdb_zalloc(block_size, UM_SLEEP);

	if (read(kdump->kd_fd, cpage, pd.size) != pd.size) {
		mdb_warn("Failed to read compressed page\n");
		goto error;
	}

	if (pd.flags & (DUMP_DH_COMPRESSED_LZO | DUMP_DH_COMPRESSED_SNAPPY)) {
		mdb_warn("Compression format not supported\n");
		goto error;
	} else if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
		unsigned long retlen = block_size;
		int ret = uncompress(upage, &retlen, cpage, pd.size);
		if ((ret != Z_OK) || (retlen != block_size)) {
			mdb_warn("Failed to decompress page\n");
			goto error;
		}
	} else {
		if (pd.size != block_size) {
			mdb_warn("Page size not equal to block size\n");
			goto error;
		}

		memcpy(upage, cpage, block_size);
	}

	size = MIN(size, pd.size);
	memcpy(buf, upage + page_offset, size);
	mdb_free(cpage, pd.size);
	mdb_free(upage, block_size);
	return (size);

error:
	mdb_free(cpage, pd.size);
	mdb_free(upage, block_size);
	return (-1);
}

static ssize_t
kdump_kread(void *data, uintptr_t addr, void *buf, size_t size)
{
	kdump_data_t *kdump = data;
	const unsigned long start_kernel_map = 0xffffffff80000000UL;
	const unsigned long phys_base = kdump->kd_hdr.kh_sub_header.phys_base;

	uintptr_t paddr = addr - start_kernel_map + phys_base;

#if DEBUG_PRINTF
	printf("%s: vaddr: %lx\n", __FUNCTION__, addr);
	printf("%s: paddr: %lx\n", __FUNCTION__, paddr);
	printf("%s: size: %lx\n", __FUNCTION__, size);
#endif

	return (kdump_pread(kdump, paddr, buf, size));
}

static mdb_kb_ops_t kdump_kb_ops = {
	.kb_open	= kdump_open,
	.kb_close	= kdump_close,
	.kb_sym_io	= kdump_sym_io,
	.kb_kread	= kdump_kread,
	.kb_kwrite	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_aread	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_awrite	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_pread	= kdump_pread,
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
