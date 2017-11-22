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

#include <sys/ucontext.h>
#include <sys/privmregs.h>

#define	DEBUG_PRINTF	0

#define	NR_CPUS		8192

#define	divideup(x, y)	(((x) + ((y) - 1)) / (y))
#define	round(x, y)	(((x) / (y)) * (y))
#define	roundup(x, y)	((((x) + ((y) - 1)) / (y)) * (y))

#define	DUMP_PARTITION_SIGNATURE	"diskdump"
#define	SIG_LEN				(sizeof (DUMP_PARTITION_SIGNATURE) - 1)
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

typedef struct x86_64_user_regs_struct {
	unsigned long r15, r14, r13, r12, bp, bx;
	unsigned long r11, r10, r9, r8, ax, cx, dx;
	unsigned long si, di, orig_ax, ip, cs;
	unsigned long flags, sp, ss, fs_base;
	unsigned long gs_base, ds, es, fs, gs;
} user_regs_t;

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
	void			*kd_elfnotes;
	size_t			kd_elfnotes_size;
	void			**kd_nt_prstatus;
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

	if (kdump->kd_elfnotes != NULL) {
		mdb_free(kdump->kd_elfnotes, kdump->kd_elfnotes_size);
	}

	if (kdump->kd_nt_prstatus != NULL) {
		mdb_free(kdump->kd_nt_prstatus, NR_CPUS * sizeof (void *));
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

static void init_kernel_vm(kdump_data_t *);

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
	    kdump->kd_vmcoreinfo_size - 1) != kdump->kd_vmcoreinfo_size - 1) {
		mdb_warn("Failed to read vmcoreinfo\n");
		goto error;
	}

	kdump->kd_vmcoreinfo[kdump->kd_vmcoreinfo_size] = '\0';

	off_t elfnotes_offset = kdump->kd_hdr.kh_sub_header.offset_note;
	kdump->kd_elfnotes_size = kdump->kd_hdr.kh_sub_header.size_note;

	if (lseek(kdump->kd_fd, elfnotes_offset, SEEK_SET) == -1) {
		mdb_warn("Failed to seek to ELF notes\n");
		goto error;
	}

	kdump->kd_elfnotes = mdb_alloc(kdump->kd_elfnotes_size, UM_SLEEP);

	if (read(kdump->kd_fd, kdump->kd_elfnotes,
	    kdump->kd_elfnotes_size) != kdump->kd_elfnotes_size) {
		mdb_warn("Failed to read ELF notes\n");
		goto error;
	}

	kdump->kd_nt_prstatus = mdb_zalloc(NR_CPUS * sizeof (void *), UM_SLEEP);

	unsigned int cpu = 0;
	for (size_t i = 0, len = 0; i < kdump->kd_elfnotes_size; i += len) {
		Elf64_Nhdr *nt = kdump->kd_elfnotes + i;

		if (nt->n_type == NT_PRSTATUS) {
			kdump->kd_nt_prstatus[cpu] = nt;
			cpu += 1;
		}

		len = sizeof (*nt);
		len = roundup(len + nt->n_namesz, 4);
		len = roundup(len + nt->n_descsz, 4);
	}

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

	init_kernel_vm(kdump);

	return (kdump);

error:
	kdump_free(kdump);
	return (NULL);
}

static void fini_kernel_vm(kdump_data_t *);

static int
kdump_close(void *data)
{
	kdump_free(data);
	fini_kernel_vm(data);
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
kdump_pread(void *data, uint64_t  addr, void *buf, size_t size)
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

	size = MIN(size, block_size);
	memcpy(buf, upage + page_offset, size);
	mdb_free(cpage, pd.size);
	mdb_free(upage, block_size);
	return (size);

error:
	mdb_free(cpage, pd.size);
	mdb_free(upage, block_size);
	return (-1);
}

static uint64_t kdump_vtop(void *, struct as *, uintptr_t);

static ssize_t
kdump_kread(void *data, uintptr_t addr, void *buf, size_t size)
{
	kdump_data_t *kdump = data;
	uintptr_t paddr;

	paddr = kdump_vtop(data, data, addr);
	if (paddr == (uintptr_t)-1LLU)
		return (-1);

#if DEBUG_PRINTF
	printf("%s: vaddr: %lx\n", __FUNCTION__, addr);
	printf("%s: paddr: %lx\n", __FUNCTION__, paddr);
	printf("%s: size: %lx\n", __FUNCTION__, size);
#endif

	return (kdump_pread(kdump, paddr, buf, size));
}

/*
 * Virtual to Physical Mapping
 */

#define	START_KERNEL_MAP	0xffffffff80000000ULL
#define	PAGE_OFFSET		0xffff880000000000ULL

#define	VMALLOC_START	(machdep->machspec->vmalloc_start_addr)
#define	VMALLOC_END	(machdep->machspec->vmalloc_end)

#define	IS_LAST_PGD_READ(pgd)	((ulong_t)(pgd) == machdep->last_pgd_read)
#define	IS_LAST_PMD_READ(pmd)	((ulong_t)(pmd) == machdep->last_pmd_read)
#define	IS_LAST_PTBL_READ(ptbl)	((ulong_t)(ptbl) == machdep->last_ptbl_read)

#define	FILL_PGD(PGD, TYPE, SIZE)					\
	if (!IS_LAST_PGD_READ(PGD)) {					\
		readmem(kdump, (uint64_t)((ulong_t)(PGD)), TYPE,	\
		    machdep->pgd, SIZE, "pgd page");			\
		machdep->last_pgd_read = (ulong_t)(PGD);		\
	}

#define	FILL_PMD(PMD, TYPE, SIZE)					\
	if (!IS_LAST_PMD_READ(PMD)) {					\
		readmem(kdump, (uint64_t)(PMD), TYPE, machdep->pmd,	\
		    SIZE, "pmd page");					\
		machdep->last_pmd_read = (ulong_t)(PMD);		\
	}

#define	FILL_PTBL(PTBL, TYPE, SIZE)					\
	if (!IS_LAST_PTBL_READ(PTBL)) {					\
		readmem(kdump, (uint64_t)(PTBL), TYPE, machdep->ptbl,	\
		    SIZE, "page table");				\
		machdep->last_ptbl_read = (ulong_t)(PTBL);		\
	}

#define	KVADDR		(0x1)
#define	UVADDR		(0x2)
#define	PHYSADDR	(0x4)


#define	PTOV(X)		((unsigned long)(X)+(machdep->kvbase))
#define	VTOP(X)		((unsigned long)(X)-(machdep->kvbase))
#define	IS_VMALLOC_ADDR(X) \
	(vt->vmalloc_start && (ulong_t)(X) >= vt->vmalloc_start)
#define	KVBASE_MASK	(0x1ffffff)

#define	PGDIR_SHIFT_2LEVEL	(22)
#define	PTRS_PER_PTE_2LEVEL	(1024)
#define	PTRS_PER_PGD_2LEVEL	(1024)

#define	PGDIR_SHIFT_3LEVEL	(30)
#define	PTRS_PER_PTE_3LEVEL	(512)
#define	PTRS_PER_PGD_3LEVEL	(4)


#define	PML4_SHIFT	39
#define	PTRS_PER_PML4	512
#define	PGDIR_SHIFT	30
#define	PTRS_PER_PGD	512
#define	PMD_SHIFT	21
#define	PTRS_PER_PMD	512
#define	PTRS_PER_PTE	512

#define	P4D_SHIFT	39
#define	PTRS_PER_P4D	512

#define	__PGDIR_SHIFT	PGDIR_SHIFT

#define	pml4_index(address)	(((address) >> PML4_SHIFT) & (PTRS_PER_PML4-1))
#define	p4d_index(address)	(((address) >> P4D_SHIFT) & (PTRS_PER_P4D - 1))
#define	pgd_index(address) (((address) >> __PGDIR_SHIFT) & (PTRS_PER_PGD-1))
#define	pmd_index(address)	(((address) >> PMD_SHIFT) & (PTRS_PER_PMD-1))
#define	pte_index(address)	(((address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

#define	IS_LAST_PML4_READ(pml4) \
	((ulong_t)(pml4) == machdep->machspec->last_pml4_read)

#define	FILL_PML4() { \
	if (!IS_LAST_PML4_READ(vt->kernel_pgd[0])) {		\
		readmem(kdump, vt->kernel_pgd[0], KVADDR,	\
		    machdep->machspec->pml4, PAGESIZE,		\
		    "init_level4_pgt");				\
		machdep->machspec->last_pml4_read =		\
		    (ulong_t)(vt->kernel_pgd[0]);		\
	}							\
}

#define	FILL_PML4_HYPER() { \
	if (!machdep->machspec->last_pml4_read) {		\
		unsigned long idle_pg_table =			\
		    symbol_exists("idle_pg_table_4") ?		\
		    symbol_value("idle_pg_table_4") :		\
		    symbol_value("idle_pg_table");		\
		readmem(kdump, idle_pg_table, KVADDR,		\
		    machdep->machspec->pml4, PAGESIZE,		\
		    "idle_pg_table");				\
		machdep->machspec->last_pml4_read = idle_pg_table; \
	}							\
}

#define	IS_LAST_UPML_READ(pml) \
	((ulong_t)(pml) == machdep->machspec->last_upml_read)

#define	FILL_UPML(PML, TYPE, SIZE)					\
	if (!IS_LAST_UPML_READ(PML)) {					\
		readmem(kdump, (uint64_t)((ulong_t)(PML)), TYPE,	\
		    machdep->machspec->upml, SIZE, "pml page");		\
		machdep->machspec->last_upml_read = (ulong_t)(PML);	\
	}

#define	IS_LAST_P4D_READ(p4d) \
	((ulong_t)(p4d) == machdep->machspec->last_p4d_read)

#define	FILL_P4D(P4D, TYPE, SIZE)					\
	if (!IS_LAST_P4D_READ(P4D)) {					\
		readmem(kdump, (uint64_t)((ulong_t)(P4D)), TYPE,	\
		    machdep->machspec->p4d,  SIZE, "p4d page");		\
		machdep->machspec->last_p4d_read = (ulong_t)(P4D);	\
	}


#define	__PHYSICAL_MASK_SHIFT_2_6	46
#define	__PHYSICAL_MASK_SHIFT		__PHYSICAL_MASK_SHIFT_2_6
#define	__PHYSICAL_MASK			((1UL << __PHYSICAL_MASK_SHIFT) - 1)
#define	__VIRTUAL_MASK_SHIFT		48
#define	__VIRTUAL_MASK			((1UL << __VIRTUAL_MASK_SHIFT) - 1)
#define	PAGE_SHIFT	12
#define	PAGE_SIZE	(1UL << PAGE_SHIFT)
#define	PHYSICAL_PAGE_MASK \
	(~(PAGE_SIZE-1) & (__PHYSICAL_MASK << PAGE_SHIFT))

#define	_PAGE_BIT_NX	63
#define	_PAGE_PRESENT	0x001
#define	_PAGE_RW	0x002
#define	_PAGE_USER	0x004
#define	_PAGE_PWT	0x008
#define	_PAGE_PCD	0x010
#define	_PAGE_ACCESSED	0x020
#define	_PAGE_DIRTY	0x040
#define	_PAGE_4M	0x080   /* 4 MB page, Pentium+, if present.. */
#define	_PAGE_PSE	0x080   /* 4 MB (or 2MB) page, Pentium+, if present.. */
#define	_PAGE_GLOBAL	0x100   /* Global TLB entry PPro+ */
#define	_PAGE_PROTNONE	(machdep->machspec->page_protnone)
#define	_PAGE_NX	(0x8000000000000000ULL)

#define	PAGEOFFSET	(PAGESIZE - 1)
#define	PAGEBASE(X)	(((ulong_t)(X)) & (ulong_t)PAGEMASK)

#define	PAGEOFFSETMASK(X)	(((ulong_t)(X)) & PAGEOFFSET)

#define	ULONG(ADDR)	*((ulong_t *)((char *)(ADDR)))

#define	KILOBYTES(x)	((x) * (1024))
#define	MEGABYTES(x)	((x) * (1048576))
#define	GIGABYTES(x)	((x) * (1073741824))
#define	TB_SHIFT	(40)
#define	TERABYTES(x)	((x) * (1UL << TB_SHIFT))

#define	_2MB_PAGE_MASK	(~((MEGABYTES(2))-1))


struct vm_table {
	ulong_t	kernel_pgd[8];
};

struct machine_specific {
	ulong_t vmalloc_start_addr;
	ulong_t vmalloc_end;
	char	*pml4;
	ulong_t last_pml4_read;
	ulong_t	last_p4d_read;
};

struct machdep_table {
	ulong_t last_pgd_read;
	ulong_t last_pmd_read;
	ulong_t last_ptbl_read;

	char	*pgd;
	char	*pmd;
	char	*ptbl;
	struct	machine_specific *machspec;
};

struct machine_specific x86_64_machine_specific = { 0 };

struct vm_table vm_table = { 0 };
struct vm_table *vt = &vm_table;

struct machdep_table machdep_table = { 0 };
struct machdep_table *machdep = &machdep_table;

static void
init_kernel_vm(kdump_data_t *kdump)
{
	/* normally part of x86_64_init() */
	if (machdep->machspec == NULL) {
		machdep->machspec = &x86_64_machine_specific;
		machdep->machspec->pml4 = (char *)malloc(PAGESIZE*2);
		machdep->pgd = (char *)malloc(PAGESIZE);
		machdep->pmd = (char *)malloc(PAGESIZE);
		machdep->ptbl = (char *)malloc(PAGESIZE);
	}

	/* normally part of x86_64_init_kernel_pgd() */
	if (vt->kernel_pgd[0] == 0) {
		char *init_level4_pgt;
		size_t size;

		init_level4_pgt = kdump_vmcoreinfo_lookup(kdump,
		    "SYMBOL(init_level4_pgt)", &size);
		if (init_level4_pgt == NULL) {
			mdb_warn("Failed to lookup init_level4_pgt\n");
			return;
		}
		vt->kernel_pgd[0] = strtoull(init_level4_pgt, NULL, 16);
#if DEBUG_PRINTF
		(void) printf("init_level4_pgt was 0x%lx\n", vt->kernel_pgd[0]);
#endif
	}
	/*
	 * TODO: once we can locate kernel symbols, read 'vmalloc_base' here
	 */
	if (vt->kernel_pgd[0] == 0xffffffff92609000ULL)
		machdep->machspec->vmalloc_start_addr = 0xffffa724c0000000ULL;
	else
		machdep->machspec->vmalloc_start_addr = 0xffffc90000000000ULL;
	machdep->machspec->vmalloc_end =
	    machdep->machspec->vmalloc_start_addr + TERABYTES(32) - 1;
}

static void
fini_kernel_vm(kdump_data_t *kdump)
{
	free(machdep->machspec->pml4);
	free(machdep->pgd);
	free(machdep->pmd);
	free(machdep->ptbl);
}

static int
is_vmalloc_addr(uintptr_t vaddr)
{
	return (vaddr >= VMALLOC_START && vaddr <= VMALLOC_END);
}

static int
is_kladdr(uintptr_t addr)
{
	return (addr >= START_KERNEL_MAP /* && addr < PAGE_OFFSET */);
}

/*
 * Translates a kernel logical address to its physical address.
 */
static ulong_t
kltop(kdump_data_t *kdump, uintptr_t vaddr, boolean_t verbose)
{
	ulong_t phys_base = kdump->kd_hdr.kh_sub_header.phys_base;

	return (vaddr - (START_KERNEL_MAP + phys_base));
}

/*
 * read memory from the dumpfile
 *
 * Input:
 *	addr:		a user, kernel or physical memory address
 *	memtype:	addr type of UVADDR, KVADDR, or PHYSADDR
 *	buffer  supplied buffer to read the data into
 *	size  number of bytes to read
 *	type  string describing the request
 *	error_handle  what to do if the read fails
 */
static void
readmem(kdump_data_t *kdump, uint64_t addr, int memtype, void *buffer,
    long size, char *type)
{
	long cnt;
	char *bufptr;

#if DEBUG_PRINTF
	(void) printf("<readmem: %llx, %s, \"%s\", %ld, %lx>\n",
	    addr, memtype == PHYSADDR ? "PHYSADDR" : "KVADDR", type, size,
	    (ulong_t)buffer);
#endif
	bufptr = (char *)buffer;

	while (size > 0) {
		ssize_t bytes = 0;
		/*
		 * Compute bytes till end of page.
		 */
		cnt = PAGESIZE - PAGEOFFSETMASK(addr);
		if (cnt > size)
			cnt = size;

		if (memtype == PHYSADDR)
			bytes = kdump_pread(kdump, addr, bufptr, cnt);
		else if (memtype == KVADDR)
			bytes = kdump_kread(kdump, addr, bufptr, cnt);

		if (bytes != cnt) {
			mdb_warn("Failed to read page\n");
			exit(123);	/* TBD */
		}

		addr += cnt;
		bufptr += cnt;
		size -= cnt;
	}
}

static int
x86_64_translate_pte(ulong_t pte, void *physaddr, uint64_t unused)
{
	return (0);
}

/*
 * Translates a kernel virtual address to its physical address.
 *
 * Currently this supports kmalloc virtual pages
 */
static ulong_t
kvtop(kdump_data_t *kdump, uintptr_t kvaddr, boolean_t verbose)
{
	ulong_t *pml4;
	ulong_t *pgd;
	ulong_t pgd_paddr;
	ulong_t pgd_pte;
	ulong_t *pmd;
	ulong_t pmd_paddr;
	ulong_t pmd_pte;
	ulong_t *ptep;
	ulong_t pte_paddr;
	ulong_t pte;
	physaddr_t paddr;

	/*
	 * Linear address bits for page table mapping
	 *
	 * +---------+---------+---------+---------+------------+
	 * | PGD off | PUD off | PMD off | PTE off |  Page off  |
	 * +---------+---------+---------+---------+------------+
	 */

	FILL_PML4();
	pml4 = ((ulong_t *)machdep->machspec->pml4) + pml4_index(kvaddr);
	if (verbose) {
		(void) printf("PML4 DIRECTORY: %lx\n", vt->kernel_pgd[0]);
		(void) printf("PAGE DIRECTORY: %lx\n", *pml4);
	}

	if (!(*pml4 & _PAGE_PRESENT)) {
		(void) printf("kvtop(0x%lx) pml4 NO PAGE\n", kvaddr);
		return (-1ULL);
	}

	/*
	 * find page global directory (PGD)
	 */
	pgd_paddr = (*pml4) & PHYSICAL_PAGE_MASK;
	FILL_PGD(pgd_paddr, PHYSADDR, PAGESIZE);
	pgd = ((ulong_t *)pgd_paddr) + pgd_index(kvaddr);
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSETMASK(pgd));
	if (verbose)
		(void) printf("   PUD: %lx => %lx\n", (ulong_t)pgd, pgd_pte);

	if (!(pgd_pte & _PAGE_PRESENT)) {
		(void) printf("kvtop(0x%lx) pgd_pte NO PAGE\n", kvaddr);
		return (-1ULL);
	}

	/*
	 * find page middle directory (PMD)
	 *
	 * pmd = pmd_offset(pgd, addr);
	 */
	pmd_paddr = pgd_pte & PHYSICAL_PAGE_MASK;
	FILL_PMD(pmd_paddr, PHYSADDR, PAGESIZE);
	pmd = ((ulong_t *)pmd_paddr) + pmd_index(kvaddr);
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSETMASK(pmd));
	if (verbose)
		(void) printf("   PMD: %lx => %lx\n", (ulong_t)pmd, pmd_pte);
	if (!(pmd_pte & _PAGE_PRESENT)) {
		(void) printf("kvtop(0x%lx) pmd_pte NO PAGE\n", kvaddr);
		return (-1ULL);
	}
	if (pmd_pte & _PAGE_PSE) {
		if (verbose) {
			(void) printf("  PAGE: %lx  (2MB)\n\n",
			    PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);
			x86_64_translate_pte(pmd_pte, 0, 0);
		}

		paddr = (PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK) +
		    (kvaddr & ~_2MB_PAGE_MASK);

		(void) printf("kvtop(0x%lx) --> 0x%lx _PAGE_PSE\n",
		    kvaddr, paddr);

		return (paddr);
	}

	/*
	 * find page table entry (PTE)
	 *
	 * ptep = pte_offset_map(pmd, addr);
	 * pte = *ptep;
	 */
	pte_paddr = pmd_pte & PHYSICAL_PAGE_MASK;
	FILL_PTBL(pte_paddr, PHYSADDR, PAGESIZE);
	ptep = ((ulong_t *)pte_paddr) + pte_index(kvaddr);
	pte = ULONG(machdep->ptbl + PAGEOFFSETMASK(ptep));
	if (verbose)
		(void) printf("   PTE: %lx => %lx\n", (ulong_t)ptep, pte);

	if (!(pte & (_PAGE_PRESENT))) {
		if (pte && verbose) {
			(void) printf("\n");
			x86_64_translate_pte(pte, 0, 0);
		}
		(void) printf("kvtop(0x%lx) pte NO PAGE\n", kvaddr);
		return (-1ULL);
	}

	paddr = (PAGEBASE(pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSETMASK(kvaddr);

	if (verbose) {
		(void) printf("  PAGE: %lx\n\n",
		    PAGEBASE(paddr) & PHYSICAL_PAGE_MASK);
		x86_64_translate_pte(pte, 0, 0);
	}

	return (paddr);
}

static uint64_t
kdump_vtop(void *data, struct as *as, uintptr_t addr)
{
	kdump_data_t *kdump = data;
	boolean_t verbose = (as == NULL);

	if (is_vmalloc_addr(addr))
		return (kvtop(kdump, (ulong_t)addr, verbose));
	else if (is_kladdr(addr))
		return (kltop(kdump, (ulong_t)addr, verbose));

	mdb_warn("unable to translate virtual address");

	return (-1ULL);
}

static int
kdump_getmregs(void *data, uint_t cpu, struct privmregs *mregs)
{
	kdump_data_t *kdump = data;

#if DEBUG_PRINTF
	printf("%s: cpu: %lx\n", __FUNCTION__, cpu);
#endif

	Elf64_Nhdr *nt = kdump->kd_nt_prstatus[cpu];
	size_t len = sizeof (*nt);
	len = roundup(len + nt->n_namesz, 4);
	len = roundup(len + nt->n_descsz, 4);

	if ((char *)nt + len >
	    (char *)kdump->kd_elfnotes + kdump->kd_elfnotes_size) {
		mdb_warn("Failed to get mregs for cpu: %lu\n", cpu);
		return (-1);
	}

	bzero(mregs, sizeof (*mregs));
	struct regs *regs = &mregs->pm_gregs;
	char *user_regs = (char *)nt + len -
	    sizeof (user_regs_t) - sizeof (long);

	regs->r_ss = *((long *)(user_regs + offsetof(user_regs_t, ss)));
	regs->r_cs = *((long *)(user_regs + offsetof(user_regs_t, cs)));
	regs->r_ds = *((long *)(user_regs + offsetof(user_regs_t, ds)));
	regs->r_es = *((long *)(user_regs + offsetof(user_regs_t, es)));
	regs->r_fs = *((long *)(user_regs + offsetof(user_regs_t, fs)));
	regs->r_gs = *((long *)(user_regs + offsetof(user_regs_t, gs)));

	regs->r_savfp = *((long *)(user_regs + offsetof(user_regs_t, bp)));
	regs->r_savpc = *((long *)(user_regs + offsetof(user_regs_t, ip)));

	regs->r_rdi = *((long *)(user_regs + offsetof(user_regs_t, di)));
	regs->r_rsi = *((long *)(user_regs + offsetof(user_regs_t, si)));
	regs->r_rdx = *((long *)(user_regs + offsetof(user_regs_t, dx)));
	regs->r_rcx = *((long *)(user_regs + offsetof(user_regs_t, cx)));
	regs->r_r8 = *((long *)(user_regs + offsetof(user_regs_t, r8)));
	regs->r_r9 = *((long *)(user_regs + offsetof(user_regs_t, r9)));
	regs->r_rax = *((long *)(user_regs + offsetof(user_regs_t, ax)));
	regs->r_rbx = *((long *)(user_regs + offsetof(user_regs_t, bx)));
	regs->r_rbp = *((long *)(user_regs + offsetof(user_regs_t, bp)));
	regs->r_r10 = *((long *)(user_regs + offsetof(user_regs_t, r10)));
	regs->r_r11 = *((long *)(user_regs + offsetof(user_regs_t, r11)));
	regs->r_r12 = *((long *)(user_regs + offsetof(user_regs_t, r12)));
	regs->r_r13 = *((long *)(user_regs + offsetof(user_regs_t, r13)));
	regs->r_r14 = *((long *)(user_regs + offsetof(user_regs_t, r14)));
	regs->r_r15 = *((long *)(user_regs + offsetof(user_regs_t, r15)));
	regs->r_rip = *((long *)(user_regs + offsetof(user_regs_t, ip)));
	regs->r_rfl = *((long *)(user_regs + offsetof(user_regs_t, flags)));
	regs->r_rsp = *((long *)(user_regs + offsetof(user_regs_t, sp)));

	/*
	 * TODO: What about "r_trapno" and "r_err"?
	 */

	return (0);
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
	.kb_vtop	= kdump_vtop,
	.kb_getmregs	= kdump_getmregs,
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
