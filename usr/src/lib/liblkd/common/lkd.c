/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <lkd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>
#include <errno.h>
#include <zlib.h>
#include <sys/sysmacros.h>

#include "diskdump_mod.h"

#define	fail(lkd, ...) lkd_fail(lkd, __VA_ARGS__)
#define	dprintf(lkd, ...) \
	lkd_dprintf(lkd, __FILE__, __func__, __LINE__, __VA_ARGS__)

struct lkd {
	struct disk_dump_header	lkd_hdr;
	struct kdump_sub_header	lkd_subhdr;
	char			*lkd_debug;
	int			lkd_openflag;
	int			lkd_corefd;
	unsigned long long	lkd_max_mapnr;
	off_t			lkd_data_offset;
	void			*lkd_first_bitmap;
	void			*lkd_second_bitmap;
	unsigned long		*lkd_valid_pages;
	char			*lkd_vmcoreinfo;
	void			*lkd_elfnote;
	void			**lkd_nt_prstatus;
};

static void
lkd_dprintf(lkd_t *lkd, const char *file, const char *func, int line,
    const char *fmt, ...)
{
	va_list args;

	if (lkd->lkd_debug == NULL)
		return;

	va_start(args, fmt);
	(void) fprintf(stderr, "LKD_DEBUG: %s:%d %s: ", file, line, func);
	(void) vfprintf(stderr, fmt, args);
	(void) fprintf(stderr, "\n");
	va_end(args);
}

static lkd_t *
lkd_fail(lkd_t *lkd, const char *err, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (err || (lkd && lkd->lkd_debug)) {
		(void) fprintf(stderr, "%s: ", err ? err : "LKD_DEBUG");
		(void) vfprintf(stderr, fmt, args);
		(void) fprintf(stderr, "\n");
	}
	va_end(args);
	if (lkd != NULL)
		(void) lkd_close(lkd);
	return (NULL);
}

static int
lkd_is_partial(lkd_t *lkd)
{
	return (lkd->lkd_hdr.bitmap_blocks >=
	    divideup(divideup(lkd->lkd_max_mapnr, 8),
	    lkd->lkd_hdr.block_size) * 2);
}

static int
lkd_page_is_dumpable(lkd_t *lkd, unsigned long nr)
{
	char *bitmap = lkd->lkd_second_bitmap;
	return (bitmap[nr >> 3] & (1 << (nr & 7)));
}

/*ARGSUSED*/
lkd_t *
lkd_open(const char *namelist, const char *corefile, const char *swapfile,
    int flag, const char *err)
{
	lkd_t *lkd;

	if ((lkd = calloc(1, sizeof (lkd_t))) == NULL)
		return (fail(NULL, err, "cannot allocate memory for lkd_t"));

	lkd->lkd_corefd = -1;
	lkd->lkd_debug = getenv("LKD_DEBUG");

	dprintf(lkd, "attempting to open Linux Kdump library");

	if ((lkd->lkd_openflag = flag) != O_RDONLY && flag != O_RDWR)
		return (fail(lkd, err, "illegal flag %x to lkd_open()", flag));

	if (corefile == NULL)
		return (fail(lkd, err, "corefile not specified to lkd_open()"));

	if ((lkd->lkd_corefd = open64(corefile, flag)) == -1)
		return (fail(lkd, err, "cannot open %s", corefile));

	if (pread64(lkd->lkd_corefd, &lkd->lkd_hdr,
	    sizeof (lkd->lkd_hdr), 0) != sizeof (lkd->lkd_hdr))
		return (fail(lkd, err, "cannot read kdump header"));

	if (memcmp(lkd->lkd_hdr.signature, KDUMP_SIGNATURE,
	    sizeof (lkd->lkd_hdr.signature)) != 0) {
		return (fail(lkd, err, "%s is not a kdump core file "
		    "(bad signature '%s')", corefile,
		    lkd->lkd_hdr.signature));
	}

	int blksz = lkd->lkd_hdr.block_size;
	if (pread64(lkd->lkd_corefd, &lkd->lkd_subhdr,
	    sizeof (lkd->lkd_subhdr), blksz) != sizeof (lkd->lkd_subhdr))
		return (fail(lkd, err, "cannot read kdump sub header"));

	if (lkd->lkd_hdr.header_version >= 6)
		lkd->lkd_max_mapnr = lkd->lkd_subhdr.max_mapnr_64;
	else
		lkd->lkd_max_mapnr = lkd->lkd_hdr.max_mapnr;

	size_t vmcoreinfosz = lkd->lkd_subhdr.size_vmcoreinfo + 1;
	if ((lkd->lkd_vmcoreinfo = malloc(vmcoreinfosz)) == NULL)
		return (fail(lkd, err, "cannot allocate vmcoreinfo"));

	if (pread64(lkd->lkd_corefd, lkd->lkd_vmcoreinfo,
	    vmcoreinfosz, lkd->lkd_subhdr.offset_vmcoreinfo) != vmcoreinfosz)
		return (fail(lkd, err, "cannot read kdump vmcoreinfo"));

	lkd->lkd_vmcoreinfo[vmcoreinfosz] = '\0';

	size_t elfnotesz = lkd->lkd_subhdr.size_note;
	if ((lkd->lkd_elfnote = malloc(elfnotesz)) == NULL)
		return (fail(lkd, err, "cannot allocate ELF note"));

	if (pread64(lkd->lkd_corefd, lkd->lkd_elfnote,
	    elfnotesz, lkd->lkd_subhdr.offset_note) != elfnotesz)
		return (fail(lkd, err, "cannot read kdump ELF note"));

	if ((lkd->lkd_nt_prstatus = calloc(NR_CPUS, sizeof (void *))) == NULL)
		return (fail(lkd, err, "cannot allocate prstatus"));

	unsigned int cpu = 0;
	for (size_t i = 0, len = 0; i < elfnotesz; i += len) {
		Elf64_Nhdr *nt = lkd->lkd_elfnote + i;

		if (nt->n_type == NT_PRSTATUS) {
			lkd->lkd_nt_prstatus[cpu] = nt;
			cpu += 1;
		}

		len = sizeof (*nt);
		len = roundup(len + nt->n_namesz, 4);
		len = roundup(len + nt->n_descsz, 4);
	}

	off_t bitmapoff = (1 + lkd->lkd_hdr.sub_hdr_size) * blksz;
	size_t bitmapsz = lkd->lkd_hdr.bitmap_blocks * blksz;

	if ((lkd->lkd_first_bitmap = calloc(1, bitmapsz)) == NULL)
		return (fail(lkd, err, "cannot allocate first bitmap"));

	if (pread64(lkd->lkd_corefd, lkd->lkd_first_bitmap,
	    bitmapsz, bitmapoff) != bitmapsz)
		return (fail(lkd, err, "cannot read kdump bitmap"));

	if ((lkd->lkd_second_bitmap = calloc(1, bitmapsz)) == NULL)
		return (fail(lkd, err, "cannot allocate second bitmap"));

	if (lkd_is_partial(lkd)) {
		memcpy(lkd->lkd_second_bitmap,
		    lkd->lkd_first_bitmap + (bitmapsz / 2), bitmapsz / 2);
	} else {
		memcpy(lkd->lkd_second_bitmap, lkd->lkd_first_bitmap, bitmapsz);
	}

	lkd->lkd_data_offset =
	    (1 + lkd->lkd_hdr.sub_hdr_size + lkd->lkd_hdr.bitmap_blocks) *
	    blksz;

	unsigned long pfn = 0;
	unsigned long max_sect_len = divideup(lkd->lkd_max_mapnr, blksz);
	lkd->lkd_valid_pages = calloc(max_sect_len, sizeof (unsigned long));
	if (lkd->lkd_valid_pages == NULL)
		return (fail(lkd, err, "cannot allocate valid pages"));

	for (unsigned long i = 1; i < max_sect_len + 1; i++) {
		lkd->lkd_valid_pages[i] = lkd->lkd_valid_pages[i - 1];
		for (unsigned long j = 0; j < blksz; j++, pfn++) {
			if (lkd_page_is_dumpable(lkd, pfn))
				lkd->lkd_valid_pages[i]++;
		}
	}

	dprintf(lkd, "successfully opened Linux Kdump library");

	return (lkd);
}

int
lkd_close(lkd_t *lkd)
{
	dprintf(lkd, "attempting to close Linux Kdump library");

	if (lkd->lkd_corefd != -1)
		(void) close(lkd->lkd_corefd);

	free(lkd->lkd_valid_pages);
	free(lkd->lkd_elfnote);
	free(lkd->lkd_vmcoreinfo);
	free(lkd->lkd_second_bitmap);
	free(lkd->lkd_first_bitmap);

	dprintf(lkd, "successfully closed Linux Kdump library");

	free(lkd);

	return (0);
}

static unsigned long
lkd_addr_to_pfn(lkd_t *lkd, uintptr_t addr)
{
	uintptr_t page_addr = addr & ~(lkd->lkd_hdr.block_size - 1);
	return (page_addr >> (ffs(lkd->lkd_hdr.block_size) - 1));
}

static unsigned long
lkd_pfn_to_pdi(lkd_t *lkd, unsigned long pfn)
{
	unsigned long p1 = pfn;
	unsigned long p2 = round(pfn, lkd->lkd_hdr.block_size);
	unsigned long pdi = lkd->lkd_valid_pages[p1 / lkd->lkd_hdr.block_size];

	for (unsigned long j = p2; j <= pfn; j++) {
		if (lkd_page_is_dumpable(lkd, j))
			pdi++;
	}

	return (pdi);
}

ssize_t
lkd_pread(lkd_t *lkd, uint64_t addr, void *buf, size_t size)
{
	int blksz = lkd->lkd_hdr.block_size;
	unsigned long pfn = lkd_addr_to_pfn(lkd, addr);
	unsigned long pdi = lkd_pfn_to_pdi(lkd, pfn);
	off_t offset = lkd->lkd_data_offset +
	    ((off_t)(pdi - 1) * sizeof (page_desc_t));
	void *cpage, *upage;
	page_desc_t pd;
	int rc = -1;

	dprintf(lkd, "pread of address: 0x%llx", addr);

	if (pread64(lkd->lkd_corefd, &pd,
	    sizeof (pd), offset) != sizeof (pd)) {
		dprintf(lkd, "cannot read page descriptor");
		goto out;
	}

	if ((cpage = calloc(1, pd.size)) == NULL) {
		dprintf(lkd, "cannot allocate compressed page");
		goto out_cpage;
	}

	if (pread64(lkd->lkd_corefd, cpage, pd.size, pd.offset) != pd.size) {
		dprintf(lkd, "cannot read compressed page");
		goto out_cpage;
	}

	dprintf(lkd, "compressed page offset 0x%llx, size 0x%llx, flags 0x%llx",
	    pd.offset, pd.size, pd.flags);

	if ((upage = calloc(1, blksz)) == NULL) {
		dprintf(lkd, "cannot allocate uncompressed page");
		goto out_upage;
	}

	if (pd.flags & (DUMP_DH_COMPRESSED_LZO | DUMP_DH_COMPRESSED_SNAPPY)) {
		dprintf(lkd, "compression format not supported");
		goto out_upage;
	} else if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
		unsigned long retlen = blksz;
		int ret = uncompress(upage, &retlen, cpage, pd.size);
		if ((ret != Z_OK) || (retlen != blksz)) {
			dprintf(lkd, "cannot decompress page");
			goto out_upage;
		}
	} else {
		memcpy(upage, cpage, blksz);
	}

	size = MIN(size, blksz);
	memcpy(buf, upage + (addr & (blksz - 1)), size);
	rc = size;

out_upage:
	free(upage);
out_cpage:
	free(cpage);
out:
	return (rc);
}

ssize_t
lkd_kread(lkd_t *lkd, uint64_t addr, void *buf, size_t size)
{
	const unsigned long long phys_base = lkd->lkd_subhdr.phys_base;
	const unsigned long long start_kernel_map = 0xffffffff80000000ULL;

	uintptr_t paddr = addr - start_kernel_map + phys_base;

	dprintf(lkd, "kread of address: 0x%llx", addr);

	return (lkd_pread(lkd, paddr, buf, size));
}

char *
lkd_vmcoreinfo_lookup(lkd_t *lkd, const char *key)
{
	size_t keylen = strlen(key);
	char *lookup = NULL;
	char *value = NULL;
	size_t valuelen;
	char *p1, *p2;

	dprintf(lkd, "lookup key: %s", key);

	if ((lookup = malloc(keylen + 2)) == NULL) {
		dprintf(lkd, "cannot allocate memory for lookup");
		return (NULL);
	}

	snprintf(lookup, keylen + 2, "%s=", key);
	lookup[keylen + 2] = '\0';

	if ((p1 = strstr(lkd->lkd_vmcoreinfo, lookup)) != NULL) {
		p2 = p1 + strlen(lookup);
		p1 = strstr(p2, "\n");

		valuelen = p1 - p2;

		if ((value = malloc(valuelen)) == NULL) {
			dprintf(lkd, "cannot allocate memory for value");
			goto out;
		}

		strncpy(value, p2, valuelen);
		value[valuelen] = '\0';
	}

	dprintf(lkd, "lookup value: %s", value);

out:
	free(lookup);
	return (value);
}
