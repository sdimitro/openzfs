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
 * Copyright (c) 2017, 2018 by Delphix. All rights reserved.
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

typedef struct x86_64_user_regs_struct {
	unsigned long r15, r14, r13, r12, bp, bx;
	unsigned long r11, r10, r9, r8, ax, cx, dx;
	unsigned long si, di, orig_ax, ip, cs;
	unsigned long flags, sp, ss, fs_base;
	unsigned long gs_base, ds, es, fs, gs;
} user_regs_t;

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
	size_t			lkd_elfnotesz;
	void			**lkd_nt_prstatus;
	uint64_t		lkd_init_level4_pgt;
	char			lkd_namelist[MAXNAMELEN + 1];
	uint64_t		lkd_vmalloc_start;
	uint64_t		lkd_vmalloc_end;
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

	dprintf(lkd, "hdr: signature: %s", lkd->lkd_hdr.signature);
	dprintf(lkd, "hdr: version: 0x%llx", lkd->lkd_hdr.header_version);
	dprintf(lkd, "hdr: status: 0x%llx", lkd->lkd_hdr.status);
	dprintf(lkd, "hdr: current_cpu: 0x%llx", lkd->lkd_hdr.current_cpu);
	dprintf(lkd, "hdr: nr_cpus: 0x%llx", lkd->lkd_hdr.nr_cpus);

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

	dprintf(lkd, "subhdr: phys_base: 0x%llx", lkd->lkd_subhdr.phys_base);
	dprintf(lkd, "subhdr: dump_level: 0x%llx", lkd->lkd_subhdr.dump_level);
	dprintf(lkd, "subhdr: split: 0x%llx", lkd->lkd_subhdr.split);

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

	lkd->lkd_elfnotesz = lkd->lkd_subhdr.size_note;
	if ((lkd->lkd_elfnote = malloc(lkd->lkd_elfnotesz)) == NULL)
		return (fail(lkd, err, "cannot allocate ELF note"));

	if (pread64(lkd->lkd_corefd, lkd->lkd_elfnote, lkd->lkd_elfnotesz,
	    lkd->lkd_subhdr.offset_note) != lkd->lkd_elfnotesz)
		return (fail(lkd, err, "cannot read kdump ELF note"));

	if ((lkd->lkd_nt_prstatus = calloc(NR_CPUS, sizeof (void *))) == NULL)
		return (fail(lkd, err, "cannot allocate prstatus"));

	unsigned int cpu = 0;
	for (size_t i = 0, len = 0; i < lkd->lkd_elfnotesz; i += len) {
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

	/*
	 * We must do this _after_ we read in the vmcoreinfo data from
	 * the Kdump file, which we did earlier in this function.
	 */
	char *init_level4_pgt = lkd_vmcoreinfo_lookup(lkd,
	    "SYMBOL(init_level4_pgt)");
	if (init_level4_pgt == NULL)
		return (fail(lkd, err, "cannot lookup init_level4_pgt"));
	lkd->lkd_init_level4_pgt = strtoull(init_level4_pgt, NULL, 16);
	free(init_level4_pgt);

	if (namelist == NULL) {
		/*
		 * FUTURE NOTE:
		 * if mdb is to be ported in Linux and we were to enhance it
		 * for live-debugging this is where we would reach out for
		 * something like /proc/kallsyms instead of failing.
		 */
		return (fail(lkd, err, "the current version of the library "
		    "requires that a namelist is supplied"));
	}
	(void) strncpy(lkd->lkd_namelist, namelist, MAXNAMELEN);

	/*
	 * XXX - Explain that whatever we do from now on is to extracting
	 * the KERNEL_VIRTUAL_BASE. Also explaining why this works would
	 * be great, and adding some references. The rest of the code in
	 * this function locates KERNEL_VIRTUAL_BASE.
	 *
	 * TODO: I think it is necessary to spend some time to
	 * [1] get our terminology right vmalloc_start, KERNEL_VIRTUAL_BASE,
	 * page_offset_base, and give a small explanation on how are all
	 * these related and used to locate the area when will be doing our
	 * vtop translations (or at least point to a definitive source as a
	 * reference).
	 * [2] list our assumptions on what the targets look like in the
	 * current version of this code (e.g. kdump compressed and not ELF
	 * dumps, kernel versions 4.8 and up or whatever with KASLR enabled
	 * that are x86_64).
	 */
	struct nlist nl[2] = { { "page_offset_base"}, { "" } };
	if (nlist(lkd->lkd_namelist, nl) == -1) {
		return (fail(lkd, err, "nlist() returned %d: %s; ensure that "
		    "namelist %s and symbol %s are valid",
		    errno, strerror(errno),
		    lkd->lkd_namelist, nl[0].n_name));
	}
	uint64_t page_offset_base = nl[0].n_value;
	dprintf(lkd, "page_offset_base: %p", page_offset_base);

	/*
	 * XXX - See where this part should go/be factored as we read the
	 * same variable from vmcore info through the mdb parts.
	 */
	char *offset = lkd_vmcoreinfo_lookup(lkd, "KERNELOFFSET");
	if (offset == NULL)
		return (fail(lkd, err, "cannot lookup KERNELOFFSET"));
	uint64_t kernel_offset = strtoull(offset, NULL, 16);
	free(offset);
	dprintf(lkd, "namelist:    kernel_offset: %llx", kernel_offset);

	/*
	 * We can't use lkd_vtop() yet for the traslation below as we
	 * have not initialized lkd_vmalloc_start yet. Thus we do the
	 * translation on the spot.
	 */
	uint64_t vmalloc_start_ptr_vaddr = kernel_offset + page_offset_base;
	uint64_t vmalloc_start_ptr_paddr = vmalloc_start_ptr_vaddr -
	    START_KERNEL_MAP + lkd->lkd_subhdr.phys_base;

	uint64_t vmalloc_start = 0;
	if (lkd_pread(lkd, vmalloc_start_ptr_paddr, &vmalloc_start,
	    sizeof (vmalloc_start)) != sizeof (vmalloc_start)) {
		return (fail(lkd, err,
		    "failed to read vmalloc base from dump"));
	}
	lkd->lkd_vmalloc_start = vmalloc_start;

	/*
	 * There appears to be 32TB of address space for vmalloc,
	 * starting at the "start address" determined above.
	 */
	lkd->lkd_vmalloc_end = lkd->lkd_vmalloc_start + (32 * (1ULL << 40)) - 1;

	dprintf(lkd, "vmalloc start: 0x%llx", lkd->lkd_vmalloc_start);
	dprintf(lkd, "vmalloc end: 0x%llx", lkd->lkd_vmalloc_end);

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
lkd_addr_to_pfn(lkd_t *lkd, uint64_t addr)
{
	uint64_t page_addr = addr & ~(lkd->lkd_hdr.block_size - 1);
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

	dprintf(lkd, "compressed page offset 0x%lx, size 0x%lx, flags 0x%lx",
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

uint64_t
lkd_vtop_vmalloc(lkd_t *lkd, uint64_t addr)
{
	uint64_t *pml4 = NULL, *pdpt = NULL, *pdt = NULL, *pt = NULL;
	uint64_t paddr = -1ULL;

	uint64_t pml4idx = pml4_index(addr);
	uint64_t pdptidx = pdpt_index(addr);
	uint64_t pdtidx = pdt_index(addr);
	uint64_t ptidx = pt_index(addr);
	uint64_t pageidx = page_index(addr);

	dprintf(lkd, "pml4 index: 0x%llx", pml4idx);
	dprintf(lkd, "pdpt index: 0x%llx", pdptidx);
	dprintf(lkd, "pdt index: 0x%llx", pdtidx);
	dprintf(lkd, "pt index: 0x%llx", ptidx);
	dprintf(lkd, "page index: 0x%llx", pageidx);

	if ((pml4 = malloc(PAGE_SIZE)) == NULL) {
		dprintf(lkd, "cannot allocate pml4");
		goto out;
	}

	dprintf(lkd, "pml4 vaddr: 0x%llx", lkd->lkd_init_level4_pgt);

	if (lkd_vread(lkd,
	    lkd->lkd_init_level4_pgt, pml4, PAGE_SIZE) != PAGE_SIZE) {
		dprintf(lkd, "cannot read pml4");
		goto out;
	}

	if (!(pml4[pml4idx] & PRESENT_MASK)) {
		dprintf(lkd, "pml4 entry absent");
		goto out;
	}

	dprintf(lkd, "pdpt paddr: 0x%llx", pml4[pml4idx] & ADDRESS_MASK);

	if ((pdpt = malloc(PAGE_SIZE)) == NULL) {
		dprintf(lkd, "cannot allocate pdpt");
		goto out;
	}

	if (lkd_pread(lkd,
	    pml4[pml4idx] & ADDRESS_MASK, pdpt, PAGE_SIZE) != PAGE_SIZE) {
		dprintf(lkd, "cannot read pdpt");
		goto out;
	}

	if (!(pdpt[pdptidx] & PRESENT_MASK)) {
		dprintf(lkd, "pdpt entry absent");
		goto out;
	}

	if (pdpt[pdptidx] & BIGPAGE_MASK) {
		/*
		 * We don't yet support 1GB pages.
		 */
		dprintf(lkd, "pdpt entry 1GB page set");
		goto out;
	}

	dprintf(lkd, "pdt paddr: 0x%llx", pdpt[pdptidx] & ADDRESS_MASK);

	if ((pdt = malloc(PAGE_SIZE)) == NULL) {
		dprintf(lkd, "cannot allocate pdt");
		goto out;
	}

	if (lkd_pread(lkd,
	    pdpt[pdptidx] & ADDRESS_MASK, pdt, PAGE_SIZE) != PAGE_SIZE) {
		dprintf(lkd, "cannot read pdt");
		goto out;
	}

	if (!(pdt[pdtidx] & PRESENT_MASK)) {
		dprintf(lkd, "pdt entry absent");
		goto out;
	}

	if (pdt[pdtidx] & BIGPAGE_MASK) {
		/*
		 * We don't yet support 2MB pages.
		 */
		dprintf(lkd, "pdt entry 2MB page set");
		goto out;
	}

	dprintf(lkd, "pt paddr: 0x%llx", pdt[pdtidx] & ADDRESS_MASK);

	if ((pt = malloc(PAGE_SIZE)) == NULL) {
		dprintf(lkd, "cannot allocate pt");
		goto out;
	}

	if (lkd_pread(lkd,
	    pdt[pdtidx] & ADDRESS_MASK, pt, PAGE_SIZE) != PAGE_SIZE) {
		dprintf(lkd, "cannot read pt");
		goto out;
	}

	if (!(pt[ptidx] & PRESENT_MASK)) {
		dprintf(lkd, "pt entry absent");
		goto out;
	}

	dprintf(lkd, "page paddr: 0x%llx", pt[ptidx] & ADDRESS_MASK);

	paddr = (pt[ptidx] & ADDRESS_MASK) + pageidx;
	dprintf(lkd, "final paddr: 0x%llx", paddr);

out:
	free(pt);
	free(pdt);
	free(pdpt);
	free(pml4);

	return (paddr);
}

uint64_t
lkd_vtop(lkd_t *lkd, uint64_t addr)
{
	dprintf(lkd, "vtop of address: 0x%llx", addr);

	if (lkd->lkd_vmalloc_start <= addr && addr <= lkd->lkd_vmalloc_end)
		return (lkd_vtop_vmalloc(lkd, addr));
	else if (START_KERNEL_MAP <= addr)
		return (addr - START_KERNEL_MAP + lkd->lkd_subhdr.phys_base);
	else
		return (addr - PAGE_OFFSET);

	return (-1ULL);
}

ssize_t
lkd_vread(lkd_t *lkd, uint64_t addr, void *buf, size_t size)
{
	uint64_t paddr;

	dprintf(lkd, "vread of address: 0x%llx", addr);

	if ((paddr = lkd_vtop(lkd, addr)) == (uint64_t)-1ULL)
		return (-1);

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

int
lkd_getmregs(lkd_t *lkd, uint_t cpu, struct privmregs *mregs)
{
	Elf64_Nhdr *nt = lkd->lkd_nt_prstatus[cpu];
	size_t len = sizeof (*nt);
	len = roundup(len + nt->n_namesz, 4);
	len = roundup(len + nt->n_descsz, 4);

	if ((char *)nt + len >
	    (char *)lkd->lkd_elfnote + lkd->lkd_elfnotesz) {
		dprintf(lkd, "failed to get mregs for cpu: %lu\n", cpu);
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

#if defined(__amd64)
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
#endif

	/*
	 * TODO: What about "r_trapno" and "r_err"?
	 */

	return (0);
}
