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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*
 * This is a KVM backend implementation to support VMware save state files
 * (*.vmss).
 *
 * Only supports amd64.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_kb.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_ctf.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/debug_info.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/sysmacros.h>
#include <sys/privregs.h>
#include <sys/privmregs.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <vm/hat_pte.h>

#ifdef VMSS_DEBUG
#define	dprintf(...)	mdb_warn(__VA_ARGS__)
#else
#define	dprintf(...)
#endif

/* Tag name, group name and index values for VMSS data */
#define	GROUP_NAME_LEN		64
#define	GROUP_CPU		"cpu"
#define	GROUP_MEMORY		"memory"

#define	TAG_SIZE_MASK		0x3F
#define	TAG_CR64		"CR64"
#define	TAG_DR64		"DR64"
#define	TAG_REGION_CNT		"regionsCount"
#define	TAG_MEMORY		"Memory"
#define	TAG_REGION_PPN		"regionPPN"
#define	TAG_REGION_SIZE		"regionSize"
#define	TAG_REGION_PAGE_NUM	"regionPageNum"
#define	TAG_NUM_VCPUS		"cpu:numVCPUs"

#define	MAX_INDECES		3
#define	INDEX_CR3		(uint_t []) { 0, 3 }
#define	INDEX_MEMORY		(uint_t []) { 0, 0 }

/* VMSS magic numbers, version 0 (0xbad0bad0) is not supported */
#define	NUM_MAGIC		3
#define	VMSS_MAGIC_V1		0xbad1bad1
#define	VMSS_MAGIC_V2		0xbed2bed2
#define	VMSS_MAGIC_V3		0xbed3bed3

#define	VMSS_MAX_STR		1024

/* Symbol table macros */
#define	VMSS_SHDR_NULL		0
#define	VMSS_SHDR_SYMTAB	1
#define	VMSS_SHDR_STRTAB	2
#define	VMSS_SHDR_SHSTRTAB	3
#define	VMSS_SHDR_NUM		4

#define	VMSS_WALK_LOCAL		0x1
#define	VMSS_WALK_GLOBAL	0x2
#define	VMSS_WALK_STR		0x4
#define	VMSS_WALK_ALL		\
	(VMSS_WALK_LOCAL | VMSS_WALK_GLOBAL | VMSS_WALK_STR)

/* Number of control/debug registers */
#define	NUM_CRREGS		8
#define	NUM_DRREGS		8

/* Register definitions, format is (enum name, tag name) */
#define	REGS			\
	REG_DEF(R8,   "r8")	\
	REG_DEF(R9,   "r9")	\
	REG_DEF(R10, "r10")	\
	REG_DEF(R11, "r11")	\
	REG_DEF(R12, "r12")	\
	REG_DEF(R13, "r13")	\
	REG_DEF(R14, "r14")	\
	REG_DEF(R15, "r15")	\
	REG_DEF(RSP, "rsp")	\
	REG_DEF(RBP, "rbp")	\
	REG_DEF(RSI, "rsi")	\
	REG_DEF(RDI, "rdi")	\
	REG_DEF(RDX, "rdx")	\
	REG_DEF(RCX, "rcx")	\
	REG_DEF(RBX, "rbx")	\
	REG_DEF(RAX, "rax")	\
	REG_DEF(RIP, "rip")

#define	REG_DEF(_enum, _name)	\
	_enum,

typedef enum vmss_reg {
	REGS
	NUM_GREGS
} vmss_reg_t;

#undef  REG_DEF
#define	REG_DEF(_enum, _name)	\
	[_enum] = _name,

char *vmss_reg_tags[] = {
	REGS
};

uint_t magic_vals[NUM_MAGIC] = {
	VMSS_MAGIC_V1,
	VMSS_MAGIC_V2,
	VMSS_MAGIC_V3
};

/*
 * High level layout of vmss data
 *
 *              +-------------+
 *              |   Header    |
 *              +-------------+
 *              |  Group 1    | ----+
 *              +-------------+     |
 *        +---- |  Group 2    |     |
 *        |     +-------------+     |
 *        |           ...           |
 *        |     +-------------+     |
 *        |     |  Group N    |     |
 *        |     +-------------+     |
 *        |           ...           |
 *        |     +-------------+     |
 *        |     |    Tag 1    | <---+
 *        |     +-------------+
 *        |     | Tag 1 Data  |
 *        |     +-------------+
 *        |     |   Tag 2     |
 *        |     +-------------+
 *        |     | Tag 2 Data  |
 *        |     +-------------+
 *        |           ...
 *        |     +-------------+
 *        +---> |    Tag 1    |
 *              +-------------+
 *              | Tag 1 Data  |
 *              +-------------+
 *                    ...
 *
 * Groups are identified by their name and contain a collection of tags which
 * provide the actual data.
 *
 * Tags are identified by their name and an optional number of indices.  For
 * example, control registers are indexed by the CPU number and the CR number.
 * To find the value of CR3 for CPU 0 you lookup the tag with name "CR64" and
 * indices [0, 3] in the "cpu" group.
 *
 * The tag structure has two different formats depending on the value of the
 * 'flags' field.  The 'flags' field is a bit field which contains the number
 * of indices associated with the tag as well the size of the tag data.  The
 * tag data size has 2 reserved values (62-63) which indicate that there is
 * additional data in the tag structure.
 *
 * [] - Denotes optional data.
 *
 *              +-------------+
 *              |     Tag     |
 *              +-------------+
 *              |    Name     |
 *              |    Flags    | ----> Bit field:
 *              |  [Indices]  |       - [7-6] = Number of indices
 *              +-------------+       - [5-0] = Size
 *                   |  |
 *           Flags   |  |   Flags
 *        Size >= 62 |  | Size < 62
 *        +----------+  +----------+
 *        |                        |
 *        |                        |
 *        v                        v
 *  +-----------+            +-----------+
 *  |  Unknown  |            |   Data    |
 *  | Data size |            +-----------+
 *  |  Pad len  |
 *  | [Padding] |
 *  |   Data    |
 *  +-----------+
 *
 */
typedef struct vmss_tag {
	uchar_t		vt_flags;
	uchar_t		vt_name_len;
	char		*vt_name;
	uint_t		vt_num_idx;
	uint_t		vt_idx[MAX_INDECES];
	ulong_t		vt_data_size;
	ushort_t	vt_padlen;
	ulong_t		vt_data_off;
	struct vmss_tag	*vt_next;
} vmss_tag_t;

typedef struct vmss_grp {
	char		vg_name[GROUP_NAME_LEN];
	ulong_t		vg_tags_off;
	uchar_t		vg_pad0[8];
} vmss_grp_t;

typedef struct vmss_grp_ext {
	vmss_grp_t	grp;
	vmss_tag_t	*tag_list;
} vmss_grp_ext_t;

typedef struct vmss_header {
	uint_t		vh_magic;
	uchar_t		vh_pad0[4];
	uint_t		vh_grp_count;
} vmss_header_t;

typedef struct vmss_region {
	uint64_t	vr_base;
	size_t		vr_size;
	void		*vr_data;
} vmss_region_t;

/* Minimal mmu structure to resolve kernel virtual addresses */
typedef struct mmu_info {
	size_t		mi_max;
	size_t		mi_shift[4];
	size_t		mi_mask[4];
	size_t		mi_ptes;
} mmu_info_t;

static const char vmss_shstrtab[] = "\0.symtab\0.strtab\0.shstrtab\0";

/* Symbol table */
typedef struct vmss_ksyms {
	Ehdr		kh_elf_hdr;
	Phdr		kh_text_phdr;
	Phdr		kh_data_phdr;
	Shdr		kh_shdr[VMSS_SHDR_NUM];
	char		shstrings[sizeof (vmss_shstrtab)];
} vmss_ksyms_t;

typedef struct vmss_vcpu {
	uint64_t	vc_greg[NUM_GREGS];
	uint64_t	vc_creg[NUM_CRREGS];
	uint64_t	vc_dreg[NUM_DRREGS];
} vmss_vcpu_t;

typedef struct vmss_data {
	int		vs_fd;
	vmss_header_t	vs_hdr;
	vmss_grp_ext_t	*vs_grps;
	mmu_info_t	vs_mmu;
	pfn_t		vs_tlpfn;
	int		vs_num_regions;
	vmss_region_t	*vs_regions;
	debug_info_t	vs_debug_info;
	char		*vs_ksyms;
	size_t		vs_ksyms_size;
	int		vs_num_vcpu;
	vmss_vcpu_t	*vs_vcpus;
} vmss_data_t;

static void
vmss_free_tags(vmss_tag_t *tag)
{
	vmss_tag_t	*next;

	while (tag != NULL) {
		next = tag->vt_next;
		mdb_free(tag->vt_name, tag->vt_name_len);
		mdb_free(tag, sizeof (*tag));
		tag = next;
	}
}

#ifdef VMSS_DEBUG
static void
vmss_print_tags(vmss_tag_t *tag)
{
	while (tag != NULL) {
		mdb_printf("%s %x %#llx %#llx\n", tag->vt_name, tag->vt_flags,
		    tag->vt_data_size, tag->vt_data_off);
		tag = tag->vt_next;
	}
}
#endif /* VMSS_DEBUG */

static int
vmss_read_tags(int fd, vmss_grp_ext_t *grp_ext)
{
	vmss_grp_t	*grp = (vmss_grp_t *)grp_ext;
	vmss_tag_t	*tag_list = NULL;
	vmss_tag_t	*tag;
	size_t		size;

	if (lseek(fd, grp->vg_tags_off, SEEK_SET) != grp->vg_tags_off) {
		mdb_warn("Failed to seek to tags offset for group '%s'\n",
		    grp->vg_name);
		goto error;
	}

	for (;;) {
		tag = mdb_zalloc(sizeof (*tag), UM_SLEEP);
		if (read(fd, tag, 2) != 2) {
			mdb_warn("Failed to read tag data\n");
			goto error;
		}

		if (tag->vt_flags == 0 || tag->vt_name_len == 0) {
			mdb_free(tag, sizeof (*tag));
			break;
		}

		tag->vt_next = tag_list;
		tag_list = tag;

		tag->vt_name = mdb_zalloc(tag->vt_name_len + 1, UM_SLEEP);
		if (read(fd, tag->vt_name, tag->vt_name_len) !=
		    tag->vt_name_len) {
			mdb_warn("Failed to read tag name\n");
			goto error;
		}

		tag->vt_num_idx = (tag->vt_flags >> 6) & 3;
		size = sizeof (tag->vt_idx[0]) * tag->vt_num_idx;
		if (tag->vt_num_idx > 0 && read(fd, tag->vt_idx, size) !=
		    size) {
			mdb_warn("Failed to read tag indices\n");
			goto error;
		}

		/* A size of 62 or 63 includes extended data */
		if ((tag->vt_flags & TAG_SIZE_MASK) >= 62) {
			/* Skip 8 bytes (not sure what is in these bytes) */
			if (lseek(fd, 8, SEEK_CUR) == (off_t)-1) {
				mdb_warn("Failed to read tag data\n");
				goto error;
			}

			if (read(fd, &tag->vt_data_size,
			    sizeof (tag->vt_data_size)) !=
			    sizeof (tag->vt_data_size)) {
				mdb_warn("Failed to read tag data size\n");
				goto error;
			}

			if (read(fd, &tag->vt_padlen, sizeof (tag->vt_padlen))
			    != sizeof (tag->vt_padlen)) {
				mdb_warn("Failed to read tag padlen\n");
				goto error;
			}

			if (lseek(fd, tag->vt_padlen, SEEK_CUR) == (off_t)-1) {
				mdb_warn("Failed to skip tag pad\n");
				goto error;
			}

		} else {
			tag->vt_data_size = tag->vt_flags & TAG_SIZE_MASK;
		}

		if ((tag->vt_data_off = lseek(fd, 0, SEEK_CUR)) ==
		    (off_t)-1) {
			mdb_warn("Failed to get tag data offset\n");
			goto error;
		}

		if (lseek64(fd, tag->vt_data_size, SEEK_CUR) == (off_t)-1) {
			mdb_warn("Failed to seek next tag\n");
			goto error;
		}
	}

	grp_ext->tag_list = tag_list;
	return (0);

error:
	vmss_free_tags(tag_list);
	return (-1);
}

static int
vmss_groups_init(vmss_data_t *vmss)
{
	vmss_grp_ext_t	*ext_grps;
	vmss_grp_t	*grp;
	vmss_header_t	*hdr = &vmss->vs_hdr;
	size_t		ext_grps_size;
	off_t		grp_off;
	int		i;

	ext_grps_size = sizeof (*ext_grps) * hdr->vh_grp_count;
	ext_grps = mdb_zalloc(ext_grps_size, UM_SLEEP);

	if ((grp_off = lseek(vmss->vs_fd, 0, SEEK_CUR)) == -1) {
		mdb_warn("Failed to seek to groups offset\n");
		goto error;
	}

	for (i = 0; i < hdr->vh_grp_count; i++) {
		grp = &ext_grps[i].grp;

		if (pread(vmss->vs_fd, grp, sizeof (*grp), grp_off) !=
		    sizeof (*grp)) {
			mdb_warn("Failed to read group '%s'\n", grp->vg_name);
			goto error;
		}

		if (vmss_read_tags(vmss->vs_fd, &ext_grps[i]) == -1) {
			mdb_warn("Failed to read tags for group '%s'\n",
			    grp->vg_name);
			goto error;
		}

		grp_off += sizeof (*grp);
	}

	vmss->vs_grps = ext_grps;
	return (0);

error:
	mdb_free(ext_grps, ext_grps_size);
	return (-1);
}

static void
vmss_groups_fini(vmss_data_t *vmss)
{
	size_t	groups_size;
	int	i;

	if (vmss->vs_grps == NULL) {
		return;
	}

	for (i = 0; i < vmss->vs_hdr.vh_grp_count; i++) {
		vmss_free_tags(vmss->vs_grps[i].tag_list);
	}

	groups_size = sizeof (*vmss->vs_grps) * vmss->vs_hdr.vh_grp_count;
	mdb_free(vmss->vs_grps, groups_size);
}

static vmss_tag_t *
vmss_grp_tag_lookup(vmss_grp_ext_t *grp_ext, char *tag_name, uint_t *idx,
    int num_idx)
{
	vmss_tag_t	*tag;

	for (tag = grp_ext->tag_list; tag != NULL; tag = tag->vt_next) {
		if (strcmp(tag->vt_name, tag_name) == 0 && tag->vt_num_idx ==
		    num_idx && memcmp(tag->vt_idx, idx, sizeof (*idx) *
		    num_idx) == 0) {
			return (tag);
		}
	}

	mdb_warn("Tag '%s' not found\n", tag_name);
	return (NULL);
}

static vmss_grp_ext_t *
vmss_grp_lookup(vmss_data_t *vmss, char *grp_name)
{
	int	i;

	for (i = 0; i < vmss->vs_hdr.vh_grp_count; i++) {
		if (strcmp(vmss->vs_grps[i].grp.vg_name, grp_name) == 0) {
			return (&vmss->vs_grps[i]);
		}
	}

	mdb_warn("Group '%s' not found\n", grp_name);
	return (NULL);
}

static vmss_tag_t *
vmss_tag_lookup(vmss_data_t *vmss, char *grp_name, char *tag_name, uint_t *idx,
    int num_idx)
{
	vmss_grp_ext_t	*grp_ext;

	if ((grp_ext = vmss_grp_lookup(vmss, grp_name)) == NULL) {
		return (NULL);
	}

	return (vmss_grp_tag_lookup(grp_ext, tag_name, idx, num_idx));
}

static int
vmss_read_value(vmss_data_t *vmss, char *grp_name, char *tag_name, uint_t *idx,
    int num_idx, void *val)
{
	vmss_tag_t	*tag;

	tag = vmss_tag_lookup(vmss, grp_name, tag_name, idx, num_idx);
	if (tag == NULL) {
		return (-1);
	}

	if (pread(vmss->vs_fd, val, tag->vt_data_size, tag->vt_data_off) !=
	    tag->vt_data_size) {
		mdb_warn("Failed to read tag data\n");
		return (-1);
	}

	return (0);
}

static int
vmss_region_init(vmss_region_t *rgn, uint64_t base, uint64_t size, int fd,
    uint64_t file_off)
{
	rgn->vr_base = base;
	rgn->vr_size = size;
	rgn->vr_data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, file_off);
	if (rgn->vr_data == MAP_FAILED) {
		mdb_warn("Failed to mmap region data\n");
		return (-1);
	}

	return (0);
}

static void
vmss_region_fini(vmss_region_t *rgn)
{
	if (rgn->vr_data != MAP_FAILED) {
		(void) munmap(rgn->vr_data, rgn->vr_size);
	}
}

/*ARGSUSED*/
static void
vmss_init_mmu(vmss_data_t *vmss)
{
	vmss->vs_mmu.mi_max = 3;
	vmss->vs_mmu.mi_shift[0] = 12;
	vmss->vs_mmu.mi_shift[1] = 21;
	vmss->vs_mmu.mi_shift[2] = 30;
	vmss->vs_mmu.mi_shift[3] = 39;
	vmss->vs_mmu.mi_mask[0] = UINT64_C(0xfff);
	vmss->vs_mmu.mi_mask[1] = UINT64_C(0x1fffff);
	vmss->vs_mmu.mi_mask[2] = UINT64_C(0x3fffffff);
	vmss->vs_mmu.mi_mask[3] = UINT64_C(0x7fffffffff);
	vmss->vs_mmu.mi_ptes = 512;
}

static int
vmss_mem_init(vmss_data_t *vmss)
{
	vmss_region_t	*regions = NULL;
	vmss_tag_t	*mem_tag;
	uint_t		region_data;
	uint_t		region_idx[1];
	uint64_t	region_base;
	uint64_t	region_len;
	uint64_t	region_file_off;
	size_t		regions_size;
	int		i;

	/* Top level page table PFN is stored in CR3 */
	if (vmss_read_value(vmss, GROUP_CPU, TAG_CR64, INDEX_CR3, 2,
	    &vmss->vs_tlpfn) == -1) {
		mdb_warn("Failed to read value of CR3\n");
		goto error;
	}
	dprintf("CR3: %p\n", vmss->vs_tlpfn);
	vmss->vs_tlpfn >>= PAGESHIFT;

	if (vmss_read_value(vmss, GROUP_MEMORY, TAG_REGION_CNT, NULL, 0,
	    &vmss->vs_num_regions) == -1) {
		mdb_warn("Fail to read region count\n");
		goto error;
	}

	/* Single region case */
	if (vmss->vs_num_regions == 0) {
		if ((mem_tag = vmss_tag_lookup(vmss, GROUP_MEMORY, TAG_MEMORY,
		    NULL, 0)) == NULL) {
			mdb_warn("Memory tag not found\n");
			goto error;
		}

		regions_size = sizeof (*regions);
		regions = mdb_zalloc(regions_size, UM_SLEEP);

		if (vmss_region_init(regions, 0, mem_tag->vt_data_size,
		    vmss->vs_fd, mem_tag->vt_data_off) == -1) {
			goto error;
		}

		vmss->vs_num_regions = 1;
		vmss->vs_regions = regions;

		return (0);
	}

	if ((mem_tag = vmss_tag_lookup(vmss, GROUP_MEMORY, TAG_MEMORY,
	    INDEX_MEMORY, 2)) == NULL) {
		mdb_warn("Memory tag not found\n");
		goto error;
	}

	regions_size = sizeof (*regions) * vmss->vs_num_regions;
	regions = mdb_zalloc(regions_size, UM_SLEEP);

	for (i = 0; i < vmss->vs_num_regions; i++) {
		region_idx[0] = i;

		if (vmss_read_value(vmss, GROUP_MEMORY, TAG_REGION_PPN,
		    region_idx, 1, &region_data) == -1) {
			mdb_warn("Failed to get region ppn\n");
			goto error;
		}
		region_base = region_data * UINT64_C(PAGESIZE);

		if (vmss_read_value(vmss, GROUP_MEMORY, TAG_REGION_SIZE,
		    region_idx, 1, &region_data) == -1) {
			mdb_warn("Failed to get region size\n");
			goto error;
		}
		region_len = region_data * UINT64_C(PAGESIZE);

		if (vmss_read_value(vmss, GROUP_MEMORY, TAG_REGION_PAGE_NUM,
		    region_idx, 1, &region_data) == -1) {
			mdb_warn("Failed to get region size\n");
			goto error;
		}
		region_file_off = (region_data * PAGESIZE) +
		    mem_tag->vt_data_off;

		if (vmss_region_init(&regions[i], region_base, region_len,
		    vmss->vs_fd, region_file_off) == -1) {
			mdb_warn("Failed to initialize region\n");
			goto error;
		}
	}
	vmss->vs_regions = regions;

	vmss_init_mmu(vmss);

	return (0);
error:
	if (regions != NULL) {
		mdb_free(regions, regions_size);
	}

	return (-1);
}

static void
vmss_mem_fini(vmss_data_t *vmss)
{
	vmss_region_t	*rgn;
	size_t		regions_size;
	int		i;

	if (vmss->vs_regions == NULL) {
		return;
	}

	for (i = 0; i < vmss->vs_num_regions; i++) {
		rgn = &vmss->vs_regions[i];
		vmss_region_fini(rgn);
	}

	regions_size = sizeof (*vmss->vs_regions) * vmss->vs_num_regions;
	mdb_free(vmss->vs_regions, regions_size);
}

static vmss_region_t *
vmss_region_lookup(vmss_data_t *vmss, uintptr_t addr)
{
	int	i;

	for (i = 0; i < vmss->vs_num_regions; i++) {
		vmss_region_t *rgn;

		rgn = &vmss->vs_regions[i];
		if (addr >= rgn->vr_base && addr < (rgn->vr_base +
		    rgn->vr_size)) {
			return (rgn);
		}
	}

	return (NULL);
}

static ssize_t
vmss_read(vmss_data_t *vmss, uintptr_t addr, void *buf, size_t len)
{
	vmss_region_t	*rgn;
	uintptr_t	rgn_off;
	ssize_t		to_read;

	if ((rgn = vmss_region_lookup(vmss, addr)) == NULL) {
		return (-1);
	}

	rgn_off = addr - rgn->vr_base;
	to_read = MIN(len, rgn->vr_size - rgn_off);
	(void) memcpy(buf, (uint8_t *)rgn->vr_data + rgn_off, to_read);

	return (to_read);
}

/* Return a pointer to a page table for the given PFN */
static uint64_t *
vmss_get_ptbl(vmss_data_t *vmss, pfn_t pfn)
{
	vmss_region_t	*rgn;
	uintptr_t	pa;
	uintptr_t	off;

	pa = pfn << PAGESHIFT;
	dprintf("pfn: %p pa: %p\n", pfn, pa);
	if ((rgn = vmss_region_lookup(vmss, pa)) == NULL) {
		return (NULL);
	}

	off = pa - (uintptr_t)rgn->vr_base;
	return ((uint64_t *)((uintptr_t)rgn->vr_data + off));
}

/* Convert the given virtual address into a physical address */
static uintptr_t
vmss_va_to_pa(vmss_data_t *vmss, uintptr_t va)
{
	mmu_info_t	*mmu = &vmss->vs_mmu;
	pfn_t		pfn = vmss->vs_tlpfn;
	uint64_t	*ptbl;
	uint64_t	pte;
	size_t		level;
	int		idx;

	dprintf("va = %p\n", va);

	for (level = mmu->mi_max; ; --level) {
		ptbl = vmss_get_ptbl(vmss, pfn);
		if (ptbl == NULL) {
			dprintf("No page table for pfn: %p\n", pfn);
			return (0);
		}

		idx = (va >> mmu->mi_shift[level]) & (mmu->mi_ptes - 1);
		pte = ptbl[idx];
		pfn = PTE2PFN(pte, level);
		dprintf("idx: %d pte: %p pfn: %p\n", idx, pte, pfn);
		if (level == 0 || PTE_IS_LGPG(pte, level)) {
			return (pfn << PAGESHIFT | (va & mmu->mi_mask[level]));
		}
	}
}

static ssize_t
vmss_vread(vmss_data_t *vmss, uintptr_t addr, void *buf, size_t len)
{
	uintptr_t	pa;
	uintptr_t	page_end;
	size_t		bytes_left = len;
	size_t		to_read;

	/* Don't cross page boundaries for physical reads */
	while (bytes_left > 0) {
		pa = vmss_va_to_pa(vmss, addr);
		if (pa == 0) {
			return (-1);
		}

		page_end = (pa + PAGESIZE) & PAGEMASK;
		to_read = MIN(bytes_left, page_end - pa);

		if (vmss_read(vmss, pa, buf, to_read) != to_read) {
			return (-1);
		}

		addr += to_read;
		buf = (void *)((uintptr_t)buf + to_read);
		bytes_left -= to_read;
	}

	return (len);
}

static int
vmss_debug_info_init(vmss_data_t *vmss)
{
	debug_info_t	*di = &vmss->vs_debug_info;

	if (vmss_vread(vmss, (uintptr_t)DEBUG_INFO_VA, di, sizeof (*di)) !=
	    sizeof (*di)) {
		mdb_warn("Failed to read debug info from %p\n", DEBUG_INFO_VA);
		return (-1);
	}

	if (di->di_version != 1) {
		mdb_warn("Invalid debug info version: %d\n", di->di_version);
		return (-1);
	}

	return (0);
}

static int
vmss_read_word(vmss_data_t *vmss, uintptr_t addr, uintptr_t *buf)
{
	if (vmss_vread(vmss, addr, buf, sizeof (uintptr_t)) !=
	    sizeof (uintptr_t)) {
		return (-1);
	}

	return (0);
}

static int
vmss_readstr(vmss_data_t *vmss, uintptr_t addr, char *s, size_t len)
{
	int	i;

	for (i = 0; i < len; i++) {
		if (vmss_vread(vmss, addr + i, s + i, 1) != 1) {
			return (-1);
		}

		if (s[i] == '\0') {
			break;
		}
	}

	if (i == len) {
		return (-1);
	}

	return (0);
}

static int
vmss_read_module(vmss_data_t *vmss, uintptr_t modaddr, struct module *modp,
    uintptr_t *sym_addr, uintptr_t *sym_count, uintptr_t *str_addr)
{
	if (vmss_vread(vmss, modaddr, modp, sizeof (*modp)) != sizeof (*modp)) {
		return (-1);
	}

	if (vmss_read_word(vmss, (uintptr_t)modp->symhdr +
	    offsetof(Shdr, sh_addr), sym_addr) == -1) {
		return (-1);
	}

	if (vmss_read_word(vmss, (uintptr_t)modp->symhdr +
	    offsetof(Shdr, sh_size), sym_count) == -1) {
		return (-1);
	}
	*sym_count /= sizeof (Sym);

	if (vmss_read_word(vmss, (uintptr_t)modp->strhdr +
	    offsetof(Shdr, sh_addr), str_addr) == -1) {
		return (-1);
	}

	return (0);
}

static int
vmss_read_modsyms(vmss_data_t *vmss, char **buf, size_t *sizes, int types,
    uintptr_t sym_addr, uintptr_t str_addr, uintptr_t sym_count)
{
	char	name[VMSS_MAX_STR];
	int	i;

	for (i = 0; i < sym_count; i++) {
		Sym	sym;
		size_t	sz;
		int	type = VMSS_WALK_GLOBAL;

		if (vmss_vread(vmss, sym_addr + i * sizeof (sym), &sym,
		    sizeof (sym)) != sizeof (sym)) {
			return (-1);
		}

		if (GELF_ST_BIND(sym.st_info) == STB_LOCAL) {
			type = VMSS_WALK_LOCAL;
		}

		if (vmss_readstr(vmss, str_addr + sym.st_name, name,
		    sizeof (name)) == -1) {
			return (-1);
		}

		sym.st_shndx = SHN_ABS;
		sym.st_name = sizes[VMSS_WALK_STR];

		sizes[type] += sizeof (sym);
		sz = strlen(name) + 1;
		sizes[VMSS_WALK_STR] += sz;

		if (buf != NULL) {
			if (types & type) {
				bcopy(&sym, *buf, sizeof (sym));
				*buf += sizeof (sym);
			}
			if (types & VMSS_WALK_STR) {
				bcopy(name, *buf, sz);
				*buf += sz;
			}
		}
	}

	return (0);
}

static int
vmss_walk_syms(vmss_data_t *vmss, uintptr_t modhead, char **buf,
    size_t *sizes, int types)
{
	uintptr_t	modctl = modhead;
	uintptr_t	modulep;
	struct		module module;
	uintptr_t	sym_count;
	uintptr_t	sym_addr;
	uintptr_t	str_addr;

	bzero(sizes, sizeof (*sizes) * (VMSS_WALK_STR + 1));

	/* First symbol is empty */
	sizes[VMSS_WALK_LOCAL] += sizeof (Sym);
	sizes[VMSS_WALK_STR] += 1;

	if (buf != NULL) {
		if (types & VMSS_WALK_LOCAL) {
			Sym tmp;
			bzero(&tmp, sizeof (tmp));
			bcopy(&tmp, *buf, sizeof (tmp));
			*buf += sizeof (tmp);
		}
		if (types & VMSS_WALK_STR) {
			**buf = '\0';
			(*buf)++;
		}
	}

	for (;;) {
		if (vmss_read_word(vmss,
		    modctl + offsetof(struct modctl, mod_mp), &modulep) == -1) {
			return (-1);
		}

		if (modulep == NULL) {
			goto next;
		}

		if (vmss_read_module(vmss, modulep, &module, &sym_addr,
		    &sym_count, &str_addr) == -1) {
			return (-1);
		}

		if ((module.flags & KOBJ_NOKSYMS)) {
			goto next;
		}

		if (vmss_read_modsyms(vmss, buf, sizes, types, sym_addr,
		    str_addr, sym_count) == -1) {
			return (-1);
		}

next:
		if (vmss_read_word(vmss,
		    modctl + offsetof(struct modctl, mod_next), &modctl) ==
		    -1) {
			return (-1);
		}

		if (modctl == modhead) {
			break;
		}
	}

	return (0);
}

static int
vmss_ksyms_init(vmss_data_t *vmss)
{
	debug_info_t	*di = &vmss->vs_debug_info;
	size_t		sizes[VMSS_WALK_STR + 1];
	vmss_ksyms_t	*hdr;
	char		*buf;
	modctl_t	modctl;
	uintptr_t	module;
	Shdr		*shp;

	if (vmss_vread(vmss, di->di_modules, &modctl, sizeof (modctl)) !=
	    sizeof (modctl)) {
		goto error;
	}

	module = (uintptr_t)modctl.mod_mp;
	if (vmss_walk_syms(vmss, di->di_modules, NULL, sizes,
	    VMSS_WALK_LOCAL | VMSS_WALK_GLOBAL | VMSS_WALK_STR) == -1) {
		goto error;
	}

	vmss->vs_ksyms_size = sizeof (vmss_ksyms_t);
	vmss->vs_ksyms_size += sizes[VMSS_WALK_LOCAL];
	vmss->vs_ksyms_size += sizes[VMSS_WALK_GLOBAL];
	vmss->vs_ksyms_size += sizes[VMSS_WALK_STR];

	vmss->vs_ksyms = mdb_zalloc(vmss->vs_ksyms_size, UM_SLEEP);

	/* LINTED - alignment */
	hdr = (vmss_ksyms_t *)vmss->vs_ksyms;

	if (vmss_vread(vmss, module + offsetof(struct module, hdr),
	    &hdr->kh_elf_hdr, sizeof (Ehdr)) != sizeof (Ehdr)) {
		goto error;
	}

	hdr->kh_elf_hdr.e_phoff = offsetof(vmss_ksyms_t, kh_text_phdr);
	hdr->kh_elf_hdr.e_shoff = offsetof(vmss_ksyms_t, kh_shdr);
	hdr->kh_elf_hdr.e_phnum = 2;
	hdr->kh_elf_hdr.e_shnum = VMSS_SHDR_NUM;
	hdr->kh_elf_hdr.e_shstrndx = VMSS_SHDR_SHSTRTAB;

	hdr->kh_text_phdr.p_type = PT_LOAD;
	hdr->kh_text_phdr.p_vaddr = (Addr)di->di_s_text;
	hdr->kh_text_phdr.p_memsz = (Word)(di->di_e_text - di->di_s_text);
	hdr->kh_text_phdr.p_flags = PF_R | PF_X;

	hdr->kh_data_phdr.p_type = PT_LOAD;
	hdr->kh_data_phdr.p_vaddr = (Addr)di->di_s_data;
	hdr->kh_data_phdr.p_memsz = (Word)(di->di_e_data - di->di_s_data);
	hdr->kh_data_phdr.p_flags = PF_R | PF_W | PF_X;

	shp = &hdr->kh_shdr[VMSS_SHDR_SYMTAB];
	shp->sh_name = 1;	/* vmss_shstrtab[1] = ".symtab" */
	shp->sh_type = SHT_SYMTAB;
	shp->sh_offset = sizeof (vmss_ksyms_t);
	shp->sh_size = sizes[VMSS_WALK_LOCAL] + sizes[VMSS_WALK_GLOBAL];
	shp->sh_link = VMSS_SHDR_STRTAB;
	shp->sh_info = sizes[VMSS_WALK_LOCAL] / sizeof (Sym);
	shp->sh_addralign = sizeof (Addr);
	shp->sh_entsize = sizeof (Sym);
	shp->sh_addr = (Addr)(vmss->vs_ksyms + shp->sh_offset);


	shp = &hdr->kh_shdr[VMSS_SHDR_STRTAB];
	shp->sh_name = 9;	/* vmss_shstrtab[9] = ".strtab" */
	shp->sh_type = SHT_STRTAB;
	shp->sh_offset = sizeof (vmss_ksyms_t) +
	    sizes[VMSS_WALK_LOCAL] + sizes[VMSS_WALK_GLOBAL];
	shp->sh_size = sizes[VMSS_WALK_STR];
	shp->sh_addralign = 1;
	shp->sh_addr = (Addr)(vmss->vs_ksyms + shp->sh_offset);

	shp = &hdr->kh_shdr[VMSS_SHDR_SHSTRTAB];
	shp->sh_name = 17;	/* vmss_shstrtab[17] = ".shstrtab" */
	shp->sh_type = SHT_STRTAB;
	shp->sh_offset = offsetof(vmss_ksyms_t, shstrings);
	shp->sh_size = sizeof (vmss_shstrtab);
	shp->sh_addralign = 1;
	shp->sh_addr = (Addr)(vmss->vs_ksyms + shp->sh_offset);

	bcopy(vmss_shstrtab, hdr->shstrings, sizeof (vmss_shstrtab));

	buf = vmss->vs_ksyms + sizeof (vmss_ksyms_t);

	if (vmss_walk_syms(vmss, di->di_modules, &buf, sizes,
	    VMSS_WALK_LOCAL) == -1) {
		goto error;
	}

	if (vmss_walk_syms(vmss, di->di_modules, &buf, sizes,
	    VMSS_WALK_GLOBAL) == -1) {
		goto error;
	}

	if (vmss_walk_syms(vmss, di->di_modules, &buf, sizes,
	    VMSS_WALK_STR) == -1) {
		goto error;
	}

	return (0);

error:
	if (vmss->vs_ksyms != NULL) {
		mdb_free(vmss->vs_ksyms, vmss->vs_ksyms_size);
	}
	return (-1);
}

static void
vmss_ksyms_fini(vmss_data_t *vmss)
{
	if (vmss->vs_ksyms == NULL) {
		return;
	}

	mdb_free(vmss->vs_ksyms, vmss->vs_ksyms_size);
}

static int
vmss_vcpu_init(vmss_data_t *vmss)
{
	vmss_vcpu_t	*vcpus = NULL;
	size_t		vcpus_size;
	uint_t		idx[2];
	int		i, j;

	if (vmss_read_value(vmss, GROUP_CPU, TAG_NUM_VCPUS, NULL, 0,
	    &vmss->vs_num_vcpu) == -1) {
		mdb_warn("Failed to read number of vcpus\n");
		goto error;
	}

	vcpus_size = sizeof (*vcpus) * vmss->vs_num_vcpu;
	vcpus = mdb_zalloc(vcpus_size, UM_SLEEP);

	for (i = 0; i < vmss->vs_num_vcpu; i++) {
		idx[0] = i;

		for (j = 0; j < NUM_GREGS; j++) {
			if (vmss_read_value(vmss, GROUP_CPU, vmss_reg_tags[j],
			    idx, 1, &vcpus[i].vc_greg[j]) == -1) {
				mdb_warn("Failed to read %s\n",
				    vmss_reg_tags[j]);
				goto error;
			}
		}

		for (j = 0; j < NUM_CRREGS; j++) {
			idx[1] = j;

			if (vmss_read_value(vmss, GROUP_CPU, TAG_CR64, idx, 2,
			    &vcpus[i].vc_creg[j]) == -1) {
				mdb_warn("Failed to read CR64 %d\n", j);
				goto error;
			}
		}

		for (j = 0; j < NUM_DRREGS; j++) {
			idx[1] = j;

			if (vmss_read_value(vmss, GROUP_CPU, TAG_DR64, idx, 2,
			    &vcpus[i].vc_dreg[j]) == -1) {
				mdb_warn("Failed to read DR64 %d\n", j);
				goto error;
			}
		}

	}

	vmss->vs_vcpus = vcpus;

	return (0);

error:
	if (vcpus != NULL) {
		mdb_free(vcpus, vcpus_size);
	}

	return (-1);
}

static void
vmss_vcpu_fini(vmss_data_t *vmss)
{
	size_t	vcpus_size;

	if (vmss->vs_vcpus == NULL) {
		return;
	}

	vcpus_size = sizeof (*vmss->vs_vcpus) * vmss->vs_num_vcpu;
	mdb_free(vmss->vs_vcpus, vcpus_size);
}

static void
vmss_free(vmss_data_t *vmss)
{
	if (vmss->vs_fd != -1) {
		(void) close(vmss->vs_fd);
	}

	vmss_groups_fini(vmss);
	vmss_mem_fini(vmss);
	vmss_ksyms_fini(vmss);
	vmss_vcpu_fini(vmss);

	mdb_free(vmss, sizeof (*vmss));
}

/* Identify function */
int
vmss_identify(const char *file, int *longmode)
{
	uint_t	magic;
	int	fd;
	int	i;

	if ((fd = open(file, O_RDONLY)) == -1) {
		mdb_warn("Failed to open file '%s'\n", file);
		return (-1);
	}

	if (read(fd, &magic, sizeof (magic)) != sizeof (magic)) {
		mdb_warn("Failed to read vmss magic\n");
		return (-1);
	}

	for (i = 0; i < NUM_MAGIC; i++) {
		if (magic == magic_vals[i]) {
			(void) close(fd);
			*longmode = 1;
			return (1);
		}
	}

	(void) close(fd);
	return (-1);
}

/* KVM backend ops */

/*ARGSUSED*/
static void *
vmss_open(const char *symfile, const char *corefile, const char *swapfile,
    int flags, const char *err)
{
	vmss_data_t	*vmss;
	vmss_header_t	*hdr;
	int		i;

	vmss = mdb_alloc(sizeof (*vmss), UM_SLEEP);
	vmss->vs_fd = open(corefile, O_RDONLY);
	if (vmss->vs_fd == -1) {
		mdb_warn("Failed to open file '%s'\n", corefile);
		goto error;
	}

	hdr = &vmss->vs_hdr;
	if (read(vmss->vs_fd, hdr, sizeof (*hdr)) != sizeof (*hdr)) {
		mdb_warn("Failed to read vmss header\n");
		goto error;
	}

	for (i = 0; i < NUM_MAGIC; i++) {
		if (hdr->vh_magic == magic_vals[i]) {
			break;
		}
	}

	if (i == NUM_MAGIC) {
		goto error;
	}

	if (vmss_groups_init(vmss) == -1) {
		goto error;
	}

	if (vmss_mem_init(vmss) == -1) {
		goto error;
	}

	if (vmss_debug_info_init(vmss) == -1) {
		goto error;
	}

	if (vmss_ksyms_init(vmss) == -1) {
		goto error;
	}

	if (vmss_vcpu_init(vmss) == -1) {
		goto error;
	}

	return (vmss);

error:
	vmss_free(vmss);
	return (NULL);
}

static int
vmss_close(void *data)
{
	vmss_free(data);
	return (0);
}

/*ARGSUSED*/
static mdb_io_t *
vmss_sym_io(void *data, const char *symfile)
{
	vmss_data_t	*vmss = data;
	mdb_io_t	*io;

	io = mdb_memio_create(vmss->vs_ksyms, vmss->vs_ksyms_size);
	if (io == NULL) {
		mdb_warn("failed to create ksyms\n");
	}

	return (io);
}

static ssize_t
vmss_kread(void *data, uintptr_t addr, void *buf, size_t size)
{
	return (vmss_vread(data, addr, buf, size));
}

static ssize_t
vmss_pread(void *data, uint64_t addr, void *buf, size_t size)
{
	return (vmss_read(data, addr, buf, size));
}

/*
 * If we return -1 from our vtop operation mdb will call the platform specific
 * vtop function to resolve the virtual address.
 */
/*ARGSUSED*/
static uint64_t
vmss_vtop(void *data, struct as *as, uintptr_t addr)
{
	return (-1);
}

static int
vmss_getmregs(void *data, uint_t cpu, struct privmregs *mregs)
{
	vmss_data_t	*vmss = data;
	vmss_vcpu_t	*vcpu;
	struct regs	*regs = &mregs->pm_gregs;
	uint64_t	*vregs;

	if (cpu >= vmss->vs_num_vcpu) {
		errno = EINVAL;
		return (-1);
	}

	vcpu = &vmss->vs_vcpus[cpu];
	vregs = vcpu->vc_greg;

	regs->r_savfp = vregs[RBP];
	regs->r_savpc = vregs[RIP];
	regs->r_r8 = vregs[R8];
	regs->r_r9 = vregs[R9];
	regs->r_r10 = vregs[R10];
	regs->r_r11 = vregs[R11];
	regs->r_r12 = vregs[R12];
	regs->r_r13 = vregs[R13];
	regs->r_r14 = vregs[R14];
	regs->r_r15 = vregs[R15];
	regs->r_rax = vregs[RAX];
	regs->r_rbx = vregs[RBX];
	regs->r_rcx = vregs[RCX];
	regs->r_rdx = vregs[RDX];
	regs->r_rdi = vregs[RDI];
	regs->r_rsi = vregs[RSI];
	regs->r_rbp = vregs[RBP];
	regs->r_rsp = vregs[RSP];
	regs->r_rip = vregs[RIP];

	(void) memcpy(mregs->pm_cr, vcpu->vc_creg, sizeof (vcpu->vc_creg));
	(void) memcpy(mregs->pm_dr, vcpu->vc_dreg, sizeof (vcpu->vc_dreg));

	mregs->pm_flags = PM_GREGS | PM_CRREGS | PM_DRREGS;

	return (0);
}

static mdb_kb_ops_t vmss_kb_ops = {
	.kb_open	= vmss_open,
	.kb_close	= vmss_close,
	.kb_sym_io	= vmss_sym_io,
	.kb_kread	= vmss_kread,
	.kb_kwrite	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_aread	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_awrite	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_pread	= vmss_pread,
	.kb_pwrite	= (ssize_t (*)())mdb_tgt_notsup,
	.kb_vtop	= vmss_vtop,
	.kb_getmregs	= vmss_getmregs
};

mdb_kb_ops_t *
mdb_vmss_ops(void)
{
	return (&vmss_kb_ops);
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
