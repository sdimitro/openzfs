/*
 * diskdump.h
 *
 * Copyright (C) 2004, 2005 David Anderson
 * Copyright (C) 2004, 2005 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005  FUJITSU LIMITED
 * Copyright (C) 2005  NEC Corporation
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef _DISKDUMP_MOD_H
#define _DISKDUMP_MOD_H

#include <elf.h>

#define PAGE_SHIFT			12
#define PAGE_SIZE			(1UL << PAGE_SHIFT)

/*
 *       47      39 38      30 29      21 20     12 11        0
 * -----+----------+----------+----------+---------+-----------+
 *  ... | PML4 idx | PDPT idx |  PDT idx |  PT idx |  Page idx |
 * -----+----------+----------+----------+---------+-----------+
 *         9 bits     9 bits     9 bits     9 bits    12 bits
 *
 * See Intel's Software Developer's Manual for more details.
 */
#define pml4_index(vaddr)		(((vaddr) >> 39) & ((1ULL << 9) - 1))
#define pdpt_index(vaddr)		(((vaddr) >> 30) & ((1ULL << 9) - 1))
#define pdt_index(vaddr)		(((vaddr) >> 21) & ((1ULL << 9) - 1))
#define pt_index(vaddr)			(((vaddr) >> 12) & ((1ULL << 9) - 1))
#define page_index(vaddr)		((vaddr) & ((1ULL << 12) - 1))

#define __PHYSICAL_MASK_SHIFT		46
#define __PHYSICAL_MASK			((1ULL << __PHYSICAL_MASK_SHIFT) - 1)

#define ADDRESS_MASK			(~(PAGE_SIZE - 1) & __PHYSICAL_MASK)
#define PRESENT_MASK			(1ULL << 0)
#define BIGPAGE_MASK			(1ULL << 7)

#define PML4E_PRESENT_MASK		(1ULL << 0)
#define PML4E_PRESENT_MASK		(1ULL << 0)

#define NR_CPUS				8192
#define START_KERNEL_MAP		0xffffffff80000000ULL
#define PAGE_OFFSET			0xffff880000000000ULL

#define divideup(x, y)			(((x) + ((y) - 1)) / (y))
#define round(x, y)			(((x) / (y)) * (y))

#define DUMP_PARTITION_SIGNATURE	"diskdump"
#define DISK_DUMP_SIGNATURE		"DISKDUMP"
#define KDUMP_SIGNATURE			"KDUMP   "
#define SIG_LEN (sizeof(DUMP_PARTITION_SIGNATURE) - 1)
#define DISKDUMP_HEADER_BLOCKS		(1)

/*
 * These are all remnants of the old "diskdump" facility,
 * none of them are ever used by makedumpfile.
 */
#define DUMP_HEADER_COMPLETED		0
#define DUMP_HEADER_INCOMPLETED		1
#define DUMP_HEADER_COMPRESSED		8

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct disk_dump_header {
	char			signature[SIG_LEN];	/* = "KDUMP   " */
	int			header_version; /* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	struct timeval		timestamp;	/* Time stamp */
	unsigned int		status; 	/* Above flags */
	int			block_size;	/* Size of a block in byte */
	int			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	unsigned int		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	unsigned int		max_mapnr;	/* = max_mapnr, OBSOLETE!
						   32bit only, full 64bit
						   in sub header. */
	unsigned int		total_ram_blocks;/* Number of blocks should be
						   written */
	unsigned int		device_blocks;	/* Number of total blocks in
						 * the dump device */
	unsigned int		written_blocks; /* Number of written blocks */
	unsigned int		current_cpu;	/* CPU# which handles dump */
	int			nr_cpus;	/* Number of CPUs */
	struct task_struct	*tasks[0];
};

/*
 * Sub header for KDUMP
 * But Common header of KDUMP is disk_dump_header of diskdump.
 */
struct kdump_sub_header {
	unsigned long	phys_base;
	int		dump_level;	/* header_version 1 and later */
	int		split;		/* header_version 2 and later */
	unsigned long	start_pfn;	/* header_version 2 and later,
					   OBSOLETE! 32bit only, full
					   64bit in start_pfn_64. */
	unsigned long	end_pfn;	/* header_version 2 and later,
					   OBSOLETE! 32bit only, full
					   64bit in end_pfn_64. */
	off_t		offset_vmcoreinfo;/* header_version 3 and later */
	unsigned long	size_vmcoreinfo;  /* header_version 3 and later */
	off_t		offset_note;      /* header_version 4 and later */
	unsigned long	size_note;        /* header_version 4 and later */
	off_t		offset_eraseinfo; /* header_version 5 and later */
	unsigned long	size_eraseinfo;   /* header_version 5 and later */
	unsigned long long start_pfn_64;  /* header_version 6 and later */
	unsigned long long end_pfn_64;	  /* header_version 6 and later */
	unsigned long long max_mapnr_64;  /* header_version 6 and later */
};

/* page flags */
#define DUMP_DH_COMPRESSED_ZLIB	0x1	/* page is compressed with zlib */
#define DUMP_DH_COMPRESSED_LZO	0x2	/* paged is compressed with lzo */
#define DUMP_DH_COMPRESSED_SNAPPY	0x4
					/* paged is compressed with snappy */
#define DUMP_DH_COMPRESSED_INCOMPLETE	0x8
					/* indicate an incomplete dumpfile */
#define DUMP_DH_EXCLUDED_VMEMMAP 0x10	/* unused vmemmap pages are excluded */

/* descriptor of each page for vmcore */
typedef struct page_desc {
	off_t			offset;		/* the offset of the page data*/
	unsigned int		size;		/* the size of this dump page */
	unsigned int		flags;		/* flags */
	unsigned long long	page_flags;	/* page flags */
} page_desc_t;

#define DISKDUMP_CACHED_PAGES	(16)
#define PAGE_VALID		(0x1)	/* flags */
#define DISKDUMP_VALID_PAGE(flags)	((flags) & PAGE_VALID)

#endif  /* DISKDUMP_MOD_H */

