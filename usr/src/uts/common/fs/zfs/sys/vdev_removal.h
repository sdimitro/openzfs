/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2014, 2015 by Delphix. All rights reserved.
 */

#ifndef _SYS_VDEV_REMOVAL_H
#define	_SYS_VDEV_REMOVAL_H

#include <sys/spa.h>
#include <sys/bpobj.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct vdev_indirect_mapping_entry_phys {
	/*
	 * Decode with DVA_MAPPING_* macros.
	 * Contains:
	 *   the source offset (low 63 bits)
	 *   the one-bit "mark", used for garbage collection (by zdb)
	 */
	uint64_t dm_src;

	/*
	 * Note: the DVA's asize is 24 bits, and can thus store ranges
	 * up to 8GB.
	 */
	dva_t	dm_dst;
} vdev_indirect_mapping_entry_phys_t;

/*
 * Each entry indicates that everything up to but not including vib_offset
 * was copied in vib_phys_birth_txg.  Entries are sorted by vib_offset.
 */
typedef struct vdev_indirect_birth_entry_phys {
	uint64_t vibe_offset;
	uint64_t vibe_phys_birth_txg;
} vdev_indirect_birth_entry_phys_t;

#define	DVA_MAPPING_GET_SRC_OFFSET(dm)	\
	BF64_GET_SB((dm)->dm_src, 0, 63, SPA_MINBLOCKSHIFT, 0)
#define	DVA_MAPPING_SET_SRC_OFFSET(dm, x)	\
	BF64_SET_SB((dm)->dm_src, 0, 63, SPA_MINBLOCKSHIFT, 0, x)
#define	DVA_MAPPING_GET_MARK(dm)	BF64_GET((dm)->dm_src, 63, 1)
#define	DVA_MAPPING_SET_MARK(dm, x)	BF64_SET((dm)->dm_src, 63, 1, x)

typedef struct vdev_indirect_mapping_entry {
	vdev_indirect_mapping_entry_phys_t	dme_mapping;
	list_node_t		dme_node;
} vdev_indirect_mapping_entry_t;

typedef struct vdev_indirect_mapping_phys {
	uint64_t	vim_max_offset;
	uint64_t	vim_bytes_mapped;
	uint64_t	vim_count; /* count of v_i_m_entry_phys_t's */
} vdev_indirect_mapping_phys_t;

typedef struct vdev_indirect_birth_phys {
	uint64_t	vib_count; /* count of v_i_b_entry_phys_t's */
} vdev_indirect_birth_phys_t;

typedef struct spa_vdev_removal {
	vdev_t		*svr_vdev;
	uint64_t	svr_max_synced_offset;
	uint64_t	svr_max_offset_to_sync[TXG_SIZE];
	/* Thread performing a vdev removal. */
	kthread_t	*svr_thread;
	/* Segments left to copy from the current metaslab. */
	range_tree_t	*svr_allocd_segs;
	kmutex_t	svr_lock;
	kcondvar_t	svr_cv;
	boolean_t	svr_thread_exit;

	/*
	 * New mappings to write out each txg.
	 */
	list_t		svr_new_segments[TXG_SIZE];

	/*
	 * Ranges that were freed while a mapping was in flight.  This is
	 * a subset of the ranges covered by vdev_im_new_segments.
	 */
	range_tree_t	*svr_frees[TXG_SIZE];

	/*
	 * Number of bytes which we have finished our work for
	 * in each txg.  This could be data copied (which will be part of
	 * the mappings in vdev_im_new_segments), or data freed before
	 * we got around to copying it.
	 */
	uint64_t	svr_bytes_done[TXG_SIZE];
} spa_vdev_removal_t;

extern int spa_remove_init(spa_t *);
extern void spa_restart_removal(spa_t *);
extern int spa_vdev_remove(spa_t *, uint64_t, boolean_t);
extern void free_from_removing_vdev(vdev_t *, uint64_t, uint64_t, uint64_t);
extern int spa_removal_get_stats(spa_t *, pool_removal_stat_t *);
void svr_sync(spa_t *spa, dmu_tx_t *tx);
extern void spa_vdev_remove_suspend(spa_t *);
extern int spa_vdev_remove_cancel(spa_t *);
void spa_vdev_removal_destroy(spa_vdev_removal_t *svr);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VDEV_REMOVAL_H */
