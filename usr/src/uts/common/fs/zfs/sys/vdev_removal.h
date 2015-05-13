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

typedef struct spa_vdev_removal {
	vdev_t		*svr_vdev;
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
