/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/dnode.h>
#include <sys/dsl_pool.h>
#include <sys/zio.h>
#include <sys/space_map.h>
#include <sys/refcount.h>
#include <sys/zfeature.h>

/*
 * This value controls how the space map's block size is allowed to grow.
 * If the value is set to the same size as SPACE_MAP_INITIAL_BLOCKSIZE then
 * the space map block size will remain fixed. Setting this value to something
 * greater than SPACE_MAP_INITIAL_BLOCKSIZE will allow the space map to
 * increase its block size as needed. To maintain backwards compatibilty the
 * space map's block size must be a power of 2 and SPACE_MAP_INITIAL_BLOCKSIZE
 * or larger.
 */
int space_map_max_blksz = (1 << 12);

/*
 * Wait for any in-progress space_map_load() to complete.
 */
void
space_map_load_wait(space_map_t *sm)
{
	ASSERT(MUTEX_HELD(sm->sm_lock));

	while (sm->sm_loading) {
		ASSERT(!sm->sm_loaded);
		cv_wait(&sm->sm_load_cv, sm->sm_lock);
	}
}

/*
 * Load the space map disk into the specified range tree. Segments of maptype
 * are added to the range tree, other segment types are removed.
 *
 * Note: space_map_load() will drop sm_lock across dmu_read() calls.
 * The caller must be OK with this.
 */
int
space_map_load(space_map_t *sm, range_tree_t *rt, maptype_t maptype)
{
	objset_t *os = sm->sm_os;
	uint64_t *entry, *entry_map, *entry_map_end;
	uint64_t bufsize, size, offset, end, space;
	uint64_t mapstart = sm->sm_start;
	int error = 0;

	ASSERT(MUTEX_HELD(sm->sm_lock));
	ASSERT(!sm->sm_loaded);
	ASSERT(!sm->sm_loading);

	sm->sm_loading = B_TRUE;
	end = space_map_length(sm);
	space = space_map_allocated(sm);

	VERIFY0(range_tree_space(rt));

	if (maptype == SM_FREE) {
		range_tree_add(rt, sm->sm_start, sm->sm_size);
		space = sm->sm_size - space;
	}

	bufsize = MAX(sm->sm_blksz, SPA_MINBLOCKSIZE);
	entry_map = zio_buf_alloc(bufsize);

	mutex_exit(sm->sm_lock);
	if (end > bufsize)
		dmu_prefetch(os, space_map_object(sm), bufsize, end - bufsize);
	mutex_enter(sm->sm_lock);

	for (offset = 0; offset < end; offset += bufsize) {
		size = MIN(end - offset, bufsize);
		VERIFY(P2PHASE(size, sizeof (uint64_t)) == 0);
		VERIFY(size != 0);
		ASSERT3U(sm->sm_blksz, !=, 0);

		dprintf("object=%llu  offset=%llx  size=%llx\n",
		    space_map_object(sm), offset, size);

		mutex_exit(sm->sm_lock);
		error = dmu_read(os, space_map_object(sm), offset, size,
		    entry_map, DMU_READ_PREFETCH);
		mutex_enter(sm->sm_lock);
		if (error != 0)
			break;

		entry_map_end = entry_map + (size / sizeof (uint64_t));
		for (entry = entry_map; entry < entry_map_end; entry++) {
			uint64_t e = *entry;
			uint64_t offset, size;

			if (SM_DEBUG_DECODE(e))		/* Skip debug entries */
				continue;

			offset = (SM_OFFSET_DECODE(e) << sm->sm_shift) +
			    mapstart;
			size = SM_RUN_DECODE(e) << sm->sm_shift;

			VERIFY0(P2PHASE(offset, 1ULL << sm->sm_shift));
			VERIFY0(P2PHASE(size, 1ULL << sm->sm_shift));
			VERIFY3U(offset, >=, sm->sm_start);
			VERIFY3U(offset + size, <=, sm->sm_start + sm->sm_size);
			if (SM_TYPE_DECODE(e) == maptype) {
				VERIFY3U(range_tree_space(rt) + size, <=,
				    sm->sm_size);
				range_tree_add(rt, offset, size);
			} else {
				range_tree_remove(rt, offset, size);
			}
		}
	}

	if (error == 0) {
		VERIFY3U(range_tree_space(rt), ==, space);
		sm->sm_loaded = B_TRUE;
	} else {
		range_tree_vacate(rt, NULL, NULL);
	}

	zio_buf_free(entry_map, bufsize);

	sm->sm_loading = B_FALSE;

	cv_broadcast(&sm->sm_load_cv);

	return (error);
}

void
space_map_unload(space_map_t *sm)
{
	ASSERT(MUTEX_HELD(sm->sm_lock));
	sm->sm_loaded = B_FALSE;
}

void
space_map_histogram_clear(space_map_t *sm)
{
	if (sm->sm_dbuf->db_size != sizeof (space_map_phys_t))
		return;

	bzero(sm->sm_phys->smp_histogram, sizeof (sm->sm_phys->smp_histogram));
}

boolean_t
space_map_histogram_verify(space_map_t *sm, range_tree_t *rt)
{
	/*
	 * Verify that the in-core range tree does not have any
	 * ranges smaller than our sm_shift size.
	 */
	for (int i = 0; i < sm->sm_shift; i++) {
		if (rt->rt_histogram[i] != 0)
			return (B_FALSE);
	}
	return (B_TRUE);
}

void
space_map_histogram_add(space_map_t *sm, range_tree_t *rt, dmu_tx_t *tx)
{
	int idx = 0;

	ASSERT(MUTEX_HELD(rt->rt_lock));
	ASSERT(dmu_tx_is_syncing(tx));
	VERIFY3U(space_map_object(sm), !=, 0);

	if (sm->sm_dbuf->db_size != sizeof (space_map_phys_t))
		return;

	dmu_buf_will_dirty(sm->sm_dbuf, tx);

	ASSERT(space_map_histogram_verify(sm, rt));

	/*
	 * Transfer the content of the range tree histogram to the space
	 * map histogram. The space map histogram contains 32 buckets ranging
	 * between 2^sm_shift to 2^(32+sm_shift-1). The range tree,
	 * however, can represent ranges from 2^0 to 2^63. Since the space
	 * map only cares about allocatable blocks (minimum of sm_shift) we
	 * can safely ignore all ranges in the range tree smaller than sm_shift.
	 */
	for (int i = sm->sm_shift; i < RANGE_TREE_MAX_BUCKETS; i++) {

		/*
		 * Since the largest histogram bucket in the space map is
		 * 2^(32+sm_shift-1), we need to normalize the values in
		 * the range tree for any bucket larger than that size. For
		 * example given an sm_shift of 9, ranges larger than 2^40
		 * would get normalized as if they were 1TB ranges. Assume
		 * the range tree had a count of 5 in the 2^44 (16TB) bucket,
		 * the calculation below would normalize this to 5 * 2^4 (16).
		 */
		ASSERT3U(i, >=, idx + sm->sm_shift);
		sm->sm_phys->smp_histogram[idx] +=
		    rt->rt_histogram[i] << (i - idx - sm->sm_shift);

		/*
		 * Increment the space map's index as long as we haven't
		 * reached the maximum bucket size. Accumulate all ranges
		 * larger than the max bucket size into the last bucket.
		 */
		if (idx < SPACE_MAP_HISTOGRAM_SIZE(sm) - 1) {
			ASSERT3U(idx + sm->sm_shift, ==, i);
			idx++;
			ASSERT3U(idx, <, SPACE_MAP_HISTOGRAM_SIZE(sm));
		}
	}
}

uint64_t
space_map_entries(space_map_t *sm, range_tree_t *rt)
{
	avl_tree_t *t = &rt->rt_root;
	range_seg_t *rs;
	uint64_t size, entries;

	/*
	 * All space_maps always have a debug entry so account for it here.
	 */
	entries = 1;

	/*
	 * Traverse the range tree and calculate the number of space map
	 * entries that would be required to write out the range tree.
	 */
	for (rs = avl_first(t); rs != NULL; rs = AVL_NEXT(t, rs)) {
		size = (rs->rs_end - rs->rs_start) >> sm->sm_shift;
		entries += howmany(size, SM_RUN_MAX);
	}
	return (entries);
}

void
space_map_set_blocksize(space_map_t *sm, uint64_t size, dmu_tx_t *tx)
{
	uint32_t blksz;
	u_longlong_t blocks;

	ASSERT3U(sm->sm_blksz, !=, 0);
	ASSERT3U(space_map_object(sm), !=, 0);
	ASSERT(sm->sm_dbuf != NULL);
	VERIFY(ISP2(space_map_max_blksz));

	if (sm->sm_blksz == space_map_max_blksz)
		return;

	/*
	 * The object contains more than one block so we can't adjust
	 * its size.
	 */
	if (sm->sm_phys->smp_objsize > sm->sm_blksz)
		return;

	if (size > sm->sm_blksz) {
		uint64_t newsz;

		/*
		 * Older software versions treat space map blocks as fixed
		 * entities. The DMU is capable of handling different block
		 * sizes making it possible for us to increase the
		 * block size and maintain backwards compatibility. The
		 * caveat is that the new block sizes must be a
		 * power of 2 so that old software can append to the file,
		 * adding more blocks. The block size can grow until it
		 * reaches space_map_max_blksz.
		 */
		newsz = ISP2(size) ? size : 1ULL << highbit(size);
		if (newsz > space_map_max_blksz)
			newsz = space_map_max_blksz;

		VERIFY0(dmu_object_set_blocksize(sm->sm_os,
		    space_map_object(sm), newsz, 0, tx));
		dmu_object_size_from_db(sm->sm_dbuf, &blksz, &blocks);

		zfs_dbgmsg("txg %llu, spa %s, increasing blksz from %d to %d",
		    dmu_tx_get_txg(tx), spa_name(dmu_objset_spa(sm->sm_os)),
		    sm->sm_blksz, blksz);

		VERIFY3U(newsz, ==, blksz);
		VERIFY3U(sm->sm_blksz, <, blksz);
		sm->sm_blksz = blksz;
	}
}

/*
 * Note: space_map_write() will drop sm_lock across dmu_write() calls.
 */
void
space_map_write(space_map_t *sm, range_tree_t *rt, maptype_t maptype,
    dmu_tx_t *tx)
{
	objset_t *os = sm->sm_os;
	spa_t *spa = dmu_objset_spa(os);
	avl_tree_t *t = &rt->rt_root;
	range_seg_t *rs;
	uint64_t size, total, rt_space, nodes;
	uint64_t *entry, *entry_map, *entry_map_end;
	uint64_t newsz, expected_entries, actual_entries = 1;

	ASSERT(MUTEX_HELD(rt->rt_lock));
	ASSERT(dsl_pool_sync_context(dmu_objset_pool(os)));
	VERIFY3U(space_map_object(sm), !=, 0);

	if (range_tree_space(rt) == 0) {
		VERIFY3U(sm->sm_object, ==, sm->sm_phys->smp_object);
		return;
	}

	dmu_buf_will_dirty(sm->sm_dbuf, tx);

	if (maptype == SM_ALLOC)
		sm->sm_phys->smp_alloc += range_tree_space(rt);
	else
		sm->sm_phys->smp_alloc -= range_tree_space(rt);

	expected_entries = space_map_entries(sm, rt);

	/*
	 * Calculate the new size for the space map on-disk and see if
	 * we can grow the block size to accommodate the new size.
	 */
	newsz = sm->sm_phys->smp_objsize + expected_entries * sizeof (uint64_t);
	space_map_set_blocksize(sm, newsz, tx);

	entry_map = zio_buf_alloc(sm->sm_blksz);
	entry_map_end = entry_map + (sm->sm_blksz / sizeof (uint64_t));
	entry = entry_map;

	*entry++ = SM_DEBUG_ENCODE(1) |
	    SM_DEBUG_ACTION_ENCODE(maptype) |
	    SM_DEBUG_SYNCPASS_ENCODE(spa_sync_pass(spa)) |
	    SM_DEBUG_TXG_ENCODE(dmu_tx_get_txg(tx));

	total = 0;
	nodes = avl_numnodes(&rt->rt_root);
	rt_space = range_tree_space(rt);
	for (rs = avl_first(t); rs != NULL; rs = AVL_NEXT(t, rs)) {
		uint64_t start;

		size = (rs->rs_end - rs->rs_start) >> sm->sm_shift;
		start = (rs->rs_start - sm->sm_start) >> sm->sm_shift;

		total += size << sm->sm_shift;

		while (size != 0) {
			uint64_t run_len;

			run_len = MIN(size, SM_RUN_MAX);

			if (entry == entry_map_end) {
				mutex_exit(rt->rt_lock);
				dmu_write(os, space_map_object(sm),
				    sm->sm_phys->smp_objsize, sm->sm_blksz,
				    entry_map, tx);
				mutex_enter(rt->rt_lock);
				sm->sm_phys->smp_objsize += sm->sm_blksz;
				entry = entry_map;
			}

			*entry++ = SM_OFFSET_ENCODE(start) |
			    SM_TYPE_ENCODE(maptype) |
			    SM_RUN_ENCODE(run_len);

			start += run_len;
			size -= run_len;
			actual_entries++;
		}
	}

	if (entry != entry_map) {
		size = (entry - entry_map) * sizeof (uint64_t);
		mutex_exit(rt->rt_lock);
		dmu_write(os, space_map_object(sm), sm->sm_phys->smp_objsize,
		    size, entry_map, tx);
		mutex_enter(rt->rt_lock);
		sm->sm_phys->smp_objsize += size;
	}
	ASSERT3U(expected_entries, ==, actual_entries);

	/*
	 * Ensure that the space_map's accounting wasn't changed
	 * while we were in the middle of writing it out.
	 */
	VERIFY3U(nodes, ==, avl_numnodes(&rt->rt_root));
	VERIFY3U(range_tree_space(rt), ==, rt_space);
	VERIFY3U(range_tree_space(rt), ==, total);

	zio_buf_free(entry_map, sm->sm_blksz);
}

void
space_map_truncate(space_map_t *sm, dmu_tx_t *tx)
{
	objset_t *os = sm->sm_os;
	spa_t *spa = dmu_objset_spa(os);
	dnode_t *dn;
	zfeature_info_t *space_map_histogram =
	    &spa_feature_table[SPA_FEATURE_SPACEMAP_HISTOGRAM];
	int bonuslen;

	ASSERT(dsl_pool_sync_context(dmu_objset_pool(os)));
	VERIFY0(dmu_free_range(os, space_map_object(sm), 0, -1ULL, tx));
	VERIFY0(dnode_hold(os, space_map_object(sm), FTAG, &dn));

	if (spa_feature_is_enabled(spa, space_map_histogram)) {
		if (dn->dn_bonuslen == SPACE_MAP_SIZE_V0)
			spa_feature_incr(spa, space_map_histogram, tx);
		bonuslen = sizeof (space_map_phys_t);
		ASSERT3U(bonuslen, <=, dmu_bonus_max());
	} else {
		bonuslen = SPACE_MAP_SIZE_V0;
	}

	if (bonuslen != dn->dn_bonuslen ||
	    dn->dn_datablksz != SPACE_MAP_INITIAL_BLOCKSIZE) {
		dnode_reallocate(dn, dn->dn_type,
		    SPACE_MAP_INITIAL_BLOCKSIZE, dn->dn_bonustype,
		    bonuslen, tx);
		sm->sm_blksz = SPACE_MAP_INITIAL_BLOCKSIZE;
	}
	dnode_rele(dn, FTAG);

	dmu_buf_will_dirty(sm->sm_dbuf, tx);
	sm->sm_phys->smp_objsize = 0;
	sm->sm_phys->smp_alloc = 0;
}

/*
 * Update the in-core space_map allocation and length values.
 */
void
space_map_update(space_map_t *sm)
{
	if (sm->sm_dbuf == NULL) {
		ASSERT0(space_map_allocated(sm));
		ASSERT0(space_map_length(sm));
		return;
	}

	mutex_enter(sm->sm_lock);
	sm->sm_alloc = sm->sm_phys->smp_alloc;
	sm->sm_length = sm->sm_phys->smp_objsize;
	mutex_exit(sm->sm_lock);
}

uint64_t
space_map_alloc(space_map_t *sm, objset_t *os, dmu_tx_t *tx)
{
	spa_t *spa = dmu_objset_spa(os);
	zfeature_info_t *space_map_histogram =
	    &spa_feature_table[SPA_FEATURE_SPACEMAP_HISTOGRAM];
	uint64_t object;
	int bonuslen;

	ASSERT(sm->sm_dbuf == NULL);

	if (spa_feature_is_enabled(spa, space_map_histogram)) {
		spa_feature_incr(spa, space_map_histogram, tx);
		bonuslen = sizeof (*sm->sm_phys);
		ASSERT3U(bonuslen, <=, dmu_bonus_max());
	} else {
		bonuslen = SPACE_MAP_SIZE_V0;
	}

	object = dmu_object_alloc(os,
	    DMU_OT_SPACE_MAP, SPACE_MAP_INITIAL_BLOCKSIZE,
	    DMU_OT_SPACE_MAP_HEADER, bonuslen, tx);

	return (object);
}

void
space_map_free(space_map_t *sm, dmu_tx_t *tx)
{
	objset_t *os = sm->sm_os;
	spa_t *spa = dmu_objset_spa(os);
	zfeature_info_t *space_map_histogram =
	    &spa_feature_table[SPA_FEATURE_SPACEMAP_HISTOGRAM];

	if (spa_feature_is_enabled(spa, space_map_histogram)) {
		dmu_object_info_t doi;

		dmu_object_info_from_db(sm->sm_dbuf, &doi);
		if (doi.doi_bonus_size != SPACE_MAP_SIZE_V0) {
			VERIFY(spa_feature_is_active(spa, space_map_histogram));
			spa_feature_decr(spa, space_map_histogram, tx);
		}
	}

	VERIFY3U(dmu_object_free(os, space_map_object(sm), tx), ==, 0);
	sm->sm_object = 0;
}

int
space_map_open(space_map_t **smp, objset_t *os, uint64_t object,
    uint64_t start, uint64_t size, uint8_t shift, kmutex_t *lp)
{
	space_map_t *sm;
	u_longlong_t blocks;
	int error;

	if (*smp == NULL) {

		sm = kmem_zalloc(sizeof (space_map_t), KM_SLEEP);

		cv_init(&sm->sm_load_cv, NULL, CV_DEFAULT, NULL);

		sm->sm_start = start;
		sm->sm_size = size;
		sm->sm_shift = shift;
		sm->sm_lock = lp;
		*smp = sm;
	}
	sm = *smp;

	if (object == 0) {
		ASSERT0(space_map_allocated(sm));
		ASSERT0(space_map_length(sm));
		return (0);
	}

	ASSERT(sm->sm_dbuf == NULL);
	ASSERT(sm->sm_os == NULL);
	ASSERT(sm->sm_object == 0);
	ASSERT(sm->sm_blksz == 0);
	sm->sm_os = os;
	sm->sm_object = object;

	error = dmu_bonus_hold(os, object, sm, &sm->sm_dbuf);
	if (error)
		return (error);

	dmu_object_size_from_db(sm->sm_dbuf, &sm->sm_blksz, &blocks);
	sm->sm_phys = sm->sm_dbuf->db_data;

	/*
	 * This field is no longer necessary since the in-core space map
	 * now contains the object number but is maintained for backwards
	 * compatibility.
	 */
	if (sm->sm_phys->smp_object == 0)
		sm->sm_phys->smp_object = object;

	ASSERT3U(sm->sm_object, ==, sm->sm_phys->smp_object);
	return (0);
}

void
space_map_close(space_map_t *sm)
{
	ASSERT(!sm->sm_loaded && !sm->sm_loading);

	if (sm->sm_dbuf != NULL)
		dmu_buf_rele(sm->sm_dbuf, sm);
	sm->sm_dbuf = NULL;
	sm->sm_phys = NULL;

	cv_destroy(&sm->sm_load_cv);
	kmem_free(sm, sizeof (*sm));
}

uint64_t
space_map_object(space_map_t *sm)
{
	return (sm->sm_object);
}

/*
 * Returns the already synced, on-disk allocated space.
 */
uint64_t
space_map_allocated(space_map_t *sm)
{
	return (sm->sm_alloc);
}

/*
 * Returns the already synced, on-disk length;
 */
uint64_t
space_map_length(space_map_t *sm)
{
	return (sm->sm_length);
}

/*
 * Returns the allocated space that is currently syncing.
 */
int64_t
space_map_alloc_delta(space_map_t *sm)
{
	if (sm->sm_dbuf == NULL) {
		ASSERT0(space_map_allocated(sm));
		ASSERT0(space_map_length(sm));
		return (0);
	}

	return (sm->sm_phys->smp_alloc - space_map_allocated(sm));
}
