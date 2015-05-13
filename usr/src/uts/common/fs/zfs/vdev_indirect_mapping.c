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
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

#include <sys/dmu_tx.h>
#include <sys/dsl_pool.h>
#include <sys/spa.h>
#include <sys/vdev_impl.h>
#include <sys/vdev_indirect_mapping.h>
#include <util/bsearch.h>


static boolean_t
vdev_indirect_mapping_verify(vdev_indirect_mapping_t *vim)
{
	ASSERT(vim != NULL);

	ASSERT(vim->vim_object != 0);
	ASSERT(vim->vim_objset != NULL);
	ASSERT(vim->vim_phys != NULL);
	ASSERT(vim->vim_dbuf != NULL);

	EQUIV(vim->vim_phys->vimp_count > 0,
	    vim->vim_entries != NULL);
	if (vim->vim_phys->vimp_count > 0) {
		vdev_indirect_mapping_entry_phys_t *last_entry =
		    &vim->vim_entries[vim->vim_phys->vimp_count - 1];
		uint64_t offset = DVA_MAPPING_GET_SRC_OFFSET(last_entry);
		uint64_t size = DVA_GET_ASIZE(&last_entry->vimep_dst);

		ASSERT3U(vim->vim_phys->vimp_max_offset, >=, offset + size);
	}


	return (B_TRUE);
}

uint64_t
vdev_indirect_mapping_count(vdev_indirect_mapping_t *vim)
{
	ASSERT(vdev_indirect_mapping_verify(vim));

	return (vim->vim_phys->vimp_count);
}

uint64_t
vdev_indirect_mapping_max_offset(vdev_indirect_mapping_t *vim)
{
	ASSERT(vdev_indirect_mapping_verify(vim));

	return (vim->vim_phys->vimp_max_offset);
}

uint64_t
vdev_indirect_mapping_object(vdev_indirect_mapping_t *vim)
{
	ASSERT(vdev_indirect_mapping_verify(vim));

	return (vim->vim_object);
}

uint64_t
vdev_indirect_mapping_bytes_mapped(vdev_indirect_mapping_t *vim)
{
	ASSERT(vdev_indirect_mapping_verify(vim));

	return (vim->vim_phys->vimp_bytes_mapped);
}

/*
 * An internal version of the mapping_size function that doesn't check
 * structure invariants.
 */
static uint64_t
vdev_indirect_mapping_size_impl(vdev_indirect_mapping_t *vim)
{
	return (vim->vim_phys->vimp_count * sizeof (*vim->vim_entries));
}

/*
 * The length (in bytes) of the mapping object array in memory and
 * on disk.
 */
uint64_t
vdev_indirect_mapping_size(vdev_indirect_mapping_t *vim)
{
	ASSERT(vdev_indirect_mapping_verify(vim));

	return (vdev_indirect_mapping_size_impl(vim));
}

static int
dva_mapping_overlap_compare(const void *v_key, const void *v_array_elem)
{
	const uint64_t const *key = v_key;
	const vdev_indirect_mapping_entry_phys_t const *array_elem =
	    v_array_elem;
	uint64_t src_offset = DVA_MAPPING_GET_SRC_OFFSET(array_elem);

	if (*key < src_offset) {
		return (-1);
	} else if (*key < src_offset + DVA_GET_ASIZE(&array_elem->vimep_dst)) {
		return (0);
	} else {
		return (1);
	}
}

/*
 * Returns the mapping entry for the given offset.
 *
 * The offset must be present in the mapping.
 */
vdev_indirect_mapping_entry_phys_t *
vdev_indirect_mapping_entry_for_offset(vdev_indirect_mapping_t *vim,
    uint64_t offset)
{
	ASSERT(vdev_indirect_mapping_verify(vim));
	ASSERT(vim->vim_phys->vimp_count > 0);

	vdev_indirect_mapping_entry_phys_t *entry =
	    bsearch(&offset, vim->vim_entries, vim->vim_phys->vimp_count,
	    sizeof (vdev_indirect_mapping_entry_phys_t),
	    dva_mapping_overlap_compare);

	ASSERT(entry != NULL);

	return (entry);
}

void
vdev_indirect_mapping_close(vdev_indirect_mapping_t *vim)
{
	ASSERT(vdev_indirect_mapping_verify(vim));

	if (vim->vim_phys->vimp_count > 0) {
		uint64_t map_size = vdev_indirect_mapping_size_impl(vim);
		kmem_free(vim->vim_entries, map_size);
		vim->vim_entries = NULL;
	}

	dmu_buf_rele(vim->vim_dbuf, vim);

	vim->vim_objset = NULL;
	vim->vim_object = 0;
	vim->vim_dbuf = NULL;
	vim->vim_phys = NULL;

	kmem_free(vim, sizeof (*vim));
}

uint64_t
vdev_indirect_mapping_alloc(objset_t *os, dmu_tx_t *tx)
{
	ASSERT(dmu_tx_is_syncing(tx));

	return (dmu_object_alloc(os,
	    DMU_OTN_UINT64_METADATA, SPA_OLD_MAXBLOCKSIZE,
	    DMU_OTN_UINT64_METADATA, sizeof (vdev_indirect_mapping_phys_t),
	    tx));
}


vdev_indirect_mapping_t *
vdev_indirect_mapping_open(objset_t *os, uint64_t mapping_object)
{
	vdev_indirect_mapping_t *vim = kmem_zalloc(sizeof (*vim), KM_SLEEP);

	vim->vim_objset = os;
	vim->vim_object = mapping_object;

	VERIFY0(dmu_bonus_hold(os, vim->vim_object, vim,
	    &vim->vim_dbuf));
	vim->vim_phys = vim->vim_dbuf->db_data;

	if (vim->vim_phys->vimp_count > 0) {
		uint64_t map_size = vdev_indirect_mapping_size_impl(vim);
		vim->vim_entries = kmem_alloc(map_size, KM_SLEEP);
		VERIFY0(dmu_read(os, vim->vim_object, 0, map_size,
		    vim->vim_entries, DMU_READ_PREFETCH));
	}

	ASSERT(vdev_indirect_mapping_verify(vim));

	return (vim);
}

void
vdev_indirect_mapping_free(objset_t *os, uint64_t object, dmu_tx_t *tx)
{
	VERIFY0(dmu_object_free(os, object, tx));
}

void
vdev_indirect_mapping_add_entries(vdev_indirect_mapping_t *vim,
    list_t *list, dmu_tx_t *tx)
{
	vdev_indirect_mapping_entry_phys_t *mapbuf;
	uint64_t new_size;
	uint64_t old_size;
	vdev_indirect_mapping_entry_phys_t *old_entries;
	uint64_t old_count;

	ASSERT(vdev_indirect_mapping_verify(vim));
	ASSERT(dmu_tx_is_syncing(tx));
	ASSERT(dsl_pool_sync_context(dmu_tx_pool(tx)));
	ASSERT(!list_is_empty(list));

	old_size = vdev_indirect_mapping_size_impl(vim);
	old_entries = vim->vim_entries;
	old_count = vim->vim_phys->vimp_count;

	dmu_buf_will_dirty(vim->vim_dbuf, tx);

	mapbuf = zio_buf_alloc(SPA_OLD_MAXBLOCKSIZE);
	while (!list_is_empty(list)) {
		uint64_t i;
		/*
		 * Write entries from the list to the
		 * vdev_im_object in batches of size SPA_OLD_MAXBLOCKSIZE.
		 */
		for (i = 0; i < SPA_OLD_MAXBLOCKSIZE / sizeof (*mapbuf); i++) {
			vdev_indirect_mapping_entry_t *entry =
			    list_remove_head(list);
			if (entry == NULL) {
				break;
			}
			mapbuf[i] = entry->vime_mapping;
			uint64_t size = DVA_GET_ASIZE(&mapbuf[i].vimep_dst);
			uint64_t src_offset =
			    DVA_MAPPING_GET_SRC_OFFSET(&mapbuf[i]);

			vim->vim_phys->vimp_bytes_mapped += size;
			ASSERT3U(src_offset, >=,
			    vim->vim_phys->vimp_max_offset);
			vim->vim_phys->vimp_max_offset = src_offset + size;
			kmem_free(entry, sizeof (*entry));
		}
		dmu_write(vim->vim_objset, vim->vim_object,
		    vdev_indirect_mapping_size_impl(vim),
		    i * sizeof (vdev_indirect_mapping_entry_phys_t),
		    mapbuf, tx);
		vim->vim_phys->vimp_count += i;
	}
	zio_buf_free(mapbuf, SPA_OLD_MAXBLOCKSIZE);

	/*
	 * Update the entry array to reflect the new entries. First, copy
	 * over any old entries then read back the new entries we just wrote.
	 */
	new_size = vdev_indirect_mapping_size_impl(vim);
	ASSERT3U(new_size, >, old_size);
	vim->vim_entries = kmem_alloc(new_size, KM_SLEEP);
	if (old_size > 0) {
		bcopy(old_entries, vim->vim_entries, old_size);
		kmem_free(old_entries, old_size);
	}
	VERIFY0(dmu_read(vim->vim_objset, vim->vim_object, old_size,
	    new_size - old_size, &vim->vim_entries[old_count],
	    DMU_READ_PREFETCH));
}
