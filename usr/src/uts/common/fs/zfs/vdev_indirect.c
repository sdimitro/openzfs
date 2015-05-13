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

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#include <sys/metaslab.h>
#include <sys/refcount.h>
#include <sys/dmu.h>
#include <sys/vdev_indirect_mapping.h>

/*
 * An indirect vdev corresponds to a vdev that has been removed. Since
 * we cannot rewrite block pointers of snapshots, etc., we keep a
 * mapping from old location on the removed device to the new location
 * on another device in the pool and use this mapping whenever we
 * would use the DVA. Unfortunately, this mapping did not respect
 * logical block boundaries when it was first created, and so a
 * DVA on this indirect vdev may be "split" into multiple sections
 * that each map to a different location. As a consequence, not all DVAs
 * can be translated to an equivalent new DVA.  Instead we must provide
 * a "vdev_remap" operation that executes a callback on each contiguous
 * segment of the new location. This function is used in multiple ways:
 *  - reads and repair writes to this device use the callback to create
 *    a child io for each mapped segment.
 *  - frees and claims to this device use the callback to free or
 *    claim each mapped segment.
 */

/* ARGSUSED */
static void
vdev_indirect_close(vdev_t *vd)
{
}

/* ARGSUSED */
static void
vdev_indirect_io_done(zio_t *zio)
{
}

/* ARGSUSED */
static int
vdev_indirect_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
	*psize = *max_psize = vd->vdev_asize +
	    VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE;
	*ashift = vd->vdev_ashift;
	return (0);
}

static void
vdev_indirect_remap(vdev_t *vd, uint64_t offset, uint64_t asize,
    void (*func)(uint64_t, vdev_t *, uint64_t, uint64_t, void *), void *arg)
{
	spa_t *spa = vd->vdev_spa;
	uint64_t split_offset = 0;
	vdev_indirect_mapping_t *vim = vd->vdev_indirect_mapping;

	ASSERT(spa_config_held(spa, SCL_ALL, RW_READER) != 0);

	vdev_indirect_mapping_entry_phys_t *mapping =
	    vdev_indirect_mapping_entry_for_offset(vim, offset);

	while (asize > 0) {
		/*
		 * Note: the vdev_indirect_mapping can not change while we
		 * are running.  It only changes while the removal
		 * is in progress, and then only from syncing context.
		 * While a removal is in progress, this function is only
		 * called for frees, which also only happen from syncing
		 * context.
		 */

		if (spa->spa_mark_indirect_mappings)
			DVA_MAPPING_SET_MARK(mapping, B_TRUE);

		uint64_t size = DVA_GET_ASIZE(&mapping->vimep_dst);
		uint64_t dst_offset = DVA_GET_OFFSET(&mapping->vimep_dst);
		uint64_t dst_vdev = DVA_GET_VDEV(&mapping->vimep_dst);

		ASSERT3U(offset, >=, DVA_MAPPING_GET_SRC_OFFSET(mapping));
		ASSERT3U(offset, <,
		    DVA_MAPPING_GET_SRC_OFFSET(mapping) + size);
		ASSERT3U(dst_vdev, !=, vd->vdev_id);

		uint64_t inner_offset = offset -
		    DVA_MAPPING_GET_SRC_OFFSET(mapping);
		uint64_t inner_size = MIN(asize, size - inner_offset);

		func(split_offset, vdev_lookup_top(spa, dst_vdev),
		    dst_offset + inner_offset, inner_size, arg);
		offset += inner_size;
		asize -= inner_size;
		split_offset += inner_size;
		mapping++;
	}
}

static void
vdev_indirect_child_io_done(zio_t *zio)
{
	zio_t *pio = zio->io_private;

	mutex_enter(&pio->io_lock);
	pio->io_error = zio_worst_error(pio->io_error, zio->io_error);
	mutex_exit(&pio->io_lock);
}

static void
vdev_indirect_io_start_cb(uint64_t split_offset, vdev_t *vd, uint64_t offset,
    uint64_t size, void *arg)
{
	zio_t *zio = arg;
	char *data = zio->io_data;

	ASSERT3P(data, !=, NULL);
	ASSERT3P(vd, !=, NULL);

	/*
	 * An indirect vdev can dereference to another indirect
	 * vdev.  To limit the stack size, we ZIO_FLAG_DISPATCH
	 * this to another thread.
	 */
	zio_nowait(zio_vdev_child_io(zio, NULL, vd, offset,
	    &data[split_offset], size, zio->io_type, zio->io_priority,
	    ZIO_FLAG_DISPATCH, vdev_indirect_child_io_done, zio));
}

static void
vdev_indirect_io_start(zio_t *zio)
{
	spa_t *spa = zio->io_spa;

	ASSERT(spa_config_held(spa, SCL_ALL, RW_READER) != 0);
	if (zio->io_type != ZIO_TYPE_READ) {
		ASSERT3U(zio->io_type, ==, ZIO_TYPE_WRITE);
		ASSERT((zio->io_flags &
		    (ZIO_FLAG_SELF_HEAL | ZIO_FLAG_INDUCE_DAMAGE)) != 0);
	}

	vdev_indirect_remap(zio->io_vd, zio->io_offset, zio->io_size,
	    vdev_indirect_io_start_cb, zio);

	zio_execute(zio);
}

vdev_ops_t vdev_indirect_ops = {
	vdev_indirect_open,
	vdev_indirect_close,
	vdev_default_asize,
	vdev_indirect_io_start,
	vdev_indirect_io_done,
	NULL,
	NULL,
	NULL,
	vdev_indirect_remap,
	VDEV_TYPE_INDIRECT,	/* name of this vdev type */
	B_FALSE			/* leaf vdev */
};
