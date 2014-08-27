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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2011, 2014 by Delphix. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 * Copyright 2014 HybridCluster. All rights reserved.
 */

#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dmu_tx.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/zfs_ioctl.h>
#include <sys/zap.h>
#include <sys/zio_checksum.h>
#include <sys/zfs_znode.h>
#include <zfs_fletcher.h>
#include <sys/avl.h>
#include <sys/ddt.h>
#include <sys/zfs_onexit.h>
#include <sys/dmu_send.h>
#include <sys/dsl_destroy.h>
#include <sys/mooch_byteswap.h>
#include <sys/blkptr.h>
#include <sys/dsl_bookmark.h>
#include <sys/zfeature.h>
#include <sys/bqueue.h>

/* Set this tunable to TRUE to replace corrupt data with 0x2f5baddb10c */
int zfs_send_corrupt_data = B_FALSE;
int zfs_send_queue_length = 16 * 1024 * 1024;

static char *dmu_recv_tag = "dmu_recv_tag";
static const char *recv_clone_name = "%recv";

#define	BP_SPAN(datablkszsec, indblkshift, level) \
	(((uint64_t)datablkszsec) << (SPA_MINBLOCKSHIFT + \
	(level) * (indblkshift - SPA_BLKPTRSHIFT)))

#define	BP_SPANB(indblkshift, level) \
	(((uint64_t)1) << ((level) * ((indblkshift) - SPA_BLKPTRSHIFT)))
#define	COMPARE_META_LEVEL	0x80000000ul

struct send_thread_arg {
	bqueue_t	q;
	dsl_dataset_t	*ds;		/* Dataset to traverse */
	uint64_t	fromtxg;	/* Traverse from this txg */
	objset_t	*to_os;		/* The "to" objset (from thread only) */
	int		flags;		/* flags to pass to traverse_dataset */
	int		error_code;
	boolean_t	cancel;
};

struct send_block_record {
	boolean_t		eos_marker;
	blkptr_t		bp;
	zbookmark_phys_t	zb;
	uint8_t			indblkshift;
	uint16_t		datablkszsec;
	bqueue_node_t		ln;
};

static int
dump_bytes(dmu_sendarg_t *dsp, void *buf, int len)
{
	dsl_dataset_t *ds = dsp->dsa_os->os_dsl_dataset;
	ssize_t resid; /* have to get resid to get detailed errno */
	ASSERT0(len % 8);

	dsp->dsa_err = vn_rdwr(UIO_WRITE, dsp->dsa_vp,
	    (caddr_t)buf, len,
	    0, UIO_SYSSPACE, FAPPEND, RLIM64_INFINITY, CRED(), &resid);

	mutex_enter(&ds->ds_sendstream_lock);
	*dsp->dsa_off += len;
	mutex_exit(&ds->ds_sendstream_lock);

	return (dsp->dsa_err);
}

/*
 * For all record types except BEGIN, fill in the checksum (overlaid in
 * drr_u.drr_checksum.drr_checksum).  The checksum verifies everything
 * up to the start of the checksum itself.
 */
static int
dump_record(dmu_sendarg_t *dsp, void *payload, int payload_len)
{
	ASSERT3U(offsetof(dmu_replay_record_t, drr_u.drr_checksum.drr_checksum),
	    ==, sizeof (dmu_replay_record_t) - sizeof (zio_cksum_t));
	fletcher_4_incremental_native(dsp->dsa_drr,
	    offsetof(dmu_replay_record_t, drr_u.drr_checksum.drr_checksum),
	    &dsp->dsa_zc);
	if (dsp->dsa_drr->drr_type != DRR_BEGIN) {
		ASSERT(ZIO_CHECKSUM_IS_ZERO(&dsp->dsa_drr->drr_u.
		    drr_checksum.drr_checksum));
		dsp->dsa_drr->drr_u.drr_checksum.drr_checksum = dsp->dsa_zc;
	}
	fletcher_4_incremental_native(&dsp->dsa_drr->
	    drr_u.drr_checksum.drr_checksum,
	    sizeof (zio_cksum_t), &dsp->dsa_zc);
	if (dump_bytes(dsp, dsp->dsa_drr, sizeof (dmu_replay_record_t)) != 0)
		return (SET_ERROR(EINTR));
	if (payload_len != 0) {
		fletcher_4_incremental_native(payload, payload_len,
		    &dsp->dsa_zc);
		if (dump_bytes(dsp, payload, payload_len) != 0)
			return (SET_ERROR(EINTR));
	}
	return (0);
}

static int
dump_free(dmu_sendarg_t *dsp, uint64_t object, uint64_t offset,
    uint64_t length)
{
	struct drr_free *drrf = &(dsp->dsa_drr->drr_u.drr_free);

	/*
	 * When we receive a free record, dbuf_free_range() assumes
	 * that the receiving system doesn't have any dbufs in the range
	 * being freed.  This is always true because there is a one-record
	 * constraint: we only send one WRITE record for any given
	 * object+offset.  We know that the one-record constraint is
	 * true because we always send data in increasing order by
	 * object,offset.
	 *
	 * If the increasing-order constraint ever changes, we should find
	 * another way to assert that the one-record constraint is still
	 * satisfied.
	 */
	ASSERT(object > dsp->dsa_last_data_object ||
	    (object == dsp->dsa_last_data_object &&
	    offset > dsp->dsa_last_data_offset));

	/*
	 * If we are doing a non-incremental send, then there can't
	 * be any data in the dataset we're receiving into.  Therefore
	 * a free record would simply be a no-op.  Save space by not
	 * sending it to begin with.
	 */
	if (!dsp->dsa_incremental)
		return (0);

	if (length != -1ULL && offset + length < offset)
		length = -1ULL;

	/*
	 * If there is a pending op, but it's not PENDING_FREE, push it out,
	 * since free block aggregation can only be done for blocks of the
	 * same type (i.e., DRR_FREE records can only be aggregated with
	 * other DRR_FREE records.  DRR_FREEOBJECTS records can only be
	 * aggregated with other DRR_FREEOBJECTS records.
	 */
	if (dsp->dsa_pending_op != PENDING_NONE &&
	    dsp->dsa_pending_op != PENDING_FREE) {
		if (dump_record(dsp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dsp->dsa_pending_op = PENDING_NONE;
	}

	if (dsp->dsa_pending_op == PENDING_FREE) {
		/*
		 * There should never be a PENDING_FREE if length is -1
		 * (because dump_dnode is the only place where this
		 * function is called with a -1, and only after flushing
		 * any pending record).
		 */
		ASSERT(length != -1ULL);
		/*
		 * Check to see whether this free block can be aggregated
		 * with pending one.
		 */
		if (drrf->drr_object == object && drrf->drr_offset +
		    drrf->drr_length == offset) {
			drrf->drr_length += length;
			return (0);
		} else {
			/* not a continuation.  Push out pending record */
			if (dump_record(dsp, NULL, 0) != 0)
				return (SET_ERROR(EINTR));
			dsp->dsa_pending_op = PENDING_NONE;
		}
	}
	/* create a FREE record and make it pending */
	bzero(dsp->dsa_drr, sizeof (dmu_replay_record_t));
	dsp->dsa_drr->drr_type = DRR_FREE;
	drrf->drr_object = object;
	drrf->drr_offset = offset;
	drrf->drr_length = length;
	drrf->drr_toguid = dsp->dsa_toguid;
	if (length == -1ULL) {
		if (dump_record(dsp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
	} else {
		dsp->dsa_pending_op = PENDING_FREE;
	}

	return (0);
}

static int
dump_write(dmu_sendarg_t *dsp, dmu_object_type_t type,
    uint64_t object, uint64_t offset, int blksz, const blkptr_t *bp, void *data)
{
	struct drr_write *drrw = &(dsp->dsa_drr->drr_u.drr_write);

	/*
	 * We send data in increasing object, offset order.
	 * See comment in dump_free() for details.
	 */
	ASSERT(object > dsp->dsa_last_data_object ||
	    (object == dsp->dsa_last_data_object &&
	    offset > dsp->dsa_last_data_offset));
	dsp->dsa_last_data_object = object;
	dsp->dsa_last_data_offset = offset + blksz - 1;

	/*
	 * If there is any kind of pending aggregation (currently either
	 * a grouping of free objects or free blocks), push it out to
	 * the stream, since aggregation can't be done across operations
	 * of different types.
	 */
	if (dsp->dsa_pending_op != PENDING_NONE) {
		if (dump_record(dsp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dsp->dsa_pending_op = PENDING_NONE;
	}
	/* write a WRITE record */
	bzero(dsp->dsa_drr, sizeof (dmu_replay_record_t));
	dsp->dsa_drr->drr_type = DRR_WRITE;
	drrw->drr_object = object;
	drrw->drr_type = type;
	drrw->drr_offset = offset;
	drrw->drr_length = blksz;
	drrw->drr_toguid = dsp->dsa_toguid;
	if (BP_IS_EMBEDDED(bp)) {
		/*
		 * There's no pre-computed checksum of embedded BP's, so
		 * (like fletcher4-checkummed blocks) userland will have
		 * to compute a dedup-capable checksum itself.
		 */
		drrw->drr_checksumtype = ZIO_CHECKSUM_OFF;
	} else {
		drrw->drr_checksumtype = BP_GET_CHECKSUM(bp);
		if (zio_checksum_table[drrw->drr_checksumtype].ci_dedup)
			drrw->drr_checksumflags |= DRR_CHECKSUM_DEDUP;
		DDK_SET_LSIZE(&drrw->drr_key, BP_GET_LSIZE(bp));
		DDK_SET_PSIZE(&drrw->drr_key, BP_GET_PSIZE(bp));
		DDK_SET_COMPRESS(&drrw->drr_key, BP_GET_COMPRESS(bp));
		drrw->drr_key.ddk_cksum = bp->blk_cksum;
	}

	if (dump_record(dsp, data, blksz) != 0)
		return (SET_ERROR(EINTR));
	return (0);
}

static int
dump_write_embedded(dmu_sendarg_t *dsp, uint64_t object, uint64_t offset,
    int blksz, const blkptr_t *bp)
{
	char buf[BPE_PAYLOAD_SIZE];
	struct drr_write_embedded *drrw =
	    &(dsp->dsa_drr->drr_u.drr_write_embedded);

	if (dsp->dsa_pending_op != PENDING_NONE) {
		if (dump_record(dsp, NULL, 0) != 0)
			return (EINTR);
		dsp->dsa_pending_op = PENDING_NONE;
	}

	ASSERT(BP_IS_EMBEDDED(bp));

	bzero(dsp->dsa_drr, sizeof (dmu_replay_record_t));
	dsp->dsa_drr->drr_type = DRR_WRITE_EMBEDDED;
	drrw->drr_object = object;
	drrw->drr_offset = offset;
	drrw->drr_length = blksz;
	drrw->drr_toguid = dsp->dsa_toguid;
	drrw->drr_compression = BP_GET_COMPRESS(bp);
	drrw->drr_etype = BPE_GET_ETYPE(bp);
	drrw->drr_lsize = BPE_GET_LSIZE(bp);
	drrw->drr_psize = BPE_GET_PSIZE(bp);

	decode_embedded_bp_compressed(bp, buf);

	if (dump_record(dsp, buf, P2ROUNDUP(drrw->drr_psize, 8)) != 0)
		return (EINTR);
	return (0);
}

static int
dump_spill(dmu_sendarg_t *dsp, uint64_t object, int blksz, void *data)
{
	struct drr_spill *drrs = &(dsp->dsa_drr->drr_u.drr_spill);

	if (dsp->dsa_pending_op != PENDING_NONE) {
		if (dump_record(dsp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dsp->dsa_pending_op = PENDING_NONE;
	}

	/* write a SPILL record */
	bzero(dsp->dsa_drr, sizeof (dmu_replay_record_t));
	dsp->dsa_drr->drr_type = DRR_SPILL;
	drrs->drr_object = object;
	drrs->drr_length = blksz;
	drrs->drr_toguid = dsp->dsa_toguid;

	if (dump_record(dsp, data, blksz) != 0)
		return (SET_ERROR(EINTR));
	return (0);
}

static int
dump_freeobjects(dmu_sendarg_t *dsp, uint64_t firstobj, uint64_t numobjs)
{
	struct drr_freeobjects *drrfo = &(dsp->dsa_drr->drr_u.drr_freeobjects);

	/* See comment in dump_free(). */
	if (!dsp->dsa_incremental)
		return (0);

	/*
	 * If there is a pending op, but it's not PENDING_FREEOBJECTS,
	 * push it out, since free block aggregation can only be done for
	 * blocks of the same type (i.e., DRR_FREE records can only be
	 * aggregated with other DRR_FREE records.  DRR_FREEOBJECTS records
	 * can only be aggregated with other DRR_FREEOBJECTS records.
	 */
	if (dsp->dsa_pending_op != PENDING_NONE &&
	    dsp->dsa_pending_op != PENDING_FREEOBJECTS) {
		if (dump_record(dsp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dsp->dsa_pending_op = PENDING_NONE;
	}
	if (dsp->dsa_pending_op == PENDING_FREEOBJECTS) {
		/*
		 * See whether this free object array can be aggregated
		 * with pending one
		 */
		if (drrfo->drr_firstobj + drrfo->drr_numobjs == firstobj) {
			drrfo->drr_numobjs += numobjs;
			return (0);
		} else {
			/* can't be aggregated.  Push out pending record */
			if (dump_record(dsp, NULL, 0) != 0)
				return (SET_ERROR(EINTR));
			dsp->dsa_pending_op = PENDING_NONE;
		}
	}

	/* write a FREEOBJECTS record */
	bzero(dsp->dsa_drr, sizeof (dmu_replay_record_t));
	dsp->dsa_drr->drr_type = DRR_FREEOBJECTS;
	drrfo->drr_firstobj = firstobj;
	drrfo->drr_numobjs = numobjs;
	drrfo->drr_toguid = dsp->dsa_toguid;

	dsp->dsa_pending_op = PENDING_FREEOBJECTS;

	return (0);
}

static int
dump_dnode(dmu_sendarg_t *dsp, uint64_t object, dnode_phys_t *dnp)
{
	struct drr_object *drro = &(dsp->dsa_drr->drr_u.drr_object);

	if (dnp == NULL || dnp->dn_type == DMU_OT_NONE)
		return (dump_freeobjects(dsp, object, 1));

	if (dsp->dsa_pending_op != PENDING_NONE) {
		if (dump_record(dsp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dsp->dsa_pending_op = PENDING_NONE;
	}

	/* write an OBJECT record */
	bzero(dsp->dsa_drr, sizeof (dmu_replay_record_t));
	dsp->dsa_drr->drr_type = DRR_OBJECT;
	drro->drr_object = object;
	drro->drr_type = dnp->dn_type;
	drro->drr_bonustype = dnp->dn_bonustype;
	drro->drr_blksz = dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	drro->drr_bonuslen = dnp->dn_bonuslen;
	drro->drr_checksumtype = dnp->dn_checksum;
	drro->drr_compress = dnp->dn_compress;
	drro->drr_toguid = dsp->dsa_toguid;

	if (dump_record(dsp, DN_BONUS(dnp),
	    P2ROUNDUP(dnp->dn_bonuslen, 8)) != 0) {
		return (SET_ERROR(EINTR));
	}

	/* Free anything past the end of the file. */
	if (dump_free(dsp, object, (dnp->dn_maxblkid + 1) *
	    (dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT), -1ULL) != 0)
		return (SET_ERROR(EINTR));
	if (dsp->dsa_err != 0)
		return (SET_ERROR(EINTR));
	return (0);
}

static boolean_t
backup_do_embed(dmu_sendarg_t *dsp, const blkptr_t *bp)
{
	if (!BP_IS_EMBEDDED(bp))
		return (B_FALSE);

	/*
	 * Compression function must be legacy, or explicitly enabled.
	 */
	if ((BP_GET_COMPRESS(bp) >= ZIO_COMPRESS_LEGACY_FUNCTIONS &&
	    !(dsp->dsa_featureflags & DMU_BACKUP_FEATURE_EMBED_DATA_LZ4)))
		return (B_FALSE);

	/*
	 * Embed type must be explicitly enabled.
	 */
	switch (BPE_GET_ETYPE(bp)) {
	case BP_EMBEDDED_TYPE_DATA:
		if (dsp->dsa_featureflags & DMU_BACKUP_FEATURE_EMBED_DATA)
			return (B_TRUE);
		break;
	case BP_EMBEDDED_TYPE_MOOCH_BYTESWAP:
		if (dsp->dsa_featureflags &
		    DMU_BACKUP_FEATURE_EMBED_MOOCH_BYTESWAP)
			return (B_TRUE);
		break;
	default:
		return (B_FALSE);
	}
	return (B_FALSE);
}


/*
 * Compare two zbookmark_phys_t's to see which we would reach first in a
 * pre-order traversal of the object tree.
 *
 * This is simple in every case aside from the meta-dnode object. For all other
 * objects, we traverse them in order (object 1 before object 2, and so on).
 * However, all of these objects are traversed while traversing object 0, since
 * the data it points to is the list of objects.  Thus, we need to convert to a
 * canonical representation so we can compare meta-dnode bookmarks to
 * non-meta-dnode bookmarks.
 *
 * We do this by calculating "equivalents" for each field of the zbookmark.
 * zbookmarks outside of the meta-dnode use their own object and level, and
 * calculate the level 0 equivalent (the first L0 blkid that is contained in the
 * blocks this bookmark refers to) by multiplying their blkid by their span
 * (the number of L0 blocks contained within one block at their level).
 * zbookmarks inside the meta-dnode calculate their object equivalent
 * (which is L0equiv * dnodes per data block), use 0 for their L0equiv, and use
 * level + 1<<31 (any value larger than a level could ever be) for their level.
 * This causes them to always compare before a bookmark in their object
 * equivalent, compare appropriately to bookmarks in other objects, and to
 * compare appropriately to other bookmarks in the meta-dnode.
 */
static int
zbookmark_compare(uint16_t dbss1, uint8_t ibs1, uint16_t dbss2, uint8_t ibs2,
    const zbookmark_phys_t *zb1, const zbookmark_phys_t *zb2)
{
	/*
	 * These variables represent the "equivalent" values for the zbookmark,
	 * after converting zbookmarks inside the meta dnode to their
	 * normal-object equivalents.
	 */
	uint64_t zb1obj, zb2obj;
	uint64_t zb1L0, zb2L0;
	uint64_t zb1level, zb2level;

	if (zb1->zb_object == zb2->zb_object &&
	    zb1->zb_level == zb2->zb_level &&
	    zb1->zb_blkid == zb2->zb_blkid)
		return (0);

	/*
	 * BP_SPANB calculates the span in blocks.
	 */
	zb1L0 = (zb1->zb_blkid) * BP_SPANB(ibs1, zb1->zb_level);
	zb2L0 = (zb2->zb_blkid) * BP_SPANB(ibs2, zb2->zb_level);

	if (zb1->zb_object == DMU_META_DNODE_OBJECT) {
		zb1obj = zb1L0 * (dbss1 << (SPA_MINBLOCKSHIFT - DNODE_SHIFT));
		zb1L0 = 0;
		zb1level = zb1->zb_level + COMPARE_META_LEVEL;
	} else {
		zb1obj = zb1->zb_object;
		zb1level = zb1->zb_level;
	}

	if (zb2->zb_object == DMU_META_DNODE_OBJECT) {
		zb2obj = zb2L0 * (dbss2 << (SPA_MINBLOCKSHIFT - DNODE_SHIFT));
		zb2L0 = 0;
		zb2level = zb2->zb_level + COMPARE_META_LEVEL;
	} else {
		zb2obj = zb2->zb_object;
		zb2level = zb2->zb_level;
	}

	/* Now that we have a canonical representation, do the comparison. */
	if (zb1obj != zb2obj)
		return (zb1obj < zb2obj ? -1 : 1);
	else if (zb1L0 != zb2L0)
		return (zb1L0 < zb2L0 ? -1 : 1);
	else if (zb1level != zb2level)
		return (zb1level > zb2level ? -1 : 1);
	/*
	 * This can (theoretically) happen if the bookmarks have the same object
	 * and level, but different blkids, if the block sizes are not the same.
	 * There is presently no way to change the indirect block sizes
	 */
	return (0);
}

/*
 * This thread finds any blocks in the given object between start and start +
 * len (or the end of the file, if len is 0), and creates artificial records for
 * them.  This will force the main thread to use the to_ds's version of the
 * data.  It does this via dmu_offset_next, which intelligently traverses the
 * tree using the blkfill field in the blkptrs.
 */
static int
enqueue_range_blocks(objset_t *os, uint64_t object, uint64_t start,
    uint64_t len, bqueue_t *bq) {
	uint64_t offset = start;
	int err = 0;
	dmu_object_info_t doi;
	err = dmu_object_info(os, object, &doi);
	if (err != 0)
		return (err);

	err = dmu_offset_next(os, object, B_FALSE, &offset);
	while ((len == 0 || offset < start + len) && err == 0) {
		struct send_block_record *record;
		record = kmem_zalloc(sizeof (*record), KM_SLEEP);
		record->eos_marker = B_FALSE;
		record->zb.zb_objset = os->os_dsl_dataset->ds_object;
		record->zb.zb_object = object;
		record->zb.zb_level = 0;
		record->zb.zb_blkid = offset / (doi.doi_data_block_size);
		record->indblkshift = highbit64(doi.doi_metadata_block_size)
		    - 1;
		record->datablkszsec = doi.doi_data_block_size >>
		    SPA_MINBLOCKSHIFT;

		dmu_prefetch(os, record->zb.zb_object, record->zb.zb_blkid,
		    record->datablkszsec << SPA_MINBLOCKSHIFT,
		    ZIO_PRIORITY_ASYNC_READ);
		bqueue_enqueue(bq, record, doi.doi_data_block_size);
		offset += doi.doi_data_block_size;
		err = dmu_offset_next(os, object, B_FALSE, &offset);
	}
	if (err == ESRCH)
		err = 0;
	return (err);
}

static int
enqueue_whole_object(objset_t *os, uint64_t object, bqueue_t *bq) {
	int err = enqueue_range_blocks(os, object, 0, 0, bq);
	if (err == ENOENT)
		err = 0;
	return (err);
}

/*
 * This function handles some of the special cases described in send_cb.  If a
 * hole is created in the meta-dnode, this thread calls hole_object on every
 * object that is allocated in the corresponding range in the to_ds.  It finds
 * these objects by using dmu_object_next, which uses the blkfill field of the
 * blkptrs to efficiently traverse the tree.
 *
 * If a hole is created inside an object, we calculate the range it covers, and
 * use equiv_find to fabricate records for any data blocks that might exist in
 * to_ds.
 *
 * Finally, if neither of the above happened, and this is a level 0 block, we
 * prefetch the data in the to_ds version of this block so that when the main
 * thread goes to dump a write record, it ideally won't have to block too long,
 * if at all.
 */
static int
enqueue_holes_prefetch(const zbookmark_phys_t *zb, const blkptr_t *bp, int err,
    uint8_t indblkshift, uint16_t datablkszsec, objset_t *to_os,
    struct send_thread_arg *sta)
{
	uint64_t span = BP_SPAN(datablkszsec, indblkshift, zb->zb_level);
	uint64_t blkid = zb->zb_blkid;
	if (zb->zb_object == DMU_META_DNODE_OBJECT && BP_IS_HOLE(bp)) {
		uint64_t start_object = 0;
		uint64_t end_object = 0;
		uint64_t curr;

		start_object = curr = span * blkid >> DNODE_SHIFT;
		end_object = start_object + (span >> DNODE_SHIFT);
		err = dmu_object_next(to_os, &curr, B_FALSE, 0);
		while (err == 0 && curr < end_object) {
			err = enqueue_whole_object(to_os, curr, &sta->q);
			if (err != 0)
				break;
			curr++;
			err = dmu_object_next(to_os, &curr, B_FALSE, 0);
		}
		if (err == ESRCH)
			err = 0;
	} else if (BP_IS_HOLE(bp) && zb->zb_level > 0) {
		err = enqueue_range_blocks(to_os, zb->zb_object, span * blkid,
		    span, &sta->q);
	} else if (zb->zb_level == 0 &&
	    zb->zb_object != DMU_META_DNODE_OBJECT) {
		dmu_prefetch(to_os, zb->zb_object, blkid * span, span,
		    ZIO_PRIORITY_ASYNC_READ);
	}

	return (err);
}

/*
 * This is the callback function to traverse_dataset that acts as the worker
 * thread for dmu_send_impl.  This thread manages some of the special cases that
 * come up so dmu_send_impl doesn't have to worry about them.  These special
 * cases only apply to the from_ds.
 *
 * The first case is if a hole is created in the meta-dnode.  This means that
 * some block of dnodes was unallocated in the from_ds.  We need to go through
 * each object in that range that is present in the to_ds and manually traverse
 * it, because the to_ds may not do so if those objects have not been modified
 * since the common ancestor.  This case is handled in enqueue_holes_prefetch.
 *
 * The second case is when one object is freed in the from_ds.  We need to
 * manually traverse the version of the object in the to_ds, because to_ds
 * thread won't necessarily do so.  We call hole_object to handle
 * this if we find an unallocated dnode that is allocated in the to_ds.
 *
 * The third case is if a hole is created inside an object.  Again, we need to
 * manually traverse that area.  This is also handled in enqueue_holes_prefetch.
 */
/*ARGSUSED*/
static int
send_cb(spa_t *spa, zilog_t *zilog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const struct dnode_phys *dnp, void *arg) {
	struct send_thread_arg *sta = arg;
	objset_t *to_os = sta->to_os;
	struct send_block_record *record;
	uint64_t record_size;
	int err = 0;

	if (sta->cancel)
		return (SET_ERROR(EINTR));

	if (bp == NULL) {
		if (dnp->dn_type == DMU_OT_NONE && to_os) {
			dmu_object_info_t doi;
			if (zb->zb_object == 0)
				return (err);
			err = dmu_object_info(to_os, zb->zb_object, &doi);
			if (err == ENOENT) {
				err = 0;
			} else {
				err = enqueue_whole_object(to_os, zb->zb_object,
				    &sta->q);
			}
		}
		return (err);
	} else if (zb->zb_level < 0) {
		return (0);
	}

	record = kmem_zalloc(sizeof (struct send_block_record), KM_SLEEP);
	record->eos_marker = B_FALSE;
	record->bp = *bp;
	record->zb = *zb;
	record->indblkshift = dnp->dn_indblkshift;
	record->datablkszsec = dnp->dn_datablkszsec;
	record_size = dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	bqueue_enqueue(&sta->q, record, record_size);

	/*
	 * If the data was modified in the from_ds, we will need to send the
	 * data in the to_os, so we prefetch it first.  However, we also need to
	 * handle another case: If there is a new hole in the from_ds that was
	 * not modified from the common ancestor in the to_ds, we have to
	 * iterate over the data in the to_ds to get the blocks to send so that
	 * we can recreate the to_ds.  This function, enqueue_holes_prefetch,
	 * handles both of those things.  We only call it when to_os is passed
	 * in because that is how we know we're the thread handling the from_ds.
	 */
	if (to_os != NULL) {
		err = enqueue_holes_prefetch(zb, bp, err, dnp->dn_indblkshift,
		    dnp->dn_datablkszsec, to_os, sta);
	}
	return (err);
}

/*
 * This function kicks off the traverse_dataset.  It also handles setting the
 * error code of the thread in case something goes wrong, and pushes the End of
 * Stream record when the traverse_dataset call has finished.  If there is no
 * dataset to traverse, the thread immediately pushes End of Stream marker.
 */
static void
send_traverse_thread(void *arg) {
	struct send_thread_arg *st_arg = arg;
	int err;
	struct send_block_record *data;

	if (st_arg->ds != NULL) {
		err = traverse_dataset(st_arg->ds, st_arg->fromtxg,
		    st_arg->flags, send_cb, arg);
		if (err != EINTR)
			st_arg->error_code = err;
	}
	data = kmem_zalloc(sizeof (*data), KM_SLEEP);
	data->eos_marker = B_TRUE;
	bqueue_enqueue(&st_arg->q, data, 1);
}

/*
 * This function actually handles figuring out what kind of record needs to be
 * dumped, reading the data (which has hopefully been prefetched), and calling
 * the appropriate helper function.
 */
static int
do_dump(dsl_dataset_t *ds, struct send_block_record *data, dmu_sendarg_t *dsp)
{
	const blkptr_t *bp = &data->bp;
	const zbookmark_phys_t *zb = &data->zb;
	uint8_t indblkshift = data->indblkshift;
	uint16_t dblkszsec = data->datablkszsec;
	spa_t *spa = ds->ds_dir->dd_pool->dp_spa;
	dmu_object_type_t type = bp ? BP_GET_TYPE(bp) : DMU_OT_NONE;

	int err = 0;

	ASSERT3U(zb->zb_level, >=, 0);

	if (zb->zb_object != DMU_META_DNODE_OBJECT &&
	    DMU_OBJECT_IS_SPECIAL(zb->zb_object)) {
		return (0);
	} else if (BP_IS_HOLE(bp) &&
	    zb->zb_object == DMU_META_DNODE_OBJECT) {
		uint64_t span = BP_SPAN(dblkszsec, indblkshift, zb->zb_level);
		uint64_t dnobj = (zb->zb_blkid * span) >> DNODE_SHIFT;
		err = dump_freeobjects(dsp, dnobj, span >> DNODE_SHIFT);
	} else if (BP_IS_HOLE(bp)) {
		uint64_t span = BP_SPAN(dblkszsec, indblkshift, zb->zb_level);
		err = dump_free(dsp, zb->zb_object, zb->zb_blkid * span, span);
	} else if (zb->zb_level > 0 || type == DMU_OT_OBJSET) {
		return (0);
	} else if (type == DMU_OT_DNODE) {
		dnode_phys_t *blk;
		int i;
		int blksz = BP_GET_LSIZE(bp);
		arc_flags_t aflags = ARC_FLAG_WAIT;
		arc_buf_t *abuf;

		if (arc_read(NULL, spa, bp, arc_getbuf_func, &abuf,
		    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_CANFAIL,
		    &aflags, zb) != 0)
			return (SET_ERROR(EIO));

		blk = abuf->b_data;
		for (i = 0; i < blksz >> DNODE_SHIFT; i++) {
			uint64_t dnobj = (zb->zb_blkid <<
			    (DNODE_BLOCK_SHIFT - DNODE_SHIFT)) + i;
			err = dump_dnode(dsp, dnobj, blk+i);
			if (err != 0)
				break;
		}
		(void) arc_buf_remove_ref(abuf, &abuf);
	} else if (type == DMU_OT_SA) {
		arc_flags_t aflags = ARC_FLAG_WAIT;
		arc_buf_t *abuf;
		int blksz = BP_GET_LSIZE(bp);

		if (arc_read(NULL, spa, bp, arc_getbuf_func, &abuf,
		    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_CANFAIL,
		    &aflags, zb) != 0)
			return (SET_ERROR(EIO));

		err = dump_spill(dsp, zb->zb_object, blksz, abuf->b_data);
		(void) arc_buf_remove_ref(abuf, &abuf);
	} else if (backup_do_embed(dsp, bp)) {
		/* it's an embedded level-0 block of a regular object */
		int blksz = dblkszsec << SPA_MINBLOCKSHIFT;
		err = dump_write_embedded(dsp, zb->zb_object,
		    zb->zb_blkid * blksz, blksz, bp);
	} else { /* it's a level-0 block of a regular object */
		arc_flags_t aflags = ARC_FLAG_WAIT;
		arc_buf_t *abuf;
		int blksz = dblkszsec << SPA_MINBLOCKSHIFT;

		ASSERT0(zb->zb_level);

		if (BP_IS_EMBEDDED(bp) &&
		    BPE_GET_ETYPE(bp) == BP_EMBEDDED_TYPE_MOOCH_BYTESWAP) {
			objset_t *origin_objset;
			dmu_buf_t *origin_db;
			uint64_t origin_obj;

			VERIFY0(dmu_objset_mooch_origin(dsp->dsa_os,
			    &origin_objset));
			VERIFY0(dmu_objset_mooch_obj_refd(dsp->dsa_os,
			    zb->zb_object, &origin_obj));
			err = dmu_buf_hold(origin_objset, origin_obj,
			    zb->zb_blkid * blksz, FTAG, &origin_db, 0);
			ASSERT3U(blksz, ==, origin_db->db_size);
			if (err == 0) {
				abuf = arc_buf_alloc(spa, origin_db->db_size,
				    &abuf, ARC_BUFC_DATA);
				mooch_byteswap_reconstruct(origin_db,
				    abuf->b_data, bp);
				dmu_buf_rele(origin_db, FTAG);
			}
		} else {
			ASSERT3U(blksz, ==, BP_GET_LSIZE(bp));
			err = arc_read(NULL, spa, bp, arc_getbuf_func, &abuf,
			    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_CANFAIL,
			    &aflags, zb);
		}
		if (err != 0) {
			if (zfs_send_corrupt_data) {
				/* Send a block filled with 0x"zfs badd bloc" */
				abuf = arc_buf_alloc(spa, blksz, &abuf,
				    ARC_BUFC_DATA);
				uint64_t *ptr;
				for (ptr = abuf->b_data;
				    (char *)ptr < (char *)abuf->b_data + blksz;
				    ptr++)
					*ptr = 0x2f5baddb10c;
			} else {
				return (SET_ERROR(EIO));
			}
		}

		err = dump_write(dsp, type, zb->zb_object, zb->zb_blkid * blksz,
		    blksz, bp, abuf->b_data);
		(void) arc_buf_remove_ref(abuf, &abuf);
	}

	ASSERT(err == 0 || err == EINTR);
	return (err);
}

/*
 * Utility function that causes End of Stream records to compare ahead of all
 * others, so that the main thread's logic can stay simple.
 */
static int
send_record_compare(struct send_block_record *from,
    struct send_block_record *to)
{
	if (from->eos_marker == B_TRUE)
		return (1);
	else if (to->eos_marker == B_TRUE)
		return (-1);
	return (zbookmark_compare(from->datablkszsec,
	    from->indblkshift, to->datablkszsec,
	    to->indblkshift, &from->zb, &to->zb));
}

/*
 * Pop the new data off the queue, check that the records we receive are in
 * the right order, and free the old data.
 */
static struct send_block_record *
get_next_record(bqueue_t *bq, struct send_block_record *data) {
	struct send_block_record *tmp = bqueue_dequeue(bq);
	ASSERT3S(send_record_compare(data, tmp), ==, -1);
	kmem_free(data, sizeof (*data));
	return (tmp);
}

/*
 * We pull the data out of the embedded bp, whether it's compressed or not;
 * either way, byte-by-byte equality will test for data equality, since there's
 * only one compression algorithm for embedded block pointers.
 */
static int
embedded_bp_eq(blkptr_t *from_bp, blkptr_t *to_bp)
{
	if (BP_GET_LSIZE(from_bp) == BP_GET_LSIZE(to_bp)) {
		uint64_t from_buf[BPE_PAYLOAD_SIZE];
		uint64_t to_buf[BPE_PAYLOAD_SIZE];
		bzero(from_buf, sizeof (from_buf));
		bzero(to_buf, sizeof (to_buf));
		decode_embedded_bp_compressed(to_bp, to_buf);
		decode_embedded_bp_compressed(from_bp, from_buf);
		return (bcmp(to_buf, from_buf, sizeof (from_buf)) == 0);
	}
	return (0);
}

/*
 * Actually do the bulk of the work in a zfs send.
 *
 * The idea is that we want to do a send from from_ds to to_ds, and their common
 * ancestor's information is in ancestor_zb.  We do this by creating two worker
 * threads; each one will do dataset_traverse on one of the two datasets.  As
 * they encounter changes made by their dataset since the common ancestor, they
 * will push them onto a blocking queue.  Since traverse_dataset has a canonical
 * order, we can compare each change as they're pulled off the queues.
 *
 * If this is not a rebase send, the from_ds will be null.  We just send
 * everything that was changed in the to_ds since the ancestor's creation txg.
 *
 * If this is a rebase send, we need to send all the differences between from_ds
 * and to_ds.  Anything that hasn't been modified since the common ancestor
 * can't be different between them.  Thus, we send:
 *
 * 1) Everything that's changed in to_ds since the common ancestor (just like in
 * the non-rebase case).
 * 2) Everything that's changed in from_ds since the common ancestor, but we
 * send the the data in to_ds.  For example, from_ds changed object 6 block
 * 10, so we send a record for object 6 block 10, but the data is the data from
 * to_ds.
 * 3) As an exception to the above, if the data has the same checksum (and the
 * checksums are cryptographically secure), then we don't need to send it.
 *
 * To keep performance acceptable, we want to prefetch the data in the worker
 * threads.  The to_ds thread can simply use the PREFETCH_DATA feature built
 * into traverse_dataset, but the from_ds thread needs to manually prefetch data
 * in the to_ds.  In addition, to prevent the prefetchers getting too far ahead
 * of the main thread, the blocking queues are capped not by the number of
 * entries in the queue, but by the sum of the size of the prefetches associated
 * with them.  The limit on the amount of data that the threads can prefetch
 * beyond what the main thread has reached is controlled by the global variable
 * zfs_send_queue_length.
 *
 * Note: Releases dp using the specified tag.
 */
static int
dmu_send_impl(void *tag, dsl_pool_t *dp, dsl_dataset_t *to_ds,
    dsl_dataset_t *from_ds, zfs_bookmark_phys_t *ancestor_zb,
    boolean_t is_clone, boolean_t embedok, int outfd, vnode_t *vp,
    offset_t *off)
{
	objset_t *os;
	dmu_replay_record_t *drr;
	dmu_sendarg_t *dsp;
	int err;
	uint64_t fromtxg = 0;
	uint64_t featureflags = 0;
	struct send_thread_arg from_arg, to_arg;

	err = dmu_objset_from_ds(to_ds, &os);
	if (err != 0) {
		dsl_pool_rele(dp, tag);
		return (err);
	}

	drr = kmem_zalloc(sizeof (dmu_replay_record_t), KM_SLEEP);
	drr->drr_type = DRR_BEGIN;
	drr->drr_u.drr_begin.drr_magic = DMU_BACKUP_MAGIC;
	DMU_SET_STREAM_HDRTYPE(drr->drr_u.drr_begin.drr_versioninfo,
	    DMU_SUBSTREAM);

#ifdef _KERNEL
	if (dmu_objset_type(os) == DMU_OST_ZFS) {
		uint64_t version;
		if (zfs_get_zplprop(os, ZFS_PROP_VERSION, &version) != 0) {
			kmem_free(drr, sizeof (dmu_replay_record_t));
			dsl_pool_rele(dp, tag);
			return (SET_ERROR(EINVAL));
		}
		if (version >= ZPL_VERSION_SA) {
			featureflags |= DMU_BACKUP_FEATURE_SA_SPILL;
		}
	}
#endif

	if (embedok &&
	    spa_feature_is_active(dp->dp_spa, SPA_FEATURE_EMBEDDED_DATA)) {
		featureflags |= DMU_BACKUP_FEATURE_EMBED_DATA;
		if (spa_feature_is_active(dp->dp_spa, SPA_FEATURE_LZ4_COMPRESS))
			featureflags |= DMU_BACKUP_FEATURE_EMBED_DATA_LZ4;
	}

	/*
	 * Note: If we are sending a full stream (non-incremental), then
	 * we can not send mooch records, because the receiver won't have
	 * the origin to mooch from.
	 */
	if (embedok && to_ds->ds_mooch_byteswap && ancestor_zb != NULL) {
		featureflags |= DMU_BACKUP_FEATURE_EMBED_MOOCH_BYTESWAP;
	}

	DMU_SET_FEATUREFLAGS(drr->drr_u.drr_begin.drr_versioninfo,
	    featureflags);

	drr->drr_u.drr_begin.drr_creation_time =
	    to_ds->ds_phys->ds_creation_time;
	drr->drr_u.drr_begin.drr_type = dmu_objset_type(os);
	if (is_clone)
		drr->drr_u.drr_begin.drr_flags |= DRR_FLAG_CLONE;
	drr->drr_u.drr_begin.drr_toguid = to_ds->ds_phys->ds_guid;
	if (to_ds->ds_phys->ds_flags & DS_FLAG_CI_DATASET)
		drr->drr_u.drr_begin.drr_flags |= DRR_FLAG_CI_DATA;

	if (ancestor_zb != NULL) {
		/*
		 * We're doing an incremental send; if from_ds is non-null, then
		 * this is a rebase send, and we have to specify the guid of the
		 * snapshot we're rebasing from.  If it is null, then this is a
		 * normal incremental send, and we should specify the guid of
		 * the ancestor_zb.
		 */
		if (from_ds != NULL) {
			drr->drr_u.drr_begin.drr_fromguid =
			    from_ds->ds_phys->ds_guid;
		} else {
			drr->drr_u.drr_begin.drr_fromguid =
			    ancestor_zb->zbm_guid;
		}
		fromtxg = ancestor_zb->zbm_creation_txg;
	}
	dsl_dataset_name(to_ds, drr->drr_u.drr_begin.drr_toname);
	if (!dsl_dataset_is_snapshot(to_ds)) {
		(void) strlcat(drr->drr_u.drr_begin.drr_toname, "@--head--",
		    sizeof (drr->drr_u.drr_begin.drr_toname));
	}

	dsp = kmem_zalloc(sizeof (dmu_sendarg_t), KM_SLEEP);

	dsp->dsa_drr = drr;
	dsp->dsa_vp = vp;
	dsp->dsa_outfd = outfd;
	dsp->dsa_proc = curproc;
	dsp->dsa_os = os;
	dsp->dsa_off = off;
	dsp->dsa_toguid = to_ds->ds_phys->ds_guid;
	dsp->dsa_pending_op = PENDING_NONE;
	dsp->dsa_incremental = (ancestor_zb != NULL);
	dsp->dsa_featureflags = featureflags;

	mutex_enter(&to_ds->ds_sendstream_lock);
	list_insert_head(&to_ds->ds_sendstreams, dsp);
	mutex_exit(&to_ds->ds_sendstream_lock);

	dsl_dataset_long_hold(to_ds, FTAG);
	dsl_pool_rele(dp, tag);

	if (dump_record(dsp, NULL, 0) != 0) {
		err = dsp->dsa_err;
		goto out;
	}

	err = bqueue_init(&to_arg.q, zfs_send_queue_length,
	    offsetof(struct send_block_record, ln));
	to_arg.error_code = 0;
	to_arg.cancel = B_FALSE;
	to_arg.ds = to_ds;
	to_arg.fromtxg = fromtxg;
	to_arg.flags = TRAVERSE_PRE | TRAVERSE_PREFETCH;
	to_arg.to_os = NULL;
	(void) thread_create(NULL, 0, send_traverse_thread, &to_arg, 0, curproc,
	    TS_RUN, minclsyspri);

	err = bqueue_init(&from_arg.q, zfs_send_queue_length,
	    offsetof(struct send_block_record, ln));

	from_arg.error_code = 0;
	from_arg.cancel = B_FALSE;
	from_arg.ds = from_ds;
	from_arg.fromtxg = fromtxg;
	from_arg.flags = TRAVERSE_PRE | TRAVERSE_PREFETCH_METADATA;
	from_arg.to_os = os;

	/*
	 * If from_ds is null, send_traverse_thread just returns success and
	 * enqueues an eos marker.
	 */
	(void) thread_create(NULL, 0, send_traverse_thread, &from_arg, 0,
	    curproc, TS_RUN, minclsyspri);

	struct send_block_record *from_data, *to_data;
	from_data = bqueue_dequeue(&from_arg.q);
	to_data = bqueue_dequeue(&to_arg.q);

	while (!(from_data->eos_marker == B_TRUE &&
	    to_data->eos_marker == B_TRUE) && err == 0) {
		int cmp = send_record_compare(from_data, to_data);
		/*
		 * Bookmarks are the same: send data unless it's identical.
		 */
		if (cmp == 0) {
			boolean_t strong = zio_checksum_table
			    [BP_GET_CHECKSUM(&to_data->bp)].ci_dedup;
			if (BP_IS_EMBEDDED(&to_data->bp) &&
			    BP_IS_EMBEDDED(&from_data->bp)) {
				if (!embedded_bp_eq(&from_data->bp,
				    &to_data->bp))
					err = do_dump(to_ds, to_data, dsp);
			} else if (!(strong && BP_GET_CHECKSUM(&to_data->bp) ==
			    BP_GET_CHECKSUM(&from_data->bp) &&
			    ZIO_CHECKSUM_EQUAL(to_data->bp.blk_cksum,
			    from_data->bp.blk_cksum))) {
				err = do_dump(to_ds, to_data, dsp);
			}
			from_data = get_next_record(&from_arg.q, from_data);
			to_data = get_next_record(&to_arg.q, to_data);
		/*
		 * From bookmark is ahead, get and send to's version of the data
		 */
		} else if (cmp < 0) {
			blkptr_t bp;
			const zbookmark_phys_t *zb = &from_data->zb;

			err = dbuf_bookmark_findbp(os, zb->zb_object,
			    zb->zb_level, zb->zb_blkid, &bp,
			    &from_data->datablkszsec,
			    &from_data->indblkshift);
			if (err == ENOENT) {
				/*
				 * The block was modified in the from dataset,
				 * but doesn't exist in the to dataset; if it
				 * was deleted in the to dataset, then we'll
				 * visit the hole bp for it at some point.
				 */
				err = 0;
			} else if (err == 0) {
				from_data->zb.zb_objset = to_ds->ds_object;
				from_data->bp = bp;
				err = do_dump(to_ds, from_data, dsp);
			}
			from_data = get_next_record(&from_arg.q, from_data);
		/*
		 * To bookmark is ahead, send the data.
		 */
		} else {
			err = do_dump(to_ds, to_data, dsp);
			to_data = get_next_record(&to_arg.q, to_data);
		}
		if (issig(JUSTLOOKING) && issig(FORREAL))
	                err = EINTR;
	}

	if (err != 0) {
		to_arg.cancel = B_TRUE;
		while (!to_data->eos_marker) {
			to_data = get_next_record(&to_arg.q, to_data);
		}
		from_arg.cancel = B_TRUE;
		while (!from_data->eos_marker) {
			from_data = get_next_record(&from_arg.q, from_data);
		}
	}
	kmem_free(from_data, sizeof (*from_data));
	kmem_free(to_data, sizeof (*to_data));

	bqueue_destroy(&to_arg.q);
	bqueue_destroy(&from_arg.q);

	if (err == 0 && from_arg.error_code != 0)
		err = from_arg.error_code;
	if (err == 0 && to_arg.error_code != 0)
		err = to_arg.error_code;

	if (err != 0)
		goto out;

	if (dsp->dsa_pending_op != PENDING_NONE)
		if (dump_record(dsp, NULL, 0) != 0)
			err = SET_ERROR(EINTR);

	if (err != 0) {
		if (err == EINTR && dsp->dsa_err != 0)
			err = dsp->dsa_err;
		goto out;
	}

	bzero(drr, sizeof (dmu_replay_record_t));
	drr->drr_type = DRR_END;
	drr->drr_u.drr_end.drr_checksum = dsp->dsa_zc;
	drr->drr_u.drr_end.drr_toguid = dsp->dsa_toguid;

	if (dump_record(dsp, NULL, 0) != 0)
		err = dsp->dsa_err;

out:
	mutex_enter(&to_ds->ds_sendstream_lock);
	list_remove(&to_ds->ds_sendstreams, dsp);
	mutex_exit(&to_ds->ds_sendstream_lock);

	kmem_free(drr, sizeof (dmu_replay_record_t));
	kmem_free(dsp, sizeof (dmu_sendarg_t));

	dsl_dataset_long_rele(to_ds, FTAG);

	return (err);
}

static int
dsl_dataset_walk_origin(dsl_pool_t *dp, dsl_dataset_t **ds, void *tag) {
	uint64_t origin_obj = (*ds)->ds_dir->dd_phys->dd_origin_obj;
	dsl_dataset_t *prev;
	int err = dsl_dataset_hold_obj(dp, origin_obj, tag, &prev);
	if (err != 0)
		return (err);
	dsl_dataset_rele(*ds, tag);
	*ds = prev;
	prev = NULL;
	return (err);
}

/*
 * Find the common ancestor of two datasets.
 *
 * We first measure how far each dataset is from the ORIGIN$ORIGIN by stepping
 * back through each object's origin snapshot.  We then walk the one that is
 * further up it's origin snapshots until each dataset is the same distance from
 * ORIGIN$ORIGIN.  Now, at each step we compare to see whether the two datasets
 * are in the same ds_dir.  Once they are, we compare the two snapshots; the
 * older of the two is the common ancestor of the two datasets.
 */
static int
find_common_ancestor(dsl_pool_t *dp, dsl_dataset_t *ds1, dsl_dataset_t *ds2,
    zfs_bookmark_phys_t *zb)
{
	uint32_t steps1, steps2, diff;
	dsl_dataset_t *walker1, *walker2;
	int err = 0;

	if (ds1->ds_dir == ds2->ds_dir) {
		err = dsl_dataset_hold_obj(dp, ds1->ds_object, FTAG, &walker1);
		if (err != 0)
			return (err);
		err = dsl_dataset_hold_obj(dp, ds2->ds_object, FTAG, &walker2);
		if (err != 0) {
			dsl_dataset_rele(walker1, FTAG);
			return (err);
		}
		goto fini;
	}

	/*
	 * Count how far ds1 is from $ORIGIN.
	 */
	err = dsl_dataset_hold_obj(dp, ds1->ds_object, FTAG, &walker1);
	if (err != 0)
		return (err);

	steps1 = 0;
	while (dsl_dataset_is_clone(walker1, dp->dp_origin_snap)) {
		err = dsl_dataset_walk_origin(dp, &walker1, FTAG);
		if (err != 0) {
			dsl_dataset_rele(walker1, FTAG);
			return (err);
		}
		steps1++;
	}
	dsl_dataset_rele(walker1, FTAG);

	/*
	 * Count how far ds2 is from $ORIGIN
	 */
	err = dsl_dataset_hold_obj(dp, ds2->ds_object, FTAG, &walker1);
	if (err != 0)
		return (err);

	steps2 = 0;
	while (dsl_dataset_is_clone(walker1, dp->dp_origin_snap)) {
		err = dsl_dataset_walk_origin(dp, &walker1, FTAG);
		if (err != 0) {
			dsl_dataset_rele(walker1, FTAG);
			return (err);
		}
		steps2++;
	}
	dsl_dataset_rele(walker1, FTAG);

	/*
	 * Calculate which ds is farther from $ORIGIN, assign that to walker1,
	 * and assign the other to walker2.  Assign the difference in distances
	 * to diff.
	 */
	if (steps1 > steps2) {
		diff = steps1 - steps2;
		err = dsl_dataset_hold_obj(dp, ds1->ds_object, FTAG, &walker1);
		if (err != 0)
			return (err);
		err = dsl_dataset_hold_obj(dp, ds2->ds_object, FTAG, &walker2);
		if (err != 0) {
			dsl_dataset_rele(walker1, FTAG);
			return (err);
		}
	} else {
		diff = steps2 - steps1;
		err = dsl_dataset_hold_obj(dp, ds2->ds_object, FTAG, &walker1);
		if (err != 0)
			return (err);
		err = dsl_dataset_hold_obj(dp, ds1->ds_object, FTAG, &walker2);
		if (err != 0) {
			dsl_dataset_rele(walker1, FTAG);
			return (err);
		}
	}

	/*
	 * Walk walker1 back diff steps so both systems are the same distance
	 * from $ORIGIN.
	 */
	for (int i = 0; i < diff; i++) {
		err = dsl_dataset_walk_origin(dp, &walker1, FTAG);
		if (err != 0) {
			dsl_dataset_rele(walker1, FTAG);
			dsl_dataset_rele(walker2, FTAG);
			return (err);
		}
	}

	/*
	 * Walk back in step, and stop when the two walkers are snapshots in the
	 * same dataset dir.
	 */
	while ((walker1->ds_dir != walker2->ds_dir) &&
	    !(walker1->ds_dir->dd_phys->dd_origin_obj == 0 &&
	    walker2->ds_dir->dd_phys->dd_origin_obj == 0)) {
		err = dsl_dataset_walk_origin(dp, &walker1, FTAG);
		if (err != 0) {
			dsl_dataset_rele(walker1, FTAG);
			dsl_dataset_rele(walker2, FTAG);
			return (err);
		}


		err = dsl_dataset_walk_origin(dp, &walker2, FTAG);
		if (err != 0) {
			dsl_dataset_rele(walker1, FTAG);
			dsl_dataset_rele(walker2, FTAG);
			return (err);
		}
	}

fini:
	/*
	 * Load the zb with the data from the older snapshot.
	 */
	if (walker1->ds_dir != walker2->ds_dir) {
		zb->zbm_creation_txg = 0;
		zb->zbm_creation_time = 0;
		zb->zbm_guid = 0;
	} else if (walker1->ds_phys->ds_creation_txg >
	    walker2->ds_phys->ds_creation_txg) {
		zb->zbm_creation_txg = walker2->ds_phys->ds_creation_txg;
		zb->zbm_creation_time = walker2->ds_phys->ds_creation_time;
		zb->zbm_guid = walker2->ds_phys->ds_guid;
	} else {
		zb->zbm_creation_txg = walker1->ds_phys->ds_creation_txg;
		zb->zbm_creation_time = walker1->ds_phys->ds_creation_time;
		zb->zbm_guid = walker1->ds_phys->ds_guid;
	}
	dsl_dataset_rele(walker1, FTAG);
	dsl_dataset_rele(walker2, FTAG);
	return (err);
}

int
dmu_send_obj(const char *pool, uint64_t tosnap, uint64_t fromsnap,
    boolean_t embedok, int outfd, vnode_t *vp, offset_t *off)
{
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	dsl_dataset_t *fromds = NULL;
	int err;

	err = dsl_pool_hold(pool, FTAG, &dp);
	if (err != 0)
		return (err);

	err = dsl_dataset_hold_obj(dp, tosnap, FTAG, &ds);
	if (err != 0) {
		dsl_pool_rele(dp, FTAG);
		return (err);
	}

	if (fromsnap != 0) {
		zfs_bookmark_phys_t zb;
		boolean_t is_clone;

		err = dsl_dataset_hold_obj(dp, fromsnap, FTAG, &fromds);
		if (err != 0) {
			dsl_dataset_rele(ds, FTAG);
			dsl_pool_rele(dp, FTAG);
			return (err);
		}

		err = find_common_ancestor(dp, fromds, ds, &zb);
		if (err != 0) {
			dsl_dataset_rele(ds, FTAG);
			dsl_dataset_rele(fromds, FTAG);
			dsl_pool_rele(dp, FTAG);
			return (err);
		}

		if (dsl_dataset_is_before(ds, fromds, 0)) {
			is_clone = (ds->ds_dir != fromds->ds_dir);
			dsl_dataset_rele(fromds, FTAG);
			fromds = NULL;
		} else {
			is_clone = B_FALSE;
		}

		err = dmu_send_impl(FTAG, dp, ds, fromds, &zb, is_clone,
		    embedok, outfd, vp, off);

		if (fromds != NULL)
			dsl_dataset_rele(fromds, FTAG);
	} else {
		err = dmu_send_impl(FTAG, dp, ds, NULL, NULL, B_FALSE, embedok,
		    outfd, vp, off);
	}
	dsl_dataset_rele(ds, FTAG);
	return (err);
}

int
dmu_send(const char *tosnap, const char *fromsnap, boolean_t embedok,
    int outfd, vnode_t *vp, offset_t *off)
{
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	int err;
	boolean_t owned = B_FALSE;

	if (fromsnap != NULL && strpbrk(fromsnap, "@#") == NULL)
		return (SET_ERROR(EINVAL));

	err = dsl_pool_hold(tosnap, FTAG, &dp);
	if (err != 0)
		return (err);

	if (strchr(tosnap, '@') == NULL && spa_writeable(dp->dp_spa)) {
		/*
		 * We are sending a filesystem or volume.  Ensure
		 * that it doesn't change by owning the dataset.
		 */
		err = dsl_dataset_own(dp, tosnap, FTAG, &ds);
		owned = B_TRUE;
	} else {
		err = dsl_dataset_hold(dp, tosnap, FTAG, &ds);
	}
	if (err != 0) {
		dsl_pool_rele(dp, FTAG);
		return (err);
	}

	if (fromsnap != NULL) {
		zfs_bookmark_phys_t zb;
		dsl_dataset_t *fromds = NULL;
		boolean_t is_clone = B_FALSE;
		int fsnamelen = strchr(tosnap, '@') - tosnap;

		/*
		 * If the fromsnap is in a different filesystem, then
		 * mark the send stream as a clone.
		 */
		if (strncmp(tosnap, fromsnap, fsnamelen) != 0 ||
		    (fromsnap[fsnamelen] != '@' &&
		    fromsnap[fsnamelen] != '#')) {
			is_clone = B_TRUE;
		}

		if (strchr(fromsnap, '@')) {
			err = dsl_dataset_hold(dp, fromsnap, FTAG, &fromds);
			if (err != 0)
				goto out;

			err = find_common_ancestor(dp, fromds, ds, &zb);
			if (err != 0)
				goto out;

			if (dsl_dataset_is_before(ds, fromds, 0)) {
				is_clone = (ds->ds_dir != fromds->ds_dir);
				dsl_dataset_rele(fromds, FTAG);
				fromds = NULL;
			} else {
				is_clone = B_FALSE;
			}
		} else {
			err = dsl_bookmark_lookup(dp, fromsnap, ds, &zb);
			if (err != 0)
				goto out;
		}
		err = dmu_send_impl(FTAG, dp, ds, fromds, &zb, is_clone,
		    embedok, outfd, vp, off);
out:
		if (fromds != NULL)
			dsl_dataset_rele(fromds, FTAG);
	} else {
		err = dmu_send_impl(FTAG, dp, ds, NULL, NULL, B_FALSE, embedok,
		    outfd, vp, off);
	}
	if (owned)
		dsl_dataset_disown(ds, FTAG);
	else
		dsl_dataset_rele(ds, FTAG);
	return (err);
}

int
dmu_send_estimate(dsl_dataset_t *ds, dsl_dataset_t *fromds, uint64_t *sizep)
{
	dsl_pool_t *dp = ds->ds_dir->dd_pool;
	int err;
	uint64_t size;

	ASSERT(dsl_pool_config_held(dp));

	/* tosnap must be a snapshot */
	if (!dsl_dataset_is_snapshot(ds))
		return (SET_ERROR(EINVAL));

	/*
	 * fromsnap must be an earlier snapshot from the same fs as tosnap,
	 * or the origin's fs.
	 */
	if (fromds != NULL && !dsl_dataset_is_before(ds, fromds, 0))
		return (SET_ERROR(EXDEV));

	/* Get uncompressed size estimate of changed data. */
	if (fromds == NULL) {
		size = ds->ds_phys->ds_uncompressed_bytes;
	} else {
		uint64_t used, comp;
		err = dsl_dataset_space_written(fromds, ds,
		    &used, &comp, &size);
		if (err != 0)
			return (err);
	}

	/*
	 * Assume that space (both on-disk and in-stream) is dominated by
	 * data.  We will adjust for indirect blocks and the copies property,
	 * but ignore per-object space used (eg, dnodes and DRR_OBJECT records).
	 */

	/*
	 * Subtract out approximate space used by indirect blocks.
	 * Assume most space is used by data blocks (non-indirect, non-dnode).
	 * Assume all blocks are recordsize.  Assume ditto blocks and
	 * internal fragmentation counter out compression.
	 *
	 * Therefore, space used by indirect blocks is sizeof(blkptr_t) per
	 * block, which we observe in practice.
	 */
	uint64_t recordsize;
	err = dsl_prop_get_int_ds(ds, "recordsize", &recordsize);
	if (err != 0)
		return (err);
	size -= size / recordsize * sizeof (blkptr_t);

	/* Add in the space for the record associated with each block. */
	size += size / recordsize * sizeof (dmu_replay_record_t);

	*sizep = size;

	return (0);
}

typedef struct dmu_recv_begin_arg {
	const char *drba_origin;
	dmu_recv_cookie_t *drba_cookie;
	cred_t *drba_cred;
	uint64_t drba_snapobj;
} dmu_recv_begin_arg_t;

static int
recv_begin_check_existing_impl(dmu_recv_begin_arg_t *drba, dsl_dataset_t *ds,
    uint64_t fromguid)
{
	uint64_t val;
	int error;
	dsl_pool_t *dp = ds->ds_dir->dd_pool;

	/* temporary clone name must not exist */
	error = zap_lookup(dp->dp_meta_objset,
	    ds->ds_dir->dd_phys->dd_child_dir_zapobj, recv_clone_name,
	    8, 1, &val);
	if (error != ENOENT)
		return (error == 0 ? EBUSY : error);

	/* new snapshot name must not exist */
	error = zap_lookup(dp->dp_meta_objset,
	    ds->ds_phys->ds_snapnames_zapobj, drba->drba_cookie->drc_tosnap,
	    8, 1, &val);
	if (error != ENOENT)
		return (error == 0 ? EEXIST : error);

	/*
	 * Check snapshot limit before receiving. We'll recheck again at the
	 * end, but might as well abort before receiving if we're already over
	 * the limit.
	 *
	 * Note that we do not check the file system limit with
	 * dsl_dir_fscount_check because the temporary %clones don't count
	 * against that limit.
	 */
	error = dsl_fs_ss_limit_check(ds->ds_dir, 1, ZFS_PROP_SNAPSHOT_LIMIT,
	    NULL, drba->drba_cred);
	if (error != 0)
		return (error);

	if (fromguid != 0) {
		dsl_dataset_t *snap;
		uint64_t obj = ds->ds_phys->ds_prev_snap_obj;

		/* Find snapshot in this dir that matches fromguid. */
		while (obj != 0) {
			error = dsl_dataset_hold_obj(dp, obj, FTAG,
			    &snap);
			if (error != 0)
				return (SET_ERROR(ENODEV));
			if (snap->ds_dir != ds->ds_dir) {
				dsl_dataset_rele(snap, FTAG);
				return (SET_ERROR(ENODEV));
			}
			if (snap->ds_phys->ds_guid == fromguid)
				break;
			obj = snap->ds_phys->ds_prev_snap_obj;
			dsl_dataset_rele(snap, FTAG);
		}
		if (obj == 0)
			return (SET_ERROR(ENODEV));

		if (drba->drba_cookie->drc_force) {
			drba->drba_snapobj = obj;
		} else {
			/*
			 * If we are not forcing, there must be no
			 * changes since fromsnap.
			 */
			if (dsl_dataset_modified_since_snap(ds, snap)) {
				dsl_dataset_rele(snap, FTAG);
				return (SET_ERROR(ETXTBSY));
			}
			drba->drba_snapobj = ds->ds_prev->ds_object;
		}

		dsl_dataset_rele(snap, FTAG);
	} else {
		/* if full, most recent snapshot must be $ORIGIN */
		if (ds->ds_phys->ds_prev_snap_txg >= TXG_INITIAL)
			return (SET_ERROR(ENODEV));
		drba->drba_snapobj = ds->ds_phys->ds_prev_snap_obj;
	}

	return (0);

}

static int
dmu_recv_begin_check(void *arg, dmu_tx_t *tx)
{
	dmu_recv_begin_arg_t *drba = arg;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	struct drr_begin *drrb = drba->drba_cookie->drc_drrb;
	uint64_t fromguid = drrb->drr_fromguid;
	int flags = drrb->drr_flags;
	int error;
	uint64_t featureflags = DMU_GET_FEATUREFLAGS(drrb->drr_versioninfo);
	dsl_dataset_t *ds;
	const char *tofs = drba->drba_cookie->drc_tofs;

	/* already checked */
	ASSERT3U(drrb->drr_magic, ==, DMU_BACKUP_MAGIC);

	if (DMU_GET_STREAM_HDRTYPE(drrb->drr_versioninfo) ==
	    DMU_COMPOUNDSTREAM ||
	    drrb->drr_type >= DMU_OST_NUMTYPES ||
	    ((flags & DRR_FLAG_CLONE) && drba->drba_origin == NULL))
		return (SET_ERROR(EINVAL));

	/* Verify pool version supports SA if SA_SPILL feature set */
	if ((featureflags & DMU_BACKUP_FEATURE_SA_SPILL) &&
	    spa_version(dp->dp_spa) < SPA_VERSION_SA)
		return (SET_ERROR(ENOTSUP));

	/*
	 * The receiving code doesn't know how to translate a WRITE_EMBEDDED
	 * record to a plan WRITE record, so the pool must have the
	 * EMBEDDED_DATA feature enabled if the stream has WRITE_EMBEDDED
	 * records.  Same with WRITE_EMBEDDED records that use LZ4 compression.
	 */
	if ((featureflags & DMU_BACKUP_FEATURE_EMBED_DATA) &&
	    !spa_feature_is_enabled(dp->dp_spa, SPA_FEATURE_EMBEDDED_DATA))
		return (SET_ERROR(ENOTSUP));
	if ((featureflags & DMU_BACKUP_FEATURE_EMBED_DATA_LZ4) &&
	    !spa_feature_is_enabled(dp->dp_spa, SPA_FEATURE_LZ4_COMPRESS))
		return (SET_ERROR(ENOTSUP));

	error = dsl_dataset_hold(dp, tofs, FTAG, &ds);
	if (error == 0) {
		/* target fs already exists; recv into temp clone */

		/* Can't recv a clone into an existing fs */
		if (flags & DRR_FLAG_CLONE) {
			dsl_dataset_rele(ds, FTAG);
			return (SET_ERROR(EINVAL));
		}

		error = recv_begin_check_existing_impl(drba, ds, fromguid);
		dsl_dataset_rele(ds, FTAG);
	} else if (error == ENOENT) {
		/* target fs does not exist; must be a full backup or clone */
		char buf[MAXNAMELEN];

		/*
		 * If it's a non-clone incremental, we are missing the
		 * target fs, so fail the recv.
		 */
		if (fromguid != 0 && !(flags & DRR_FLAG_CLONE ||
		    drba->drba_origin))
			return (SET_ERROR(ENOENT));

		/* Open the parent of tofs */
		ASSERT3U(strlen(tofs), <, MAXNAMELEN);
		(void) strlcpy(buf, tofs, strrchr(tofs, '/') - tofs + 1);
		error = dsl_dataset_hold(dp, buf, FTAG, &ds);
		if (error != 0)
			return (error);

		/*
		 * Check filesystem and snapshot limits before receiving. We'll
		 * recheck snapshot limits again at the end (we create the
		 * filesystems and increment those counts during begin_sync).
		 */
		error = dsl_fs_ss_limit_check(ds->ds_dir, 1,
		    ZFS_PROP_FILESYSTEM_LIMIT, NULL, drba->drba_cred);
		if (error != 0) {
			dsl_dataset_rele(ds, FTAG);
			return (error);
		}

		error = dsl_fs_ss_limit_check(ds->ds_dir, 1,
		    ZFS_PROP_SNAPSHOT_LIMIT, NULL, drba->drba_cred);
		if (error != 0) {
			dsl_dataset_rele(ds, FTAG);
			return (error);
		}

		if (drba->drba_origin != NULL) {
			dsl_dataset_t *origin;
			error = dsl_dataset_hold(dp, drba->drba_origin,
			    FTAG, &origin);
			if (error != 0) {
				dsl_dataset_rele(ds, FTAG);
				return (error);
			}
			if (!dsl_dataset_is_snapshot(origin)) {
				dsl_dataset_rele(origin, FTAG);
				dsl_dataset_rele(ds, FTAG);
				return (SET_ERROR(EINVAL));
			}
			if (origin->ds_phys->ds_guid != fromguid) {
				dsl_dataset_rele(origin, FTAG);
				dsl_dataset_rele(ds, FTAG);
				return (SET_ERROR(ENODEV));
			}
			dsl_dataset_rele(origin, FTAG);
		}
		dsl_dataset_rele(ds, FTAG);
		error = 0;
	}
	return (error);
}

static void
dmu_recv_begin_sync(void *arg, dmu_tx_t *tx)
{
	dmu_recv_begin_arg_t *drba = arg;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	struct drr_begin *drrb = drba->drba_cookie->drc_drrb;
	const char *tofs = drba->drba_cookie->drc_tofs;
	dsl_dataset_t *ds, *newds;
	uint64_t dsobj;
	int error;
	uint64_t crflags;

	crflags = (drrb->drr_flags & DRR_FLAG_CI_DATA) ?
	    DS_FLAG_CI_DATASET : 0;

	error = dsl_dataset_hold(dp, tofs, FTAG, &ds);
	if (error == 0) {
		/* create temporary clone */
		dsl_dataset_t *snap = NULL;
		if (drba->drba_snapobj != 0) {
			VERIFY0(dsl_dataset_hold_obj(dp,
			    drba->drba_snapobj, FTAG, &snap));
		}
		dsobj = dsl_dataset_create_sync(ds->ds_dir, recv_clone_name,
		    snap, crflags, drba->drba_cred, tx);
		dsl_dataset_rele(snap, FTAG);
		dsl_dataset_rele(ds, FTAG);
	} else {
		dsl_dir_t *dd;
		const char *tail;
		dsl_dataset_t *origin = NULL;

		VERIFY0(dsl_dir_hold(dp, tofs, FTAG, &dd, &tail));

		if (drba->drba_origin != NULL) {
			VERIFY0(dsl_dataset_hold(dp, drba->drba_origin,
			    FTAG, &origin));
		}

		/* Create new dataset. */
		dsobj = dsl_dataset_create_sync(dd,
		    strrchr(tofs, '/') + 1,
		    origin, crflags, drba->drba_cred, tx);
		if (origin != NULL)
			dsl_dataset_rele(origin, FTAG);
		dsl_dir_rele(dd, FTAG);
		drba->drba_cookie->drc_newfs = B_TRUE;
	}

	VERIFY0(dsl_dataset_own_obj(dp, dsobj, dmu_recv_tag, &newds));

	if ((DMU_GET_FEATUREFLAGS(drrb->drr_versioninfo) &
	    DMU_BACKUP_FEATURE_EMBED_MOOCH_BYTESWAP) &&
	    !newds->ds_mooch_byteswap) {
		dsl_dataset_activate_mooch_byteswap_sync_impl(dsobj, tx);
		newds->ds_mooch_byteswap = B_TRUE;
	}

	dmu_buf_will_dirty(newds->ds_dbuf, tx);
	newds->ds_phys->ds_flags |= DS_FLAG_INCONSISTENT;

	/*
	 * If we actually created a non-clone, we need to create the
	 * objset in our new dataset.
	 */
	if (BP_IS_HOLE(dsl_dataset_get_blkptr(newds))) {
		(void) dmu_objset_create_impl(dp->dp_spa,
		    newds, dsl_dataset_get_blkptr(newds), drrb->drr_type, tx);
	}

	drba->drba_cookie->drc_ds = newds;

	spa_history_log_internal_ds(newds, "receive", tx, "");
}

/*
 * NB: callers *MUST* call dmu_recv_stream() if dmu_recv_begin()
 * succeeds; otherwise we will leak the holds on the datasets.
 */
int
dmu_recv_begin(char *tofs, char *tosnap, struct drr_begin *drrb,
    boolean_t force, char *origin, dmu_recv_cookie_t *drc)
{
	dmu_recv_begin_arg_t drba = { 0 };
	dmu_replay_record_t *drr;

	bzero(drc, sizeof (dmu_recv_cookie_t));
	drc->drc_drrb = drrb;
	drc->drc_tosnap = tosnap;
	drc->drc_tofs = tofs;
	drc->drc_force = force;
	drc->drc_cred = CRED();

	if (drrb->drr_magic == BSWAP_64(DMU_BACKUP_MAGIC))
		drc->drc_byteswap = B_TRUE;
	else if (drrb->drr_magic != DMU_BACKUP_MAGIC)
		return (SET_ERROR(EINVAL));

	drr = kmem_zalloc(sizeof (dmu_replay_record_t), KM_SLEEP);
	drr->drr_type = DRR_BEGIN;
	drr->drr_u.drr_begin = *drc->drc_drrb;
	if (drc->drc_byteswap) {
		fletcher_4_incremental_byteswap(drr,
		    sizeof (dmu_replay_record_t), &drc->drc_cksum);
	} else {
		fletcher_4_incremental_native(drr,
		    sizeof (dmu_replay_record_t), &drc->drc_cksum);
	}
	kmem_free(drr, sizeof (dmu_replay_record_t));

	if (drc->drc_byteswap) {
		drrb->drr_magic = BSWAP_64(drrb->drr_magic);
		drrb->drr_versioninfo = BSWAP_64(drrb->drr_versioninfo);
		drrb->drr_creation_time = BSWAP_64(drrb->drr_creation_time);
		drrb->drr_type = BSWAP_32(drrb->drr_type);
		drrb->drr_toguid = BSWAP_64(drrb->drr_toguid);
		drrb->drr_fromguid = BSWAP_64(drrb->drr_fromguid);
	}

	drba.drba_origin = origin;
	drba.drba_cookie = drc;
	drba.drba_cred = CRED();

	return (dsl_sync_task(tofs, dmu_recv_begin_check, dmu_recv_begin_sync,
	    &drba, 5, ZFS_SPACE_CHECK_NORMAL));
}

struct restorearg {
	objset_t *os;
	int err;
	boolean_t byteswap;
	vnode_t *vp;
	uint64_t voff;
	int bufsize; /* amount of memory allocated for buf */

	dmu_replay_record_t *drr;
	dmu_replay_record_t *next_drr;
	char *buf;
	zio_cksum_t cksum;
	zio_cksum_t prev_cksum;

	avl_tree_t *guid_to_ds_map;
};

typedef struct guid_map_entry {
	uint64_t	guid;
	dsl_dataset_t	*gme_ds;
	avl_node_t	avlnode;
} guid_map_entry_t;

static int
guid_compare(const void *arg1, const void *arg2)
{
	const guid_map_entry_t *gmep1 = arg1;
	const guid_map_entry_t *gmep2 = arg2;

	if (gmep1->guid < gmep2->guid)
		return (-1);
	else if (gmep1->guid > gmep2->guid)
		return (1);
	return (0);
}

static void
free_guid_map_onexit(void *arg)
{
	avl_tree_t *ca = arg;
	void *cookie = NULL;
	guid_map_entry_t *gmep;

	while ((gmep = avl_destroy_nodes(ca, &cookie)) != NULL) {
		dsl_dataset_long_rele(gmep->gme_ds, gmep);
		dsl_dataset_rele(gmep->gme_ds, gmep);
		kmem_free(gmep, sizeof (guid_map_entry_t));
	}
	avl_destroy(ca);
	kmem_free(ca, sizeof (avl_tree_t));
}

static int
restore_read(struct restorearg *ra, int len, void *buf)
{
	int done = 0;

	/* some things will require 8-byte alignment, so everything must */
	ASSERT0(len % 8);

	while (done < len) {
		ssize_t resid;

		ra->err = vn_rdwr(UIO_READ, ra->vp,
		    (char *)buf + done, len - done,
		    ra->voff, UIO_SYSSPACE, FAPPEND,
		    RLIM64_INFINITY, CRED(), &resid);

		if (resid == len - done)
			ra->err = SET_ERROR(EINVAL);
		ra->voff += len - done - resid;
		done = len - resid;
		if (ra->err != 0)
			return (ra->err);
	}

	ASSERT3U(done, ==, len);
	return (0);
}

static void
byteswap_record(dmu_replay_record_t *drr)
{
#define	DO64(X) (drr->drr_u.X = BSWAP_64(drr->drr_u.X))
#define	DO32(X) (drr->drr_u.X = BSWAP_32(drr->drr_u.X))
	drr->drr_type = BSWAP_32(drr->drr_type);
	drr->drr_payloadlen = BSWAP_32(drr->drr_payloadlen);

	switch (drr->drr_type) {
	case DRR_BEGIN:
		DO64(drr_begin.drr_magic);
		DO64(drr_begin.drr_versioninfo);
		DO64(drr_begin.drr_creation_time);
		DO32(drr_begin.drr_type);
		DO32(drr_begin.drr_flags);
		DO64(drr_begin.drr_toguid);
		DO64(drr_begin.drr_fromguid);
		break;
	case DRR_OBJECT:
		DO64(drr_object.drr_object);
		DO32(drr_object.drr_type);
		DO32(drr_object.drr_bonustype);
		DO32(drr_object.drr_blksz);
		DO32(drr_object.drr_bonuslen);
		DO64(drr_object.drr_toguid);
		break;
	case DRR_FREEOBJECTS:
		DO64(drr_freeobjects.drr_firstobj);
		DO64(drr_freeobjects.drr_numobjs);
		DO64(drr_freeobjects.drr_toguid);
		break;
	case DRR_WRITE:
		DO64(drr_write.drr_object);
		DO32(drr_write.drr_type);
		DO64(drr_write.drr_offset);
		DO64(drr_write.drr_length);
		DO64(drr_write.drr_toguid);
		ZIO_CHECKSUM_BSWAP(&drr->drr_u.drr_write.drr_key.ddk_cksum);
		DO64(drr_write.drr_key.ddk_prop);
		break;
	case DRR_WRITE_BYREF:
		DO64(drr_write_byref.drr_object);
		DO64(drr_write_byref.drr_offset);
		DO64(drr_write_byref.drr_length);
		DO64(drr_write_byref.drr_toguid);
		DO64(drr_write_byref.drr_refguid);
		DO64(drr_write_byref.drr_refobject);
		DO64(drr_write_byref.drr_refoffset);
		ZIO_CHECKSUM_BSWAP(&drr->drr_u.drr_write_byref.
		    drr_key.ddk_cksum);
		DO64(drr_write_byref.drr_key.ddk_prop);
		break;
	case DRR_WRITE_EMBEDDED:
		DO64(drr_write_embedded.drr_object);
		DO64(drr_write_embedded.drr_offset);
		DO64(drr_write_embedded.drr_length);
		DO64(drr_write_embedded.drr_toguid);
		DO32(drr_write_embedded.drr_lsize);
		DO32(drr_write_embedded.drr_psize);
		break;
	case DRR_FREE:
		DO64(drr_free.drr_object);
		DO64(drr_free.drr_offset);
		DO64(drr_free.drr_length);
		DO64(drr_free.drr_toguid);
		break;
	case DRR_SPILL:
		DO64(drr_spill.drr_object);
		DO64(drr_spill.drr_length);
		DO64(drr_spill.drr_toguid);
		break;
	case DRR_END:
		DO64(drr_end.drr_toguid);
		ZIO_CHECKSUM_BSWAP(&drr->drr_u.drr_end.drr_checksum);
		break;
	}

	if (drr->drr_type != DRR_BEGIN) {
		ZIO_CHECKSUM_BSWAP(&drr->drr_u.drr_checksum.drr_checksum);
	}

#undef DO64
#undef DO32
}

static inline uint8_t
deduce_nblkptr(dmu_object_type_t bonus_type, uint64_t bonus_size)
{
	if (bonus_type == DMU_OT_SA) {
		return (1);
	} else {
		return (1 +
		    ((DN_MAX_BONUSLEN - bonus_size) >> SPA_BLKPTRSHIFT));
	}
}

static int
restore_object(struct restorearg *ra, struct drr_object *drro, void *data)
{
	dmu_object_info_t doi;
	dmu_tx_t *tx;
	uint64_t object;
	int err;

	if (drro->drr_type == DMU_OT_NONE ||
	    !DMU_OT_IS_VALID(drro->drr_type) ||
	    !DMU_OT_IS_VALID(drro->drr_bonustype) ||
	    drro->drr_checksumtype >= ZIO_CHECKSUM_FUNCTIONS ||
	    drro->drr_compress >= ZIO_COMPRESS_FUNCTIONS ||
	    P2PHASE(drro->drr_blksz, SPA_MINBLOCKSIZE) ||
	    drro->drr_blksz < SPA_MINBLOCKSIZE ||
	    drro->drr_blksz > SPA_MAXBLOCKSIZE ||
	    drro->drr_bonuslen > DN_MAX_BONUSLEN) {
		return (SET_ERROR(EINVAL));
	}

	err = dmu_object_info(ra->os, drro->drr_object, &doi);

	if (err != 0 && err != ENOENT)
		return (SET_ERROR(EINVAL));
	object = err == 0 ? drro->drr_object : DMU_NEW_OBJECT;

	/*
	 * If we are losing blkptrs or changing the block size this must
	 * be a new file instance.  We must clear out the previous file
	 * contents before we can change this type of metadata in the dnode.
	 */
	if (err == 0) {
		int nblkptr;

		nblkptr = deduce_nblkptr(drro->drr_bonustype,
		    drro->drr_bonuslen);

		if (drro->drr_blksz != doi.doi_data_block_size ||
		    nblkptr < doi.doi_nblkptr) {
			err = dmu_free_long_range(ra->os, drro->drr_object,
			    0, DMU_OBJECT_END);
			if (err != 0)
				return (SET_ERROR(EINVAL));
		}
	}

	tx = dmu_tx_create(ra->os);
	dmu_tx_hold_bonus(tx, object);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		dmu_tx_abort(tx);
		return (err);
	}

	if (object == DMU_NEW_OBJECT) {
		/* currently free, want to be allocated */
		err = dmu_object_claim(ra->os, drro->drr_object,
		    drro->drr_type, drro->drr_blksz,
		    drro->drr_bonustype, drro->drr_bonuslen, tx);
	} else if (drro->drr_type != doi.doi_type ||
	    drro->drr_blksz != doi.doi_data_block_size ||
	    drro->drr_bonustype != doi.doi_bonus_type ||
	    drro->drr_bonuslen != doi.doi_bonus_size) {
		/* currently allocated, but with different properties */
		err = dmu_object_reclaim(ra->os, drro->drr_object,
		    drro->drr_type, drro->drr_blksz,
		    drro->drr_bonustype, drro->drr_bonuslen, tx);
	}
	if (err != 0) {
		dmu_tx_commit(tx);
		return (SET_ERROR(EINVAL));
	}

	dmu_object_set_checksum(ra->os, drro->drr_object,
	    drro->drr_checksumtype, tx);
	dmu_object_set_compress(ra->os, drro->drr_object,
	    drro->drr_compress, tx);

	if (data != NULL) {
		dmu_buf_t *db;

		VERIFY0(dmu_bonus_hold(ra->os, drro->drr_object, FTAG, &db));
		dmu_buf_will_dirty(db, tx);

		ASSERT3U(db->db_size, >=, drro->drr_bonuslen);
		bcopy(data, db->db_data, drro->drr_bonuslen);
		if (ra->byteswap) {
			dmu_object_byteswap_t byteswap =
			    DMU_OT_BYTESWAP(drro->drr_bonustype);
			dmu_ot_byteswap[byteswap].ob_func(db->db_data,
			    drro->drr_bonuslen);
		}
		dmu_buf_rele(db, FTAG);
	}
	dmu_tx_commit(tx);
	return (0);
}

/* ARGSUSED */
static int
restore_freeobjects(struct restorearg *ra,
    struct drr_freeobjects *drrfo)
{
	uint64_t obj;

	if (drrfo->drr_firstobj + drrfo->drr_numobjs < drrfo->drr_firstobj)
		return (SET_ERROR(EINVAL));

	for (obj = drrfo->drr_firstobj;
	    obj < drrfo->drr_firstobj + drrfo->drr_numobjs;
	    (void) dmu_object_next(ra->os, &obj, FALSE, 0)) {
		int err;

		if (dmu_object_info(ra->os, obj, NULL) != 0)
			continue;

		err = dmu_free_long_object(ra->os, obj);
		if (err != 0)
			return (err);
	}
	return (0);
}

static int
restore_write(struct restorearg *ra, struct drr_write *drrw, arc_buf_t *abuf)
{
	dmu_tx_t *tx;
	int err;

	if (drrw->drr_offset + drrw->drr_length < drrw->drr_offset ||
	    !DMU_OT_IS_VALID(drrw->drr_type))
		return (SET_ERROR(EINVAL));

	if (dmu_object_info(ra->os, drrw->drr_object, NULL) != 0)
		return (SET_ERROR(EINVAL));

	tx = dmu_tx_create(ra->os);

	dmu_tx_hold_write(tx, drrw->drr_object,
	    drrw->drr_offset, drrw->drr_length);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		dmu_tx_abort(tx);
		return (err);
	}
	if (ra->byteswap) {
		dmu_object_byteswap_t byteswap =
		    DMU_OT_BYTESWAP(drrw->drr_type);
		dmu_ot_byteswap[byteswap].ob_func(abuf->b_data,
		    drrw->drr_length);
	}

	dmu_buf_t *bonus;
	if (dmu_bonus_hold(ra->os, drrw->drr_object, FTAG, &bonus) != 0)
		return (SET_ERROR(EINVAL));
	dmu_assign_arcbuf(bonus, drrw->drr_offset, abuf, tx);
	dmu_tx_commit(tx);
	dmu_buf_rele(bonus, FTAG);
	return (0);
}

/*
 * Handle a DRR_WRITE_BYREF record.  This record is used in dedup'ed
 * streams to refer to a copy of the data that is already on the
 * system because it came in earlier in the stream.  This function
 * finds the earlier copy of the data, and uses that copy instead of
 * data from the stream to fulfill this write.
 */
static int
restore_write_byref(struct restorearg *ra, struct drr_write_byref *drrwbr)
{
	dmu_tx_t *tx;
	int err;
	guid_map_entry_t gmesrch;
	guid_map_entry_t *gmep;
	avl_index_t where;
	objset_t *ref_os = NULL;
	dmu_buf_t *dbp;

	if (drrwbr->drr_offset + drrwbr->drr_length < drrwbr->drr_offset)
		return (SET_ERROR(EINVAL));

	/*
	 * If the GUID of the referenced dataset is different from the
	 * GUID of the target dataset, find the referenced dataset.
	 */
	if (drrwbr->drr_toguid != drrwbr->drr_refguid) {
		gmesrch.guid = drrwbr->drr_refguid;
		if ((gmep = avl_find(ra->guid_to_ds_map, &gmesrch,
		    &where)) == NULL) {
			return (SET_ERROR(EINVAL));
		}
		if (dmu_objset_from_ds(gmep->gme_ds, &ref_os))
			return (SET_ERROR(EINVAL));
	} else {
		ref_os = ra->os;
	}

	err = dmu_buf_hold(ref_os, drrwbr->drr_refobject,
	    drrwbr->drr_refoffset, FTAG, &dbp, DMU_READ_PREFETCH);
	if (err != 0)
		return (err);

	tx = dmu_tx_create(ra->os);

	dmu_tx_hold_write(tx, drrwbr->drr_object,
	    drrwbr->drr_offset, drrwbr->drr_length);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		dmu_tx_abort(tx);
		return (err);
	}
	dmu_write(ra->os, drrwbr->drr_object,
	    drrwbr->drr_offset, drrwbr->drr_length, dbp->db_data, tx);
	dmu_buf_rele(dbp, FTAG);
	dmu_tx_commit(tx);
	return (0);
}

static int
restore_write_embedded(struct restorearg *ra,
    struct drr_write_embedded *drrwnp, void *data)
{
	dmu_tx_t *tx;
	int err;

	if (drrwnp->drr_offset + drrwnp->drr_length < drrwnp->drr_offset)
		return (EINVAL);

	if (drrwnp->drr_psize > BPE_PAYLOAD_SIZE)
		return (EINVAL);

	if (drrwnp->drr_etype >= NUM_BP_EMBEDDED_TYPES)
		return (EINVAL);
	if (drrwnp->drr_compression >= ZIO_COMPRESS_FUNCTIONS)
		return (EINVAL);

	tx = dmu_tx_create(ra->os);

	dmu_tx_hold_write(tx, drrwnp->drr_object,
	    drrwnp->drr_offset, drrwnp->drr_length);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		dmu_tx_abort(tx);
		return (err);
	}

	dmu_write_embedded(ra->os, drrwnp->drr_object,
	    drrwnp->drr_offset, data, drrwnp->drr_etype,
	    drrwnp->drr_compression, drrwnp->drr_lsize, drrwnp->drr_psize,
	    ra->byteswap ^ ZFS_HOST_BYTEORDER, tx);

	dmu_tx_commit(tx);
	return (0);
}

static int
restore_spill(struct restorearg *ra, struct drr_spill *drrs, void *data)
{
	dmu_tx_t *tx;
	dmu_buf_t *db, *db_spill;
	int err;

	if (drrs->drr_length < SPA_MINBLOCKSIZE ||
	    drrs->drr_length > SPA_MAXBLOCKSIZE)
		return (SET_ERROR(EINVAL));

	if (dmu_object_info(ra->os, drrs->drr_object, NULL) != 0)
		return (SET_ERROR(EINVAL));

	VERIFY(0 == dmu_bonus_hold(ra->os, drrs->drr_object, FTAG, &db));
	if ((err = dmu_spill_hold_by_bonus(db, FTAG, &db_spill)) != 0) {
		dmu_buf_rele(db, FTAG);
		return (err);
	}

	tx = dmu_tx_create(ra->os);

	dmu_tx_hold_spill(tx, db->db_object);

	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		dmu_buf_rele(db, FTAG);
		dmu_buf_rele(db_spill, FTAG);
		dmu_tx_abort(tx);
		return (err);
	}
	dmu_buf_will_dirty(db_spill, tx);

	if (db_spill->db_size < drrs->drr_length)
		VERIFY(0 == dbuf_spill_set_blksz(db_spill,
		    drrs->drr_length, tx));
	bcopy(data, db_spill->db_data, drrs->drr_length);

	dmu_buf_rele(db, FTAG);
	dmu_buf_rele(db_spill, FTAG);

	dmu_tx_commit(tx);
	return (0);
}

/* ARGSUSED */
static int
restore_free(struct restorearg *ra, struct drr_free *drrf)
{
	int err;

	if (drrf->drr_length != -1ULL &&
	    drrf->drr_offset + drrf->drr_length < drrf->drr_offset)
		return (SET_ERROR(EINVAL));

	if (dmu_object_info(ra->os, drrf->drr_object, NULL) != 0)
		return (SET_ERROR(EINVAL));

	err = dmu_free_long_range(ra->os, drrf->drr_object,
	    drrf->drr_offset, drrf->drr_length);
	return (err);
}

/* used to destroy the drc_ds on error */
static void
dmu_recv_cleanup_ds(dmu_recv_cookie_t *drc)
{
	char name[MAXNAMELEN];
	dsl_dataset_name(drc->drc_ds, name);
	dsl_dataset_disown(drc->drc_ds, dmu_recv_tag);
	(void) dsl_destroy_head(name);
}

static void
restore_cksum(struct restorearg *ra, int len, void *buf)
{
	if (ra->byteswap) {
		fletcher_4_incremental_byteswap(buf, len, &ra->cksum);
	} else {
		fletcher_4_incremental_native(buf, len, &ra->cksum);
	}
}

/*
 * If len != 0, read payload into buf.
 * Read next record's header into ra->next_drr.
 * Verify checksum of payload and next record.
 */
static int
restore_read_payload_and_next_header(struct restorearg *ra, int len, void *buf)
{
	int err;

	if (len != 0) {
		ASSERT3U(len, <=, ra->bufsize);
		err = restore_read(ra, len, buf);
		if (err != 0)
			return (err);
		restore_cksum(ra, len, buf);
	}

	ra->prev_cksum = ra->cksum;

	err = restore_read(ra, sizeof (*ra->next_drr), ra->next_drr);
	if (err != 0)
		return (err);
	if (ra->next_drr->drr_type == DRR_BEGIN)
		return (SET_ERROR(EINVAL));

	/*
	 * Note: checksum is of everything up to but not including the
	 * checksum itself.
	 */
	ASSERT3U(offsetof(dmu_replay_record_t, drr_u.drr_checksum.drr_checksum),
	    ==, sizeof (dmu_replay_record_t) - sizeof (zio_cksum_t));
	restore_cksum(ra,
	    offsetof(dmu_replay_record_t, drr_u.drr_checksum.drr_checksum),
	    ra->next_drr);

	zio_cksum_t cksum_orig = ra->next_drr->drr_u.drr_checksum.drr_checksum;
	zio_cksum_t *cksump = &ra->next_drr->drr_u.drr_checksum.drr_checksum;

	if (ra->byteswap)
		byteswap_record(ra->next_drr);

	if ((!ZIO_CHECKSUM_IS_ZERO(cksump)) &&
	    !ZIO_CHECKSUM_EQUAL(ra->cksum, *cksump))
		return (SET_ERROR(ECKSUM));

	restore_cksum(ra, sizeof (cksum_orig), &cksum_orig);

	return (0);
}

static int
restore_process_record(struct restorearg *ra)
{
	int err;

	switch (ra->drr->drr_type) {
	case DRR_OBJECT:
	{
		struct drr_object *drro = &ra->drr->drr_u.drr_object;
		err = restore_read_payload_and_next_header(ra,
		    P2ROUNDUP(drro->drr_bonuslen, 8), ra->buf);
		if (err != 0)
			return (err);
		return (restore_object(ra, drro, ra->buf));
	}
	case DRR_FREEOBJECTS:
	{
		struct drr_freeobjects *drrfo =
		    &ra->drr->drr_u.drr_freeobjects;
		err = restore_read_payload_and_next_header(ra, 0, NULL);
		if (err != 0)
			return (err);
		return (restore_freeobjects(ra, drrfo));
	}
	case DRR_WRITE:
	{
		struct drr_write *drrw = &ra->drr->drr_u.drr_write;
		arc_buf_t *abuf = arc_loan_buf(dmu_objset_spa(ra->os),
		    drrw->drr_length);

		err = restore_read_payload_and_next_header(ra,
		    drrw->drr_length, abuf->b_data);
		if (err != 0)
			return (err);
		err = restore_write(ra, drrw, abuf);
		/* if restore_write() is successful, it consumes the arc_buf */
		if (err != 0)
			dmu_return_arcbuf(abuf);
		return (err);
	}
	case DRR_WRITE_BYREF:
	{
		struct drr_write_byref *drrwbr =
		    &ra->drr->drr_u.drr_write_byref;
		err = restore_read_payload_and_next_header(ra, 0, NULL);
		if (err != 0)
			return (err);
		return (restore_write_byref(ra, drrwbr));
	}
	case DRR_WRITE_EMBEDDED:
	{
		struct drr_write_embedded *drrwe =
		    &ra->drr->drr_u.drr_write_embedded;
		err = restore_read_payload_and_next_header(ra,
		    P2ROUNDUP(drrwe->drr_psize, 8), ra->buf);
		if (err != 0)
			return (err);
		return (restore_write_embedded(ra, drrwe, ra->buf));
	}
	case DRR_FREE:
	{
		struct drr_free *drrf = &ra->drr->drr_u.drr_free;
		err = restore_read_payload_and_next_header(ra, 0, NULL);
		if (err != 0)
			return (err);
		return (restore_free(ra, drrf));
	}
	case DRR_END:
	{
		struct drr_end *drre = &ra->drr->drr_u.drr_end;
		if (!ZIO_CHECKSUM_EQUAL(ra->prev_cksum, drre->drr_checksum))
			return (SET_ERROR(EINVAL));
		return (0);
	}
	case DRR_SPILL:
	{
		struct drr_spill *drrs = &ra->drr->drr_u.drr_spill;
		err = restore_read_payload_and_next_header(ra,
		    drrs->drr_length, ra->buf);
		if (err != 0)
			return (err);
		return (restore_spill(ra, drrs, ra->buf));
	}
	default:
		return (SET_ERROR(EINVAL));
	}
}

/*
 * NB: callers *must* call dmu_recv_end() if this succeeds.
 */
int
dmu_recv_stream(dmu_recv_cookie_t *drc, vnode_t *vp, offset_t *voffp,
    int cleanup_fd, uint64_t *action_handlep)
{
	int err = 0;
	struct restorearg ra = { 0 };
	int featureflags;

	ra.byteswap = drc->drc_byteswap;
	ra.cksum = drc->drc_cksum;
	ra.vp = vp;
	ra.voff = *voffp;
	ra.bufsize = SPA_MAXBLOCKSIZE;
	ra.drr = kmem_alloc(sizeof (*ra.drr), KM_SLEEP);
	ra.buf = kmem_alloc(ra.bufsize, KM_SLEEP);
	ra.next_drr = kmem_alloc(sizeof (*ra.next_drr), KM_SLEEP);

	/* these were verified in dmu_recv_begin */
	ASSERT3U(DMU_GET_STREAM_HDRTYPE(drc->drc_drrb->drr_versioninfo), ==,
	    DMU_SUBSTREAM);
	ASSERT3U(drc->drc_drrb->drr_type, <, DMU_OST_NUMTYPES);

	/*
	 * Open the objset we are modifying.
	 */
	VERIFY0(dmu_objset_from_ds(drc->drc_ds, &ra.os));

	ASSERT(drc->drc_ds->ds_phys->ds_flags & DS_FLAG_INCONSISTENT);

	featureflags = DMU_GET_FEATUREFLAGS(drc->drc_drrb->drr_versioninfo);

	/* if this stream is dedup'ed, set up the avl tree for guid mapping */
	if (featureflags & DMU_BACKUP_FEATURE_DEDUP) {
		minor_t minor;

		if (cleanup_fd == -1) {
			ra.err = SET_ERROR(EBADF);
			goto out;
		}
		ra.err = zfs_onexit_fd_hold(cleanup_fd, &minor);
		if (ra.err != 0) {
			cleanup_fd = -1;
			goto out;
		}

		if (*action_handlep == 0) {
			ra.guid_to_ds_map =
			    kmem_alloc(sizeof (avl_tree_t), KM_SLEEP);
			avl_create(ra.guid_to_ds_map, guid_compare,
			    sizeof (guid_map_entry_t),
			    offsetof(guid_map_entry_t, avlnode));
			err = zfs_onexit_add_cb(minor,
			    free_guid_map_onexit, ra.guid_to_ds_map,
			    action_handlep);
			if (ra.err != 0)
				goto out;
		} else {
			err = zfs_onexit_cb_data(minor, *action_handlep,
			    (void **)&ra.guid_to_ds_map);
			if (ra.err != 0)
				goto out;
		}

		drc->drc_guid_to_ds_map = ra.guid_to_ds_map;
	}

	err = restore_read_payload_and_next_header(&ra, 0, NULL);
	if (err != 0)
		goto out;
	for (;;) {
		void *tmp;

		if (issig(JUSTLOOKING) && issig(FORREAL)) {
			err = SET_ERROR(EINTR);
			break;
		}

		tmp = ra.next_drr;
		ra.next_drr = ra.drr;
		ra.drr = tmp;

		/* process ra.drr, read in ra.next_drr */
		err = restore_process_record(&ra);
		if (err != 0)
			break;
		if (ra.drr->drr_type == DRR_END)
			break;
	}

out:
	if ((featureflags & DMU_BACKUP_FEATURE_DEDUP) && (cleanup_fd != -1))
		zfs_onexit_fd_rele(cleanup_fd);

	if (err != 0) {
		/*
		 * destroy what we created, so we don't leave it in the
		 * inconsistent restoring state.
		 */
		dmu_recv_cleanup_ds(drc);
	}

	kmem_free(ra.drr, sizeof (*ra.drr));
	kmem_free(ra.buf, ra.bufsize);
	kmem_free(ra.next_drr, sizeof (*ra.next_drr));
	*voffp = ra.voff;
	return (err);
}

static int
dmu_recv_end_check(void *arg, dmu_tx_t *tx)
{
	dmu_recv_cookie_t *drc = arg;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	int error;

	ASSERT3P(drc->drc_ds->ds_owner, ==, dmu_recv_tag);

	if (!drc->drc_newfs) {
		dsl_dataset_t *origin_head;

		error = dsl_dataset_hold(dp, drc->drc_tofs, FTAG, &origin_head);
		if (error != 0)
			return (error);
		if (drc->drc_force) {
			/*
			 * We will destroy any snapshots in tofs (i.e. before
			 * origin_head) that are after the origin (which is
			 * the snap before drc_ds, because drc_ds can not
			 * have any snaps of its own).
			 */
			uint64_t obj = origin_head->ds_phys->ds_prev_snap_obj;
			while (obj != drc->drc_ds->ds_phys->ds_prev_snap_obj) {
				dsl_dataset_t *snap;
				error = dsl_dataset_hold_obj(dp, obj, FTAG,
				    &snap);
				if (error != 0)
					return (error);
				if (snap->ds_dir != origin_head->ds_dir)
					error = SET_ERROR(EINVAL);
				if (error == 0)  {
					error = dsl_destroy_snapshot_check_impl(
					    snap, B_FALSE);
				}
				obj = snap->ds_phys->ds_prev_snap_obj;
				dsl_dataset_rele(snap, FTAG);
				if (error != 0)
					return (error);
			}
		}
		error = dsl_dataset_clone_swap_check_impl(drc->drc_ds,
		    origin_head, drc->drc_force, drc->drc_owner, tx);
		if (error != 0) {
			dsl_dataset_rele(origin_head, FTAG);
			return (error);
		}
		error = dsl_dataset_snapshot_check_impl(origin_head,
		    drc->drc_tosnap, tx, B_TRUE, 1, drc->drc_cred);
		dsl_dataset_rele(origin_head, FTAG);
		if (error != 0)
			return (error);

		error = dsl_destroy_head_check_impl(drc->drc_ds, 1);
	} else {
		error = dsl_dataset_snapshot_check_impl(drc->drc_ds,
		    drc->drc_tosnap, tx, B_TRUE, 1, drc->drc_cred);
	}
	return (error);
}

static void
dmu_recv_end_sync(void *arg, dmu_tx_t *tx)
{
	dmu_recv_cookie_t *drc = arg;
	dsl_pool_t *dp = dmu_tx_pool(tx);

	spa_history_log_internal_ds(drc->drc_ds, "finish receiving",
	    tx, "snap=%s", drc->drc_tosnap);

	/*
	 * We must evict the objset, because it may have invalid
	 * dn_origin_obj_refd (see dmu_objset_mooch_obj_refd()).
	 */
	if (drc->drc_ds->ds_objset != NULL) {
		dmu_objset_evict(drc->drc_ds->ds_objset);
		drc->drc_ds->ds_objset = NULL;
	}

	if (!drc->drc_newfs) {
		dsl_dataset_t *origin_head;

		VERIFY0(dsl_dataset_hold(dp, drc->drc_tofs, FTAG,
		    &origin_head));

		if (drc->drc_force) {
			/*
			 * Destroy any snapshots of drc_tofs (origin_head)
			 * after the origin (the snap before drc_ds).
			 */
			uint64_t obj = origin_head->ds_phys->ds_prev_snap_obj;
			while (obj != drc->drc_ds->ds_phys->ds_prev_snap_obj) {
				dsl_dataset_t *snap;
				VERIFY0(dsl_dataset_hold_obj(dp, obj, FTAG,
				    &snap));
				ASSERT3P(snap->ds_dir, ==, origin_head->ds_dir);
				obj = snap->ds_phys->ds_prev_snap_obj;
				dsl_destroy_snapshot_sync_impl(snap,
				    B_FALSE, tx);
				dsl_dataset_rele(snap, FTAG);
			}
		}
		VERIFY3P(drc->drc_ds->ds_prev, ==,
		    origin_head->ds_prev);

		dsl_dataset_clone_swap_sync_impl(drc->drc_ds,
		    origin_head, tx);
		dsl_dataset_snapshot_sync_impl(origin_head,
		    drc->drc_tosnap, tx);

		/* set snapshot's creation time and guid */
		dmu_buf_will_dirty(origin_head->ds_prev->ds_dbuf, tx);
		origin_head->ds_prev->ds_phys->ds_creation_time =
		    drc->drc_drrb->drr_creation_time;
		origin_head->ds_prev->ds_phys->ds_guid =
		    drc->drc_drrb->drr_toguid;
		origin_head->ds_prev->ds_phys->ds_flags &=
		    ~DS_FLAG_INCONSISTENT;

		dmu_buf_will_dirty(origin_head->ds_dbuf, tx);
		origin_head->ds_phys->ds_flags &= ~DS_FLAG_INCONSISTENT;

		dsl_dataset_rele(origin_head, FTAG);
		dsl_destroy_head_sync_impl(drc->drc_ds, tx);

		if (drc->drc_owner != NULL)
			VERIFY3P(origin_head->ds_owner, ==, drc->drc_owner);
	} else {
		dsl_dataset_t *ds = drc->drc_ds;

		dsl_dataset_snapshot_sync_impl(ds, drc->drc_tosnap, tx);

		/* set snapshot's creation time and guid */
		dmu_buf_will_dirty(ds->ds_prev->ds_dbuf, tx);
		ds->ds_prev->ds_phys->ds_creation_time =
		    drc->drc_drrb->drr_creation_time;
		ds->ds_prev->ds_phys->ds_guid = drc->drc_drrb->drr_toguid;
		ds->ds_prev->ds_phys->ds_flags &= ~DS_FLAG_INCONSISTENT;

		dmu_buf_will_dirty(ds->ds_dbuf, tx);
		ds->ds_phys->ds_flags &= ~DS_FLAG_INCONSISTENT;
	}
	drc->drc_newsnapobj = drc->drc_ds->ds_phys->ds_prev_snap_obj;
	/*
	 * Release the hold from dmu_recv_begin.  This must be done before
	 * we return to open context, so that when we free the dataset's dnode,
	 * we can evict its bonus buffer.
	 */
	dsl_dataset_disown(drc->drc_ds, dmu_recv_tag);
	drc->drc_ds = NULL;
}

static int
add_ds_to_guidmap(const char *name, avl_tree_t *guid_map, uint64_t snapobj)
{
	dsl_pool_t *dp;
	dsl_dataset_t *snapds;
	guid_map_entry_t *gmep;
	int err;

	ASSERT(guid_map != NULL);

	err = dsl_pool_hold(name, FTAG, &dp);
	if (err != 0)
		return (err);
	gmep = kmem_alloc(sizeof (*gmep), KM_SLEEP);
	err = dsl_dataset_hold_obj(dp, snapobj, gmep, &snapds);
	if (err == 0) {
		gmep->guid = snapds->ds_phys->ds_guid;
		gmep->gme_ds = snapds;
		avl_add(guid_map, gmep);
		dsl_dataset_long_hold(snapds, gmep);
	} else {
		kmem_free(gmep, sizeof (*gmep));
	}

	dsl_pool_rele(dp, FTAG);
	return (err);
}

static int dmu_recv_end_modified_blocks = 3;

static int
dmu_recv_existing_end(dmu_recv_cookie_t *drc)
{
	int error;
	char name[MAXNAMELEN];

#ifdef _KERNEL
	/*
	 * We will be destroying the ds; make sure its origin is unmounted if
	 * necessary.
	 */
	dsl_dataset_name(drc->drc_ds, name);
	zfs_destroy_unmount_origin(name);
#endif

	error = dsl_sync_task(drc->drc_tofs,
	    dmu_recv_end_check, dmu_recv_end_sync, drc,
	    dmu_recv_end_modified_blocks, ZFS_SPACE_CHECK_NORMAL);

	if (error != 0)
		dmu_recv_cleanup_ds(drc);
	return (error);
}

static int
dmu_recv_new_end(dmu_recv_cookie_t *drc)
{
	int error;

	error = dsl_sync_task(drc->drc_tofs,
	    dmu_recv_end_check, dmu_recv_end_sync, drc,
	    dmu_recv_end_modified_blocks, ZFS_SPACE_CHECK_NORMAL);

	if (error != 0) {
		dmu_recv_cleanup_ds(drc);
	} else if (drc->drc_guid_to_ds_map != NULL) {
		(void) add_ds_to_guidmap(drc->drc_tofs,
		    drc->drc_guid_to_ds_map,
		    drc->drc_newsnapobj);
	}
	return (error);
}

int
dmu_recv_end(dmu_recv_cookie_t *drc, void *owner)
{
	drc->drc_owner = owner;

	if (drc->drc_newfs)
		return (dmu_recv_new_end(drc));
	else
		return (dmu_recv_existing_end(drc));
}

/*
 * Return TRUE if this objset is currently being received into.
 */
boolean_t
dmu_objset_is_receiving(objset_t *os)
{
	return (os->os_dsl_dataset != NULL &&
	    os->os_dsl_dataset->ds_owner == dmu_recv_tag);
}
