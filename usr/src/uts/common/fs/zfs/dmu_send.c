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
 * Copyright (c) 2011, 2016 by Delphix. All rights reserved.
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
#include <sys/objlist.h>
#ifdef _KERNEL
#include <sys/zfs_vfsops.h>
#endif

/* Set this tunable to TRUE to replace corrupt data with 0x2f5baddb10c */
int zfs_send_corrupt_data = B_FALSE;
/*
 * This tunable controls the amount of data (measured in bytes) that will be
 * prefetched by zfs send.  If the main thread is blocking on reads that haven't
 * completed, this variable might need to be increased.  If instead the main
 * thread is issuing new reads because the prefetches have fallen out of the
 * cache, this may need to be decreased.
 */
int zfs_send_queue_length = 16 * 1024 * 1024;
/*
 * This tunable controls the length of the queues that zfs send worker threads
 * use to communicate.  If the send_main_thread is blocking on these queues,
 * this variable may need to be increased.  If there is a significant slowdown
 * at the start of a send as these threads consume all the available IO
 * resources, this variable may need to be decreased.
 */
int zfs_send_no_prefetch_queue_length = 1024 * 1024;
/*
 * These tunables control the fill fraction of the queues by zfs send.  The fill
 * fraction controls the frequency with which threads have to be cv_signaled.
 * If a lot of cpu time is being spent on cv_signal, then these should be tuned
 * down.  If the queues empty before the signalled thread can catch up, then
 * these should be tuned up.
 */
uint64_t zfs_send_queue_ff = 20;
uint64_t zfs_send_no_prefetch_queue_ff = 20;

/*
 * Controls how often to update the redaction list when performing a redacted
 * zfs send.
 */
uint64_t redaction_list_update_interval_ns = 1000 * 1000 * 1000ULL; /* NS */

/*
 * This controls the number of entries in the buffer the redaction_list_update
 * synctask uses to buffer writes to the redaction list.
 */
int redact_sync_bufsize = 1024;

static inline boolean_t
overflow_multiply(uint64_t a, uint64_t b, uint64_t *c)
{
	uint64_t temp = a * b;
	if (b != 0 && temp / b != a)
		return (B_FALSE);
	*c = temp;
	return (B_TRUE);
}

/*
 * Note that this calculation cannot overflow with the current maximum indirect
 * block size (128k).  If that maximum is increased to 1M, however, this
 * calculation can overflow, and handling would need to be added to ensure
 * continued correctness.
 */
static inline uint64_t
bp_span_in_blocks(uint8_t indblkshift, uint64_t level)
{
	unsigned int shift = level * (indblkshift - SPA_BLKPTRSHIFT);
	ASSERT3U(shift, <, 64);
	return (1ULL << shift);
}

/*
 * Return B_TRUE and modifies *out to the span if the span is less than 2^64,
 * returns B_FALSE otherwise.
 */
static inline boolean_t
bp_span(uint32_t datablksz, uint8_t indblkshift, uint64_t level, uint64_t *out)
{
	uint64_t spanb = bp_span_in_blocks(indblkshift, level);
	return (overflow_multiply(spanb, datablksz, out));
}

struct send_thread_arg {
	bqueue_t	q;
	dsl_dataset_t	*ds;		/* Dataset to traverse */
	redaction_list_t *redaction_list;
	struct send_redact_record *current_record;
	uint64_t	fromtxg;	/* Traverse from this txg */
	objset_t	*to_os;		/* The "to" objset (from thread only) */
	uint64_t	ignore_object;	/* ignore further callbacks on this */
	int		flags;		/* flags to pass to traverse_dataset */
	int		error_code;
	boolean_t	cancel;
	zbookmark_phys_t resume;
	objlist_t	*deleted_objs;
	uint64_t	*num_blocks_visited;
};

struct redact_merge_thread_arg {
	struct send_thread_arg	*thread_args;
	uint32_t		num_threads;
	boolean_t		cancel;
	bqueue_t		q;
	zbookmark_phys_t	resume;
	redaction_list_t	*rl;
	int			error_code;
	uint64_t		*num_blocks_visited;
};

/*
 * A wrapper around struct redact_block so it can be stored in a list_t.
 */
struct redact_block_list_node {
	redact_block_phys_t	block;
	list_node_t		node;
};

struct redact_bookmark_info {
	redact_block_phys_t	rbi_furthest[TXG_SIZE];
	/* Lists of struct redact_block_list_node. */
	list_t			rbi_blocks[TXG_SIZE];
	boolean_t		rbi_synctasc_txg[TXG_SIZE];
	uint64_t		rbi_latest_synctask_txg;
	redaction_list_t	*rbi_redaction_list;
};

struct send_merge_thread_arg {
	bqueue_t			q;
	objset_t			*os;
	struct send_thread_arg		*from_arg;
	struct send_thread_arg		*to_arg;
	struct redact_merge_thread_arg	*redact_arg;
	int				error;
	boolean_t			cancel;
	struct redact_bookmark_info	rbi;
	/*
	 * If we're resuming a redacted send, then the object/offset from the
	 * resume token may be different from the object/offset that we have
	 * updated the bookmark to.  resume_redact_zb will store the earlier of
	 * the two object/offset pairs, and bookmark_before will be B_TRUE if
	 * resume_redact_zb has the object/offset for resuming the redaction
	 * bookmark, and B_FALSE if resume_redact_zb is storing the
	 * object/offset from the resume token.
	 */
	zbookmark_phys_t		resume_redact_zb;
	boolean_t			bookmark_before;
};

struct send_block_record {
	boolean_t		eos_marker; /* Marks the end of the stream */
	/* Marks that this record should be redacted. */
	boolean_t		redact_marker;
	blkptr_t		bp;
	zbookmark_phys_t	zb;
	uint8_t			indblkshift;
	uint32_t		datablksz;
	dmu_object_type_t	obj_type;
	bqueue_node_t		ln;
};

struct send_redact_record {
	bqueue_node_t		ln;
	boolean_t		eos_marker; /* Marks the end of the stream */
	uint64_t		start_object;
	uint64_t		start_blkid;
	uint64_t		end_object;
	uint64_t		end_blkid;
	uint8_t			indblkshift;
	uint32_t		datablksz;
};

/*
 * The list of data whose inclusion in a send stream can be pending from
 * one call to backup_cb to another.  Multiple calls to dump_free(),
 * dump_freeobjects(), and dump_redact() can be aggregated into a single
 * DRR_FREE, DRR_FREEOBJECTS, or DRR_REDACT replay record.
 */
typedef enum {
	PENDING_NONE,
	PENDING_FREE,
	PENDING_FREEOBJECTS,
	PENDING_REDACT
} dmu_pendop_t;

typedef struct dmu_send_cookie {
	dmu_replay_record_t *dsc_drr;
	dmu_send_outparams_t *dsc_dso;
	offset_t *dsc_off;
	objset_t *dsc_os;
	zio_cksum_t dsc_zc;
	uint64_t dsc_toguid;
	int dsc_err;
	dmu_pendop_t dsc_pending_op;
	uint64_t dsc_featureflags;
	uint64_t dsc_last_data_object;
	uint64_t dsc_last_data_offset;
	uint64_t dsc_resume_object;
	uint64_t dsc_resume_offset;
	boolean_t dsc_sent_begin;
	boolean_t dsc_sent_end;
} dmu_send_cookie_t;

/*
 * The redaction node is a wrapper around the redaction record that is used
 * by the redaction merging thread to sort the records and determine overlaps.
 *
 * It contains two nodes; one sorts the records by their start_zb, and the other
 * sorts the records by their end_zb.
 */
struct redact_node {
	avl_node_t			avl_node_start;
	avl_node_t			avl_node_end;
	struct send_redact_record	*record;
	struct send_thread_arg		*st_arg;
	uint32_t			thread_num;
};

/*
 * For all record types except BEGIN, fill in the checksum (overlaid in
 * drr_u.drr_checksum.drr_checksum).  The checksum verifies everything
 * up to the start of the checksum itself.
 */
static int
dump_record(dmu_send_cookie_t *dscp, void *payload, int payload_len)
{
	dmu_send_outparams_t *dso = dscp->dsc_dso;
	ASSERT3U(offsetof(dmu_replay_record_t, drr_u.drr_checksum.drr_checksum),
	    ==, sizeof (dmu_replay_record_t) - sizeof (zio_cksum_t));
	(void) fletcher_4_incremental_native(dscp->dsc_drr,
	    offsetof(dmu_replay_record_t, drr_u.drr_checksum.drr_checksum),
	    &dscp->dsc_zc);
	if (dscp->dsc_drr->drr_type == DRR_BEGIN) {
		dscp->dsc_sent_begin = B_TRUE;
	} else {
		ASSERT(ZIO_CHECKSUM_IS_ZERO(&dscp->dsc_drr->drr_u.
		    drr_checksum.drr_checksum));
		dscp->dsc_drr->drr_u.drr_checksum.drr_checksum = dscp->dsc_zc;
	}
	if (dscp->dsc_drr->drr_type == DRR_END) {
		dscp->dsc_sent_end = B_TRUE;
	}
	(void) fletcher_4_incremental_native(&dscp->dsc_drr->
	    drr_u.drr_checksum.drr_checksum,
	    sizeof (zio_cksum_t), &dscp->dsc_zc);
	*dscp->dsc_off += sizeof (dmu_replay_record_t);
	dscp->dsc_err = dso->dso_outfunc(dscp->dsc_drr,
	    sizeof (dmu_replay_record_t), dso->dso_arg);
	if (dscp->dsc_err != 0)
		return (SET_ERROR(EINTR));
	if (payload_len != 0) {
		*dscp->dsc_off += payload_len;
		/*
		 * payload is null when dso->ryrun == B_TRUE (i.e. when we're
		 * doing a send size calculation)
		 */
		if (payload != NULL) {
			(void) fletcher_4_incremental_native(
			    payload, payload_len, &dscp->dsc_zc);
		}
		dscp->dsc_err = dso->dso_outfunc(payload, payload_len,
		    dso->dso_arg);
		if (dscp->dsc_err != 0)
			return (SET_ERROR(EINTR));
	}
	return (0);
}

/*
 * Fill in the drr_free struct, or perform aggregation if the previous record is
 * also a free record, and the two are adjacent.
 *
 * Note that we send free records even for a full send, because we want to be
 * able to receive a full send as a clone, which requires a list of all the free
 * and freeobject records that were generated on the source.
 */
static int
dump_free(dmu_send_cookie_t *dscp, uint64_t object, uint64_t offset,
    uint64_t length)
{
	struct drr_free *drrf = &(dscp->dsc_drr->drr_u.drr_free);

	/*
	 * When we receive a free record, dbuf_free_range() assumes
	 * that the receiving system doesn't have any dbufs in the range
	 * being freed.  This is always true because there is a one-record
	 * constraint: we only send one WRITE record for any given
	 * object,offset.  We know that the one-record constraint is
	 * true because we always send data in increasing order by
	 * object,offset.
	 *
	 * If the increasing-order constraint ever changes, we should find
	 * another way to assert that the one-record constraint is still
	 * satisfied.
	 */
	ASSERT(object > dscp->dsc_last_data_object ||
	    (object == dscp->dsc_last_data_object &&
	    offset > dscp->dsc_last_data_offset));

	if (length != -1ULL && offset + length < offset)
		length = -1ULL;

	/*
	 * If there is a pending op, but it's not PENDING_FREE, push it out,
	 * since free block aggregation can only be done for blocks of the
	 * same type (i.e., DRR_FREE records can only be aggregated with
	 * other DRR_FREE records.  DRR_FREEOBJECTS records can only be
	 * aggregated with other DRR_FREEOBJECTS records).
	 */
	if (dscp->dsc_pending_op != PENDING_NONE &&
	    dscp->dsc_pending_op != PENDING_FREE) {
		if (dump_record(dscp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dscp->dsc_pending_op = PENDING_NONE;
	}

	if (dscp->dsc_pending_op == PENDING_FREE) {
		/*
		 * Check to see whether this free block can be aggregated
		 * with pending one.
		 */
		if (drrf->drr_object == object && drrf->drr_offset +
		    drrf->drr_length == offset) {
			if (length == UINT64_MAX)
				drrf->drr_length = UINT64_MAX;
			else
				drrf->drr_length += length;
			return (0);
		} else {
			/* not a continuation.  Push out pending record */
			if (dump_record(dscp, NULL, 0) != 0)
				return (SET_ERROR(EINTR));
			dscp->dsc_pending_op = PENDING_NONE;
		}
	}
	/* create a FREE record and make it pending */
	bzero(dscp->dsc_drr, sizeof (dmu_replay_record_t));
	dscp->dsc_drr->drr_type = DRR_FREE;
	drrf->drr_object = object;
	drrf->drr_offset = offset;
	drrf->drr_length = length;
	drrf->drr_toguid = dscp->dsc_toguid;
	if (length == -1ULL) {
		if (dump_record(dscp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
	} else {
		dscp->dsc_pending_op = PENDING_FREE;
	}

	return (0);
}

/*
 * Fill in the drr_redact struct, or perform aggregation if the previous record
 * is also a redaction record, and the two are adjacent.
 */
static int
dump_redact(dmu_send_cookie_t *dscp, uint64_t object, uint64_t offset,
    uint64_t length)
{
	struct drr_redact *drrr = &dscp->dsc_drr->drr_u.drr_redact;

	/*
	 * If there is a pending op, but it's not PENDING_REDACT, push it out,
	 * since free block aggregation can only be done for blocks of the
	 * same type (i.e., DRR_REDACT records can only be aggregated with
	 * other DRR_REDACT records).
	 */
	if (dscp->dsc_pending_op != PENDING_NONE &&
	    dscp->dsc_pending_op != PENDING_REDACT) {
		if (dump_record(dscp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dscp->dsc_pending_op = PENDING_NONE;
	}

	if (dscp->dsc_pending_op == PENDING_REDACT) {
		/*
		 * Check to see whether this redacted block can be aggregated
		 * with pending one.
		 */
		if (drrr->drr_object == object && drrr->drr_offset +
		    drrr->drr_length == offset) {
			drrr->drr_length += length;
			return (0);
		} else {
			/* not a continuation.  Push out pending record */
			if (dump_record(dscp, NULL, 0) != 0)
				return (SET_ERROR(EINTR));
			dscp->dsc_pending_op = PENDING_NONE;
		}
	}
	/* create a REDACT record and make it pending */
	bzero(dscp->dsc_drr, sizeof (dmu_replay_record_t));
	dscp->dsc_drr->drr_type = DRR_REDACT;
	drrr->drr_object = object;
	drrr->drr_offset = offset;
	drrr->drr_length = length;
	drrr->drr_toguid = dscp->dsc_toguid;
	dscp->dsc_pending_op = PENDING_REDACT;

	return (0);
}

static int
dump_write(dmu_send_cookie_t *dscp, dmu_object_type_t type,
    uint64_t object, uint64_t offset, int lsize, int psize, const blkptr_t *bp,
    void *data)
{
	uint64_t payload_size;
	struct drr_write *drrw = &(dscp->dsc_drr->drr_u.drr_write);

	/*
	 * We send data in increasing object, offset order.
	 * See comment in dump_free() for details.
	 */
	ASSERT(object > dscp->dsc_last_data_object ||
	    (object == dscp->dsc_last_data_object &&
	    offset > dscp->dsc_last_data_offset));
	dscp->dsc_last_data_object = object;
	dscp->dsc_last_data_offset = offset + lsize - 1;

	/*
	 * If there is any kind of pending aggregation (currently either
	 * a grouping of free objects or free blocks), push it out to
	 * the stream, since aggregation can't be done across operations
	 * of different types.
	 */
	if (dscp->dsc_pending_op != PENDING_NONE) {
		if (dump_record(dscp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dscp->dsc_pending_op = PENDING_NONE;
	}
	/* write a WRITE record */
	bzero(dscp->dsc_drr, sizeof (dmu_replay_record_t));
	dscp->dsc_drr->drr_type = DRR_WRITE;
	drrw->drr_object = object;
	drrw->drr_type = type;
	drrw->drr_offset = offset;
	drrw->drr_toguid = dscp->dsc_toguid;
	drrw->drr_logical_size = lsize;

	/* only set the compression fields if the buf is compressed */
	if (lsize != psize) {
		ASSERT(dscp->dsc_featureflags & DMU_BACKUP_FEATURE_COMPRESSED);
		ASSERT(!BP_IS_EMBEDDED(bp));
		ASSERT(!BP_SHOULD_BYTESWAP(bp));
		ASSERT(!DMU_OT_IS_METADATA(BP_GET_TYPE(bp)));
		ASSERT3U(BP_GET_COMPRESS(bp), !=, ZIO_COMPRESS_OFF);
		ASSERT3S(psize, >, 0);
		ASSERT3S(lsize, >=, psize);

		drrw->drr_compressiontype = BP_GET_COMPRESS(bp);
		drrw->drr_compressed_size = psize;
		payload_size = drrw->drr_compressed_size;
	} else {
		payload_size = drrw->drr_logical_size;
	}

	if (bp == NULL || BP_IS_EMBEDDED(bp)) {
		/*
		 * There's no pre-computed checksum for partial-block
		 * writes or embedded BP's, so (like
		 * fletcher4-checkummed blocks) userland will have to
		 * compute a dedup-capable checksum itself.
		 */
		drrw->drr_checksumtype = ZIO_CHECKSUM_OFF;
	} else {
		drrw->drr_checksumtype = BP_GET_CHECKSUM(bp);
		if (zio_checksum_table[drrw->drr_checksumtype].ci_flags &
		    ZCHECKSUM_FLAG_DEDUP)
			drrw->drr_checksumflags |= DRR_CHECKSUM_DEDUP;
		DDK_SET_LSIZE(&drrw->drr_key, BP_GET_LSIZE(bp));
		DDK_SET_PSIZE(&drrw->drr_key, BP_GET_PSIZE(bp));
		DDK_SET_COMPRESS(&drrw->drr_key, BP_GET_COMPRESS(bp));
		drrw->drr_key.ddk_cksum = bp->blk_cksum;
	}

	if (dump_record(dscp, data, payload_size) != 0)
		return (SET_ERROR(EINTR));
	return (0);
}

static int
dump_write_embedded(dmu_send_cookie_t *dscp, uint64_t object, uint64_t offset,
    int blksz, const blkptr_t *bp)
{
	char buf[BPE_PAYLOAD_SIZE];
	struct drr_write_embedded *drrw =
	    &(dscp->dsc_drr->drr_u.drr_write_embedded);

	if (dscp->dsc_pending_op != PENDING_NONE) {
		if (dump_record(dscp, NULL, 0) != 0)
			return (EINTR);
		dscp->dsc_pending_op = PENDING_NONE;
	}

	ASSERT(BP_IS_EMBEDDED(bp));

	bzero(dscp->dsc_drr, sizeof (dmu_replay_record_t));
	dscp->dsc_drr->drr_type = DRR_WRITE_EMBEDDED;
	drrw->drr_object = object;
	drrw->drr_offset = offset;
	drrw->drr_length = blksz;
	drrw->drr_toguid = dscp->dsc_toguid;
	drrw->drr_compression = BP_GET_COMPRESS(bp);
	drrw->drr_etype = BPE_GET_ETYPE(bp);
	drrw->drr_lsize = BPE_GET_LSIZE(bp);
	drrw->drr_psize = BPE_GET_PSIZE(bp);

	decode_embedded_bp_compressed(bp, buf);

	if (dump_record(dscp, buf, P2ROUNDUP(drrw->drr_psize, 8)) != 0)
		return (EINTR);
	return (0);
}

static int
dump_spill(dmu_send_cookie_t *dscp, uint64_t object, int blksz, void *data)
{
	struct drr_spill *drrs = &(dscp->dsc_drr->drr_u.drr_spill);

	if (dscp->dsc_pending_op != PENDING_NONE) {
		if (dump_record(dscp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dscp->dsc_pending_op = PENDING_NONE;
	}

	/* write a SPILL record */
	bzero(dscp->dsc_drr, sizeof (dmu_replay_record_t));
	dscp->dsc_drr->drr_type = DRR_SPILL;
	drrs->drr_object = object;
	drrs->drr_length = blksz;
	drrs->drr_toguid = dscp->dsc_toguid;

	if (dump_record(dscp, data, blksz) != 0)
		return (SET_ERROR(EINTR));
	return (0);
}

static int
dump_freeobjects(dmu_send_cookie_t *dscp, uint64_t firstobj, uint64_t numobjs)
{
	struct drr_freeobjects *drrfo = &(dscp->dsc_drr->drr_u.drr_freeobjects);

	/*
	 * If there is a pending op, but it's not PENDING_FREEOBJECTS,
	 * push it out, since free block aggregation can only be done for
	 * blocks of the same type (i.e., DRR_FREE records can only be
	 * aggregated with other DRR_FREE records.  DRR_FREEOBJECTS records
	 * can only be aggregated with other DRR_FREEOBJECTS records).
	 */
	if (dscp->dsc_pending_op != PENDING_NONE &&
	    dscp->dsc_pending_op != PENDING_FREEOBJECTS) {
		if (dump_record(dscp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dscp->dsc_pending_op = PENDING_NONE;
	}
	if (numobjs == 0)
		numobjs = UINT64_MAX - firstobj;

	if (dscp->dsc_pending_op == PENDING_FREEOBJECTS) {
		/*
		 * See whether this free object array can be aggregated
		 * with pending one
		 */
		if (drrfo->drr_firstobj + drrfo->drr_numobjs == firstobj) {
			drrfo->drr_numobjs += numobjs;
			return (0);
		} else {
			/* can't be aggregated.  Push out pending record */
			if (dump_record(dscp, NULL, 0) != 0)
				return (SET_ERROR(EINTR));
			dscp->dsc_pending_op = PENDING_NONE;
		}
	}

	/* write a FREEOBJECTS record */
	bzero(dscp->dsc_drr, sizeof (dmu_replay_record_t));
	dscp->dsc_drr->drr_type = DRR_FREEOBJECTS;
	drrfo->drr_firstobj = firstobj;
	drrfo->drr_numobjs = numobjs;
	drrfo->drr_toguid = dscp->dsc_toguid;

	dscp->dsc_pending_op = PENDING_FREEOBJECTS;

	return (0);
}

static int
dump_dnode(dmu_send_cookie_t *dscp, uint64_t object, dnode_phys_t *dnp)
{
	struct drr_object *drro = &(dscp->dsc_drr->drr_u.drr_object);

	if (object < dscp->dsc_resume_object) {
		/*
		 * Note: when resuming, we will visit all the dnodes in
		 * the block of dnodes that we are resuming from.  In
		 * this case it's unnecessary to send the dnodes prior to
		 * the one we are resuming from.  We should be at most one
		 * block's worth of dnodes behind the resume point.
		 */
		ASSERT3U(dscp->dsc_resume_object - object, <,
		    1 << (DNODE_BLOCK_SHIFT - DNODE_SHIFT));
		return (0);
	}

	if (dnp == NULL || dnp->dn_type == DMU_OT_NONE)
		return (dump_freeobjects(dscp, object, 1));

	if (dscp->dsc_pending_op != PENDING_NONE) {
		if (dump_record(dscp, NULL, 0) != 0)
			return (SET_ERROR(EINTR));
		dscp->dsc_pending_op = PENDING_NONE;
	}

	/* write an OBJECT record */
	bzero(dscp->dsc_drr, sizeof (dmu_replay_record_t));
	dscp->dsc_drr->drr_type = DRR_OBJECT;
	drro->drr_object = object;
	drro->drr_type = dnp->dn_type;
	drro->drr_bonustype = dnp->dn_bonustype;
	drro->drr_blksz = dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	drro->drr_bonuslen = dnp->dn_bonuslen;
	drro->drr_checksumtype = dnp->dn_checksum;
	drro->drr_compress = dnp->dn_compress;
	drro->drr_toguid = dscp->dsc_toguid;

	if (!(dscp->dsc_featureflags & DMU_BACKUP_FEATURE_LARGE_BLOCKS) &&
	    drro->drr_blksz > SPA_OLD_MAXBLOCKSIZE)
		drro->drr_blksz = SPA_OLD_MAXBLOCKSIZE;

	if (dump_record(dscp, DN_BONUS(dnp),
	    P2ROUNDUP(dnp->dn_bonuslen, 8)) != 0) {
		return (SET_ERROR(EINTR));
	}

	/* Free anything past the end of the file. */
	if (dump_free(dscp, object, (dnp->dn_maxblkid + 1) *
	    (dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT), -1ULL) != 0)
		return (SET_ERROR(EINTR));
	if (dscp->dsc_err != 0)
		return (SET_ERROR(EINTR));
	return (0);
}

static boolean_t
backup_do_embed(dmu_send_cookie_t *dscp, const blkptr_t *bp)
{
	if (!BP_IS_EMBEDDED(bp))
		return (B_FALSE);

	/*
	 * Compression function must be legacy, or explicitly enabled.
	 */
	if ((BP_GET_COMPRESS(bp) >= ZIO_COMPRESS_LEGACY_FUNCTIONS &&
	    !(dscp->dsc_featureflags & DMU_BACKUP_FEATURE_LZ4)))
		return (B_FALSE);

	/*
	 * Embed type must be explicitly enabled.
	 */
	switch (BPE_GET_ETYPE(bp)) {
	case BP_EMBEDDED_TYPE_DATA:
		if (dscp->dsc_featureflags & DMU_BACKUP_FEATURE_EMBED_DATA)
			return (B_TRUE);
		break;
	case BP_EMBEDDED_TYPE_MOOCH_BYTESWAP:
		if (dscp->dsc_featureflags &
		    DMU_BACKUP_FEATURE_EMBED_MOOCH_BYTESWAP)
			return (B_TRUE);
		break;
	default:
		return (B_FALSE);
	}
	return (B_FALSE);
}

/*
 * This function actually handles figuring out what kind of record needs to be
 * dumped, reading the data (which has hopefully been prefetched), and calling
 * the appropriate helper function.
 */
static int
do_dump(dmu_send_cookie_t *dscp, struct send_block_record *data)
{
	dsl_dataset_t *ds = dmu_objset_ds(dscp->dsc_os);
	const blkptr_t *bp = &data->bp;
	const zbookmark_phys_t *zb = &data->zb;
	uint8_t indblkshift = data->indblkshift;
	spa_t *spa = ds->ds_dir->dd_pool->dp_spa;
	dmu_object_type_t type = BP_GET_TYPE(bp);
	int err = 0;

	ASSERT3U(zb->zb_level, >=, 0);

	ASSERT(zb->zb_object == DMU_META_DNODE_OBJECT ||
	    zb->zb_object >= dscp->dsc_resume_object);

	if (zb->zb_object != DMU_META_DNODE_OBJECT &&
	    DMU_OBJECT_IS_SPECIAL(zb->zb_object)) {
		ASSERT(!data->redact_marker);
		return (0);
	} else if (BP_IS_HOLE(bp) &&
	    zb->zb_object == DMU_META_DNODE_OBJECT) {
		ASSERT(!data->redact_marker);
		uint64_t span = 0;
		/*
		 * If the block covers a range larger than 2^64 bytes, and it's
		 * not the zeroth block, then the first byte it addresses is
		 * beyond the valid size of the meta-dnode.  Such a block will
		 * always be a hole on both systems, so it's safe to simply not
		 * send it.
		 */
		if (!bp_span(data->datablksz, indblkshift, zb->zb_level,
		    &span) && zb->zb_blkid > 0) {
			return (0);
		}
		uint64_t dnobj = (zb->zb_blkid * span) >> DNODE_SHIFT;
		err = dump_freeobjects(dscp, dnobj, span >> DNODE_SHIFT);
	} else if (BP_IS_HOLE(bp)) {
		uint64_t span = UINT64_MAX;
		/*
		 * See comment in previous case.
		 */
		if (!bp_span(data->datablksz, indblkshift,
		    zb->zb_level, &span) && zb->zb_blkid > 0) {
			return (0);
		}
		uint64_t offset = 0;

		/*
		 * If this multiply overflows, we don't need to send this block.
		 * Even if it has a birth time, it can never not be a hole, so
		 * we don't need to send records for it.
		 */
		if (!overflow_multiply(zb->zb_blkid, span, &offset))
			return (0);

		/*
		 * We don't redact holes because of the case of large sparse
		 * files.  In that case, if you redact wrt no snapshots, if you
		 * redact holes you can end up trying to redact every block in
		 * your sparse file, even the ones that aren't written to.  This
		 * can cause extremely bad performance and space usage on the
		 * receiving system.
		 */
		err = dump_free(dscp, zb->zb_object, offset, span);
	} else if (zb->zb_level > 0) {
		uint64_t span = 0;
		ASSERT(!BP_IS_REDACTED(bp));
		if (!bp_span(data->datablksz, indblkshift,
		    zb->zb_level, &span) && zb->zb_blkid > 0) {
			/*
			 * In this case, we have a block which is not a hole,
			 * whose span is greater than 2^64.  In addition, it
			 * isn't the first block on that level.  This means that
			 * the first block is already adressing all 2^64 bytes,
			 * and this one claims to be address data despite the
			 * fact that the first byte of data it could address is
			 * out of bounds.
			 */
			zfs_panic_recover("bp_span overflowed");
		}
		uint64_t offset = 0;
		boolean_t overflow = overflow_multiply(zb->zb_blkid, span,
		    &offset);
		/*
		 * We're considering an indirect block that isn't a hole.
		 * Assert that its l0 equivalent's offset is < 2^64.
		 */
		ASSERT(overflow);
		ASSERT3U(span + offset, >, offset);
		return (0);
	} else if (BP_IS_REDACTED(bp)) {
		uint64_t span = UINT64_MAX;
		VERIFY(bp_span(data->datablksz, indblkshift, zb->zb_level,
		    &span));
		uint64_t offset = 0;
		boolean_t overflow = overflow_multiply(zb->zb_blkid, span,
		    &offset);
		ASSERT(overflow);
		ASSERT3U(span + offset, >, offset);
		err = dump_redact(dscp, zb->zb_object, offset, span);
	} else if (type == DMU_OT_OBJSET) {
		return (0);
	} else if (type == DMU_OT_DNODE) {
		int blksz = BP_GET_LSIZE(bp);
		arc_flags_t aflags = ARC_FLAG_WAIT;
		uint64_t dnobj = zb->zb_blkid * (blksz >> DNODE_SHIFT);
		arc_buf_t *abuf;

		ASSERT0(zb->zb_level);
		ASSERT(!data->redact_marker);

		if (arc_read(NULL, spa, bp, arc_getbuf_func, &abuf,
		    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_CANFAIL,
		    &aflags, zb) != 0)
			return (SET_ERROR(EIO));

		dnode_phys_t *blk = abuf->b_data;

		for (int i = 0; i < blksz >> DNODE_SHIFT; i++) {
			err = dump_dnode(dscp, dnobj + i, blk + i);
			if (err != 0)
				break;
		}
		arc_buf_destroy(abuf, &abuf);
	} else if (type == DMU_OT_SA) {
		arc_flags_t aflags = ARC_FLAG_WAIT;
		arc_buf_t *abuf;
		int blksz = BP_GET_LSIZE(bp);
		ASSERT(!data->redact_marker);

		if (arc_read(NULL, spa, bp, arc_getbuf_func, &abuf,
		    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_CANFAIL,
		    &aflags, zb) != 0)
			return (SET_ERROR(EIO));

		err = dump_spill(dscp, zb->zb_object, blksz,
		    abuf->b_data);
		arc_buf_destroy(abuf, &abuf);
	} else if (data->redact_marker) {
		ASSERT0(zb->zb_level);
		ASSERT(zb->zb_object > dscp->dsc_resume_object ||
		    (zb->zb_object == dscp->dsc_resume_object &&
		    zb->zb_blkid * data->datablksz >= dscp->dsc_resume_offset));
		err = dump_redact(dscp, zb->zb_object,  zb->zb_blkid *
		    data->datablksz, data->datablksz);
	} else if (backup_do_embed(dscp, bp)) {
		/* it's an embedded level-0 block of a regular object */
		ASSERT0(zb->zb_level);
		err = dump_write_embedded(dscp, zb->zb_object,
		    zb->zb_blkid * data->datablksz, data->datablksz, bp);
	} else {
		ASSERT0(zb->zb_level);
		ASSERT(zb->zb_object > dscp->dsc_resume_object ||
		    (zb->zb_object == dscp->dsc_resume_object &&
		    zb->zb_blkid * data->datablksz >= dscp->dsc_resume_offset));
		/* it's a level-0 block of a regular object */
		arc_flags_t aflags = ARC_FLAG_WAIT;
		arc_buf_t *abuf = NULL;
		uint64_t offset;

		/*
		 * If we have large blocks stored on disk but the send flags
		 * don't allow us to send large blocks, we split the data from
		 * the arc buf into chunks.
		 */
		boolean_t split_large_blocks =
		    data->datablksz > SPA_OLD_MAXBLOCKSIZE &&
		    !(dscp->dsc_featureflags & DMU_BACKUP_FEATURE_LARGE_BLOCKS);
		/*
		 * We should only request compressed data from the ARC if all
		 * the following are true:
		 *  - stream compression was requested
		 *  - we aren't splitting large blocks into smaller chunks
		 *  - the data won't need to be byteswapped before sending
		 *  - this isn't an embedded block
		 *  - this isn't metadata (if receiving on a different endian
		 *    system it can be byteswapped more easily)
		 */
		boolean_t request_compressed =
		    (dscp->dsc_featureflags & DMU_BACKUP_FEATURE_COMPRESSED) &&
		    !split_large_blocks && !BP_SHOULD_BYTESWAP(bp) &&
		    !BP_IS_EMBEDDED(bp) && !DMU_OT_IS_METADATA(BP_GET_TYPE(bp));

		ASSERT0(zb->zb_level);
		ASSERT(zb->zb_object > dscp->dsc_resume_object ||
		    (zb->zb_object == dscp->dsc_resume_object &&
		    zb->zb_blkid * data->datablksz >= dscp->dsc_resume_offset));

		ASSERT0(zb->zb_level);
		ASSERT(zb->zb_object > dscp->dsc_resume_object ||
		    (zb->zb_object == dscp->dsc_resume_object &&
		    zb->zb_blkid * data->datablksz >= dscp->dsc_resume_offset));

		if (BP_IS_EMBEDDED(bp) &&
		    BPE_GET_ETYPE(bp) == BP_EMBEDDED_TYPE_MOOCH_BYTESWAP) {
			objset_t *origin_objset;
			dmu_buf_t *origin_db;
			uint64_t origin_obj;

			VERIFY0(dmu_objset_mooch_origin(dscp->dsc_os,
			    &origin_objset));
			VERIFY0(dmu_objset_mooch_obj_refd(dscp->dsc_os,
			    zb->zb_object, &origin_obj));
			err = dmu_buf_hold(origin_objset, origin_obj,
			    zb->zb_blkid * data->datablksz, FTAG, &origin_db,
			    0);
			ASSERT3U(data->datablksz, ==, origin_db->db_size);
			if (err == 0 && !dscp->dsc_dso->dso_dryrun) {
				abuf = arc_alloc_buf(spa, &abuf, ARC_BUFC_DATA,
				    origin_db->db_size);
				mooch_byteswap_reconstruct(origin_db,
				    abuf->b_data, bp);
				dmu_buf_rele(origin_db, FTAG);
			}
		} else if (!dscp->dsc_dso->dso_dryrun) {
			enum zio_flag zioflags = ZIO_FLAG_CANFAIL;

			ASSERT3U(data->datablksz, ==, BP_GET_LSIZE(bp));

			if (request_compressed)
				zioflags |= ZIO_FLAG_RAW;

			err = arc_read(NULL, spa, bp, arc_getbuf_func, &abuf,
			    ZIO_PRIORITY_ASYNC_READ, zioflags, &aflags, zb);
		}
		if (err != 0) {
			if (zfs_send_corrupt_data &&
			    !dscp->dsc_dso->dso_dryrun) {
				/* Send a block filled with 0x"zfs badd bloc" */
				abuf = arc_alloc_buf(spa, &abuf, ARC_BUFC_DATA,
				    data->datablksz);
				uint64_t *ptr;
				for (ptr = abuf->b_data;
				    (char *)ptr < (char *)abuf->b_data +
				    data->datablksz; ptr++)
					*ptr = 0x2f5baddb10cULL;
			} else {
				return (SET_ERROR(EIO));
			}
		}

		offset = zb->zb_blkid * data->datablksz;

		if (split_large_blocks) {
			ASSERT3U(arc_get_compression(abuf), ==,
			    ZIO_COMPRESS_OFF);
			char *buf = abuf->b_data;
			while (data->datablksz > 0 && err == 0) {
				int n = MIN(data->datablksz,
				    SPA_OLD_MAXBLOCKSIZE);
				err = dump_write(dscp, type, zb->zb_object,
				    offset, n, n, NULL, buf);
				offset += n;
				buf += n;
				data->datablksz -= n;
			}
		} else {
			int psize;
			if (abuf != NULL) {
				psize = arc_buf_size(abuf);
				if (arc_get_compression(abuf) !=
				    ZIO_COMPRESS_OFF) {
					ASSERT3S(psize, ==, BP_GET_PSIZE(bp));
				}
			} else if (!request_compressed) {
				psize = data->datablksz;
			} else {
				psize = BP_GET_PSIZE(bp);
			}
			err = dump_write(dscp, type, zb->zb_object, offset,
			    data->datablksz, psize, bp, (abuf == NULL ? NULL :
			    abuf->b_data));
		}
		if (abuf != NULL)
			arc_buf_destroy(abuf, &abuf);
	}

	ASSERT(err == 0 || err == EINTR);
	return (err);
}

/*
 * This thread finds any blocks in the given object between start and start +
 * len (or the end of the file, if len is 0), and creates artificial records for
 * them.  This will force the main thread to use the to_ds's version of the
 * data.  It does this via dmu_offset_next, which intelligently traverses the
 * tree using the blkfill field in the blkptrs.
 */
static int
enqueue_block_range(struct send_thread_arg *sta,
    uint64_t object, uint64_t offset, uint64_t len)
{
	objset_t *to_os = sta->to_os;
	uint64_t end;
	int err = 0;
	dmu_object_info_t doi;

	ASSERT(object != 0);

	if (len == 0)
		end = UINT64_MAX;
	else
		end = offset + len;

	err = dmu_object_info(to_os, object, &doi);
	if (err != 0)
		return (err);

	/*
	 * When we are traversing the tosnap, we will always resume from
	 * the exact resume point.  However, when we are traversing the
	 * fromsnap, we may resume from a bookmark that is earlier than
	 * we intended, if there is not a block pointer that starts
	 * exactly at the resume point.  This is possible because the
	 * resume point corresponds to a bookmark in the tosnap, and the
	 * fromsnap can be arbitrarily different from the tosnap.
	 *
	 * To deal with this, we must adjust the records that we enqueue,
	 * so that do_dump() does not see any bookmarks that are before the
	 * resume point.
	 */

	if (object < sta->resume.zb_object)
		return (0);

	if (object == sta->resume.zb_object &&
	    offset / doi.doi_data_block_size < sta->resume.zb_blkid) {
		/*
		 * We are trying to enqueue a range that is before the
		 * resume point.  If the range is entirely before the resume
		 * point, ignore it.  Otherwise, start enqueing at the
		 * resume point.
		 */
		uint64_t resume_off =
		    sta->resume.zb_blkid * doi.doi_data_block_size;
		if (end <= resume_off)
			return (0);
		offset = resume_off;
		/*
		 * Note: Because we've advanced "offset", "len" no longer
		 * reflects the range to enqueue, and should not be used
		 * past this point.  "end" should be used instead.
		 */
	}

	err = dmu_offset_next(to_os, object, B_FALSE, &offset);
	while (offset < end && err == 0) {
		struct send_block_record *record;

		record = kmem_zalloc(sizeof (*record), KM_SLEEP);
		record->eos_marker = B_FALSE;
		record->zb.zb_objset = 0;
		record->zb.zb_object = object;
		record->zb.zb_level = 0;
		record->zb.zb_blkid = offset / doi.doi_data_block_size;
		record->indblkshift =
		    highbit64(doi.doi_metadata_block_size) - 1;
		record->datablksz = doi.doi_data_block_size;

		bqueue_enqueue(&sta->q, record, sizeof (*record));
		offset += doi.doi_data_block_size;
		err = dmu_offset_next(to_os, object, B_FALSE, &offset);
	}
	if (err == ESRCH)
		err = 0;
	return (err);
}

static int
enqueue_whole_object(struct send_thread_arg *sta, uint64_t object)
{
	int err = enqueue_block_range(sta, object, 0, 0);
	if (err == ENOENT)
		err = 0;
	return (err);
}

/*
 * This function handles some of the special cases described in send_cb.
 * If a hole is created in the meta-dnode, this thread calls
 * enqueue_whole_object on every object that is allocated in the
 * corresponding range in the to_ds.  It finds these objects by using
 * dmu_object_next, which uses the blkfill field of the blkptrs to
 * efficiently traverse the tree.
 *
 * If a hole is created inside an object, we calculate the range it
 * covers, and use equiv_find to fabricate records for any data blocks
 * that might exist in to_ds.
 */
static int
enqueue_holes(struct send_thread_arg *sta, const zbookmark_phys_t *zb,
    const blkptr_t *bp, uint8_t indblkshift, uint32_t datablksz)
{
	objset_t *to_os = sta->to_os;
	uint64_t span = 0;
	uint64_t blkid = zb->zb_blkid;
	int err = 0;
	if (!BP_IS_HOLE(bp))
		return (0);

	if (!bp_span(datablksz, indblkshift, zb->zb_level, &span) &&
	    zb->zb_blkid != 0)
		return (0);

	if (zb->zb_object == DMU_META_DNODE_OBJECT) {
		boolean_t entire_object = B_FALSE;
		if (span == 0)
			entire_object = B_TRUE;
		int epb = span >> DNODE_SHIFT; /* entries per block */

		for (uint64_t obj = blkid * epb;
		    err == 0 && (entire_object || obj < (blkid + 1) * epb);
		    err = dmu_object_next(to_os, &obj, B_FALSE, 0)) {
			/*
			 * Object 0 is invalid (used to specify
			 * the META_DNODE object).
			 */
			if (obj == 0)
				obj = 1;
			err = enqueue_whole_object(sta, obj);
			/*
			 * Note: we must explicitly "break" so that
			 * dmu_object_next() does not overwrite "err".
			 */
			if (err != 0)
				break;
		}

		if (err == ESRCH)
			err = 0;
	} else if (zb->zb_level > 0) {
		err = enqueue_block_range(sta, zb->zb_object, span * blkid,
		    span);
		if (err == ENOENT)
			err = 0;
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
    const zbookmark_phys_t *zb, const struct dnode_phys *dnp, void *arg)
{
	struct send_thread_arg *sta = arg;
	objset_t *to_os = sta->to_os;
	struct send_block_record *record;
	int err = 0;

	ASSERT(zb->zb_object == DMU_META_DNODE_OBJECT ||
	    zb->zb_object >= sta->resume.zb_object);

	if (sta->cancel)
		return (SET_ERROR(EINTR));
	atomic_inc_64(sta->num_blocks_visited);

	if (sta->ignore_object != 0 && zb->zb_object == sta->ignore_object)
		return (0);

	if (bp == NULL) {
		ASSERT3U(zb->zb_level, ==, ZB_DNODE_LEVEL);

		/* Ignore if we are traversing the tosnap. */
		if (to_os == NULL || zb->zb_object == 0)
			return (0);

		/*
		 * If this object is fundamentally different
		 * from the corresponding object in the tosnap,
		 * then we must enqueue the whole object, and ignore
		 * any further callbacks for this object.  Any callbacks
		 * we receive later that we do not ignore, then, must be
		 * for a compatible object.
		 */
		if (dnp->dn_type == DMU_OT_NONE) {
			sta->ignore_object = zb->zb_object;
			return (enqueue_whole_object(sta, zb->zb_object));
		}

		dmu_object_info_t tosnap_obj_info;
		err = dmu_object_info(to_os, zb->zb_object, &tosnap_obj_info);
		if (err == ENOENT)
			return (0);
		if (err != 0)
			return (err);
		if (tosnap_obj_info.doi_data_block_size !=
		    dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT ||
		    tosnap_obj_info.doi_metadata_block_size !=
		    1 << dnp->dn_indblkshift) {
			sta->ignore_object = zb->zb_object;
			return (enqueue_whole_object(sta, zb->zb_object));
		}
		return (0);
	} else if (zb->zb_level < 0) {
		return (0);
	}
	uint64_t span = bp_span_in_blocks(dnp->dn_indblkshift, zb->zb_level);

	if (!DMU_OT_IS_METADATA(dnp->dn_type) &&
	    span * zb->zb_blkid > dnp->dn_maxblkid) {
		ASSERT(BP_IS_HOLE(bp));
		return (0);
	}

	record = kmem_zalloc(sizeof (struct send_block_record), KM_SLEEP);
	record->eos_marker = B_FALSE;
	record->bp = *bp;
	record->zb = *zb;
	record->indblkshift = dnp->dn_indblkshift;
	record->datablksz = dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	record->obj_type = dnp->dn_type;
	bqueue_enqueue(&sta->q, record, sizeof (*record));

	/*
	 * We also need to handle a special case: If there is a new hole in the
	 * from_ds that was not modified since the common ancestor in the to_ds,
	 * we have to iterate over the data in the to_ds to get the blocks to
	 * send so that we can recreate the to_ds.  This function,
	 * enqueue_holes, handles both that case.  We only call it when to_os is
	 * passed in because that is how we know we're the thread handling the
	 * from_ds.
	 */
	if (to_os != NULL) {
		err = enqueue_holes(sta, zb, bp, dnp->dn_indblkshift,
		    dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT);
	}
	return (err);
}

struct send_redact_list_cb_arg {
	uint64_t *num_blocks_visited;
	bqueue_t *q;
	boolean_t *cancel;
};

int
send_redact_list_cb(redact_block_phys_t *rb, void *arg)
{
	struct send_redact_list_cb_arg *srlcap = arg;
	bqueue_t *q = srlcap->q;
	uint64_t *num_blocks_visited = srlcap->num_blocks_visited;
	for (uint64_t i = 0; i < redact_block_get_count(rb); i++) {
		if (*srlcap->cancel)
			return (-1);
		atomic_inc_64(num_blocks_visited);
		struct send_block_record *data;
		data = kmem_zalloc(sizeof (*data), KM_SLEEP);
		SET_BOOKMARK(&data->zb, 0, rb->rbp_object, 0,
		    rb->rbp_blkid + i);
		data->datablksz = redact_block_get_size(rb);
		/*
		 * We only redact user data, so we know that this object
		 * contained plain file contents.
		 */
		data->obj_type = DMU_OT_PLAIN_FILE_CONTENTS;
		bqueue_enqueue(q, data, sizeof (*data));
	}
	return (0);
}

/*
 * This function kicks off the traverse_dataset.  It also handles setting the
 * error code of the thread in case something goes wrong, and pushes the End of
 * Stream record when the traverse_dataset call has finished.  If there is no
 * dataset to traverse, the thread immediately pushes End of Stream marker.
 */
static void
send_traverse_thread(void *arg)
{
	struct send_thread_arg *st_arg = arg;
	int err = 0;
	struct send_block_record *data;

	if (st_arg->ds != NULL) {
		ASSERT3P(st_arg->redaction_list, ==, NULL);
		err = traverse_dataset_resume(st_arg->ds,
		    st_arg->fromtxg, &st_arg->resume,
		    st_arg->flags, send_cb, st_arg);
	} else if (st_arg->redaction_list != NULL) {
		struct send_redact_list_cb_arg srlcba = {0};
		srlcba.cancel = &st_arg->cancel;
		srlcba.num_blocks_visited = st_arg->num_blocks_visited;
		srlcba.q = &st_arg->q;
		err = dsl_redaction_list_traverse(st_arg->redaction_list,
		    &st_arg->resume, send_redact_list_cb, &srlcba);
	}

	if (err != EINTR)
		st_arg->error_code = err;
	data = kmem_zalloc(sizeof (*data), KM_SLEEP);
	data->eos_marker = B_TRUE;
	bqueue_enqueue(&st_arg->q, data, sizeof (*data));
	bqueue_flush(&st_arg->q);
}

/*
 * We've found a new redaction candidate.  In order to improve performance, we
 * coalesce these blocks when they're adjacent to each other.  This function
 * handles that.  If the new candidate block range is immediately after the
 * range we're building, coalesce it into the range we're building.  Otherwise,
 * put the record we're building on the queue, and update the build pointer to
 * point to the new record.
 */
static void
redact_record_merge_enqueue(bqueue_t *q, struct send_redact_record **build,
    struct send_redact_record *new)
{
	if (new->eos_marker) {
		if (*build != NULL)
			bqueue_enqueue(q, *build, sizeof (*build));
		bqueue_enqueue(q, new, sizeof (*new));
		return;
	}
	if (*build == NULL) {
		*build = new;
		return;
	}
	struct send_redact_record *curbuild = *build;
	if ((curbuild->end_object == new->start_object &&
	    curbuild->end_blkid + 1 == new->start_blkid) ||
	    (curbuild->end_object + 1 == new->start_object &&
	    curbuild->end_blkid == UINT64_MAX && new->start_blkid == 0)) {
		curbuild->end_object = new->end_object;
		curbuild->end_blkid = new->end_blkid;
		kmem_free(new, sizeof (*new));
	} else {
		bqueue_enqueue(q, curbuild, sizeof (*curbuild));
		*build = new;
	}
}

/*
 * This is the callback function to traverse_dataset for the redaction threads
 * for dmu_send_impl.  This thread is responsible for creating redaction records
 * for all the data that is modified by the snapshots we're redacting with
 * respect to.  Redaction records represent ranges of data that have been
 * modified by one of our redaction snapshots, and are stored in the
 * send_redact_record struct. We need to create redaction records for three
 * cases:
 *
 * First, if there's a normal write, we need to create a redaction record for
 * that block.
 *
 * Second, if there's a hole, we need to create a redaction record that covers
 * the whole range of the hole.  If the hole is in the meta-dnode, it must cover
 * every block in all of the objects in the hole.
 *
 * Third, if there is a deleted object, we need to create a redaction record for
 * all of the blocks in that object.
 *
 * While redaction is best understood as "only send blocks referenced by one of
 * the redaction snapshots", our existing infrastructure only allows us to
 * easily detect blocks that the redaction snapshots no longer reference.  As a
 * result, we have to find the intersection of the sets of no-longer-referenced
 * blocks across all the redaction snapshots; the complement of that set is the
 * set of blocks we can send.
 */
/*ARGSUSED*/
static int
redact_cb(spa_t *spa, zilog_t *zilog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const struct dnode_phys *dnp, void *arg)
{
	struct send_thread_arg *sta = arg;
	struct send_redact_record *record;

	ASSERT(zb->zb_object == DMU_META_DNODE_OBJECT ||
	    zb->zb_object >= sta->resume.zb_object);

	if (sta->cancel)
		return (SET_ERROR(EINTR));
	atomic_inc_64(sta->num_blocks_visited);

	/*
	 * If we're visiting a dnode, we need to handle the case where the
	 * object has been deleted.
	 */
	if (bp == NULL) {
		ASSERT3U(zb->zb_level, ==, ZB_DNODE_LEVEL);

		if (zb->zb_object == 0)
			return (0);

		/*
		 * If the object has been deleted, redact all of the blocks in
		 * it.
		 */
		if (dnp->dn_type == DMU_OT_NONE ||
		    objlist_exists(sta->deleted_objs, zb->zb_object)) {
			sta->ignore_object = zb->zb_object;
			record = kmem_zalloc(sizeof (struct send_redact_record),
			    KM_SLEEP);

			record->eos_marker = B_FALSE;
			record->start_object = record->end_object =
			    zb->zb_object;
			record->start_blkid = 0;
			record->end_blkid = UINT64_MAX;
			redact_record_merge_enqueue(&sta->q,
			    &sta->current_record, record);
		}
		return (0);
	} else if (zb->zb_level < 0) {
		return (0);
	} else if (zb->zb_level > 0 && !BP_IS_HOLE(bp)) {
		/*
		 * If this is an indirect block, but not a hole, it doesn't
		 * provide any useful information for redaction, so ignore it.
		 */
		return (0);
	}

	/*
	 * At this point, there are two options left for the type of block we're
	 * looking at.  Either this is a hole (which could be in the dnode or
	 * the meta-dnode), or it's a level 0 block of some sort.  If it's a
	 * hole, we create a redaction record that covers the whole range.  If
	 * the hole is in a dnode, we need to redact all the blocks in that
	 * hole.  If the hole is in the meta-dnode, we instead need to redact
	 * all blocks in every object covered by that hole.  If it's a level 0
	 * block, we only need to redact that single block.
	 */
	record = kmem_zalloc(sizeof (struct send_redact_record), KM_SLEEP);
	record->eos_marker = B_FALSE;

	record->start_object = record->end_object = zb->zb_object;
	if (BP_IS_HOLE(bp)) {
		record->start_blkid = zb->zb_blkid *
		    bp_span_in_blocks(dnp->dn_indblkshift, zb->zb_level);

		record->end_blkid = ((zb->zb_blkid + 1) *
		    bp_span_in_blocks(dnp->dn_indblkshift, zb->zb_level)) - 1;

		if (zb->zb_object == DMU_META_DNODE_OBJECT) {
			record->start_object = record->start_blkid *
			    ((SPA_MINBLOCKSIZE * dnp->dn_datablkszsec) /
			    DNODE_SIZE);
			record->start_blkid = 0;
			record->end_object = ((record->end_blkid +
			    1) * ((SPA_MINBLOCKSIZE * dnp->dn_datablkszsec) /
			    DNODE_SIZE)) - 1;
			record->end_blkid = UINT64_MAX;
		}
	} else if (zb->zb_level != 0) {
		kmem_free(record, sizeof (*record));
		return (0);
	} else {
		record->start_blkid = record->end_blkid = zb->zb_blkid;
	}
	record->indblkshift = dnp->dn_indblkshift;
	record->datablksz = dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	redact_record_merge_enqueue(&sta->q, &sta->current_record, record);

	return (0);
}

/*
 * This function kicks off the traverse_dataset call for one of the snapshots
 * we're redacting with respect to.  It also handles setting error codes when
 * something goes wrong, and pushing an End of Stream record when the traversal
 * has finished.
 */
static void
redact_traverse_thread(void *arg)
{
	struct send_thread_arg *st_arg = arg;
	int err;
	struct send_redact_record *data;
	objset_t *os;
	VERIFY0(dmu_objset_from_ds(st_arg->ds, &os));
#ifdef _KERNEL
	if (os->os_phys->os_type == DMU_OST_ZFS)
		st_arg->deleted_objs = zfs_get_deleteq(os);
	else
		st_arg->deleted_objs = objlist_create();
#else
	st_arg->deleted_objs = objlist_create();
#endif

	err = traverse_dataset_resume(st_arg->ds, st_arg->fromtxg,
	    &st_arg->resume, st_arg->flags, redact_cb, st_arg);

	if (err != EINTR)
		st_arg->error_code = err;
	objlist_destroy(st_arg->deleted_objs);
	data = kmem_zalloc(sizeof (*data), KM_SLEEP);
	data->eos_marker = B_TRUE;
	redact_record_merge_enqueue(&st_arg->q, &st_arg->current_record, data);
	bqueue_flush(&st_arg->q);
}

static inline void
create_zbookmark_from_obj_off(zbookmark_phys_t *zb, uint64_t object,
    uint64_t blkid)
{
	zb->zb_object = object;
	zb->zb_level = 0;
	zb->zb_blkid = blkid;
}

/*
 * This is a utility function that can do the comparison for the start or ends
 * of the ranges in a send_redact_record.
 */
static int
redact_range_compare(uint64_t obj1, uint64_t off1, uint32_t dbss1,
    uint64_t obj2, uint64_t off2, uint32_t dbss2)
{
	zbookmark_phys_t z1, z2;
	create_zbookmark_from_obj_off(&z1, obj1, off1);
	create_zbookmark_from_obj_off(&z2, obj2, off2);

	return (zbookmark_compare(dbss1 >> SPA_MINBLOCKSHIFT, 0,
	    dbss2 >> SPA_MINBLOCKSHIFT, 0, &z1, &z2));
}

/*
 * Utility function that compares two redaction records to determine if any part
 * of the "from" record is before any part of the "to" record. Also causes End
 * of Stream redaction records to compare after all others, so that the
 * redaction merging logic can stay simple.
 */
static boolean_t
redact_record_before(const struct send_redact_record *from,
    const struct send_redact_record *to)
{
	if (from->eos_marker == B_TRUE)
		return (B_FALSE);
	else if (to->eos_marker == B_TRUE)
		return (B_TRUE);
	return (redact_range_compare(from->start_object, from->start_blkid,
	    from->datablksz, to->end_object, to->end_blkid,
	    to->datablksz) <= 0);
}


/*
 * Compare two redaction records by their range's start location.  Also makes
 * eos records always compare last.  We use the thread number in the redact_node
 * to ensure that records do not compare equal (which is not allowed in our avl
 * trees).
 */
static int
redact_node_compare_start(const void *arg1, const void *arg2)
{
	const struct redact_node *rn1 = arg1;
	const struct redact_node *rn2 = arg2;
	const struct send_redact_record *srr1 = rn1->record;
	const struct send_redact_record *srr2 = rn2->record;
	if (srr1->eos_marker)
		return (1);
	if (srr2->eos_marker)
		return (-1);

	int cmp = redact_range_compare(srr1->start_object, srr1->start_blkid,
	    srr1->datablksz, srr2->start_object, srr2->start_blkid,
	    srr2->datablksz);
	if (cmp == 0)
		cmp = (rn1->thread_num < rn2->thread_num ? -1 : 1);
	return (cmp);
}

/*
 * Compare two redaction records by their range's end location.  Also makes
 * eos records always compare last.  We use the thread number in the redact_node
 * to ensure that records do not compare equal (which is not allowed in our avl
 * trees).
 */
static int
redact_node_compare_end(const void *arg1, const void *arg2)
{
	const struct redact_node *rn1 = arg1;
	const struct redact_node *rn2 = arg2;
	const struct send_redact_record *srr1 = rn1->record;
	const struct send_redact_record *srr2 = rn2->record;
	if (srr1->eos_marker)
		return (1);
	if (srr2->eos_marker)
		return (-1);

	int cmp = redact_range_compare(srr1->end_object, srr1->end_blkid,
	    srr1->datablksz, srr2->end_object, srr2->end_blkid,
	    srr2->datablksz);
	if (cmp == 0)
		cmp = (rn1->thread_num < rn2->thread_num ? -1 : 1);
	return (cmp);
}

/*
 * Pop a new redaction record off the queue, check that the records are in the
 * right order, and free the old data.
 */
static struct send_redact_record *
get_next_redact_record(bqueue_t *bq, struct send_redact_record *prev)
{
	struct send_redact_record *next = bqueue_dequeue(bq);
	ASSERT(redact_record_before(prev, next));
	kmem_free(prev, sizeof (*prev));
	return (next);
}

/*
 * Remove the given redaction node from both trees, pull a new redaction record
 * off the queue, free the old redaction record, update the redaction node, and
 * reinsert the node into the trees.
 */
static void
update_avl_trees(avl_tree_t *start_tree, avl_tree_t *end_tree,
    struct redact_node *redact_node)
{
	avl_remove(start_tree, redact_node);
	avl_remove(end_tree, redact_node);
	redact_node->record = get_next_redact_record(&redact_node->st_arg->q,
	    redact_node->record);
	avl_add(end_tree, redact_node);
	avl_add(start_tree, redact_node);
}

/*
 * This thread merges all the redaction records provided by the worker threads,
 * and determines which blocks are redacted by all the snapshots.  The algorithm
 * for doing so is similar to performing a merge in mergesort with n sub-lists
 * instead of 2, with some added complexity due to the fact that the entries are
 * ranges, not just single blocks.  This algorithm relies on the fact that the
 * queues are sorted, which is ensured by the fact that traverse_dataset
 * traverses the dataset in a consistent order.  We pull one entry off the front
 * of the queues of each secure dataset traversal thread.  Then we repeat the
 * following: each record represents a range of blocks modified by one of the
 * redaction snapshots, and each block in that range may need to be redacted in
 * the send stream.  Find the record with the latest start of its range, and the
 * record with the earliest end of its range. If the last start is before the
 * first end, then we know that the blocks in the range [last_start, first_end]
 * are covered by all of the ranges at the front of the queues, which means
 * every thread redacts that whole range.  For example, let's say the ranges on
 * each queue look like this:
 *
 * Block Id   1  2  3  4  5  6  7  8  9 10 11
 * Thread 1 |    [====================]
 * Thread 2 |       [========]
 * Thread 3 |             [=================]
 *
 * Thread 3 has the last start (5), and the thread 2 has the last end (6).  All
 * three threads modified the range [5,6], so that data should not be sent over
 * the wire.  After we've determined whether or not to redact anything, we take
 * the record with the first end.  We discard that record, and pull a new one
 * off the front of the queue it came from.  In the above example, we would
 * discard Thread 2's record, and pull a new one.  Let's say the next record we
 * pulled from Thread 2 covered range [10,11].  The new layout would look like
 * this:
 *
 * Block Id   1  2  3  4  5  6  7  8  9 10 11
 * Thread 1 |    [====================]
 * Thread 2 |                            [==]
 * Thread 3 |             [=================]
 *
 * When we compare the last start (10, from Thread 2) and the first end (9, from
 * Thread 1), we see that the last start is greater than the first end.
 * Therefore, we do not redact anything from these records.  We'll iterate by
 * replacing the record from Thread 1.
 *
 * We iterate by replacing the record with the lowest end because we know
 * that the record with the lowest end has helped us as much as it can.  All the
 * ranges before it that we will ever redact have been redacted.  In addition,
 * by replacing the one with the lowest end, we guarantee we catch all ranges
 * that need to be redacted.  For example, if in the case above we had replaced
 * the record from Thread 1 instead, we might have ended up with the following:
 *
 * Block Id   1  2  3  4  5  6  7  8  9 10 11 12
 * Thread 1 |                               [==]
 * Thread 2 |       [========]
 * Thread 3 |             [=================]
 *
 * If the next record from Thread 2 had been [8,10], for example, we should have
 * redacted part of that range, but because we updated Thread 1's record, we
 * missed it.
 *
 * We implement this algorithm by using two trees.  The first sorts the
 * redaction records by their start_zb, and the second sorts them by their
 * end_zb.  We use these to find the record with the last start and the record
 * with the first end.  We create a record with that start and end, and send it
 * on.  The overall runtime of this implementation is O(n log m), where n is the
 * total number of redaction records from all the different redaction snapshots,
 * and m is the number of redaction snapshots.
 *
 * If we redact with respect to zero snapshots, we create a redaction
 * record with the start object and blkid to 0, and the end object and blkid to
 * UINT64_MAX.  This will result in us redacting every block.
 */
static void
perform_thread_merge(bqueue_t *q, uint32_t num_threads,
    struct send_thread_arg *thread_args, boolean_t *cancel)
{
	struct redact_node *redact_nodes = NULL;
	avl_tree_t start_tree, end_tree;
	struct send_redact_record *record;
	struct send_redact_record *current_record = NULL;

	/*
	 * If we're redacting with respect to zero snapshots, then no data is
	 * permitted to be sent.  We enqueue a record that redacts all blocks,
	 * and an eos marker.
	 */
	if (num_threads == 0) {
		record = kmem_zalloc(sizeof (struct send_redact_record),
		    KM_SLEEP);
		record->start_object = record->start_blkid = 0;
		record->end_object = record->end_blkid = UINT64_MAX;
		bqueue_enqueue(q, record, sizeof (*record));
		return;
	}
	if (num_threads > 0) {
		redact_nodes = kmem_zalloc(num_threads *
		    sizeof (*redact_nodes), KM_SLEEP);
	}

	avl_create(&start_tree, redact_node_compare_start,
	    sizeof (struct redact_node),
	    offsetof(struct redact_node, avl_node_start));
	avl_create(&end_tree, redact_node_compare_end,
	    sizeof (struct redact_node),
	    offsetof(struct redact_node, avl_node_end));

	for (int i = 0; i < num_threads; i++) {
		struct redact_node *node = &redact_nodes[i];
		struct send_thread_arg *targ = &thread_args[i];
		node->record = bqueue_dequeue(&targ->q);
		node->st_arg = targ;
		node->thread_num = i;
		avl_add(&start_tree, node);
		avl_add(&end_tree, node);
	}

	/*
	 * Once the first record in the end tree has returned EOS, every record
	 * must be an EOS record, so we should stop.
	 */
	while (!((struct redact_node *)avl_first(&end_tree))->
	    record->eos_marker) {
		struct redact_node *last_start = avl_last(&start_tree);
		struct redact_node *first_end = avl_first(&end_tree);
		if (*cancel)
			break;

		/*
		 * If the last start record is before the first end record,
		 * then we have blocks that are redacted by all threads.
		 * Therefore, we should redact them.  Copy the record, and send
		 * it to the main thread.
		 */
		if (redact_record_before(last_start->record,
		    first_end->record)) {
			record = kmem_zalloc(sizeof (struct send_redact_record),
			    KM_SLEEP);
			*record = *first_end->record;
			record->start_object = last_start->record->start_object;
			record->start_blkid = last_start->record->start_blkid;
			redact_record_merge_enqueue(q, &current_record,
			    record);
		}
		update_avl_trees(&start_tree, &end_tree, first_end);
	}

	/*
	 * We're done; if we were cancelled, we need to cancel our workers and
	 * clear out their queues.  Either way, we need to remove every thread's
	 * redact_node struct from the avl trees.
	 */
	for (int i = 0; i < num_threads; i++) {
		if (*cancel) {
			thread_args[i].cancel = B_TRUE;
			while (!redact_nodes[i].record->eos_marker) {
				update_avl_trees(&start_tree, &end_tree,
				    &redact_nodes[i]);
			}
		}
		avl_remove(&start_tree, &redact_nodes[i]);
		avl_remove(&end_tree, &redact_nodes[i]);
		kmem_free(redact_nodes[i].record,
		    sizeof (struct send_redact_record));
	}

	avl_destroy(&start_tree);
	avl_destroy(&end_tree);
	kmem_free(redact_nodes, num_threads * sizeof (*redact_nodes));
	if (current_record != NULL)
		bqueue_enqueue(q, current_record, sizeof (current_record));
}

struct rmt_redact_list_cb_arg {
	uint64_t *num_blocks_visited;
	bqueue_t *q;
	boolean_t *cancel;
};

int
rmt_redact_list_cb(redact_block_phys_t *rb, void *arg)
{
	struct rmt_redact_list_cb_arg *rrlcbap = arg;
	bqueue_t *q = rrlcbap->q;
	uint64_t *num_blocks_visited = rrlcbap->num_blocks_visited;

	if (*rrlcbap->cancel)
		return (-1);
	atomic_inc_64(num_blocks_visited);

	struct send_redact_record *data = kmem_zalloc(sizeof (*data), KM_SLEEP);
	data->datablksz = redact_block_get_size(rb);
	data->start_blkid = rb->rbp_blkid;
	data->end_blkid = rb->rbp_blkid + redact_block_get_count(rb) - 1;
	data->start_object = rb->rbp_object;
	data->end_object = rb->rbp_object;
	bqueue_enqueue(q, data, sizeof (*data));
	return (0);
}

static void
redact_merge_thread(void *arg)
{
	struct redact_merge_thread_arg *mt_arg = arg;
	struct send_redact_record *record;
	if (mt_arg->rl != NULL) {
		struct rmt_redact_list_cb_arg rrlcba = {0};
		rrlcba.cancel = &mt_arg->cancel;
		rrlcba.q = &mt_arg->q;
		rrlcba.num_blocks_visited = mt_arg->num_blocks_visited;
		int err = dsl_redaction_list_traverse(mt_arg->rl,
		    &mt_arg->resume, rmt_redact_list_cb, &rrlcba);
		if (err != EINTR)
			mt_arg->error_code = err;
	} else {
		perform_thread_merge(&mt_arg->q, mt_arg->num_threads,
		    mt_arg->thread_args, &mt_arg->cancel);
	}
	record = kmem_zalloc(sizeof (struct send_redact_record), KM_SLEEP);
	record->eos_marker = B_TRUE;
	bqueue_enqueue(&mt_arg->q, record, sizeof (*record));
	bqueue_flush(&mt_arg->q);
}

/*
 * Utility function that causes End of Stream records to compare after of all
 * others, so that other threads' comparison logic can stay simple.
 */
static int
send_record_compare(const struct send_block_record *from,
    const struct send_block_record *to)
{
	if (from->eos_marker == B_TRUE)
		return (1);
	else if (to->eos_marker == B_TRUE)
		return (-1);
	return (zbookmark_compare(from->datablksz >> SPA_MINBLOCKSHIFT,
	    from->indblkshift, to->datablksz >> SPA_MINBLOCKSHIFT,
	    to->indblkshift, &from->zb, &to->zb));
}

/*
 * Pop the new data off the queue, check that the records we receive are in
 * the right order, but do not free the old data.  This is used so that the
 * records can be sent on to the main thread without copying the data.
 */
static struct send_block_record *
get_next_record_nofree(bqueue_t *bq, struct send_block_record *prev)
{
	struct send_block_record *next = bqueue_dequeue(bq);
	ASSERT3S(send_record_compare(prev, next), ==, -1);
	return (next);
}

/*
 * Pop the new data off the queue, check that the records we receive are in
 * the right order, and free the old data.
 */
static struct send_block_record *
get_next_record(bqueue_t *bq, struct send_block_record *prev)
{
	struct send_block_record *next = get_next_record_nofree(bq, prev);
	kmem_free(prev, sizeof (*prev));
	return (next);
}

/*
 * Returns -1 if redact_data is above data, 1 if data is above redact_data, 0 if
 * they're equal, and -2 if neither is above the other.  In this context,
 * record a being "above" record b means that record a has a higher level and
 * that record b is entirely in the tree of blocks that record a points to.  We
 * detect this by comparing the start and end of the range each record refers
 * to.
 *
 * There are two special cases; if the redact record says to redact all the
 * data, we always return -1, indicating that the data should be redacted.  If
 * the redact record is marked EOS, and isn't marked redact_all, then we return
 * -2 because the data should not be redacted.
 */
static int
is_above(struct send_redact_record *redact_data, struct send_block_record *data)
{
	zbookmark_phys_t data_start = data->zb;
	zbookmark_phys_t data_end = data->zb;
	zbookmark_phys_t redact_start;
	zbookmark_phys_t redact_end;
	int start_cmp, end_cmp;
	uint16_t ddbss = data->datablksz >> SPA_MINBLOCKSHIFT;
	uint16_t dind = data->indblkshift;
	uint16_t rdbss = redact_data->datablksz >> SPA_MINBLOCKSHIFT;
	uint16_t rind = redact_data->indblkshift;

	if (redact_data->eos_marker)
		return (-2);
	ASSERT(!data->eos_marker);
	create_zbookmark_from_obj_off(&redact_start, redact_data->start_object,
	    redact_data->start_blkid);
	create_zbookmark_from_obj_off(&redact_end, redact_data->end_object,
	    redact_data->end_blkid);

	/*
	 * Create bookmarks that point to the start and end of the block
	 * record's range.
	 */
	data_start.zb_blkid = data->zb.zb_blkid * bp_span_in_blocks(dind,
	    data->zb.zb_level);
	data_end.zb_blkid = ((data->zb.zb_blkid + 1) *
	    bp_span_in_blocks(dind, data->zb.zb_level)) - 1;
	data_start.zb_level = data_end.zb_level = 0;

	start_cmp = zbookmark_compare(rdbss, rind, ddbss, dind, &data_start,
	    &redact_start);
	end_cmp = zbookmark_compare(rdbss, rind, ddbss, dind, &data_end,
	    &redact_end);

	if (start_cmp == 0 && end_cmp == 0) {
		return (0);
	}

	if (start_cmp <= 0 && end_cmp >= 0)
		return (1);
	if (start_cmp >= 0 && end_cmp <= 0)
		return (-1);
	return (-2);
}

/*
 * Compare a redaction record to a block record.  Return -1 if the redact record
 * is strictly before the block record, and 1 if the opposite is true.  If there
 * is any overlap at all, we return 0.  There are two special cases.  If the
 * redact_all marker is set in the redact record, then they overlap and we
 * return 0.  If the eos marker is set in the redact record, then they don't
 * overlap, and we return 1, since the block record is before the redact record.
 */
static int
redact_block_compare(struct send_redact_record *redact_data,
    struct send_block_record *data)
{
	zbookmark_phys_t redact_start;
	zbookmark_phys_t redact_end;
	zbookmark_phys_t data_start = data->zb;
	zbookmark_phys_t data_end = data->zb;

	if (redact_data->eos_marker)
		return (1);
	ASSERT(!data->eos_marker);
	create_zbookmark_from_obj_off(&redact_start, redact_data->start_object,
	    redact_data->start_blkid);
	create_zbookmark_from_obj_off(&redact_end, redact_data->end_object,
	    redact_data->end_blkid);

	data_start.zb_blkid = data->zb.zb_blkid *
	    bp_span_in_blocks(data->indblkshift, data->zb.zb_level);
	data_start.zb_level = 0;
	data_end.zb_blkid = ((data->zb.zb_blkid + 1) *
	    bp_span_in_blocks(data->indblkshift, data->zb.zb_level)) - 1;
	data_end.zb_level = 0;

	if (zbookmark_compare(redact_data->datablksz >> SPA_MINBLOCKSHIFT,
	    redact_data->indblkshift, data->datablksz >> SPA_MINBLOCKSHIFT,
	    data->indblkshift, &redact_end, &data_start) < 0) {
		return (-1);
	}
	if (zbookmark_compare(redact_data->datablksz >> SPA_MINBLOCKSHIFT,
	    redact_data->indblkshift, data->datablksz >> SPA_MINBLOCKSHIFT,
	    data->indblkshift, &redact_start, &data_end) > 0) {
		return (1);
	}
	return (0);
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
 * Synctask for updating redaction lists.  We first take this txg's list of
 * redacted blocks and append those to the redaction list.  We then update the
 * redaction list's bonus buffer.  We store the furthest blocks we visited and
 * the list of snapshots that we're redacting with respect to.  We need these so
 * that redacted sends and receives can be correctly resumed.
 */
static void
redaction_list_update_sync(void *arg, dmu_tx_t *tx)
{
	struct redact_bookmark_info *rbi = arg;
	uint64_t txg = dmu_tx_get_txg(tx);
	list_t *list = &rbi->rbi_blocks[txg & TXG_MASK];
	redact_block_phys_t *furthest_visited =
	    &rbi->rbi_furthest[txg & TXG_MASK];
	objset_t *mos = tx->tx_pool->dp_meta_objset;
	redaction_list_t *rl = rbi->rbi_redaction_list;
	int bufsize = redact_sync_bufsize;
	redact_block_phys_t *buf = kmem_alloc(bufsize * sizeof (*buf),
	    KM_SLEEP);
	int index = 0;

	dmu_buf_will_dirty(rl->rl_dbuf, tx);

	for (struct redact_block_list_node *rbln = list_remove_head(list);
	    rbln != NULL; rbln = list_remove_head(list)) {
		ASSERT3U(rbln->block.rbp_object, <=,
		    furthest_visited->rbp_object);
		ASSERT(rbln->block.rbp_object < furthest_visited->rbp_object ||
		    rbln->block.rbp_blkid <= furthest_visited->rbp_blkid);
		buf[index] = rbln->block;
		index++;
		if (index == bufsize) {
			dmu_write(mos, rl->rl_object,
			    rl->rl_phys->rlp_num_entries * sizeof (*buf),
			    bufsize * sizeof (*buf), buf, tx);
			rl->rl_phys->rlp_num_entries += bufsize;
			index = 0;
		}
		kmem_free(rbln, sizeof (*rbln));
	}
	if (index > 0) {
		dmu_write(mos, rl->rl_object, rl->rl_phys->rlp_num_entries *
		    sizeof (*buf), index * sizeof (*buf), buf, tx);
		rl->rl_phys->rlp_num_entries += index;
	}
	kmem_free(buf, bufsize * sizeof (*buf));

	rbi->rbi_synctasc_txg[txg & TXG_MASK] = B_FALSE;
	rl->rl_phys->rlp_last_object = furthest_visited->rbp_object;
	rl->rl_phys->rlp_last_blkid = furthest_visited->rbp_blkid;
}

struct send_merge_data {
	list_t				redact_block_pending;
	redact_block_phys_t		coalesce_block;
	uint64_t			last_time;
};

/*
 * We want to store the list of blocks that we're redacting in the bookmark's
 * redaction list.  However, this list is stored in the MOS, which means it can
 * only be written to in syncing context.  To get around this, we create a
 * synctask that will write to the mos for us.  We tell it what to write by
 * a linked list for each current transaction group; every time we decide to
 * redact a block, we append it to the transaction group that is currently in
 * open context.  We also update some progress information that the synctask
 * will store to enable resumable redacted sends.
 */
static void
update_redaction_list(struct send_merge_data *smd, objset_t *os,
    struct redact_bookmark_info *rbi, uint64_t object, uint64_t blkid,
    uint32_t blksz, boolean_t redacted, boolean_t force)
{
	boolean_t enqueue = B_FALSE;
	redact_block_phys_t cur = {0};
	if (rbi->rbi_redaction_list == NULL)
		return;

	if (redacted) {
		ASSERT(!force);
		redact_block_phys_t *coalesce = &smd->coalesce_block;
		boolean_t new;
		if (coalesce->rbp_size_count == 0) {
			new = B_TRUE;
			enqueue = B_FALSE;
		} else  {
			uint64_t count = redact_block_get_count(coalesce);
			if (coalesce->rbp_object == object &&
			    coalesce->rbp_blkid + count == blkid &&
			    count < REDACT_BLOCK_MAX_COUNT) {
				ASSERT3U(redact_block_get_size(coalesce), ==,
				    blksz);
				redact_block_set_count(coalesce, count + 1);
				new = B_FALSE;
				enqueue = B_FALSE;
			} else {
				new = B_TRUE;
				enqueue = B_TRUE;
			}
		}

		if (new) {
			cur = *coalesce;
			coalesce->rbp_blkid = blkid;
			coalesce->rbp_object = object;

			redact_block_set_count(coalesce, 1);
			redact_block_set_size(coalesce, blksz);
		}
	} else {
		cur = smd->coalesce_block;
	}

	if ((enqueue || force) && !(redact_block_get_size(&cur) == 0)) {
		struct redact_block_list_node *rbln =
		    kmem_alloc(sizeof (struct redact_block_list_node),
		    KM_SLEEP);
		rbln->block = cur;
		list_insert_tail(&smd->redact_block_pending, rbln);
	}

	hrtime_t now = gethrtime();
	if (force || now > smd->last_time + redaction_list_update_interval_ns) {
		dmu_tx_t *tx =
		    dmu_tx_create_dd(spa_get_dsl(os->os_spa)->dp_mos_dir);
		dmu_tx_hold_space(tx, sizeof (struct redact_block_list_node));
		VERIFY0(dmu_tx_assign(tx, TXG_WAIT));
		uint64_t txg = dmu_tx_get_txg(tx);
		if (!rbi->rbi_synctasc_txg[txg & TXG_MASK]) {
			dsl_sync_task_nowait(dmu_tx_pool(tx),
			    redaction_list_update_sync, rbi, 5,
			    ZFS_SPACE_CHECK_NONE, tx);
			rbi->rbi_synctasc_txg[txg & TXG_MASK] = B_TRUE;
			rbi->rbi_latest_synctask_txg = txg;
		}

		rbi->rbi_furthest[txg & TXG_MASK].rbp_object = object;
		rbi->rbi_furthest[txg & TXG_MASK].rbp_blkid = blkid;
		list_move_tail(&rbi->rbi_blocks[txg & TXG_MASK],
		    &smd->redact_block_pending);

		dmu_tx_commit(tx);
		smd->last_time = now;
	}
}

/*
 * Merges redaction records from the redaction snapshots and block records from
 * the tosnap to figure out which blocks should be redacted.  If a block should
 * be redacted, we mark it so.  Either way, we then send the blocks to the main
 * thread.
 *
 * First, we pull redaction records until we find one that overlaps with or is
 * ahead of the block record.  Then, we check to see if either one fully
 * contains other.  If they're equal, or the redact record fully contains the
 * block record, then we know that all the data in the block record should be
 * redacted, so we mark the record as redact it and send it along.  If they
 * don't overlap at all, then we prefetch the data to improve performance, and
 * send the block record on to the main thread.  Finally, if the send record is
 * above the redaction record (perhaps because it's a hole and the redaction
 * record redacts a single block), then we ignore it.  If it's a hole, we don't
 * redact any subsets of it, because we don't need to redact a lack of data.  If
 * it's not a hole, it's an indirect block, which contains no data in and of
 * itself, so it need not be redacted.
 *
 * When we're done, we return the last redaction record we pulled off the queue.
 */
static struct send_redact_record *
redact_block_merge(struct send_merge_thread_arg *smta,
    struct send_merge_data *smd, bqueue_t *outq,
    struct send_redact_record *redact_data, struct send_block_record *data)
{
	zbookmark_phys_t *zb = &data->zb;
	int compare;
	bqueue_t *inq = &smta->redact_arg->q;
	boolean_t update_redaction = B_TRUE;
	boolean_t do_send = B_TRUE;
	objset_t *os = smta->os;

	while (redact_block_compare(redact_data, data) < 0) {
		redact_data = get_next_redact_record(inq, redact_data);
	}

	/*
	 * If the objset in the resume_redact_zb is non-zero, we are resuming a
	 * redacted send, and the redaction bookmark and the send stream did
	 * not end in the same place. Further, we have not caught up to
	 * whichever of the two was farther ahead, so we need to take special
	 * action in this case.
	 */
	if (smta->resume_redact_zb.zb_objset != 0) {
		if (zbookmark_compare(data->datablksz >> SPA_MINBLOCKSHIFT,
		    data->indblkshift, data->datablksz >> SPA_MINBLOCKSHIFT, 0,
		    &data->zb, &smta->resume_redact_zb) < 0) {
			if (smta->bookmark_before) {
				/*
				 * The bookmark's last update was before the
				 * end of the original send stream, and the
				 * current data is before the point where the
				 * original send stream ended, then we should
				 * update the redaction list and not send the
				 * data to the main thread or prefetch it.
				 */
				do_send = B_FALSE;
			} else {
				/*
				 * The bookmark's last update was after the
				 * end of the original send stream, and the
				 * current data is before the last update of the
				 * bookmark, then we should update prefetch the
				 * data and send the record to the main thread
				 * as normal, but we should not update the
				 * bookmark.
				 */
				update_redaction = B_FALSE;
			}
		} else {
			/*
			 * If the current data is after both the end of the
			 * original send stream and the end of the redaction
			 * bookmark, then the further behind of the two has
			 * caught up, and we should clear the resume_redact_zb
			 * and return to normal operation.
			 */
			bzero(&smta->resume_redact_zb,
			    sizeof (zbookmark_phys_t));
		}
	}

	if (DMU_OT_IS_METADATA(data->obj_type)) {
		compare = -2;
	} else {
		compare = is_above(redact_data, data);
	}
	switch (compare) {
	case 0:
		/*
		 * The two ranges are equal. We should redact the data.
		 */
		/* FALLTHROUGH */
	case -1:
		/*
		 * The redaction range is above the send record. Redact the data
		 * by marking it and sending it to the main thread.
		 */
		data->redact_marker = B_TRUE;
		break;
	case 1:
		/*
		 * In this case, the send record is above the redaction record.
		 * This happens if the send record points to a hole.  We don't
		 * create redaction records for holes, because doing so requires
		 * some complicated, finnicky code.  Since holes don't contain
		 * meaningful data, fabricating holes and redaction records
		 * doesn't gain us anything.
		 */
		break;
	case -2: {
		/*
		 * In this case, neither record is above the other, so we want
		 * to actually send the data on to the main thread.  For
		 * performance reasons, prefetching is handled by another
		 * thread, so we just pass the record on to them.
		 */
		break;
	}
	default:
		panic("Invalid return value from is_above: %d", compare);
		return (NULL);
	}

	if (update_redaction && zb->zb_level == 0 && zb->zb_object != 0) {
		update_redaction_list(smd, os, &smta->rbi, zb->zb_object,
		    zb->zb_blkid, data->datablksz, data->redact_marker,
		    B_FALSE);
	}
	if (do_send)
		bqueue_enqueue(outq, data, sizeof (*data));

	return (redact_data);
}

/*
 * Merge the results from the from thread and the to thread, and then hand the
 * records off to send_prefetch_thread to prefetch them.  If this is not a
 * send from a redaction bookmark, the from thread will push an end of stream
 * record and stop, and we'll just send everything that was changed in the
 * to_ds since the ancestor's creation txg. If it is, then since
 * traverse_dataset has a canonical order, we can compare each change as
 * they're pulled off the queues.  That will give us a stream that is
 * appropriately sorted, and covers all records.  In addition, we pull the
 * data from the redact_merge_thread and use that to determine which blocks
 * should be redacted.
 */
static void
send_merge_thread(void *arg)
{
	struct send_merge_thread_arg *smt_arg = arg;
	objset_t *os = smt_arg->os;
	struct send_thread_arg *from_arg = smt_arg->from_arg;
	struct send_thread_arg *to_arg = smt_arg->to_arg;
	struct redact_merge_thread_arg *rmt = smt_arg->redact_arg;
	bqueue_t *q = &smt_arg->q;
	struct send_block_record *from_data, *to_data;
	struct send_redact_record *redact_data;
	int err = 0;
	struct send_merge_data smd = { 0 };

	if (rmt == NULL) {
		redact_data = kmem_zalloc(sizeof (*redact_data), KM_SLEEP);
		redact_data->eos_marker = B_TRUE;
	} else {
		redact_data = bqueue_dequeue(&rmt->q);
		list_create(&smd.redact_block_pending,
		    sizeof (struct redact_block_list_node),
		    offsetof(struct redact_block_list_node, node));
	}
	from_data = bqueue_dequeue(&from_arg->q);
	to_data = bqueue_dequeue(&to_arg->q);

	while (!(from_data->eos_marker && to_data->eos_marker) && err == 0 &&
	    !smt_arg->cancel && from_arg->error_code == 0 &&
	    to_arg->error_code == 0 && (rmt == NULL || rmt->error_code == 0)) {
		int cmp = send_record_compare(from_data, to_data);
		if (cmp == 0) {
			/*
			 * Bookmarks are the same.
			 * Send data unless it's verifiably identical.
			 */

			/*
			 * We do this here because redact_block_merge consumes
			 * the to_data by passing it to another thread; if we
			 * get unlucky, this record will be freed before we
			 * return from redact_block_merge.
			 */
			struct send_block_record *next =
			    get_next_record_nofree(&to_arg->q, to_data);
			boolean_t strong = zio_checksum_table[
			    BP_GET_CHECKSUM(&to_data->bp)].ci_flags &
			    ZCHECKSUM_FLAG_NOPWRITE;
			if (BP_IS_EMBEDDED(&to_data->bp) &&
			    BP_IS_EMBEDDED(&from_data->bp)) {
				if (!embedded_bp_eq(&from_data->bp,
				    &to_data->bp)) {
					redact_data =
					    redact_block_merge(smt_arg, &smd, q,
					    redact_data, to_data);
				}
			} else if (!(strong && BP_GET_CHECKSUM(&to_data->bp) ==
			    BP_GET_CHECKSUM(&from_data->bp) &&
			    ZIO_CHECKSUM_EQUAL(to_data->bp.blk_cksum,
			    from_data->bp.blk_cksum))) {
				redact_data = redact_block_merge(smt_arg, &smd,
				    q, redact_data, to_data);
			}
			from_data = get_next_record(&from_arg->q, from_data);
			to_data = next;
		} else if (cmp < 0) {
			/*
			 * The "from" bookmark is ahead.  Send the record to the
			 * prefetch thread, which will retrieve and send to's
			 * version of the data.
			 */
			struct send_block_record *next =
			    get_next_record_nofree(&from_arg->q, from_data);
			ASSERT3U(from_data->zb.zb_objset, !=,
			    os->os_dsl_dataset->ds_object);
			redact_data = redact_block_merge(smt_arg, &smd, q,
			    redact_data, from_data);
			from_data = next;
		} else {
			/*
			 * The "to" bookmark is ahead.  Send the data.
			 */
			struct send_block_record *next =
			    get_next_record_nofree(&to_arg->q, to_data);
			redact_data = redact_block_merge(smt_arg, &smd, q,
			    redact_data, to_data);
			to_data = next;
		}
	}

	if (err == 0 && from_arg->error_code != 0)
		err = from_arg->error_code;
	if (err == 0 && to_arg->error_code != 0)
		err = to_arg->error_code;
	if (err == 0 && rmt != NULL && rmt->error_code != 0)
		err = rmt->error_code;

	if (err != 0 || smt_arg->cancel) {
		to_arg->cancel = B_TRUE;
		while (!to_data->eos_marker) {
			to_data = get_next_record(&to_arg->q, to_data);
		}
		from_arg->cancel = B_TRUE;
		while (!from_data->eos_marker) {
			from_data = get_next_record(&from_arg->q, from_data);
		}
		if (rmt != NULL)
			rmt->cancel = B_TRUE;
	}
	/*
	 * If there is no redaction thread, we created a dummy redaction record,
	 * so we don't need to special case that logic.  We always need to pull
	 * off any extra redaction records, in case the redaction thread was
	 * behind the from thread and the to thread.
	 */
	while (!redact_data->eos_marker) {
		redact_data = get_next_redact_record(&rmt->q, redact_data);
	}
	kmem_free(redact_data, sizeof (*redact_data));
	kmem_free(from_data, sizeof (*from_data));
	kmem_free(to_data, sizeof (*to_data));

	if (!smt_arg->cancel && err == 0) {
		update_redaction_list(&smd, os, &smt_arg->rbi, UINT64_MAX,
		    UINT64_MAX, 0, B_FALSE, B_TRUE);
	}
	/*
	 * Wait for all the redaction info to sync out before we return, so that
	 * anyone who attempts to resume this send will have all the data they
	 * need.
	 */
	if (rmt != NULL && smt_arg->rbi.rbi_redaction_list != NULL) {
		dsl_pool_t *dp = spa_get_dsl(os->os_spa);
		struct redact_bookmark_info *rbip = &smt_arg->rbi;
		if (rbip->rbi_latest_synctask_txg != 0)
			txg_wait_synced(dp, rbip->rbi_latest_synctask_txg);
		for (int i = 0; i < TXG_SIZE; i++)
			list_destroy(&rbip->rbi_blocks[i]);
	}

	smt_arg->error = err;
	from_data = kmem_zalloc(sizeof (struct send_block_record), KM_SLEEP);
	from_data->eos_marker = B_TRUE;
	bqueue_enqueue(&smt_arg->q, from_data, sizeof (*from_data));
	bqueue_flush(&smt_arg->q);
}

struct send_prefetch_thread_arg {
	struct send_merge_thread_arg *smta;
	bqueue_t q;
	boolean_t cancel;
	boolean_t issue_prefetches;
	int error;
};

/*
 * This thread is responsible for two things: First, it retrieves the correct
 * blkptr in the to ds if we need to send the data because of something from
 * the from thread.  As a result of this, we're the first ones to discover that
 * some indirect blocks can be discarded because they're not holes. Second,
 * it issues prefetches for the data we need to send.
 */
static void
send_prefetch_thread(void *arg)
{
	struct send_prefetch_thread_arg *spta = arg;
	struct send_merge_thread_arg *smta = spta->smta;
	bqueue_t *inq = &smta->q;
	bqueue_t *outq = &spta->q;
	objset_t *os = smta->os;
	struct send_block_record *data = bqueue_dequeue(inq);
	uint64_t data_size;
	int err = 0;

	/*
	 * If the record we're analyzing is from a redaction bookmark from the
	 * fromds, then we need to know whether or not it exists in the tods so
	 * we know whether to create records for it or not. If it does, we need
	 * the datablksz so we can generate an appropriate record for it.
	 * Finally, if it isn't redacted, we need the blkptr so that we can send
	 * a WRITE record containing the actual data.
	 */
	uint64_t last_obj = UINT64_MAX;
	uint64_t last_obj_exists = B_TRUE;
	uint32_t last_obj_datablksz = 0;
	while (!data->eos_marker && !spta->cancel && smta->error == 0) {
		if (data->zb.zb_objset != dmu_objset_id(os)) {
			/*
			 * This entry came from the "from bookmark" when
			 * sending from a bookmark that has a redaction
			 * list.  We need to check if this object/blkid
			 * exists in the target ("to") dataset, and if
			 * not then we drop this entry.  We also need
			 * to fill in the block pointer so that we know
			 * what to prefetch (if it is not redacted).  We also
			 * need the data block size.
			 *
			 * To accomplish the above, we have a few approaches.
			 * First, we cache whether or not the last object we
			 * examined exists, and we cache its block size. In the
			 * case of non-redacted records, we must also get the
			 * block pointer if the object does exist, so we call
			 * dbuf_bookmark_findbp.  We also call
			 * dbuf_bookmark_findbp if we're working on a new
			 * object, to see whether it exists, and we cache that
			 * information. In the case of redacted records, that is
			 * all the information we need, so we don't need to do
			 * anything else unless we're working on a new object.
			 * If we are, we use dmu_object_info to get the
			 * information (since it's much faster than
			 * dbuf_bookmark_findbp).
			 *
			 * This approach gives us a (in some tests) 300% speedup
			 * over just calling dbuf_bookmark_findbp and
			 * dmu_object_info every time.
			 */
			boolean_t object_exists = B_TRUE;
			/*
			 * If the data is redacted, we only care if it exists,
			 * so that we don't send records for objects that have
			 * been deleted.
			 */
			if (data->redact_marker) {
				if (data->zb.zb_object == last_obj) {
					object_exists = last_obj_exists;
					data->datablksz = last_obj_datablksz;
				} else {
					dmu_object_info_t doi;
					err = dmu_object_info(os,
					    data->zb.zb_object, &doi);
					if (err == ENOENT) {
						object_exists = B_FALSE;
						err = 0;
					} else if (err == 0) {
						data->datablksz =
						    doi.doi_data_block_size;
					}
					last_obj = data->zb.zb_object;
					last_obj_exists = object_exists;
					last_obj_datablksz = data->datablksz;
				}
			} else if (data->zb.zb_object == last_obj &&
			    !last_obj_exists) {
				/*
				 * If we're still examining the same object as
				 * previously, and it doesn't exist, we don't
				 * need to call dbuf_bookmark_findbp.
				 */
				object_exists = B_FALSE;
			} else {
				blkptr_t bp;
				uint16_t datablkszsec;
				err = dbuf_bookmark_findbp(os, &data->zb, &bp,
				    &datablkszsec, &data->indblkshift);
				if (err == ENOENT) {
					object_exists = B_FALSE;
					err = 0;
				} else if (err == 0) {
					data->bp = bp;
					data->datablksz = datablkszsec <<
					    SPA_MINBLOCKSHIFT;
				}
				last_obj = data->zb.zb_object;
				last_obj_exists = object_exists;
				last_obj_datablksz = data->datablksz;
			}
			if (!object_exists) {
				/*
				 * The block was modified, but doesn't
				 * exist in the to dataset; if it was
				 * deleted in the to dataset, then we'll
				 * visit the hole bp for it at some point.
				 */
				kmem_free(data, sizeof (*data));
				data = bqueue_dequeue(inq);
				err = 0;
				continue;
			} else if (err != 0) {
				break;
			} else {
				data->zb.zb_objset = dmu_objset_id(os);
			}
		}

		if (data->zb.zb_level > 0 && !BP_IS_HOLE(&data->bp)) {
			kmem_free(data, sizeof (*data));
			data = bqueue_dequeue(inq);
			continue;
		}

		if (!data->redact_marker && !BP_IS_HOLE(&data->bp) &&
		    !BP_IS_REDACTED(&data->bp) && spta->issue_prefetches &&
		    !BP_IS_EMBEDDED(&data->bp)) {
			arc_flags_t aflags = ARC_FLAG_NOWAIT |
			    ARC_FLAG_PREFETCH;
			(void) arc_read(NULL, os->os_spa, &data->bp, NULL, NULL,
			    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_CANFAIL |
			    ZIO_FLAG_SPECULATIVE, &aflags, &data->zb);
		}
		data_size = data->datablksz == 0 ? sizeof (*data) :
		    data->datablksz;
		bqueue_enqueue(outq, data, data_size);
		data = bqueue_dequeue(inq);
	}
	if (spta->cancel || err != 0) {
		smta->cancel = B_TRUE;
		spta->error = err;
	} else if (smta->error != 0) {
		spta->error = smta->error;
	}
	while (!data->eos_marker) {
		kmem_free(data, sizeof (*data));
		data = bqueue_dequeue(inq);
	}

	bqueue_enqueue(outq, data, 1);
	bqueue_flush(outq);
}

struct dmu_send_params {
	/* Pool args */
	void *tag; // Tag that dp was held with, will be used to release dp.
	dsl_pool_t *dp;
	/* To snapshot args */
	const char *tosnap;
	dsl_dataset_t *to_ds;
	/* From snapshot args */
	zfs_bookmark_phys_t ancestor_zb;
	uint64_t *fromredactsnaps;
	uint64_t numfromredactsnaps; // UINT64_MAX if not sending from redacted
	/* Stream params */
	boolean_t is_clone;
	boolean_t embedok;
	boolean_t large_block_ok;
	boolean_t compressok;
	uint64_t resumeobj;
	uint64_t resumeoff;
	enum {REDACT_NONE, REDACT_LIST, REDACT_BOOK } redact_type;
	union {
		struct rdl {
			dsl_dataset_t **redactsnaparr;
			int32_t numredactsnaps;
			const char *redactbook;
		} rdl;
		struct rdb {
			zfs_bookmark_phys_t redactbook;
		} rdb;
	} redact_data;
	/* Stream output params */
	dmu_send_outparams_t *dso;

	/* Stream progress params */
	offset_t *off;
	int outfd;
};

static int
setup_featureflags(struct dmu_send_params *dspp, objset_t *os,
    uint64_t *featureflags)
{
	dsl_dataset_t *to_ds = dspp->to_ds;
	dsl_pool_t *dp = dspp->dp;
#ifdef _KERNEL
	if (dmu_objset_type(os) == DMU_OST_ZFS) {
		uint64_t version;
		if (zfs_get_zplprop(os, ZFS_PROP_VERSION, &version) != 0)
			return (SET_ERROR(EINVAL));

		if (version >= ZPL_VERSION_SA)
			*featureflags |= DMU_BACKUP_FEATURE_SA_SPILL;
	}
#endif

	if (dspp->large_block_ok && dsl_dataset_feature_is_active(to_ds,
	    SPA_FEATURE_LARGE_BLOCKS)) {
		*featureflags |= DMU_BACKUP_FEATURE_LARGE_BLOCKS;
	}
	if (dspp->embedok &&
	    spa_feature_is_active(dp->dp_spa, SPA_FEATURE_EMBEDDED_DATA)) {
		*featureflags |= DMU_BACKUP_FEATURE_EMBED_DATA;
	}
	if (dspp->compressok) {
		*featureflags |= DMU_BACKUP_FEATURE_COMPRESSED;
	}
	if ((*featureflags &
	    (DMU_BACKUP_FEATURE_EMBED_DATA | DMU_BACKUP_FEATURE_COMPRESSED)) !=
	    0 && spa_feature_is_active(dp->dp_spa, SPA_FEATURE_LZ4_COMPRESS)) {
		*featureflags |= DMU_BACKUP_FEATURE_LZ4;
	}

	/*
	 * Note: If we are sending a full stream (non-incremental), then
	 * we can not send mooch records, because the receiver won't have
	 * the origin to mooch from.
	 */
	if (dspp->embedok && dsl_dataset_feature_is_active(to_ds,
	    SPA_FEATURE_MOOCH_BYTESWAP) &&
	    dspp->ancestor_zb.zbm_creation_txg != 0ULL) {
		*featureflags |= DMU_BACKUP_FEATURE_EMBED_MOOCH_BYTESWAP;
	}

	if (dspp->resumeobj != 0 || dspp->resumeoff != 0) {
		*featureflags |= DMU_BACKUP_FEATURE_RESUMING;
	}

	if (dspp->redact_type == REDACT_LIST ||
	    dsl_dataset_feature_is_active(to_ds,
	    SPA_FEATURE_REDACTED_DATASETS)) {
		if (dspp->redact_type == REDACT_LIST &&
		    dsl_dataset_feature_is_active(to_ds,
		    SPA_FEATURE_REDACTED_DATASETS)) {
			return (SET_ERROR(EALREADY));
		}
		*featureflags |= DMU_BACKUP_FEATURE_REDACTED;
		for (int i = 0; i < dspp->redact_data.rdl.numredactsnaps; i++) {
			if (dsl_dataset_feature_is_active(
			    dspp->redact_data.rdl.redactsnaparr[i],
			    SPA_FEATURE_REDACTED_DATASETS)) {
				return (SET_ERROR(EALREADY));
			}
		}
	} else if (dspp->redact_type == REDACT_BOOK) {
		*featureflags |= DMU_BACKUP_FEATURE_REDACTED;
	}
	return (0);
}

static dmu_replay_record_t *
create_begin_record(struct dmu_send_params *dspp, objset_t *os,
    uint64_t featureflags)
{
	dmu_replay_record_t *drr = kmem_zalloc(sizeof (dmu_replay_record_t),
	    KM_SLEEP);
	drr->drr_type = DRR_BEGIN;

	struct drr_begin *drrb = &drr->drr_u.drr_begin;
	dsl_dataset_t *to_ds = dspp->to_ds;

	drrb->drr_magic = DMU_BACKUP_MAGIC;
	drrb->drr_creation_time = dsl_dataset_phys(to_ds)->ds_creation_time;
	drrb->drr_type = dmu_objset_type(os);
	drrb->drr_toguid = dsl_dataset_phys(to_ds)->ds_guid;
	drrb->drr_fromguid = dspp->ancestor_zb.zbm_guid;

	DMU_SET_STREAM_HDRTYPE(drrb->drr_versioninfo, DMU_SUBSTREAM);
	DMU_SET_FEATUREFLAGS(drrb->drr_versioninfo, featureflags);

	if (dspp->is_clone)
		drrb->drr_flags |= DRR_FLAG_CLONE;
	if (dsl_dataset_phys(dspp->to_ds)->ds_flags & DS_FLAG_CI_DATASET)
		drrb->drr_flags |= DRR_FLAG_CI_DATA;
	drrb->drr_flags |= DRR_FLAG_FREERECORDS;

	dsl_dataset_name(to_ds, drrb->drr_toname);
	if (!to_ds->ds_is_snapshot) {
		(void) strlcat(drrb->drr_toname, "@--head--",
		    sizeof (drrb->drr_toname));
	}
	return (drr);
}

static void
setup_to_thread(struct send_thread_arg *to_arg, dsl_dataset_t *to_ds,
    dmu_sendstatus_t *dssp, uint64_t fromtxg)
{
	VERIFY0(bqueue_init(&to_arg->q, zfs_send_no_prefetch_queue_ff,
	    zfs_send_no_prefetch_queue_length,
	    offsetof(struct send_block_record, ln)));
	to_arg->error_code = 0;
	to_arg->cancel = B_FALSE;
	to_arg->ds = to_ds;
	to_arg->fromtxg = fromtxg;
	to_arg->flags = TRAVERSE_PRE | TRAVERSE_PREFETCH_METADATA;
	to_arg->to_os = NULL;
	to_arg->redaction_list = NULL;
	to_arg->num_blocks_visited = &dssp->dss_blocks;
	(void) thread_create(NULL, 0, send_traverse_thread, to_arg, 0,
	    curproc, TS_RUN, minclsyspri);
}

static void
setup_from_thread(struct send_thread_arg *from_arg, uint64_t fromtxg,
    redaction_list_t *from_rl, objset_t *os, dmu_sendstatus_t *dssp)
{
	VERIFY0(bqueue_init(&from_arg->q, zfs_send_no_prefetch_queue_ff,
	    zfs_send_no_prefetch_queue_length,
	    offsetof(struct send_block_record, ln)));
	from_arg->error_code = 0;
	from_arg->cancel = B_FALSE;
	from_arg->fromtxg = fromtxg;
	from_arg->flags = TRAVERSE_PRE | TRAVERSE_PREFETCH_METADATA;
	from_arg->to_os = os;
	from_arg->redaction_list = from_rl;
	from_arg->num_blocks_visited = &dssp->dss_blocks;
	/*
	 * If from_ds is null, send_traverse_thread just returns success and
	 * enqueues an eos marker.
	 */
	(void) thread_create(NULL, 0, send_traverse_thread, from_arg, 0,
	    curproc, TS_RUN, minclsyspri);
}

static void
setup_redact_threads(struct send_thread_arg *redact_args,
    struct dmu_send_params *dspp, objset_t *os, dmu_sendstatus_t *dssp)
{
	dsl_dataset_t *to_ds = dspp->to_ds;
	for (int i = 0; dspp->redact_type == REDACT_LIST &&
	    i < dspp->redact_data.rdl.numredactsnaps; i++) {
		struct send_thread_arg *arg = redact_args + i;
		VERIFY0(bqueue_init(&arg->q, zfs_send_no_prefetch_queue_ff,
		    zfs_send_no_prefetch_queue_length,
		    offsetof(struct send_redact_record, ln)));
		arg->error_code = 0;
		arg->cancel = B_FALSE;
		arg->ds = dspp->redact_data.rdl.redactsnaparr[i];
		arg->fromtxg = dsl_dataset_phys(to_ds)->ds_creation_txg;
		arg->flags = TRAVERSE_PRE | TRAVERSE_PREFETCH_METADATA;
		arg->to_os = os;
		arg->num_blocks_visited = &dssp->dss_blocks;

		(void) thread_create(NULL, 0, redact_traverse_thread, arg, 0,
		    curproc, TS_RUN, minclsyspri);
	}
}

static void
setup_redact_merge_thread(struct redact_merge_thread_arg *rmt_arg,
    struct dmu_send_params *dspp, struct send_thread_arg *redact_args,
    redaction_list_t *rl, dmu_sendstatus_t *dssp)
{
	if (dspp->redact_type == REDACT_NONE)
		return;

	rmt_arg->cancel = B_FALSE;
	VERIFY0(bqueue_init(&rmt_arg->q, zfs_send_no_prefetch_queue_ff,
	    zfs_send_no_prefetch_queue_length,
	    offsetof(struct send_redact_record, ln)));
	rmt_arg->error_code = 0;
	if (dspp->redact_type == REDACT_LIST) {
		rmt_arg->num_threads = dspp->redact_data.rdl.numredactsnaps;
		rmt_arg->thread_args = redact_args;
	} else if (dspp->redact_type == REDACT_BOOK) {
		rmt_arg->rl = rl;
		rmt_arg->num_blocks_visited = &dssp->dss_blocks;
	}

	(void) thread_create(NULL, 0, redact_merge_thread, rmt_arg, 0,
	    curproc, TS_RUN, minclsyspri);
}

static void
setup_merge_thread(struct send_merge_thread_arg *smt_arg,
    struct dmu_send_params *dspp, struct send_thread_arg *from_arg,
    struct send_thread_arg *to_arg, struct redact_merge_thread_arg *rmt_arg,
    redaction_list_t *new_rl, objset_t *os)
{
	VERIFY0(bqueue_init(&smt_arg->q, zfs_send_no_prefetch_queue_ff,
	    zfs_send_no_prefetch_queue_length,
	    offsetof(struct send_block_record, ln)));
	smt_arg->cancel = B_FALSE;
	smt_arg->error = 0;
	smt_arg->from_arg = from_arg;
	smt_arg->to_arg = to_arg;
	if (dspp->redact_type == REDACT_LIST) {
		smt_arg->redact_arg = rmt_arg;
		smt_arg->rbi.rbi_redaction_list = new_rl;
		smt_arg->rbi.rbi_latest_synctask_txg = 0;
		for (int i = 0; i < TXG_SIZE; i++) {
			list_create(&smt_arg->rbi.rbi_blocks[i],
			    sizeof (struct redact_block_list_node),
			    offsetof(struct redact_block_list_node, node));

		}
	} else if (dspp->redact_type == REDACT_BOOK) {
		smt_arg->redact_arg = rmt_arg;
	}

	smt_arg->os = os;
	(void) thread_create(NULL, 0, send_merge_thread, smt_arg, 0, curproc,
	    TS_RUN, minclsyspri);
}

static void
setup_prefetch_thread(struct send_prefetch_thread_arg *spt_arg,
    struct dmu_send_params *dspp, struct send_merge_thread_arg *smt_arg)
{
	VERIFY0(bqueue_init(&spt_arg->q, zfs_send_queue_ff,
	    zfs_send_queue_length, offsetof(struct send_block_record, ln)));
	spt_arg->smta = smt_arg;
	spt_arg->issue_prefetches = !dspp->dso->dso_dryrun;
	(void) thread_create(NULL, 0, send_prefetch_thread, spt_arg, 0,
	    curproc, TS_RUN, minclsyspri);
}

static int
setup_resume_points(struct dmu_send_params *dspp,
    struct send_thread_arg *to_arg, struct send_thread_arg *from_arg,
    struct send_thread_arg *redact_args,
    struct redact_merge_thread_arg *rmt_arg,
    struct send_merge_thread_arg *smt_arg, boolean_t resuming, objset_t *os,
    redaction_list_t *new_rl, redaction_list_t *redact_rl, nvlist_t *nvl)
{
	dsl_dataset_t *to_ds = dspp->to_ds;
	int err = 0;

	uint64_t obj = 0;
	uint64_t blkid = 0;
	if (resuming) {
		obj = dspp->resumeobj;
		dmu_object_info_t to_doi;
		err = dmu_object_info(os, obj, &to_doi);
		if (err != 0)
			return (err);

		blkid = dspp->resumeoff / to_doi.doi_data_block_size;
	}
	/*
	 * If we're resuming a redacted send, we have to modify where we
	 * start traversing our various datasets; if the previous send
	 * failed because this system crashed, the redaction bookmark
	 * may be missing some redaction_records.  In that case, we need
	 * to start the traversal where the redaction bookmark leaves
	 * off.  On the other hand, the redaction bookmark may be ahead
	 * of the resume location, in which case we need to make sure
	 * not to insert the same record into the redaction bookmark
	 * twice.
	 */
	smt_arg->bookmark_before = B_FALSE;
	if (new_rl != NULL) {
		uint64_t furthest_object = new_rl->rl_phys->rlp_last_object;
		uint64_t furthest_blkid = new_rl->rl_phys->rlp_last_blkid;
		if (furthest_object < dspp->resumeobj ||
		    (furthest_object == dspp->resumeobj &&
		    furthest_blkid < blkid)) {
			obj = furthest_object;
			blkid = furthest_blkid;
			SET_BOOKMARK(&smt_arg->resume_redact_zb,
			    to_ds->ds_object, obj, 0, blkid);
			smt_arg->bookmark_before = B_TRUE;
		} else if (furthest_object > dspp->resumeobj ||
		    (furthest_object == dspp->resumeobj &&
		    furthest_blkid > blkid)) {
			SET_BOOKMARK(&smt_arg->resume_redact_zb,
			    to_ds->ds_object, furthest_object, 0,
			    furthest_blkid);
		}
	} else if (redact_rl != NULL) {
		SET_BOOKMARK(&rmt_arg->resume, to_ds->ds_object, obj, 0, blkid);
	}

	SET_BOOKMARK(&to_arg->resume, to_ds->ds_object, obj, 0, blkid);
	if (nvlist_exists(nvl, BEGINNV_REDACT_FROM_SNAPS)) {
		uint64_t objset = dspp->ancestor_zb.zbm_redaction_obj;
		/*
		 * Note: If the resume point is in an object whose
		 * blocksize is different in the from vs to snapshots,
		 * we will have divided by the "wrong" blocksize.
		 * However, in this case fromsnap's send_cb() will
		 * detect that the blocksize has changed and therefore
		 * ignore this object.
		 *
		 * If we're resuming a send from a redaction bookmark,
		 * we still cannot accidentally suggest blocks behind
		 * the to_ds.  In addition, we know that any blocks in
		 * the object in the to_ds will have to be sent, since
		 * the size changed.  Therefore, we can't cause any harm
		 * this way either.
		 */
		SET_BOOKMARK(&from_arg->resume, objset, obj, 0, blkid);
	}
	if (dspp->redact_type == REDACT_LIST) {
		dsl_dataset_t **snaps = dspp->redact_data.rdl.redactsnaparr;
		for (int i = 0; i < dspp->redact_data.rdl.numredactsnaps; i++) {
			SET_BOOKMARK(&redact_args[i].resume,
			    snaps[i]->ds_object, obj, 0, blkid);
		}
	}
	if (resuming) {
		fnvlist_add_uint64(nvl, BEGINNV_RESUME_OBJECT, dspp->resumeobj);
		fnvlist_add_uint64(nvl, BEGINNV_RESUME_OFFSET, dspp->resumeoff);
	}
	return (0);
}

static dmu_sendstatus_t *
setup_send_progress(struct dmu_send_params *dspp)
{
	dmu_sendstatus_t *dssp = kmem_zalloc(sizeof (*dssp), KM_SLEEP);
	dssp->dss_outfd = dspp->outfd;
	dssp->dss_off = dspp->off;
	dssp->dss_proc = curproc;
	mutex_enter(&dspp->to_ds->ds_sendstream_lock);
	list_insert_head(&dspp->to_ds->ds_sendstreams, dssp);
	mutex_exit(&dspp->to_ds->ds_sendstream_lock);
	return (dssp);
}

/*
 * Actually do the bulk of the work in a zfs send.
 *
 * The idea is that we want to do a send from ancestor_zb to to_ds.  We also
 * want to not send any data that has been modified by all the datasets in
 * redactsnaparr, and store the list of blocks that are redacted in this way in
 * a bookmark named redactbook, created on the to_ds.  We do this by creating
 * several worker threads, whose function is described below.
 *
 * There are three cases.
 * The first case is a redacted zfs send.  In this case there are a variable
 * number of threads.  There are 5 threads plus one more for each dataset
 * redaction is occuring with respect to.  The first thread is the to_ds
 * traversal thread: it calls dataset_traverse on the to_ds and finds all the
 * blocks that have changed since ancestor_zb (if it's a full send, that's all
 * blocks in the dataset).  It then sends those blocks on to the send merge
 * thread.  The variable threads are the secure dataset traversal threads.  They
 * each call traverse_dataset on one of the redaction snapshots (typically the
 * first snapshot in a clone of the to_ds), finding all blocks that have changed
 * in that dataset since it diverged from the to_ds.  The redact merge thread
 * takes the data from the secure dataset traversal thread and merges them. Any
 * blocks modified by all the redaction snapshots should be redacted, so it
 * sends those blocks on to the send merge thread.  The send merge thread takes
 * the data from the to_ds traversal thread, and combines it with the redaction
 * records from the redact merge thread.  If a block appears in both the to_ds's
 * data and the redaction data, the send merge thread will mark it as redacted
 * and send it on to the prefetch thread.  It will also append that block to the
 * redaction list that is being created as part of the send.  Otherwise, the
 * send merge thread will send the block on to the prefetch thread unchanged.
 * The prefetch thread will issue prefetch reads for any data that isn't
 * redacted, and then send the data on to the main thread.  The main thread
 * behaves the same as in a normal send case.
 *
 * The graphic below diagrams the flow of data in the case of a redacted zfs
 * send.  Each box represents a thread, and each line represents the flow of
 * data.
 *
 * +--------------------+
 * | Secure Dataset     |
 * | Traversal Thread 1 +-------+
 * |                    |       |
 * +--------------------+       | Ranges modified by secure snap 1
 *                              | (redact_send_record)
 * +--------------------+  +----v----------------+
 * | Secure Dataset     |  |                     |
 * | Traversal Thread 2 +--> Redact Merge Thread |
 * |                    |  |                     |
 * +--------------------+  +----^-------+--------+
 *                              |       |
 *          ... Ranges modified |       | Ranges modified by every secure snap
 *              by secure snap N|       | (redact_send_record)
 * +--------------------+       |  +----v----------------------+
 * | Secure Dataset     |       |  | Send Merge Thread         |
 * | Traversal Thread N +-------+  | Apply redaction marks to  |
 * |                    |          | records as specified by   |
 * +--------------------+          | redaction ranges          |
 *                                 +----^---------------+------+
 *                                      |               | Merged data
 *                                      |               | (send_block_record)
 *                                      |  +------------v--------+
 *                                      |  | Prefetch Thread     |
 * +--------------------+               |  | Issues prefetch     |
 * | to_ds Traversal    |               |  | reads of data blocks|
 * | Thread (finds      +---------------+  +------------+--------+
 * | candidate blocks)  |  Blocks modified              | Prefetched data
 * +--------------------+  by to_ds since               | (send_block_record)
 *                         ancestor_zb     +------------v----+
 *                  (send_block_record)    | Main Thread     |  File Descriptor
 *                                         | Sends data over +->(to zfs receive)
 *                                         | wire            |
 *                                         +-----------------+
 *
 * The second case is an incremental send from a redaction bookmark.  The to_ds
 * traversal thread and the main thread behave the same as in the redacted
 * send case.  The redact merge thread notices there are no redact traversal
 * threads, and so returns immediately.  The new thread is the from bookmark
 * traversal thread.  It iterates over the redaction list in the redaction
 * bookmark, and enqueues records for each block that was redacted in the
 * original send.  The send merge thread now has to merge the data from the
 * two threads.  For details about that process, see the header comment of
 * send_merge_thread().  Any data it decides to send on will be prefetched by
 * the prefetch thread.  Note that you can perform a redacted send from an
 * incremental bookmark; in that case, the data flow behaves very similarly to
 * the flow in the redacted send case, except with the addition of the bookmark
 * traversal thread iterating over the redaction bookmark.  The
 * send_merge_thread also has to take on the responsibility of merging the
 * redact merge thread's records and the to_ds records.
 *
 * +---------------------+
 * |                     |
 * | Redact Merge Thread +--------------+
 * |                     |              |
 * +---------------------+              |
 *        Blocks in redaction list      | Ranges modified by every secure snap
 *        of from bookmark              | (or EOS if not readcted)
 *        (send_block_record)           | (send_redact_record)
 * +---------------------+   |     +----v----------------------+
 * | bookmark Traversal  |   v     | Send Merge Thread         |
 * | Thread (finds       +---------> Merges bookmark, rmt, and |
 * | candidate blocks)   |         | to_ds send records        |
 * +---------------------+         +----^---------------+------+
 *                                      |               | Merged data
 *                                      |  +------------v--------+
 *                                      |  | Prefetch Thread     |
 * +--------------------+               |  | Issues prefetch     |
 * | to_ds Traversal    |               |  | reads of data blocks|
 * | Thread (finds      +---------------+  +------------+--------+
 * | candidate blocks)  |  Blocks modified              | Prefetched data
 * +--------------------+  by to_ds since  +------------v----+
 *                         ancestor_zb     | Main Thread     |  File Descriptor
 *                  (send_block_record)    | Sends data over +->(to zfs receive)
 *                                         | wire            |
 *                                         +-----------------+
 *
 * The final case is a simple zfs full or incremental send.  In this case,
 * there are only 5 threads. The to_ds traversal thread behaves the same as
 * always. The redact merge thread is started, realizes there's no redaction
 * going on, and promptly returns. The send merge thread takes all the blocks
 * that the to_ds traveral thread sends it, prefetches the data, and sends the
 * blocks on to the main thread.  The main thread sends the data over the
 * wire.
 *
 * To keep performance acceptable, we want to prefetch the data in the worker
 * threads.  While the to_ds thread could simply use the TRAVERSE_PREFETCH
 * feature built into traverse_dataset, the combining and deletion of records
 * due to redaction and sends from redaction bookmarks mean that we could
 * issue many unnecessary prefetches.  As a result, we only prefetch data
 * after we've determined that the record is not going to be redacted.  To
 * prevent the prefetching from getting too far ahead of the main thread, the
 * blocking queues that are used for communication are capped not by the
 * number of entries in the queue, but by the sum of the size of the
 * prefetches associated with them.  The limit on the amount of data that the
 * thread can prefetch beyond what the main thread has reached is controlled
 * by the global variable zfs_send_queue_length.  In addition, to prevent poor
 * performance in the beginning of a send, we also limit the distance ahead
 * that the traversal threads can be.  That distance is controlled by the
 * zfs_send_no_prefetch_queue_length tunable.
 *
 * Note: Releases dp using the specified tag.
 */
static int
dmu_send_impl(struct dmu_send_params *dspp)
{
	objset_t *os;
	dmu_replay_record_t *drr;
	dmu_sendstatus_t *dssp;
	dmu_send_cookie_t dsc = {0};
	int err;
	uint64_t fromtxg = dspp->ancestor_zb.zbm_creation_txg;
	uint64_t featureflags = 0;
	struct send_thread_arg from_arg = { 0 };
	struct send_thread_arg to_arg = { 0 };
	struct redact_merge_thread_arg rmt_arg = { 0 };
	struct send_merge_thread_arg smt_arg = { 0 };
	struct send_prefetch_thread_arg spt_arg = { 0 };
	struct send_thread_arg *redact_args = NULL;
	struct send_block_record *rec;
	redaction_list_t *new_rl = NULL;
	redaction_list_t *from_rl = NULL;
	redaction_list_t *redact_rl = NULL;
	char newredactbook[ZFS_MAX_DATASET_NAME_LEN];
	boolean_t resuming = (dspp->resumeobj != 0 || dspp->resumeoff != 0);
	boolean_t book_resuming = resuming;

	dsl_dataset_t *to_ds = dspp->to_ds;
	zfs_bookmark_phys_t *ancestor_zb = &dspp->ancestor_zb;
	dsl_pool_t *dp = dspp->dp;
	void *tag = dspp->tag;

	err = dmu_objset_from_ds(to_ds, &os);
	if (err != 0) {
		dsl_pool_rele(dp, tag);
		return (err);
	}

	if ((err = setup_featureflags(dspp, os, &featureflags)) != 0) {
		dsl_pool_rele(dp, tag);
		return (err);
	}

	/*
	 * If we're resuming this send, find and hold the redaction list we were
	 * creating last time.  If we're doing a send redacting using a
	 * bookmark, hold the bookmark's redaction list.
	 */
	if (dspp->redact_type == REDACT_LIST) {
		zfs_bookmark_phys_t bookmark;
		(void) strncpy(newredactbook, dspp->tosnap,
		    ZFS_MAX_DATASET_NAME_LEN);
		char *c = strchr(newredactbook, '@');
		ASSERT3P(c, !=, NULL);
		int n = snprintf(c, ZFS_MAX_DATASET_NAME_LEN -
		    (c - newredactbook),
		    "#%s", dspp->redact_data.rdl.redactbook);
		if (n >= ZFS_MAX_DATASET_NAME_LEN - (c - newredactbook)) {
			dsl_pool_rele(dp, tag);
			return (SET_ERROR(ENAMETOOLONG));
		}
		err = dsl_bookmark_lookup(dp, newredactbook, NULL, &bookmark);
		if (err == 0) {
			book_resuming = B_TRUE;
		} else if (resuming) {
			dsl_pool_rele(dp, tag);
			return (SET_ERROR(ENOENT));
		}
		if (book_resuming) {
			if (bookmark.zbm_redaction_obj == 0) {
				dsl_pool_rele(dp, tag);
				return (SET_ERROR(EINVAL));
			}
			err = dsl_redaction_list_hold_obj(dp,
			    bookmark.zbm_redaction_obj, FTAG, &new_rl);
			if (err != 0) {
				dsl_pool_rele(dp, tag);
				return (SET_ERROR(EINVAL));
			}
			dsl_redaction_list_long_hold(dp, new_rl, FTAG);
		}
	} else if (dspp->redact_type == REDACT_BOOK) {
		err = dsl_redaction_list_hold_obj(dp,
		    dspp->redact_data.rdb.redactbook.zbm_redaction_obj, FTAG,
		    &redact_rl);
		if (err != 0) {
			dsl_pool_rele(dp, tag);
			return (SET_ERROR(EINVAL));
		}
		dsl_redaction_list_long_hold(dp, redact_rl, FTAG);
	}

	/*
	 * If we're sending from a redaction bookmark, hold the redaction list
	 * so that we can consider sending the redacted blocks.
	 */
	if (ancestor_zb->zbm_redaction_obj != 0) {
		err = dsl_redaction_list_hold_obj(dp,
		    ancestor_zb->zbm_redaction_obj, FTAG, &from_rl);
		if (err != 0) {
			if (new_rl != NULL) {
				dsl_redaction_list_long_rele(new_rl, FTAG);
				dsl_redaction_list_rele(new_rl, FTAG);
			}
			dsl_pool_rele(dp, tag);
			return (SET_ERROR(EINVAL));
		}
		dsl_redaction_list_long_hold(dp, from_rl, FTAG);
	}


	dsl_dataset_long_hold(to_ds, FTAG);
	if (dspp->redact_type == REDACT_LIST) {
		for (int i = 0; i < dspp->redact_data.rdl.numredactsnaps; i++) {
			dsl_dataset_long_hold(
			    dspp->redact_data.rdl.redactsnaparr[i], FTAG);
		}
	}

	drr = create_begin_record(dspp, os, featureflags);
	dssp = setup_send_progress(dspp);

	dsc.dsc_drr = drr;
	dsc.dsc_dso = dspp->dso;
	dsc.dsc_os = os;
	dsc.dsc_off = dspp->off;
	dsc.dsc_toguid = dsl_dataset_phys(to_ds)->ds_guid;
	dsc.dsc_pending_op = PENDING_NONE;
	dsc.dsc_featureflags = featureflags;
	dsc.dsc_resume_object = dspp->resumeobj;
	dsc.dsc_resume_offset = dspp->resumeoff;

	dsl_pool_rele(dp, tag);

	void *payload = NULL;
	size_t payload_len = 0;
	nvlist_t *nvl = fnvlist_alloc();

	/*
	 * If we're doing a redacted send, we include the snapshots we're
	 * redacted with respect to so that the target system knows what send
	 * streams can be correctly received on top of this dataset. If we're
	 * instead sending a redacted dataset, we include the snapshots that the
	 * dataset was created with respect to.
	 */
	if (dspp->redact_type == REDACT_LIST) {
		uint64_t *guids = NULL;
		if (dspp->redact_data.rdl.numredactsnaps > 0) {
			guids =
			    kmem_zalloc(dspp->redact_data.rdl.numredactsnaps *
			    sizeof (uint64_t), KM_SLEEP);
			redact_args = kmem_zalloc(
			    dspp->redact_data.rdl.numredactsnaps *
			    sizeof (to_arg), KM_SLEEP);
		}
		for (int i = 0; i < dspp->redact_data.rdl.numredactsnaps; i++) {
			guids[i] = dsl_dataset_phys(
			    dspp->redact_data.rdl.redactsnaparr[i])->ds_guid;
		}

		if (!book_resuming) {
			err = dsl_bookmark_create_redacted(newredactbook,
			    dspp->tosnap, dspp->redact_data.rdl.numredactsnaps,
			    guids, FTAG, &new_rl);
			if (err != 0) {
				kmem_free(guids,
				    dspp->redact_data.rdl.numredactsnaps *
				    sizeof (uint64_t));
				fnvlist_free(nvl);
				goto out;
			}
		}

		fnvlist_add_uint64_array(nvl, BEGINNV_REDACT_SNAPS, guids,
		    dspp->redact_data.rdl.numredactsnaps);
		kmem_free(guids,
		    dspp->redact_data.rdl.numredactsnaps * sizeof (uint64_t));
	} else if (dspp->redact_type == REDACT_BOOK) {
		fnvlist_add_uint64_array(nvl, BEGINNV_REDACT_SNAPS,
		    redact_rl->rl_phys->rlp_snaps,
		    redact_rl->rl_phys->rlp_num_snaps);
	} else if (dsl_dataset_feature_is_active(to_ds,
	    SPA_FEATURE_REDACTED_DATASETS)) {
		uint64_t *tods_guids;
		uint64_t length;
		VERIFY(dsl_dataset_get_uint64_array_feature(to_ds,
		    SPA_FEATURE_REDACTED_DATASETS, &length, &tods_guids));
		fnvlist_add_uint64_array(nvl, BEGINNV_REDACT_SNAPS, tods_guids,
		    length);
	}

	/*
	 * If we're sending from a redaction bookmark, then we should retrieve
	 * the guids of that bookmark so we can send them over the wire.
	 */
	if (from_rl != NULL) {
		fnvlist_add_uint64_array(nvl, BEGINNV_REDACT_FROM_SNAPS,
		    from_rl->rl_phys->rlp_snaps,
		    from_rl->rl_phys->rlp_num_snaps);
	}

	/*
	 * If the snapshot we're sending from is redacted, include the redaction
	 * list in the stream.
	 */
	if (dspp->numfromredactsnaps != UINT64_MAX) {
		ASSERT3P(from_rl, ==, NULL);
		fnvlist_add_uint64_array(nvl, BEGINNV_REDACT_FROM_SNAPS,
		    dspp->fromredactsnaps, (uint_t)dspp->numfromredactsnaps);
		if (dspp->numfromredactsnaps > 0) {
			kmem_free(dspp->fromredactsnaps,
			    dspp->numfromredactsnaps * sizeof (uint64_t));
			dspp->fromredactsnaps = NULL;
		}
	}

	if (resuming || book_resuming) {
		err = setup_resume_points(dspp, &to_arg, &from_arg, redact_args,
		    &rmt_arg, &smt_arg, resuming, os, new_rl, redact_rl, nvl);
		if (err != 0)
			goto out;
	}

	if (fnvlist_num_pairs(nvl) > 0) {
		payload = fnvlist_pack(nvl, &payload_len);
		drr->drr_payloadlen = payload_len;
	}

	fnvlist_free(nvl);
	err = dump_record(&dsc, payload, payload_len);
	fnvlist_pack_free(payload, payload_len);
	if (err != 0) {
		err = dsc.dsc_err;
		goto out;
	}

	setup_to_thread(&to_arg, to_ds, dssp, fromtxg);
	setup_from_thread(&from_arg, fromtxg, from_rl, os, dssp);
	setup_redact_threads(redact_args, dspp, os, dssp);
	setup_redact_merge_thread(&rmt_arg, dspp, redact_args, redact_rl, dssp);
	setup_merge_thread(&smt_arg, dspp, &from_arg, &to_arg, &rmt_arg, new_rl,
	    os);
	setup_prefetch_thread(&spt_arg, dspp, &smt_arg);

	rec = bqueue_dequeue(&spt_arg.q);
	while (err == 0 && !rec->eos_marker) {
		err = do_dump(&dsc, rec);
		rec = get_next_record(&spt_arg.q, rec);
		if (issig(JUSTLOOKING) && issig(FORREAL))
			err = EINTR;
	}

	/*
	 * If we hit an error or are interrupted, cancel our worker threads and
	 * clear the queue of any pending records.  The threads will pass the
	 * cancel up the tree of worker threads, and each one will clean up any
	 * pending records before exiting.
	 */
	if (err != 0) {
		spt_arg.cancel = B_TRUE;
		while (!rec->eos_marker) {
			rec = get_next_record(&spt_arg.q, rec);
		}
	}
	kmem_free(rec, sizeof (*rec));

	bqueue_destroy(&spt_arg.q);
	bqueue_destroy(&smt_arg.q);
	if (dspp->redact_type != REDACT_NONE)
		bqueue_destroy(&rmt_arg.q);
	for (int i = 0; dspp->redact_type == REDACT_LIST &&
	    i < dspp->redact_data.rdl.numredactsnaps; i++) {
		bqueue_destroy(&redact_args[i].q);
	}
	bqueue_destroy(&to_arg.q);
	bqueue_destroy(&from_arg.q);

	if (err == 0 && spt_arg.error != 0)
		err = spt_arg.error;

	if (err != 0)
		goto out;

	if (dsc.dsc_pending_op != PENDING_NONE)
		if (dump_record(&dsc, NULL, 0) != 0)
			err = SET_ERROR(EINTR);

	if (err != 0) {
		if (err == EINTR && dsc.dsc_err != 0)
			err = dsc.dsc_err;
		goto out;
	}

	bzero(drr, sizeof (dmu_replay_record_t));
	drr->drr_type = DRR_END;
	drr->drr_u.drr_end.drr_checksum = dsc.dsc_zc;
	drr->drr_u.drr_end.drr_toguid = dsc.dsc_toguid;

	if (dump_record(&dsc, NULL, 0) != 0)
		err = dsc.dsc_err;

out:
	mutex_enter(&to_ds->ds_sendstream_lock);
	list_remove(&to_ds->ds_sendstreams, dssp);
	mutex_exit(&to_ds->ds_sendstream_lock);

	VERIFY(err != 0 || (dsc.dsc_sent_begin && dsc.dsc_sent_end));

	kmem_free(drr, sizeof (dmu_replay_record_t));
	kmem_free(dssp, sizeof (dmu_sendstatus_t));
	if (dspp->redact_type == REDACT_LIST) {
		kmem_free(redact_args,
		    dspp->redact_data.rdl.numredactsnaps * sizeof (to_arg));
	}

	for (int i = 0; dspp->redact_type == REDACT_LIST &&
	    i < dspp->redact_data.rdl.numredactsnaps; i++) {
		dsl_dataset_long_rele(dspp->redact_data.rdl.redactsnaparr[i],
		    FTAG);
	}
	dsl_dataset_long_rele(to_ds, FTAG);
	if (from_rl != NULL) {
		dsl_redaction_list_long_rele(from_rl, FTAG);
		dsl_redaction_list_rele(from_rl, FTAG);
	}
	if (redact_rl != NULL) {
		dsl_redaction_list_long_rele(redact_rl, FTAG);
		dsl_redaction_list_rele(redact_rl, FTAG);
	}
	if (new_rl != NULL) {
		dsl_redaction_list_long_rele(new_rl, FTAG);
		dsl_redaction_list_rele(new_rl, FTAG);
	}

	return (err);
}

static int
dsl_dataset_walk_origin(dsl_pool_t *dp, dsl_dataset_t **ds, void *tag)
{
	uint64_t origin_obj = dsl_dir_phys((*ds)->ds_dir)->dd_origin_obj;
	dsl_dataset_t *prev;
	int err = dsl_dataset_hold_obj(dp, origin_obj, tag, &prev);
	if (err != 0)
		return (err);
	dsl_dataset_rele(*ds, tag);
	*ds = prev;
	prev = NULL;
	return (err);
}

int
dmu_send_obj(const char *pool, uint64_t tosnap, uint64_t fromsnap,
    boolean_t embedok, boolean_t large_block_ok, boolean_t compressok,
    int outfd, offset_t *off, dmu_send_outparams_t *dsop)
{
	int err;
	dsl_dataset_t *fromds;
	struct dmu_send_params dspp = {0};
	dspp.embedok = embedok;
	dspp.large_block_ok = large_block_ok;
	dspp.compressok = compressok;
	dspp.outfd = outfd;
	dspp.off = off;
	dspp.dso = dsop;
	dspp.tag = FTAG;
	dspp.redact_type = REDACT_NONE;

	err = dsl_pool_hold(pool, FTAG, &dspp.dp);
	if (err != 0)
		return (err);

	err = dsl_dataset_hold_obj(dspp.dp, tosnap, FTAG, &dspp.to_ds);
	if (err != 0) {
		dsl_pool_rele(dspp.dp, FTAG);
		return (err);
	}

	if (fromsnap != 0) {
		err = dsl_dataset_hold_obj(dspp.dp, fromsnap, FTAG,
		    &fromds);
		if (err != 0) {
			dsl_dataset_rele(dspp.to_ds, FTAG);
			dsl_pool_rele(dspp.dp, FTAG);
			return (err);
		}
		dspp.ancestor_zb.zbm_guid = dsl_dataset_phys(fromds)->ds_guid;
		dspp.ancestor_zb.zbm_creation_txg =
		    dsl_dataset_phys(fromds)->ds_creation_txg;
		dspp.ancestor_zb.zbm_creation_time =
		    dsl_dataset_phys(fromds)->ds_creation_time;
		/* See dmu_send for the reasons behind this. */
		uint64_t *fromredact;

		if (!dsl_dataset_get_uint64_array_feature(fromds,
		    SPA_FEATURE_REDACTED_DATASETS,
		    &dspp.numfromredactsnaps,
		    &fromredact)) {
			dspp.numfromredactsnaps = UINT64_MAX;
		} else if (dspp.numfromredactsnaps > 0) {
			uint64_t size = dspp.numfromredactsnaps *
			    sizeof (uint64_t);
			dspp.fromredactsnaps = kmem_zalloc(size, KM_SLEEP);
			bcopy(fromredact, dspp.fromredactsnaps, size);
		}

		if (!dsl_dataset_is_before(dspp.to_ds, fromds, 0)) {
			err = SET_ERROR(EXDEV);
		} else {
			dspp.is_clone = (dspp.to_ds->ds_dir !=
			    fromds->ds_dir);
			dsl_dataset_rele(fromds, FTAG);
			err = dmu_send_impl(&dspp);
		}
	} else {
		dspp.numfromredactsnaps = UINT64_MAX;
		err = dmu_send_impl(&dspp);
	}
	dsl_dataset_rele(dspp.to_ds, FTAG);
	return (err);
}

int
dmu_send(const char *tosnap, const char *fromsnap, boolean_t embedok,
    boolean_t large_block_ok, boolean_t compressok, uint64_t resumeobj,
    uint64_t resumeoff, nvlist_t *redactsnaps, const char *redactbook,
    const char *redactlist_book, int outfd, offset_t *off,
    dmu_send_outparams_t *dsop)
{
	int err = 0;
	boolean_t owned = B_FALSE;
	dsl_dataset_t *fromds = NULL;
	struct dmu_send_params dspp = {0};
	dspp.tosnap = tosnap;
	dspp.embedok = embedok;
	dspp.large_block_ok = large_block_ok;
	dspp.compressok = compressok;
	dspp.outfd = outfd;
	dspp.off = off;
	dspp.dso = dsop;
	dspp.tag = FTAG;
	dspp.resumeobj = resumeobj;
	dspp.resumeoff = resumeoff;

	if (fromsnap != NULL && strpbrk(fromsnap, "@#") == NULL)
		return (SET_ERROR(EINVAL));

	if (redactbook != NULL && redactlist_book != NULL)
		return (SET_ERROR(EINVAL));

	err = dsl_pool_hold(tosnap, FTAG, &dspp.dp);
	if (err != 0) {
		return (err);
	}

	if (strchr(tosnap, '@') == NULL && spa_writeable(dspp.dp->dp_spa)) {
		/*
		 * We are sending a filesystem or volume.  Ensure
		 * that it doesn't change by owning the dataset.
		 */
		err = dsl_dataset_own(dspp.dp, tosnap, FTAG, &dspp.to_ds);
		owned = B_TRUE;
	} else {
		err = dsl_dataset_hold(dspp.dp, tosnap, FTAG, &dspp.to_ds);
	}

	if (err != 0) {
		dsl_pool_rele(dspp.dp, FTAG);
		return (err);
	}

	if (redactsnaps != NULL) {
		dspp.redact_type = REDACT_LIST;
		dspp.redact_data.rdl.redactbook = redactbook;
	} else if (redactlist_book != NULL) {
		char path[ZFS_MAX_DATASET_NAME_LEN];
		(void) strlcpy(path, tosnap, sizeof (path));
		char *at = strchr(path, '@');
		if (at == NULL) {
			err = EINVAL;
		} else {
			(void) snprintf(at, sizeof (path) - (at - path), "#%s",
			    redactlist_book);
			dspp.redact_type = REDACT_BOOK;
			err = dsl_bookmark_lookup(dspp.dp, path,
			    NULL, &dspp.redact_data.rdb.redactbook);
		}
	} else {
		dspp.redact_type = REDACT_NONE;
	}
	if (err != 0) {
		if (owned)
			dsl_dataset_disown(dspp.to_ds, FTAG);
		else
			dsl_dataset_rele(dspp.to_ds, FTAG);
		dsl_pool_rele(dspp.dp, FTAG);
		return (err);
	}

	if (redactsnaps != NULL) {
		nvpair_t *pair;

		if (fnvlist_num_pairs(redactsnaps) > 0 && err == 0) {
			dspp.redact_data.rdl.redactsnaparr =
			    kmem_zalloc(fnvlist_num_pairs(redactsnaps) *
			    sizeof (dsl_dataset_t *), KM_SLEEP);
		}

		for (pair = nvlist_next_nvpair(redactsnaps, NULL); err == 0 &&
		    pair != NULL; pair =
		    nvlist_next_nvpair(redactsnaps, pair)) {
			const char *name = nvpair_name(pair);
			err = dsl_dataset_hold(dspp.dp, name, FTAG,
			    dspp.redact_data.rdl.redactsnaparr +
			    dspp.redact_data.rdl.numredactsnaps);
			if (err != 0)
				break;
			if (!dsl_dataset_is_before(
			    dspp.redact_data.rdl.redactsnaparr[
			    dspp.redact_data.rdl.numredactsnaps], dspp.to_ds,
			    0)) {
				err = EINVAL;
				dspp.redact_data.rdl.numredactsnaps++;
				break;
			}
			dspp.redact_data.rdl.numredactsnaps++;
		}
	}

	if (err != 0) {
		for (int i = 0; i < dspp.redact_data.rdl.numredactsnaps; i++) {
			dsl_dataset_rele(dspp.redact_data.rdl.redactsnaparr[i],
			    FTAG);
		}

		if (dspp.redact_data.rdl.redactsnaparr != NULL) {
			kmem_free(dspp.redact_data.rdl.redactsnaparr,
			    fnvlist_num_pairs(redactsnaps) *
			    sizeof (dsl_dataset_t *));
		}

		dsl_pool_rele(dspp.dp, FTAG);
		if (owned)
			dsl_dataset_disown(dspp.to_ds, FTAG);
		else
			dsl_dataset_rele(dspp.to_ds, FTAG);
		return (SET_ERROR(err));
	}

	if (fromsnap != NULL) {
		zfs_bookmark_phys_t *zb = &dspp.ancestor_zb;
		int fsnamelen = strpbrk(tosnap, "@#") - tosnap;
		/*
		 * If the fromsnap is in a different filesystem, then
		 * mark the send stream as a clone.
		 */
		if (strncmp(tosnap, fromsnap, fsnamelen) != 0 ||
		    (fromsnap[fsnamelen] != '@' &&
		    fromsnap[fsnamelen] != '#')) {
			dspp.is_clone = B_TRUE;
		}

		if (strchr(fromsnap, '@')) {
			err = dsl_dataset_hold(dspp.dp, fromsnap, FTAG,
			    &fromds);

			if (err != 0) {
				ASSERT3P(fromds, ==, NULL);
			} else {
				/*
				 * We need to make a deep copy of the redact
				 * snapshots of the from snapshot, because the
				 * array will be freed when we evict from_ds.
				 */
				uint64_t *fromredact;
				if (!dsl_dataset_get_uint64_array_feature(
				    fromds, SPA_FEATURE_REDACTED_DATASETS,
				    &dspp.numfromredactsnaps,
				    &fromredact)) {
					dspp.numfromredactsnaps = UINT64_MAX;
				} else if (dspp.numfromredactsnaps > 0) {
					uint64_t size =
					    dspp.numfromredactsnaps *
					    sizeof (uint64_t);
					dspp.fromredactsnaps = kmem_zalloc(size,
					    KM_SLEEP);
					bcopy(fromredact, dspp.fromredactsnaps,
					    size);
				}
				if (!dsl_dataset_is_before(dspp.to_ds, fromds,
				    0)) {
					err = SET_ERROR(EXDEV);
				} else {
					ASSERT3U(dspp.is_clone, ==,
					    (dspp.to_ds->ds_dir !=
					    fromds->ds_dir));
					zb->zbm_creation_txg =
					    dsl_dataset_phys(fromds)->
					    ds_creation_txg;
					zb->zbm_creation_time =
					    dsl_dataset_phys(fromds)->
					    ds_creation_time;
					zb->zbm_guid =
					    dsl_dataset_phys(fromds)->ds_guid;
					zb->zbm_redaction_obj = 0;
				}
				dsl_dataset_rele(fromds, FTAG);
			}
		} else {
			dspp.numfromredactsnaps = UINT64_MAX;
			err = dsl_bookmark_lookup(dspp.dp, fromsnap, dspp.to_ds,
			    zb);
			if (err == EXDEV && zb->zbm_redaction_obj != 0 &&
			    zb->zbm_guid ==
			    dsl_dataset_phys(dspp.to_ds)->ds_guid)
				err = 0;
		}

		if (err == 0) {
			/* dmu_send_impl will call dsl_pool_rele for us. */
			err = dmu_send_impl(&dspp);
		} else {
			dsl_pool_rele(dspp.dp, FTAG);
		}
	} else {
		dspp.numfromredactsnaps = UINT64_MAX;
		err = dmu_send_impl(&dspp);
	}
out:
	if (dspp.redact_type == REDACT_LIST &&
	    dspp.redact_data.rdl.numredactsnaps != 0) {
		for (int i = 0; i < dspp.redact_data.rdl.numredactsnaps; i++) {
			dsl_dataset_rele(dspp.redact_data.rdl.redactsnaparr[i],
			    FTAG);
		}
		kmem_free(dspp.redact_data.rdl.redactsnaparr,
		    fnvlist_num_pairs(redactsnaps) * sizeof (dsl_dataset_t *));
	}

	if (owned)
		dsl_dataset_disown(dspp.to_ds, FTAG);
	else
		dsl_dataset_rele(dspp.to_ds, FTAG);
	return (err);
}

static int
dmu_adjust_send_estimate_for_indirects(dsl_dataset_t *ds, uint64_t uncompressed,
    uint64_t compressed, boolean_t stream_compressed, uint64_t *sizep)
{
	int err;
	uint64_t size;
	/*
	 * Assume that space (both on-disk and in-stream) is dominated by
	 * data.  We will adjust for indirect blocks and the copies property,
	 * but ignore per-object space used (eg, dnodes and DRR_OBJECT records).
	 */
	uint64_t recordsize;
	uint64_t record_count;
	objset_t *os;
	VERIFY0(dmu_objset_from_ds(ds, &os));

	/* Assume all (uncompressed) blocks are recordsize. */
	if (os->os_phys->os_type == DMU_OST_ZVOL) {
		err = dsl_prop_get_int_ds(ds,
		    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), &recordsize);
	} else {
		err = dsl_prop_get_int_ds(ds,
		    zfs_prop_to_name(ZFS_PROP_RECORDSIZE), &recordsize);
	}
	if (err != 0)
		return (err);
	record_count = uncompressed / recordsize;

	/*
	 * If we're estimating a send size for a compressed stream, use the
	 * compressed data size to estimate the stream size. Otherwise, use the
	 * uncompressed data size.
	 */
	size = stream_compressed ? compressed : uncompressed;

	/*
	 * Subtract out approximate space used by indirect blocks.
	 * Assume most space is used by data blocks (non-indirect, non-dnode).
	 * Assume no ditto blocks or internal fragmentation.
	 *
	 * Therefore, space used by indirect blocks is sizeof(blkptr_t) per
	 * block.
	 */
	size -= record_count * sizeof (blkptr_t);

	/* Add in the space for the record associated with each block. */
	size += record_count * sizeof (dmu_replay_record_t);

	*sizep = size;

	return (0);
}

int
dmu_send_estimate_fast(dsl_dataset_t *ds, dsl_dataset_t *fromds,
    zfs_bookmark_phys_t *frombook, boolean_t stream_compressed, uint64_t *sizep)
{
	dsl_pool_t *dp = ds->ds_dir->dd_pool;
	int err;
	uint64_t uncomp, comp;

	ASSERT(dsl_pool_config_held(dp));
	ASSERT(fromds == NULL || frombook == NULL);

	/* tosnap must be a snapshot */
	if (!ds->ds_is_snapshot)
		return (SET_ERROR(EINVAL));

	if (fromds != NULL) {
		uint64_t used;
		if (!fromds->ds_is_snapshot)
			return (SET_ERROR(EINVAL));

		if (!dsl_dataset_is_before(ds, fromds, 0))
			return (SET_ERROR(EXDEV));

		err = dsl_dataset_space_written(fromds, ds, &used, &comp,
		    &uncomp);
		if (err != 0)
			return (err);
	} else if (frombook != NULL) {
		uint64_t used;
		err = dsl_dataset_space_written_bookmark(frombook, ds, &used,
		    &comp, &uncomp);
		if (err != 0)
			return (err);
	} else {
		uncomp = dsl_dataset_phys(ds)->ds_uncompressed_bytes;
		comp = dsl_dataset_phys(ds)->ds_compressed_bytes;
	}

	err = dmu_adjust_send_estimate_for_indirects(ds, uncomp, comp,
	    stream_compressed, sizep);
	/*
	 * Add the size of the BEGIN and END records to the estimate.
	 */
	*sizep += 2 * sizeof (dmu_replay_record_t);
	return (err);
}
