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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#ifndef	_DT_PQ_H
#define	_DT_PQ_H

#include <dtrace.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint64_t (*dt_pq_value_f)(void *, void *);

typedef struct dt_pq {
	dtrace_hdl_t *dtpq_hdl;		/* dtrace handle */
	void **dtpq_items;		/* array of elements */
	uint_t dtpq_size;		/* count of allocated elements */
	uint_t dtpq_last;		/* next free slot */
	dt_pq_value_f dtpq_value;	/* callback to get the value */
	void *dtpq_arg;			/* callback argument */
} dt_pq_t;

extern dt_pq_t *dt_pq_init(dtrace_hdl_t *, uint_t size, dt_pq_value_f, void *);
extern void dt_pq_fini(dt_pq_t *);

extern void dt_pq_insert(dt_pq_t *, void *);
extern void *dt_pq_pop(dt_pq_t *);
extern void *dt_pq_walk(dt_pq_t *, uint_t *);

#endif	/* _DT_PQ_H */
