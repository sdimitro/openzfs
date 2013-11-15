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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef _SYS_MOOCH_BYTESWAP_H
#define	_SYS_MOOCH_BYTESWAP_H

#include <sys/spa.h>
#include <sys/zio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	BSREC_MAX_RECORDS (BPE_PAYLOAD_SIZE / sizeof (bsrec_t))

/*
 * Byteswap record layout.
 *
 * 8               0
 * +---+-----------+
 * | T |count/instr|
 * +---+-----------+
 *
 * Legend:
 * T		2-bit record type
 * count/instr	6-bit count or instruction type
 */

#define	BSREC_GET_TYPE(rec)		BF32_GET((rec), 6, 2)
#define	BSREC_SET_TYPE(rec, x)		BF32_SET((rec), 6, 2, x)

#define	BSREC_GET_DATA(rec)		BF32_GET((rec), 0, 6)
#define	BSREC_SET_DATA(rec, x)		BF32_SET((rec), 0, 6, x)
#define	BSREC_MAX_DATA			((1 << 6) - 1)

typedef enum bsrec_type {
	BSREC_TYPE_INSTR,		/* data is bsrec_instr_t */
	BSREC_TYPE_SKIP,		/* data is number of bytes to skip */
	BSREC_TYPE_REPEAT,		/* data is number of times to repeat */
	BSREC_NUMTYPE
} bsrec_type_t;

typedef enum bsrec_instr {
	BSREC_INSTR_SKIP8,
	BSREC_INSTR_SWAP16,
	BSREC_INSTR_SWAP32,
	BSREC_INSTR_SWAP48,
	BSREC_INSTR_SWAP64,
	BSREC_INSTR_XOR16,
	BSREC_NUMINSTR
} bsrec_instr_t;

typedef uint8_t bsrec_t;

int mooch_byteswap_determine(dmu_buf_t *, dmu_buf_t *, blkptr_t *);
void mooch_byteswap_reconstruct(dmu_buf_t *, void *, const blkptr_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MOOCH_BYTESWAP_H */
