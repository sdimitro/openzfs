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
 * Copyright (c) 2012 by Delphix.  All rights reserved.
 */

/*
 * Test execution-time casting between integer types of different size.
 */

#pragma D option quiet

int64_t x;

BEGIN
{
	z = 0xfff0;

	x = (int32_t)(int16_t)z;
	printf("%16x %20d %20u\n", x, x, x);
	x = (int32_t)(uint16_t)z;
	printf("%16x %20d %20u\n", x, x, x);
	x = (uint32_t)(int16_t)z;
	printf("%16x %20d %20u\n", x, x, x);
	x = (uint32_t)(uint16_t)z;
	printf("%16x %20d %20u\n", x, x, x);
	printf("\n");

	x = (int16_t)(int32_t)z;
	printf("%16x %20d %20u\n", x, x, x);
	x = (int16_t)(uint32_t)z;
	printf("%16x %20d %20u\n", x, x, x);
	x = (uint16_t)(int32_t)z;
	printf("%16x %20d %20u\n", x, x, x);
	x = (uint16_t)(uint32_t)z;
	printf("%16x %20d %20u\n", x, x, x);

	exit(0);
}
