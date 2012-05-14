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

/*
 * Compile some code that requires exactly 9 registers. This should generate
 * invalid DIF because the kernel will flag the fact that we're using more
 * registers than are available internally.
 *
 * Changes to the code generator might cause this test to succeeed in which
 * case the code should be changed to another sequence that exhausts the
 * available internal registers.
 *
 * Note that this and err.D_NOREG.noreg.d should be kept in sync.
 */

#pragma D option iregs=9

BEGIN
{
	a = 4;
	trace((a + a) * ((a + a) * ((a + a) * ((a + a) * ((a + a) *
	    ((a + a) * (a + a)))))));
}

BEGIN
{
	exit(0);
}
