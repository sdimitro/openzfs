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
 * This test excercises the "remnant" handling of the temporal option.
 * At the end of one pass of retrieving and printing data from all CPUs,
 * some unprocessed data will remain, because its timestamp is after the
 * time covered by all CPUs' buffers.  This unprocessed data is
 * rearranged in a more space-efficient manner.  If this is done
 * incorrectly, an alignment error may occur.  To test this, we use a
 * high-frequency probe so that data will be recorded in subsequent
 * CPU's buffers after the first CPU's buffer is obtained.  The
 * combination of data traced here (a 8-byte value and a 4-byte value)
 * is effective to cause alignment problems with an incorrect
 * implementation.
 *
 * This test needs to be run on a multi-CPU system to be effective.
 */

#pragma D option quiet
#pragma D option temporal

profile-4997
{
	printf("%u %u", 1ULL, 2);
}

tick-1
/i++ == 10/
{
	exit(0);
}
