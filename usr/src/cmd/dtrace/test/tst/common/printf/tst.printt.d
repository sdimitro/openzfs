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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*
 * ASSERTION:
 * Test the format specifier %t which prints the time
 * in human readable time format.
 *
 * SECTION: Output Formatting/printf()
 *
 */

#pragma D option quiet

uint64_t uint_max;

BEGIN
{
	uint_max = 18446744073709551615ULL;
	printf("%t\n", 0);
	printf("%t\n", 9999);
	printf("%t\n", 9999999);
	printf("%t\n", 9999999999);
	printf("%t\n", 9999999999999);
	printf("%t\n", 9999999999999999);
	printf("%t\n", uint_max);

	exit(0);
}
