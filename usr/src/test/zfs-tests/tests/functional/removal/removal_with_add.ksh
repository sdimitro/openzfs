#! /bin/ksh -p
#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

#
# Copyright (c) 2014 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/removal/removal.kshlib

TMPDIR=${TMPDIR:-/var/tmp}
log_must $MKFILE 1g $TMPDIR/dsk1
log_must $MKFILE 1g $TMPDIR/dsk2

function cleanup
{
	default_cleanup_noexit
	log_must $RM -f $TMPDIR/dsk1 $TMPDIR/dsk2
}

default_setup_noexit "$DISKS"
log_onexit cleanup

function callback
{
	typeset count=$1
	if ((count == 0)); then
		log_mustnot $ZPOOL attach -f $TESTPOOL $TMPDIR/dsk1 $TMPDIR/dsk2
		log_mustnot $ZPOOL add -f $TESTPOOL \
		    raidz $TMPDIR/dsk1 $TMPDIR/dsk2
		log_must $ZPOOL add -f $TESTPOOL $TMPDIR/dsk1
	fi

	return 0
}

test_removal_with_operation callback

log_pass "Removal can only add normal disks."
