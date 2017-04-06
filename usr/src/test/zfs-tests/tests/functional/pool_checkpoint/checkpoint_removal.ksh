#!/usr/bin/ksh -p

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

#
# Copyright (c) 2017 by Delphix. All rights reserved.
#

. $STF_SUITE/tests/functional/pool_checkpoint/pool_checkpoint.kshlib

#
# DESCRIPTION:
#	Attempt to take a checkpoint while a removal is
#	in progress. The attempt should fail.
#
# STRATEGY:
#	1. Create pool with one disk
#	2. Create a big file in the pool, so when the disk
#	   is later removed, it will give us enough of a
#	   time window to attempt the checkpoint while the
#	   removal takes place
#	3. Add a second disk where all the data will be moved
#	   to when the first disk will be removed.
#	4. Start removal of first disk
#	5. Attempt to checkpoint (attempt should fail)
#

function test_cleanup
{
	default_cleanup_noexit
	log_must rm -f $DISK1 $DISK2
}

verify_runnable "global"

#
# Create pool
#
log_must mkfile $DISKSIZE $DISK1
default_setup_noexit "$DISK1"

log_onexit test_cleanup

#
# Create big empty file and do some writes at random
# offsets to ensure that it takes up space. Note that
# the implcitly created filesystem ($FS0) does not
# have compression enabled.
#
log_must mkfile $BIGFILESIZE $FS0FILE
log_must randwritecomp $FS0FILE 1000

#
# Add second disk
#
log_must mkfile $DISKSIZE $DISK2
log_must zpool add $TESTPOOL $DISK2

#
# Remove disk and attempt to take checkpoint
#
log_must zpool remove $TESTPOOL $DISK1
log_mustnot zpool checkpoint $TESTPOOL
log_must zpool status $TESTPOOL

log_pass "Attempting to checkpoint during removal fails as expected."
