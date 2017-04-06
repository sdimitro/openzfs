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
#	It shouldn't be possible to change pool's vdev config when
#	it has a checkpoint.
#
# STRATEGY:
#	1. Create pool and take checkpoint
#	2. Attempt to change guid
#	3. Attempt to attach/replace/remove device
#

verify_runnable "global"

setup_pool

log_onexit cleanup

log_must zpool checkpoint $TESTPOOL

log_mustnot zpool reguid $TESTPOOL
log_mustnot zpool attach -f $TESTPOOL $DISK1 $EXTRADISK
log_mustnot zpool replace $TESTPOOL $DISK1 $EXTRADISK
log_mustnot zpool remove $TESTPOOL $DISK1

log_pass "Cannot change pool's config when pool has checkpoint."
