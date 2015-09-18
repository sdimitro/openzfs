#!/usr/bin/ksh

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
# Copyright (c) 2014, 2015 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/rsend/rsend.kshlib

#
# Description:
# Verify that destroying the fromsnap of a zfs send -b doesn't cause an issue
#
# Strategy:
# 1. Create filesystem containing large file, snapshot
# 2. zfs send -b with above snapshot as fromsnap, after .5 seconds, destroy
#    fromsnap
# 3. Destroy the above snapshot, then try to use it as the fromsnap for zfs
#    send -b
#

verify_runnable "both"

log_assert "Destroying the fromsnap of zfs send -b doesn't cause issues."
log_onexit cleanup_pool $POOL2

log_must zfs create $POOL2/$FS
log_must zfs create $POOL2/$FS/f1
typeset mntpnt1=$(get_prop mountpoint $POOL2/$FS/f1)
log_must dd if=/dev/urandom of=$mntpnt1/file bs=1024k count=1k
log_must zfs snapshot $POOL2/$FS/f1@snap

log_must zfs create $POOL2/$FS/f2
log_must zfs snapshot  $POOL2/$FS/f2@snap

# Flush the cache so the send takes a little while
log_must zpool export $POOL2
log_must zpool import $POOL2
zfs send -b -i $POOL2/$FS/f2@snap $POOL2/$FS/f1@snap >/dev/null &
jobs=$!
log_must sleep .5
log_neg zfs destroy $POOL2/$FS/f2@snap

log_must /usr/bin/kill $jobs
wait $jobs

log_neg eval "zfs send -b -i $POOL2/$FS/f2@nonexist_snap $POOL2/$FS/f1@snap " \
">/dev/null"

log_pass "Destroying the fromsnap of zfs send -b doesn't cause issues."
