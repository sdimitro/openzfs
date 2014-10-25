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
# Copyright (c) 2014 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/rsend/rsend.kshlib

#
# Description:
# Verify that holes in files, holes in the metaobjset, and reallocation of
# objects doesn't cause issues in zfs rebase send.
#
# Strategy:
# 1. Create filesystem containing a hole in the objset, a file with recordsize
#    512, and a file with a hole
# 2. Create filesystem containing objects in the hole from the previous
#    filesystem, a file with recordsize 128k in the same object number as the
#    file with recordsize 512 from fs1.
# 3. zfs send -b with fs1 as fromsnap and fs2 as tosnap
# 4. Verify that stream does the right thing when applied
# 5. zfs send -b with fs2 as fromsnap and fs1 as tosnap
# 6. Verify that stream does the right thing when applied
#

verify_runnable "both"

log_assert "Verify odd filesystem configurations don't break zfs rebase send."
log_onexit cleanup_pool $POOL2

log_must $ZFS create $POOL2/$FS
log_must $ZFS create $POOL2/$FS/f1
typeset mntpnt1=$(get_prop mountpoint $POOL2/$FS/f1)
log_must $ZFS set recordsize=512 $POOL2/$FS/f1
for i in {1..129}
do
	$DD if=/dev/urandom of=$mntpnt1/f$i bs=512 count=1 2>/dev/null
done

log_must $DD if=/dev/urandom of=$mntpnt1/f130 bs=512 count=129 2>/dev/null
for i in {1..128}
do
	rm $mntpnt1/f$i
done

log_must $ZFS snapshot $POOL2/$FS/f1@snap

log_must $ZFS create $POOL2/$FS/f2
typeset mntpnt2=$(get_prop mountpoint $POOL2/$FS/f2)
log_must $ZFS set recordsize=128k $POOL2/$FS/f2
for i in {1..129}
do
	$DD if=/dev/urandom of=$mntpnt2/f$i bs=128k count=1 2>/dev/null
done
log_must $ZFS snapshot  $POOL2/$FS/f2@snap

log_must eval "$ZFS send $POOL2/$FS/f1@snap > $BACKDIR/fs1-strm"
log_must eval "$ZFS receive $POOL2/$FS/rfs@snap1 < $BACKDIR/fs1-strm"
log_must eval "$ZFS send -b -i $POOL2/$FS/f1@snap $POOL2/$FS/f2@snap > $BACKDIR/fs1-2strm"
log_must eval "$ZFS receive $POOL2/$FS/rfs@snap2 < $BACKDIR/fs1-2strm"
typeset mntpnt3=$(get_prop mountpoint $POOL2/$FS/rfs)
log_must $DIFF -r $mntpnt2 $mntpnt3
log_must $ZFS destroy -r $POOL2/$FS/rfs

log_must eval "$ZFS send $POOL2/$FS/f2@snap > $BACKDIR/fs2-strm"
log_must eval "$ZFS receive $POOL2/$FS/rfs@snap1 < $BACKDIR/fs2-strm"
log_must eval "$ZFS send -b -i $POOL2/$FS/f2@snap $POOL2/$FS/f1@snap > $BACKDIR/fs2-1strm"
log_must eval "$ZFS receive $POOL2/$FS/rfs@snap2 < $BACKDIR/fs2-1strm"
typeset mntpnt3=$(get_prop mountpoint $POOL2/$FS/rfs)
log_must $DIFF -r $mntpnt1 $mntpnt3
log_must $ZFS destroy -r $POOL2/$FS/rfs

log_pass "Verify odd filesystem configurations don't break zfs rebase send."
