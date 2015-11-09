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
# Copyright (c) 2015 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/redacted_send/redacted_send.kshlib

#
# Description:
# Test that redacted filesystems can be mounted, if we enable that feature.
#

verify_runnable "both"

log_assert "Verify that redacted filesystems can be mounted."

streamfile=$($MKTEMP /tmp/stream.XXXXXX)
sendfs=$POOL/sendfs
recvfs=$POOL2/recvfs

function cleanup
{
	$ZFS destroy -R $sendfs
	$ZFS destroy -R $recvfs
	$RM $streamfile
	echo "zfs_allow_redacted_dataset_mount/W 0" | $MDB -kw
}

log_onexit cleanup

log_must $ZFS create -o recordsize=512 $sendfs
typeset mntpnt=$(get_prop mountpoint $sendfs)
log_must $TOUCH $mntpnt/empty
log_must $DD if=/dev/urandom of=$mntpnt/contents1 bs=512 count=2
log_must $DD if=/dev/urandom of=$mntpnt/contents2 bs=512 count=2
log_must $MKDIR $mntpnt/dir1
log_must $TOUCH $mntpnt/dir1/empty
log_must $DD if=/dev/urandom of=$mntpnt/dir1/contents1 bs=512 count=2
log_must $DD if=/dev/urandom of=$mntpnt/dir1/contents2 bs=512 count=2
log_must $MKDIR $mntpnt/dir1/dir2
log_must $TOUCH $mntpnt/dir1/dir2/empty
log_must $DD if=/dev/urandom of=$mntpnt/dir1/dir2/file bs=512 count=2
log_must $ZFS snapshot $sendfs@snap

log_must $ZFS clone $sendfs@snap $POOL/testclone
typeset mntpnt2=$(get_prop mountpoint $POOL/testclone)
log_must $RM $mntpnt2/empty $mntpnt2/contents1
log_must $DD if=/dev/urandom of=$mntpnt2/contents2 bs=512 count=1 conv=notrunc
log_must $RM $mntpnt2/dir1/contents1
log_must $RM -rf $mntpnt2/dir1/dir2
log_must $DD if=/dev/urandom of=$mntpnt2/dir1/contents2 bs=512 count=1 \
    conv=notrunc
log_must $DD if=/dev/urandom of=$mntpnt2/dir1/empty bs=512 count=1
log_must $ZFS snapshot $POOL/testclone@snap

echo "zfs_allow_redacted_dataset_mount/W 1" | log_must $MDB -kw

log_must eval "$ZFS send --redact $POOL/testclone@snap $sendfs@snap book \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $recvfs

log_mustnot $ZFS mount $recvfs
log_must $ZFS mount -o ro -f $recvfs
typeset mntpnt3=$(get_prop mountpoint $recvfs)

# Verify that the send and recv fs both have the same files under their
# mountpoints by comparing find output with the name of the mountpoint
# deleted.
contents=$(log_must $FIND $mntpnt3)
contents_orig=$(log_must $FIND $mntpnt)
log_must $DIFF <(echo ${contents//$mntpnt3/}) <(echo ${contents_orig//$mntpnt/})

log_must $DD if=/dev/urandom of=$mntpnt/dir1/contents1 bs=512 count=2
log_must $RM $mntpnt/dir1/dir2/empty
log_must $ZFS snapshot $sendfs@snap2
log_must eval "$ZFS send -i $sendfs#book $sendfs@snap2 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $recvfs
contents=$(log_must $FIND $mntpnt3)
contents_orig=$(log_must $FIND $mntpnt)
log_must $DIFF <(echo ${contents//$mntpnt3/}) <(echo ${contents_orig//$mntpnt/})

log_must $ZPOOL export $POOL2
log_must $ZPOOL import $POOL2

log_must $ZFS unmount $recvfs

log_pass "Verify that redacted filesystems can be mounted."
