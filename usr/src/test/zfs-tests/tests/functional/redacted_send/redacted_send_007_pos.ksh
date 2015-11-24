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
# Test that sends of redacted datasets work correctly
#

verify_runnable "both"

log_assert "Verify that sends of redacted datasets work correctly"

streamfile=$($MKTEMP /tmp/stream.XXXXXX)

function cleanup
{
	$ZFS destroy -R $POOL2/rfs
	$RM $streamfile
	$ZFS destroy $POOL/$FS#book1
}

log_onexit cleanup

#
# Send the initial snapshot, receive it, and then send and receive an
# incremental.
#
typeset snaps=$POOL/rm_clone2-A@snap,$POOL/stride3_clone-A@snap
log_must eval "$ZFS send --redact $snaps $POOL/$FS@snapA book1 \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rfs

log_must $ZFS clone $POOL2/rfs@snapA $POOL2/clone
log_must $ZFS snapshot $POOL2/clone@snap

log_mustnot eval "$ZFS send --redact $POOL2/clone@snap $POOL2/rfs@snapA book2 \
    >$streamfile"
log_must eval "$ZFS send $POOL2/rfs@snapA >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rfs2

log_must eval "$ZFS send -i $POOL/$FS@snapA $POOL/stride3_clone-A@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rclone

log_pass "Verify that redacted sends of redacted datasets work correctly"
