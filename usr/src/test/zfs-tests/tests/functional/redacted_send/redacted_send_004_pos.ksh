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
# Test that redacted send streams can be received and resumed successfully.
#

verify_runnable "both"

log_assert "Verify that redacted send streams can be resumed successfully."

streamfile=$($MKTEMP /tmp/stream.XXXXXX)

function cleanup
{
	$ZFS destroy -R $POOL2/rfs
	$RM $streamfile
	$ZFS destroy $POOL/$FS#book1
	$ZFS destroy $POOL/int_clone-A#book2
	$ZFS destroy $POOL/int_clone-A#book3
}

log_onexit cleanup

#
# Send the initial snap with respect to a few snapshots at different depths,
# truncate the stream, and make sure it can be continued.
#
snaps=$POOL/rm_clone2-A@snap,$POOL/stride3_clone-A@snap,$POOL/hole_clone-A@snap
log_must eval "$ZFS send --redact \"$snaps\"  $POOL/$FS@snapA book1 >$streamfile"
$DD if=$streamfile bs=64k count=1 | log_mustnot $ZFS receive -s $POOL2/rfs
token=$($ZFS get -Hp -o value receive_resume_token $POOL2/rfs)
log_must eval "$ZFS send -t $token book1 >$streamfile"
cat $streamfile | log_must $ZFS receive $POOL2/rfs

# Verify we can receive normal children.
log_must eval "$ZFS send -i $POOL/$FS@snapA $POOL/stride3_clone-A@snap > \
    $streamfile"
cat $streamfile | log_must $ZFS receive $POOL2/rstride3_clone
log_must cmp_ds_cont $POOL/stride3_clone-A $POOL2/rstride3_clone

#
# Verify we cannot receive a normal child that we weren't redacted with respect
# to.
#
log_must eval "$ZFS send -i $POOL/$FS@snapA $POOL/stride5_clone-A@snap > \
    $streamfile"
cat $streamfile | log_mustnot $ZFS receive $POOL2/rstride5_clone

# Verify we can receive a full clone.
log_must eval "$ZFS send $POOL/stride5_clone-A@snap >$streamfile"
cat $streamfile | log_must $ZFS receive \
    -o origin=$POOL2/rfs@snapA $POOL2/rstride5_clone
log_must cmp_ds_cont $POOL/hole_clone-A $POOL2/rstride5_clone

#
# Verify we cannot receive an intermediate clone redacted with respect to
# something that isn't a subset.
#
log_must eval "$ZFS send -i $POOL/$FS@snapA --redact \
    $POOL/rm_clone2-A@snap,$POOL/write_clone-A@snap $POOL/int_clone-A@snap \
    book2 >$streamfile"
cat $streamfile | log_mustnot $ZFS receive $POOL2/rint_clone

# Verify we can receive an intermediate clone redacted with respect to a subset.
log_must eval "$ZFS send -i $POOL/$FS@snapA --redact $POOL/rm_clone2-A@snap \
    $POOL/int_clone-A@snap book3 >$streamfile"
cat $streamfile | log_must $ZFS receive $POOL2/rint_clone

# Verify that the pool can be successfully exported and imported.
log_must $ZPOOL export $POOL2
log_must $ZPOOL import $POOL2

log_pass "Verify that redacted send streams can be resumed successfully."
