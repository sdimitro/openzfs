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
# Test that incremental redacted send streams can be received and resumed
# successfully.
#

verify_runnable "both"

log_assert "Verify that incremental redacted send streams work correctly."

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
# Send the initial snapshot, receive it, and then send and receive an
# incremental.
#
typeset snaps=$POOL/rm_clone2-A@snap,$POOL/stride3_clone-A@snap
typeset snaps2=$POOL/stride5_clone-A@snap
log_must eval "$ZFS send --redact \"$snaps,$snaps2\" $POOL/$FS@snapA book1 \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rfs

typeset snaps=$POOL/rm_clone1-B@snap,$POOL/hole_clone-B@snap
log_must eval "$ZFS send -i $POOL/$FS#book1 --redact \"$snaps\" \
     $POOL/$FS@snapB book2 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rfs

#
# Verify we can receive a non-redacted clone onto a redacted snapshot correctly.
#
log_must eval "$ZFS send -i $POOL/$FS@snapB $POOL/hole_clone-B@snap \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rhole_cloneB
log_must cmp_ds_cont $POOL/hole_clone-B $POOL2/rhole_cloneB

#
# Verify we cannot receive a normal child that we weren't redacted with respect
# to.
#
log_must eval "$ZFS send -i $POOL/$FS@snapB $POOL/stride3_clone-B@snap > \
    $streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rstride3_cloneB

# Verify we can receive a full clone.
log_must eval "$ZFS send $POOL/stride3_clone-B@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive \
    -o origin=$POOL2/rfs@snapA $POOL2/rstride3_cloneB
log_must cmp_ds_cont $POOL/stride3_clone-B $POOL2/rstride3_cloneB
$ZFS destroy -r $POOL2/rstride3_cloneB

#
# Verify we can receive a child we were not redacted with respect to if we send
# from the bookmark.
#
log_must eval "$ZFS send -i $POOL/$FS#book2 $POOL/stride3_clone-B@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rstride3_cloneB
log_must cmp_ds_cont $POOL/stride3_clone-B $POOL2/rstride3_cloneB

#
# Verify we cannot receive an intermediate clone redacted with respect to
# something that isn't a subset.
#
log_must eval "$ZFS send -i $POOL/$FS@snapB --redact \
    $POOL/rm_clone2-B@snap,$POOL/write_clone-B@snap $POOL/int_clone-B@snap \
    book2 >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rint_cloneB

#
# Verify we can receive an intermediate clone redacted with respect to a
# non-subset if we send from the bookmark.
#
log_must eval "$ZFS send -i $POOL/$FS#book2 --redact \
    $POOL/rm_clone2-B@snap,$POOL/write_clone-B@snap $POOL/int_clone-B@snap \
    book4 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rint_cloneB

#
# Verify we can receive a grandchild on the child.
#
log_must eval "$ZFS send -i $POOL/int_clone-B@snap $POOL/write_clone-B@snap \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rwrite_cloneB
log_must cmp_ds_cont $POOL/write_clone-B $POOL2/rwrite_cloneB

# Verify that the pool can be successfully exported and imported.
log_must $ZPOOL export $POOL2
log_must $ZPOOL import $POOL2


#
# Send the incremental, but truncate the stream when we try to receive it.
# Resume the send and receive that.
#
typeset snaps=$POOL/rm_clone2-C@snap,$POOL/stride3_clone-C@snap
typeset snaps2=$POOL/stride5_clone-C@snap
log_must eval "$ZFS send -i $POOL/$FS#book2 --redact \"$snaps,$snaps2\" \
     $POOL/$FS@snapC book3 >$streamfile"
$DD if=$streamfile bs=64k count=1 | log_mustnot $ZFS receive -s $POOL2/rfs
token=$($ZFS get -Hp -o value receive_resume_token $POOL2/rfs)
log_must eval "$ZFS send -t $token book3 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rfs

# Verify we can receive normal children.
log_must eval "$ZFS send -i $POOL/$FS@snapC $POOL/stride3_clone-C@snap \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rstride3_cloneC
log_must cmp_ds_cont $POOL/stride3_clone-C $POOL2/rstride3_cloneC

#
# Verify we cannot receive a normal child that we weren't redacted with respect
# to.
#
log_must eval "$ZFS send -i $POOL/$FS@snapC $POOL/rm_clone1-C@snap > \
    $streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rrm_clone1C

# Verify we can receive a full clone.
log_must eval "$ZFS send $POOL/rm_clone1-C@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive \
    -o origin=$POOL2/rfs@snapC $POOL2/rrm_clone1C
log_must cmp_ds_cont $POOL/rm_clone1-C $POOL2/rrm_clone1C
$ZFS destroy -r $POOL2/rrm_clone1C

#
# Verify we can receive a child we were not redacted with respect to if we send
# from the bookmark.
#
log_must eval "$ZFS send -i $POOL/$FS#book3 $POOL/rm_clone1-C@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rrm_clone1C
log_must cmp_ds_cont $POOL/rm_clone1-C $POOL2/rrm_clone1C

#
# Verify we cannot receive an intermediate clone redacted with respect to
# something that isn't a subset.
#
log_must eval "$ZFS send -i $POOL/$FS@snapC --redact \
    $POOL/rm_clone2-C@snap,$POOL/write_clone-C@snap $POOL/int_clone-C@snap \
    book2 >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rint_cloneC

# Verify we can receive an intermediate clone redacted with respect to a subset.
log_must eval "$ZFS send -i $POOL/$FS@snapC --redact $POOL/rm_clone2-C@snap \
    $POOL/int_clone-C@snap book3 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rint_cloneC
$ZFS destroy -r $POOL2/rint_cloneC

#
# Verify we can receive an intermediate clone redacted with respect to a
# non-subset if we send from the bookmark.
#
log_must eval "$ZFS send -i $POOL/$FS#book3 --redact \
    $POOL/rm_clone2-C@snap,$POOL/write_clone-C@snap $POOL/int_clone-C@snap \
    book4 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rint_cloneC

#
# Verify we can receive a grandchild on the child.
#
log_must eval "$ZFS send -i $POOL/int_clone-C@snap $POOL/write_clone-C@snap \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rwrite_cloneC
log_must cmp_ds_cont $POOL/write_clone-C $POOL2/rwrite_cloneC

# Verify that the pool can be successfully exported and imported.
log_must $ZPOOL export $POOL2
log_must $ZPOOL import $POOL2


log_pass "Verify that redacted send streams can be resumed successfully."
