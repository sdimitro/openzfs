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
# Test that redacted send streams can be received successfully, and that
# zfs receive will prevent invalid clones from being produced
#

verify_runnable "both"

log_assert "Verify that zfs receive protects itself from invalid clones."

streamfile=$(mktemp /tmp/stream.XXXXXX)

function cleanup
{
	$ZFS destroy -R $POOL2/rfs
	$RM $streamfile
	$ZFS destroy $POOL/$FS#book1
	$ZFS destroy $POOL/$FS#book6
	$ZFS destroy $POOL/int_clone-A#book2
	$ZFS destroy $POOL/int_clone-A#book3
	$ZFS destroy $POOL/int_clone-A#book4
	$ZFS destroy $POOL/int_clone-A#book5
	$ZFS destroy $POOL/int_clone-A#book7
}

log_onexit cleanup

#
# Send the initial snap with respect to a few snapshots at different depths,
# and verify behavior.
#
typeset snaps1=$POOL/rm_clone2-A@snap,$POOL/stride3_clone-A@snap
typeset snaps2=$POOL/stride5_clone-A@snap
log_must eval "$ZFS send --redact \"$snaps1,$snaps2\"  $POOL/$FS@snapA book1 \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rfs

# Verify we can receive normal children.
log_must eval "$ZFS send -i $POOL/$FS@snapA $POOL/stride3_clone-A@snap > \
    $streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rstride3_clone
log_must cmp_ds_cont $POOL/stride3_clone-A $POOL2/rstride3_clone

log_must eval "$ZFS send -i $POOL/$FS@snapA $POOL/stride5_clone-A@snap \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rstride5_clone
log_must cmp_ds_cont $POOL/stride3_clone-A $POOL2/rstride5_clone

#
# Verify we cannot receive a normal child that we weren't redacted with respect
# to.
#
log_must eval "$ZFS send -i $POOL/$FS@snapA $POOL/hole_clone-A@snap \
    >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rhole_clone

# Verify we can receive a full clone.
log_must eval "$ZFS send $POOL/hole_clone-A@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive \
    -o origin=$POOL2/rfs@snapA $POOL2/rhole_clone
log_must cmp_ds_cont $POOL/hole_clone-A $POOL2/rhole_clone

#
# Verify we cannot receive an intermediate clone redacted with respect to
# something that isn't a subset.
#
log_must eval "$ZFS send -i $POOL/$FS@snapA --redact \
    $POOL/rm_clone2-A@snap,$POOL/write_clone-A@snap $POOL/int_clone-A@snap \
    book2  >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rint_clone

log_must eval "$ZFS send -i $POOL/$FS@snapA --redact $POOL/write_clone-A@snap \
    $POOL/int_clone-A@snap book3 >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rint_clone

# Verify we can receive an intermediate clone redacted with respect to a subset.
log_must eval "$ZFS send -i $POOL/$FS@snapA --redact \"\" \
    $POOL/int_clone-A@snap  book4 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rint_clone
log_must $ZFS destroy -r $POOL2/rint_clone

log_must eval "$ZFS send -i $POOL/$FS@snapA --redact $POOL/rm_clone2-A@snap \
    $POOL/int_clone-A@snap book5 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rint_clone

# Verify we can receive grandchildren on the child.
log_must eval "$ZFS send -i $POOL/int_clone-A@snap $POOL/rm_clone2-A@snap \
    >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rrm_clone2
log_must cmp_ds_cont $POOL/rm_clone2-A $POOL2/rrm_clone2

#
# Verify we cannot receive a grandchild that the received child wasn't redacted
# with respect to.
#
log_must eval "$ZFS send -i $POOL/int_clone-A@snap $POOL/write_clone-A@snap \
    >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rwrite_clone

# Verify we can receive a full clone of a grandchild on the child.
log_must eval "$ZFS send $POOL/write_clone-A@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive \
    -o origin=$POOL2/rint_clone@snap $POOL2/rwrite_clone
log_must cmp_ds_cont $POOL/write_clone-A $POOL2/rwrite_clone

# Verify that the pool can be successfully exported and imported.
log_must $ZPOOL export $POOL2
log_must $ZPOOL import $POOL2

log_must $ZFS destroy -R $POOL2/rfs

#
# Send the initial snap redacted with respet to nothing, verify behavior.
#
log_must eval "$ZFS send --redact \"\" $POOL/$FS@snapA book6 >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rfs

# Verify we can't receive children at the base.
log_must eval "$ZFS send -i $POOL/$FS@snapA $POOL/stride3_clone-A@snap \
    >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rstride3_clone

# Verify full sends of a child can be received as a clone.
log_must eval "$ZFS send $POOL/hole_clone-A@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive \
    -o origin=$POOL2/rfs@snapA $POOL2/rhole_clone
log_must cmp_ds_cont $POOL/hole_clone-A $POOL2/rhole_clone

# Verify we can receive a child redacted with respect to the empty list.
log_must eval "$ZFS send -i $POOL/$FS@snapA --redact \"\" \
    $POOL/int_clone-A@snap book7 >$streamfile "
$CAT $streamfile | log_must $ZFS receive $POOL2/rint_clone

# Verify we can't receive grandchildren onto the new child.
log_must eval "$ZFS send -i $POOL/int_clone-A@snap $POOL/rm_clone2-A@snap \
    >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive $POOL2/rrm_clone2

# Verify full sends of a grandchild can be received as a clone on the child.
log_must eval "$ZFS send $POOL/rm_clone2-A@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive \
    -o origin=$POOL2/rint_clone@snap $POOL2/rrm_clone2
log_must cmp_ds_cont $POOL/rm_clone2-A $POOL2/rrm_clone2

# Verify that the pool can be successfully exported and imported.
log_must $ZPOOL export $POOL2
log_must $ZPOOL import $POOL2


log_pass "Verify that zfs receive protects itself from invalid clones."
