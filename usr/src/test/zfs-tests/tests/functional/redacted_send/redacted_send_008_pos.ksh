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
# Test that receiving sends from redaction bookmarks and redacted datasets
# works correctly in certain edge cases.
# 1. Send A(B,C,D) to pool2.
# 2. Verify send from A(B, C, D) can be received onto it.
# 3. Verify send from A(B, C) can be received onto it.
# 4. Verify send from A() can be received onto it.
# 5. Verify send from A(E) cannot be received onto it.
# 6. Verify send from redaction bookmark for A(B, C) can be received onto it.
# 7. Verify send from redaction bookmark for A() can be received onto it.
# 8. Verify send from redaction bookmark for A(E) cannot be received onto it.
#

verify_runnable "both"

log_assert "Verify that sends from redacted datasets and bookmarks work correctly."

streamfile=$($MKTEMP /tmp/stream.XXXXXX)
dsA=$POOL/$FS@snapA
dsB=$POOL/hole_clone-A@snap
dsC=$POOL/rm_clone1-A@snap
dsD=$POOL/write_clone-A@snap
dsE=$POOL/stride3_clone-A@snap
dsF=$POOL/stride5_clone-A@snap
targ=$POOL2/targfs@snapA

function cleanup
{
        $ZFS destroy -R $POOL2/rBCD
        $ZFS destroy -R $POOL2/rBC
        $ZFS destroy -R $POOL2/rnone
        $ZFS destroy -R $POOL2/rE
	$ZFS destroy -R $targ
        $RM $streamfile
        $ZFS destroy $POOL/$FS#BCD
        $ZFS destroy $POOL/$FS#BC
        $ZFS destroy $POOL/$FS#none
        $ZFS destroy $POOL/$FS#E
}

log_onexit cleanup

# Set up all the filesystems and clones.
log_must eval "$ZFS send --redact \"$dsB,$dsC,$dsD\" $dsA BCD >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rBCD
$CAT $streamfile | log_must $ZFS receive $targ

log_must eval "$ZFS send --redact \"$dsB,$dsC\" $dsA BC >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rBC

log_must eval "$ZFS send --redact \"\" $dsA none >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rnone

log_must eval "$ZFS send --redact \"$dsE\" $dsA E >$streamfile"
$CAT $streamfile | log_must $ZFS receive $POOL2/rE

log_must eval "$ZFS send $dsF >$streamfile"
$CAT $streamfile | log_must $ZFS receive -o origin=$POOL2/rBCD@snapA $POOL2/BCDrF
$CAT $streamfile | log_must $ZFS receive -o origin=$POOL2/rBC@snapA $POOL2/BCrF
$CAT $streamfile | log_must $ZFS receive -o origin=$POOL2/rnone@snapA $POOL2/nonerF
$CAT $streamfile | log_must $ZFS receive -o origin=$POOL2/rE@snapA $POOL2/ErF

# Run tests from redacted datasets.
log_must eval "$ZFS send -i $POOL2/rBCD@snapA $POOL2/BCDrF@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive -o origin=$targ $POOL2/tdBCD

log_must eval "$ZFS send -i $POOL2/rBC@snapA $POOL2/BCrF@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive -o origin=$targ $POOL2/tdBC

log_must eval "$ZFS send -i $POOL2/rnone@snapA $POOL2/nonerF@snap >$streamfile"
$CAT $streamfile | log_must $ZFS receive -o origin=$targ $POOL2/tdnone

log_must eval "$ZFS send -i $POOL2/rE@snapA $POOL2/ErF@snap >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive -o origin=$targ $POOL2/tdE

# Run tests from redaction bookmarks.
log_must eval "$ZFS send -i $POOL/$FS#BC $dsF >$streamfile"
$CAT $streamfile | log_must $ZFS receive -o origin=$targ $POOL2/tbBC

log_must eval "$ZFS send -i $POOL/$FS#none $dsF >$streamfile"
$CAT $streamfile | log_must $ZFS receive -o origin=$targ $POOL2/tbnone

log_must eval "$ZFS send -i $POOL/$FS#E $dsF >$streamfile"
$CAT $streamfile | log_mustnot $ZFS receive -o origin=$targ $POOL2/tbE

log_pass "Verify that sends from redacted datasets and bookmarks work correctly."
