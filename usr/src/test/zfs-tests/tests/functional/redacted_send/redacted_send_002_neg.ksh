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
# Test that redacted send correctly detects invalid arguments.
#

verify_runnable "both"

log_assert "Verify that redacted send correctly detects invalid arguments."

function cleanup
{
	$ZFS destroy -R $sendfs
}

log_onexit cleanup
typeset sendfs="$POOL/sendfs"

log_must $ZFS create $sendfs
log_must $ZFS snapshot $sendfs@snap1
log_must $ZFS snapshot $sendfs@snap2
log_must $ZFS snapshot $sendfs@snap3
log_must $ZFS clone $sendfs@snap2 $POOL/clone1
log_must $ZFS snapshot $POOL/clone1@snap
log_must $ZFS clone $sendfs@snap2 $POOL/clone2
log_must $ZFS snapshot $POOL/clone2@snap

log_mustnot $ZFS send --redact $POOL/clone1@snap,$POOL/clone2@snap \
    $sendfs@snap2 >/dev/null
log_mustnot $ZFS send --redact $POOL/clone1@snap,$POOL/clone2 \
    $sendfs@snap2 book >/dev/null
log_mustnot $ZFS send --redact $POOL/clone1@snap,$POOL/clone2@snap, \
    $sendfs@snap2 book >/dev/null
log_must $ZFS send --redact "" $sendfs@snap2 book1 >/dev/null
log_must $ZFS send --redact $POOL/clone1@snap,$POOL/clone2@snap \
    $sendfs@snap2 book2 >/dev/null
log_must $ZFS send -i $sendfs@snap1 --redact \
    $POOL/clone1@snap,$POOL/clone2@snap $sendfs@snap2 book3 >/dev/null
log_mustnot $ZFS send --redact $POOL/clone1@snap -i $POOL/test#book2 \
    $sendfs@snap3 book4 > /dev/null

log_pass "Verify that redacted send correctly detects invalid arguments."
