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
# Copyright (c) 2016 by Delphix. All rights reserved.
#

. $STF_SUITE/tests/functional/redacted_send/redacted.kshlib

#
# Description:
# Verify that performing a redacted send using a bookmark instead of a list
# of snapshots works correctly
#
# Strategy:
# 1. Perform redacted send
# 2. Perform redacted send using bookmark, verify it's identical to the first
#    stream.
#

typeset ds_name="deleted"
typeset sendfs="$POOL/$ds_name"
typeset clone="$POOL/${ds_name}_clone"
typeset tmpdir="$(get_prop mountpoint $POOL)/tmp"
typeset stream=$(mktemp $tmpdir/stream.XXXX)
typeset stream2=$(mktemp $tmpdir/stream.XXXX)
setup_dataset $ds_name ''
typeset clone_mnt="$(get_prop mountpoint $clone)"
typeset send_mnt="$(get_prop mountpoint $sendfs)"

log_onexit redacted_cleanup $sendfs

log_must rm $clone_mnt/f1
log_must zfs snapshot $clone@snap1
log_must eval "zfs send --redact $clone@snap1 $sendfs@snap book1 >$stream"
log_must eval "zfs send --redact-bookmark book1 $sendfs@snap >$stream2"
log_must diff $stream $stream2
rm $stream
rm $stream2

log_must zfs send -nvi $sendfs#book1 $sendfs@snap

log_pass "Verify Redaction works as expected with respect to deleted files."
