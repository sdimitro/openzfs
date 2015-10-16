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
# Verify that zfs redacted send works in a variety of common cases.
#
# Strategy:
# 1. Verify that a send redacted with respect to 0 snapshots redacts all the
# data.
# 2. Verify that a send redacted with respect to a snapshot that inserts holes
# redacts the data.
# 3. Verify that a send redacted with respect to a snapshot that removes a file
# redacts all the data in the file.
# 4. Verify that a send redacted with respect to a snapshot that updates some of
# the data redacts only that data.
# 5. Verify that a send redacted with respect to multiple snapshots only redacts
# data updated by all of them.
# 6. Verify that a redacted send can be received, as can an incremental send to
# one of the snapshots it was redacted with respect to.
#

verify_runnable "both"

log_assert "Verify odd filesystem configurations don't break zfs redacted send."

function cleanup
{
	$ZFS destroy -R $POOL2/rfs
	for i in `seq 1 5`; do
		$ZFS destroy $POOL/$FS#book$i
	done
	$ZFS destroy $POOL/$FS2#book6
	$ZFS destroy $POOL/$FS#book7
}
log_onexit cleanup

#
# Parse zstreamdump -v output.  The output varies for each kind of record:
# BEGIN records are simply output as "BEGIN".  END records are outputted as "END"
# OBJECT records become "OBJECT <object num>".  FREEOBJECTS records become
# "FREEOBJECTS <startobj> <numobjs>".  All kinds of WRITE and FREE records become
# "<record type> <start> <length>".
#
function parse_dump
{
	$SED '/^WRITE/{N;s/\n/ /;}' | $GREP "^[A-Z]" | \
	    $SED -e 's/^OBJECT.*object = \([0-9]*\).*/OBJECT \1/' \
	    -e 's/^END.*/END/' -e 's/^BEGIN.*/BEGIN/' \
	    -e 's/^FREEOBJECTS.*= \([0-9]*\).*= \([0-9]\).*/FREEOBJECTS \1 \2/' \
	    -e 's/^\([A-Z]*\).*object = \([0-9]*\).*offset = \([0-9]*\).*/\1 \2 \3/'
}

#
# Determine if the first argument is in the range given by the second and third argument.
# Note that the third argument is a length, not the end of the range.
#
function in_range
{
	typeset search_offset=$1
	typeset range_offset=$2
	typeset range_length=$3
	if [[ "$search_offset" -ge "$range_offset" && ("$search_offset" -lt \
	    $(("$range_offset" + "$range_length"))) ]]; then
		return 0
	fi
	return 1
}

#
# Fail if we receive writes to objects 8, 10, or 11
#
function no_writes
{
	typeset type=$1
	typeset object=$2
	if [[ "$type" =~ "WRITE" && ("$object" -eq 8 || "$object" -eq 10 || \
	    "$object" -eq 11) ]]; then
		return 1
	fi
	return 0
}

log_must $ZFS send --redact "" $POOL/$FS@snapA book1 | zstreamdump -v | \
parse_dump | while read line; do
	if ! no_writes $line; then
	    log_fail "Redaction failed for no_writes; $line"
	fi
done

function holes
{
	typeset type=$1
	typeset object=$2
	typeset offset=$3

	if [[ "$type" == "OBJECT" || "$object" -ne 8 ]]; then
		return 0
	fi

	if in_range $offset $((512 * 128)) $((512 * 128)); then
	    return 1
	fi
	if in_range $offset $((2048 * 256)) $((2048 * 4 * 16)) &&
	    [[ $(($offset % (2048 * 4))) == 0 ]]; then
		return 1
	fi
	return 0
}

log_must $ZFS send --redact $POOL/hole_clone-A@snap $POOL/$FS@snapA book2 | \
    zstreamdump -v | parse_dump | while read line; do
	if ! holes $line; then
	    log_fail "Redaction failed for holes; $line"
	fi
done

function rm1
{
	typeset type=$1
	typeset object=$2

	if [[ "$type" =~ "WRITE" && "$object" -eq 8 ]]; then
		return 1
	fi
	return 0
}

log_must $ZFS send --redact $POOL/rm_clone1-A@snap $POOL/$FS@snapA book3 | \
    zstreamdump -v | parse_dump | while read line; do
	if ! rm1 $line; then
	    log_fail "Redaction failed for rm1; $line"
	fi
done

function write_holes
{
	typeset type=$1
	typeset object=$2
	typeset offset=$3

	if [[ "$type" == "OBJECT" || "$type" == "FREE" || "$object" -ne 10 ]]; then
		return 0
	fi

	if in_range $offset $((512 * 256)) $((512 * 128)); then
	    return 1
	fi
	if  in_range $offset 0 $((2048 * 4 * 16)) &&
	    [[ $(($offset % (2048 * 4))) == 0 ]]; then
		return 1
	fi
	return 0
}

log_must $ZFS send --redact $POOL/write_clone-A@snap $POOL/$FS@snapA book4 | \
    zstreamdump -v | parse_dump | while read line; do
	if ! write_holes $line; then
	    log_fail "Redaction failed for write_holes; $line"
	fi
done

function stride_holes
{
	typeset type=$1
	typeset object=$2
	typeset offset=$3

	if [[ "$type" == "FREE" || "$type" == "OBJECT" || "$object" -ne 11 ]]; then
		return 0
	fi

	if [[ $(($offset % (15 * 512))) -eq "0" ]]; then
		return 1
	fi
	return 0
}

typeset snaps1="$POOL/rm_clone2-A@snap,$POOL/stride3_clone-A@snap"
typeset snaps2="$POOL/stride5_clone-A@snap"
log_must $ZFS send --redact $snaps,$snaps2 $POOL/$FS@snapA book5 | \
    zstreamdump -v | parse_dump | while read line; do
	if ! stride_holes $line; then
	    log_fail "Redaction failed for stride_holes; $line"
	fi
done

function object_holes
{
	typeset type=$1
	typeset object=$2

	if [[ ! "$type" =~ "WRITE" ]]; then
		return 0
	fi

	if in_range $object 40 64; then
		return 1
	fi
	return 0
}

log_must $ZFS send --redact $POOL/manyrm_clone-A@snap $POOL/$FS2@snap book6 | \
    zstreamdump -v | parse_dump | while read line; do
	if ! object_holes $line; then
	    log_fail "Redaction failed for object_holes; $line"
	fi
done

log_must $ZFS send --redact $snaps1,$snaps2 $POOL/$FS@snapA book7 | \
    log_must $ZFS receive $POOL2/rfs

dir=$(get_prop mountpoint $POOL2/rfs)
log_mustnot ls $dir

log_mustnot $ZFS mount $POOL/rfs

log_pass "Verify odd filesystem configurations don't break zfs redacted send."
