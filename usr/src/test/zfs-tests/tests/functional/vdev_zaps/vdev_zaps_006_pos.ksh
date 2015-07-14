#!/bin/ksh

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

#
# Description:
# Verify that top-level per-vdev ZAPs are created for added devices, and
# that they persist for indirect vdevs.
#
# Strategy:
# 1. Create a pool with one disk.
# 2. Add a disk.
# 3. Verify its ZAPs were created.
# 4. Remove a disk.
# 5. Verify that its top-level ZAP persists, but not its leaf ZAP.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/vdev_zaps/vdev_zaps.kshlib
. $STF_SUITE/tests/functional/removal/removal.kshlib

DISK_ARR=($DISKS)
DISK=${DISK_ARR[0]}
log_must zpool create -f $TESTPOOL $DISK

log_assert "Per-vdev ZAPs are created for added vdevs."

log_must zpool add -f $TESTPOOL ${DISK_ARR[1]}
conf="$TESTDIR/vz006"
log_must zdb -PC $TESTPOOL > $conf

assert_has_sentinel "$conf"
orig_top=$(get_top_vd_zap ${DISK_ARR[1]} $conf)
assert_zap_common $TESTPOOL ${DISK_ARR[1]} "top" $orig_top
assert_leaf_zap $TESTPOOL ${DISK_ARR[1]} "$conf"

log_assert "Per-vdev top-level ZAP persists for indirect devices."
log_must zpool remove $TESTPOOL ${DISK_ARR[1]}
wait_for_removal $TESTPOOL
log_must zdb -PC $TESTPOOL > $conf

new_top=$(get_top_vd_zap "type: 'indirect'" "$conf")
new_leaf=$(get_leaf_vd_zap "type: 'indirect'" "$conf")

# Ensure top-level ZAP persisted.
[[ "$orig_top" -ne "$new_top" ]] && log_fail "Per-vdev top-level ZAP doesn't "\
        "persist after removal (expected $orig_top, got $new_top)"

# Ensure leaf ZAP is gone.
[[ -n "$new_leaf" ]] && log_fail "Indirect disk has a leaf-level ZAP"

log_pass
