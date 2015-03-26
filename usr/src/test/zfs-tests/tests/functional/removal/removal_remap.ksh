#! /bin/ksh -p
#
# CDDL HEADER START
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
# CDDL HEADER END
#

#
# Copyright (c) 2015 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/removal/removal.kshlib

default_setup_noexit "$DISKS"
log_onexit default_cleanup_noexit

log_must $ZFS set recordsize=512 $TESTPOOL/$TESTFS

#
# Create a large file so that we know some of the blocks will be on the
# removed device, and hence eligible for remapping.
#
log_must $DD if=/dev/urandom of=$TESTDIR/file bs=$((2**12)) count=$((2**9))

#
# Randomly rewrite some of blocks in the file so that there will be holes and
# we will not be able to remap the entire file in a few huge chunks.
#
for i in $(seq $((2**12))); do
	#
	# We have to sync periodically so that all the writes don't end up in
	# the same txg. If they were all in the same txg, only the last write
	# would go through and we would not have as many allocations to
	# fragment the file.
	#
	((i % 100 > 0 )) || $SYNC || log_fail "Could not sync."
        random_write $TESTDIR/file $((2**9)) || \
            log_fail "Could not random write."
done

#
# Remap should quietly succeed as a noop before a removal.
#
log_must $ZFS remap $TESTPOOL/$TESTFS
remaptxg_before=$($ZFS get -H -o value remaptxg $TESTPOOL/$TESTFS)
(( $? == 0 )) || log_fail "Could not get remaptxg."
(( remaptxg_before == 0 )) || log_fail "remaptxg nonzero before a removal"

log_must $ZPOOL remove $TESTPOOL $REMOVEDISK
log_must wait_for_removal $TESTPOOL
log_mustnot vdevs_in_pool $TESTPOOL $REMOVEDISK

#
# remaptxg should not be set if we haven't done a remap.
#
remaptxg_before=$($ZFS get -H -o value remaptxg $TESTPOOL/$TESTFS)
(( $? == 0 )) || log_fail "Could not get remaptxg."
(( remaptxg_before == 0 )) || log_fail "remaptxg nonzero before a remap"

percent_referenced_before=$(percent_indirect_referenced $TESTPOOL)
log_must $ZFS remap $TESTPOOL/$TESTFS
percent_referenced_after=$(percent_indirect_referenced $TESTPOOL)
log_note "only $percent_referenced_after% referenced after remap"
(( percent_referenced_after < percent_referenced_before )) || \
    log_fail "Percent referenced did not decrease: " \
    "$percent_referenced_before before to $percent_referenced_after after."
#
# After the remap, there should not be very many blocks referenced. The reason
# why our threshold is 20 instead of 10 is because our ratio of metadata to
# user data is relatively high, with only 64M of user data on the file system.
#
(( percent_referenced_after < 20 )) || \
    log_fail "Percent referenced after remap not low: " \
    $percent_referenced_after

#
# After a remap, the remaptxg should be set to a non-zero value.
#
remaptxg_after=$($ZFS get -H -o value remaptxg $TESTPOOL/$TESTFS)
(( $? == 0 )) || log_fail "Could not get remaptxg."
log_note "remap txg after remap is $remaptxg_after"
(( remaptxg_after > 0 )) || log_fail "remaptxg not increased"

#
# Remap should quietly succeed as a noop if there have been no removals since
# the last remap.
#
log_must $ZFS remap $TESTPOOL/$TESTFS
remaptxg_again=$($ZFS get -H -o value remaptxg $TESTPOOL/$TESTFS)
(( $? == 0 )) || log_fail "Could not get remaptxg."
log_note "remap txg after second remap is $remaptxg_again"
(( remaptxg_again == remaptxg_after )) || \
    log_fail "remap not noop if there has been no removal"

log_pass "Remapping a fs caused percent indirect blocks referenced to decrease."
