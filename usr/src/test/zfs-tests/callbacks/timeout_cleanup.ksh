#!/usr/bin/ksh -p

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

export STF_SUITE="/opt/zfs-tests"
export STF_TOOLS="/opt/test-runner/stf"

. $STF_SUITE/include/default.cfg
. $STF_SUITE/include/libtest.shlib

unset TESTFAIL_CALLBACKS

[[ -n $1 ]] || exit
testdir=$(dirname $1)
[[ -d $testdir ]] || exit

# Execute this test group's cleanup and setup scripts.
log_note "Running cleanup and setup for \"$(basename $testdir)\" tests"
[[ -x $testdir/cleanup ]] && sudo -E $testdir/cleanup
[[ -x $testdir/setup ]] && sudo -E $testdir/setup

# If there's no cleanup script, make a best effort to cleanup things that
# might be problematic for subsequent tests.
if [[ ! -x $testdir/cleanup ]]; then
	for pool in $TESTPOOL $TESTPOOL1 $TESTPOOL2 $TESTPOOL3; do
		poolexists $pool && sudo -E destroy_pool $pool
	done
	sudo -E rm -rf /testdir* /backdir-rsend /testpool* /dev_import*
fi
