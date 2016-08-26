#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zpool_create/zpool_create.shlib

#
#
# DESCRIPTION:
# 'zpool create' will fail with metadevice in swap
#
# STRATEGY:
# 1. Create a one way strip metadevice
# 2. Try to create a new pool with metadevice in swap
# 3. Verify the creation is failed.
#

verify_runnable "global"

function cleanup
{
	# cleanup SVM
	metastat $md_name > /dev/null 2>&1
	if [[ $? -eq 0 ]]; then
		swap -l | grep /dev/md/dsk/$md_name > /dev/null 2>&1
		if [[ $? -eq 0 ]]; then
			swap -d /dev/md/dsk/$md_name
		fi
		metaclear $md_name
	fi

	metadb | grep $mddb_dev > /dev/null 2>&1
	if [[ $? -eq 0 ]]; then
		metadb -df /dev/dsk/$mddb_dev
	fi

	if poolexists $TESTPOOL; then
		destroy_pool $TESTPOOL
	fi

}

if [[ -n $DISK ]]; then
        disk=$DISK
else
        disk=$DISK0
fi

typeset mddb_dev=${disk}s${SLICE0}
typeset md_dev=${disk}s${SLICE1}
typeset md_name=d0
typeset MD_DSK=/dev/md/dsk/d0

log_onexit cleanup

#
# use metadevice in swap to create pool, which should fail.
#
metadb | grep $mddb_dev > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
	log_must metadb -af $mddb_dev
fi

metastat $md_name > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
	metaclear $md_name
fi

log_must metainit $md_name 1 1 $md_dev
log_must swap -a $MD_DSK
unset NOINUSE_CHECK
for opt in "-n" "" "-f"; do
	log_mustnot zpool create $opt $TESTPOOL $MD_DSK
done

log_pass "'zpool create' passed as expected with inapplicable scenario."
