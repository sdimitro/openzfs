#!/usr/bin/bash

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
# Copyright (c) 2012 by Delphix. All rights reserved.
#

function fail
{
	echo $1
	exit ${2:-1}
}

function find_disks
{
	typeset all_disks=$(echo '' | sudo format | awk '/c[0-9]/ {print $2}')
	typeset used_disks=$(zpool status | awk \
	    '/c[0-9]*t[0-9a-f]*d[0-9]/ {print $1}' | sed 's/s[0-9]//g')

	typeset disk used avail_disks
	for disk in $all_disks; do
		for used in $used_disks; do
			[[ "$disk" = "$used" ]] && continue 2
		done
		[[ -z $avail_disks ]] && avail_disks="$disk"
		[[ -n $avail_disks ]] && avail_disks="$avail_disks $disk"
	done

	echo $avail_disks
}

export DISKS=$(find_disks)
export KEEP="rpool"
export ZFSTEST_BIN="/opt/zfs-tests/bin"
export STF_SUITE="/opt/zfs-tests/stf"
export STF_TOOLS="/opt/test-runner/stf"

. $STF_SUITE/default.cfg

/opt/test-runner/bin/run -c /opt/zfs-tests/runfiles/all.run

exit $?
