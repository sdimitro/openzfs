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

export STF_SUITE="/opt/zfs-tests"
export STF_TOOLS="/opt/test-runner/stf"

function fail
{
	echo $1
	exit ${2:-1}
}

function find_disks
{
	local all_disks=$(echo '' | sudo /usr/sbin/format | awk \
	    '/c[0-9]/ {print $2}')
	local used_disks=$(/sbin/zpool status | awk \
	    '/c[0-9]*t[0-9a-f]*d[0-9]/ {print $1}' | sed 's/s[0-9]//g')

	local disk used avail_disks
	for disk in $all_disks; do
		for used in $used_disks; do
			[[ "$disk" = "$used" ]] && continue 2
		done
		[[ -z $avail_disks ]] && avail_disks="$disk"
		[[ -n $avail_disks ]] && avail_disks="$avail_disks $disk"
	done

	echo $avail_disks
}

function find_rpool
{
	local ds=$(/usr/sbin/mount | awk '/^\/ / {print $3}')
	echo ${ds%%/*}
}

function find_runfile
{
	local distro=
	[[ -d /opt/delphix && -h /etc/delphix/version ]] && distro=delphix
	grep OpenIndiana /etc/motd >/dev/null && distro=openindiana

	[[ -z $distro ]] && fail "Couldn't determine distro"
	echo $STF_SUITE/runfiles/$distro.run
}

function verify_id
{
	[[ $(id -u) = "0" ]] && fail "This script must not be run as root."

	sudo -n id >/dev/null 2>&1
	[[ $? -eq 0 ]] || fail "User must be able to sudo without a password."

	local -i priv_cnt=$(ppriv $$ | egrep "[EIP]: basic$|L: all$" | wc -l)
	[[ $priv_cnt -ne 4 ]] && fail "User must only have basic privileges."
}

verify_id

while getopts c: c; do
	case $c in
	'c')
		runfile=$OPTARG
		[[ -f $runfile ]] || fail "Cannot read file: $runfile"
		;;
	esac
done
shift $((OPTIND - 1))

export DISKS=$(find_disks)
export KEEP=$(find_rpool)
[[ -z $runfile ]] && runfile=$(find_runfile)

. $STF_SUITE/include/default.cfg

num_disks=$(echo $DISKS | awk '{print NF}')
[[ $num_disks -lt 3 ]] && fail "Not enough disks to run ZFS Test Suite"

/opt/test-runner/bin/run -c $runfile

exit $?
