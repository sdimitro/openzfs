#!/bin/bash

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
# Copyright (c) 2013 by Delphix. All rights reserved.
#

function die
{
	echo "$@" >&2
	exit 1
}

ROOT="closed/root_i386"
ROOT_ND="closed/root_i386-nd"

function fix_perms
{
	perms=$1
	path=$2

	if [[ -e "$ROOT/$path" ]]; then
		chmod $perms "$ROOT/$path" || die "chmod failed"
	fi

	if [[ -e "$ROOT_ND/$path" ]]; then
		chmod $perms "$ROOT_ND/$path" || die "chmod failed"
	fi

	return 0
}

function fix_link
{
	target=$1
	link=$2

	if [[ -e "$ROOT/$target" ]]; then
		rm "$ROOT/$link" || die "rm failed"
		ln "$ROOT/$target" "$ROOT/$link" || die "ln failed"
	fi

	if [[ -e "$ROOT_ND/$target" ]]; then
		rm "$ROOT_ND/$link" || die "rm failed"
		ln "$ROOT_ND/$target" "$ROOT_ND/$link" || die "ln failed"
	fi

	return 0
}

function fix_dir
{
	perms=$1
	dir=$2

	[[ -d "$ROOT/$dir" ]] || mkdir "$ROOT/$dir" || die "mkdir failed"
	chmod $perms "$ROOT/$dir" || die "chmod failed"

	[[ -d "$ROOT_ND/$dir" ]] || mkdir "$ROOT_ND/$dir" || die "mkdir failed"
	chmod $perms "$ROOT_ND/$dir" || die "chmod failed"
}

fix_perms 0400 etc/security/tsol/label_encodings
fix_perms 0444 etc/security/tsol/label_encodings.example
fix_perms 0444 etc/security/tsol/label_encodings.gfi.multi
fix_perms 0444 etc/security/tsol/label_encodings.gfi.single
fix_perms 0444 etc/security/tsol/label_encodings.multi
fix_perms 0444 etc/security/tsol/label_encodings.single
fix_perms 0555 kernel/kmdb/amd64/mpt
fix_perms 0555 kernel/kmdb/amd64/nfs
fix_perms 0555 kernel/kmdb/mpt
fix_perms 0555 kernel/kmdb/nfs
fix_perms 0444 lib/svc/manifest/network/ipsec/ike.xml
fix_perms 0555 usr/bin/iconv
fix_perms 0555 usr/bin/pax
fix_perms 0444 usr/lib/iconv/646da.8859.t
fix_perms 0444 usr/lib/iconv/646de.8859.t
fix_perms 0444 usr/lib/iconv/646en.8859.t
fix_perms 0444 usr/lib/iconv/646es.8859.t
fix_perms 0444 usr/lib/iconv/646fr.8859.t
fix_perms 0444 usr/lib/iconv/646it.8859.t
fix_perms 0444 usr/lib/iconv/646sv.8859.t
fix_perms 0444 usr/lib/iconv/8859.646.t
fix_perms 0444 usr/lib/iconv/8859.646da.t
fix_perms 0444 usr/lib/iconv/8859.646de.t
fix_perms 0444 usr/lib/iconv/8859.646en.t
fix_perms 0444 usr/lib/iconv/8859.646es.t
fix_perms 0444 usr/lib/iconv/8859.646fr.t
fix_perms 0444 usr/lib/iconv/8859.646it.t
fix_perms 0444 usr/lib/iconv/8859.646sv.t
fix_perms 0444 usr/lib/iconv/iconv_data
fix_perms 0555 usr/lib/inet/amd64/in.iked
fix_perms 0555 usr/lib/inet/certdb
fix_perms 0555 usr/lib/inet/certlocal
fix_perms 0555 usr/lib/inet/certrldb
fix_perms 0555 usr/lib/inet/i86/in.iked
fix_perms 0555 usr/lib/labeld
fix_perms 0555 usr/lib/mdb/kvm/amd64/mpt.so
fix_perms 0555 usr/lib/mdb/kvm/amd64/nfs.so
fix_perms 0555 usr/lib/mdb/kvm/mpt.so
fix_perms 0555 usr/lib/mdb/kvm/nfs.so
fix_perms 0555 usr/sbin/chk_encodings
fix_perms 0555 usr/xpg4/bin/more

fix_link kernel/drv/amd64/sdpib kernel/strmod/amd64/sdpib
fix_link kernel/drv/sdpib kernel/strmod/sdpib
fix_link platform/i86pc/kernel/cpu/amd64/cpu_ms.GenuineIntel.6.46 \
    platform/i86pc/kernel/cpu/amd64/cpu_ms.GenuineIntel.6.47
fix_link platform/i86pc/kernel/cpu/cpu_ms.GenuineIntel.6.46 \
    platform/i86pc/kernel/cpu/cpu_ms.GenuineIntel.6.47

fix_dir 0755 usr/lib/locale/C/LC_COLLATE
fix_dir 0755 usr/lib/locale/C/LC_CTYPE
fix_dir 0755 usr/lib/locale/C/LC_MONETARY
fix_dir 0755 usr/lib/locale/C/LC_NUMERIC

exit 0
