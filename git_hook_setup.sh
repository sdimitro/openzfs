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
# Copyright (c) 2016 by Delphix. All rights reserved.
#
# This script sets up the local dlpx-os-gate git hook(s).
#

function die
{
	echo "$(basename $0): $*" >&2
	exit 1
}

base=$(git rev-parse --show-toplevel)
[[ $? -eq 0 ]] || die "git rev-parse failed to read the worspace root"

if [[ ! -d $base/.git/hooks ]]; then
	mkdir $base/.git/hooks || die "failed to mkdir $base/.git/hooks"
fi

ln -sf $base/usr/src/tools/scripts/git/local-hooks/pre-commit $base/.git/hooks/pre-commit || \
	die "ln failed"

echo "Successfully installed  $base/.git/hooks/pre-commit git hook"
exit 0
