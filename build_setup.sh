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
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
#

PATH=/usr/ccs/bin:/usr/local/bin:/usr/gnu/bin:/usr/bin:/usr/sbin:/sbin
export PATH

function die
{
	echo $*
	exit 1
}

function usage
{
	echo "$(basename $0)"
	exit 2
}

[[ $# != 0 ]] && usage

if [[ ! -f illumos.sh ]]; then
	echo "Updating environment file ... \c"
	cp usr/src/tools/env/illumos.sh illumos.sh || \
	    die "failed to copy environment file"
	echo "done."
fi

if [[ ! -f bldenv ]]; then
	echo "Setting up initial build environment ... \c"
	ksh93 usr/src/tools/scripts/bldenv.sh -d illumos.sh \
	    -c "cd usr/src && dmake setup" || die "dmake failed"
	ln -s usr/src/tools/scripts/bldenv || die "link bldenv failed"
	ln -s usr/src/tools/scripts/nightly || die "link nightly failed"
	echo "done."
fi

exit 0
