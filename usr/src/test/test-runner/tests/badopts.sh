#!/bin/bash

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

export RUN=/opt/test-runner/bin/run

function fail
{
	echo "$1"
	exit 1
}

$RUN -q -v >/dev/null 2>&1 && fail "Success with -q and -v"
$RUN -c foo -w bar >/dev/null 2>&1 && fail "Success with -c and -w"
$RUN -c extra_args >/dev/null 2>&1 && fail "Success with -c and missing file"
$RUN -c >/dev/null 2>&1 && fail "Success with -c and no runfile"
$RUN -c /not_there >/dev/null 2>&1 && fail "Success with missing runfile"
$RUN -w >/dev/null 2>&1 && fail "Success with -w and no template"
$RUN -t eleven >/dev/null 2>&1 && fail "Success with bad -t argument"

exit 0
