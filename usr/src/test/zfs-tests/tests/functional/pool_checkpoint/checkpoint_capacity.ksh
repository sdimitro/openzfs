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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

. $STF_SUITE/tests/functional/pool_checkpoint/pool_checkpoint.kshlib

#
# DESCRIPTION:
#	Ensure that we don't reuse checkpointed blocks when the
#	pool hits ENOSPC errors because of the slop space limit.
#	This test also ensures that the DSL layer correctly takes
#	into account the space used by the checkpoint when deciding
#	whether to allow operations based on the reserved slop
#	space.
#
# STRATEGY:
#	1. Create pool with one disk of 1G size
#	2. Create a file with random data of 700M in size.
#	   leaving ~200M left in pool capacity.
#	3. Checkpoint the pool
#	4. Remove the file. All of its blocks should stay around
#	   in ZFS as they are part of the checkpoint.
#	5. Create a new empty file and attempt to write ~300M
#	   of data to it. This should fail, as the reserved
#	   SLOP space for the pool should be ~128M, and we should
#	   be hitting that limit getting ENOSPC.
#	6. Use zdb to traverse and checksum all the checkpointed
#	   data to ensure its integrity.
#	7. Export the pool and rewind to ensure that everything
#	   is actually there as expected.
#

function test_cleanup
{
	default_cleanup_noexit
	log_must rm -f $DISK1
}

verify_runnable "global"

log_must mkfile 1g $DISK1
default_setup_noexit "$DISK1"

log_onexit test_cleanup

log_must dd if=/dev/urandom of=$FS0FILE bs=700M count=1
FILE0INTRO=$(head -c 100 $FS0FILE)

log_must zpool checkpoint $TESTPOOL
log_must rm $FS0FILE

#
# only for debugging purposes
#
log_must zpool list $TESTPOOL

log_mustnot dd if=/dev/urandom of=$FS0FILE bs=300M count=1

#
# only for debugging purposes
#
log_must zpool list $TESTPOOL

log_must zdb -kc $TESTPOOL

log_must zpool export $TESTPOOL
log_must zpool import -d $TMPDIR --rewind-to-checkpoint $TESTPOOL

log_must [ "$(head -c 100 $FS0FILE)" = "$FILE0INTRO" ]

log_must zdb $TESTPOOL

log_pass "Do not reuse checkpointed space at low capacity."
