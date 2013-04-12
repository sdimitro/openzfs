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
# Copyright (c) 2013 by Delphix. All rights reserved.
#

MODULE = klmmod.so
MDBTGT = kvm

MODSRCS = nlm.c

include ../../../../Makefile.cmd
include ../../../../Makefile.cmd.64
include ../../Makefile.sparcv9
include ../../../Makefile.module

ROOTKMOD = $(ROOT)/usr/kernel/kmdb$(MACHMODDIR)

$(ROOTKMOD):
	$(INS.dir)
