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

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd

SRCS = poll_test

LDLIBS += -lsocket

C99MODE = -xc99=%all

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests

CMDS = $(SRCS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(SRCS)

install: $(CMDS)

clean lint:

clobber:
	-$(RM) $(SRCS)

$(CMDS): $(TESTDIR) $(SRCS)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
