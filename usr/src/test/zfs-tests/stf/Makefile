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

SUBDIRS = include cfg

include $(SRC)/test/Makefile.com

include $(SRC)/Makefile.master

SRCS = commands.cfg default.cfg

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
STFDIR = $(ROOTOPTPKG)/stf

CMDS = $(SRCS:%=$(STFDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(SRCS)

install: $(CMDS)

clean lint clobber:

$(CMDS): $(STFDIR) $(SRCS)

$(STFDIR):
	$(INS.dir)

$(STFDIR)/%: %
	$(INS.file)
