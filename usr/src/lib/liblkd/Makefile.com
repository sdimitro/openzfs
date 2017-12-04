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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

LIBRARY=	liblkd.a
VERS=		.1

OBJECTS=	lkd.o

# include library definitions
include ../../Makefile.lib

SRCDIR =	../common

LIBS =		$(DYNLIB) $(LINTLIB)

$(LINTLIB):= SRCS=../common/llib-llkd

LINTSRC=	$(LINTLIB:%.ln=%)

C99MODE =	$(C99_ENABLE)
CFLAGS +=	$(CCVERBOSE)
DYNFLAGS32 +=	-Wl,-f,/usr/platform/\$$PLATFORM/lib/$(DYNLIBPSR)
DYNFLAGS64 +=	-Wl,-f,/usr/platform/\$$PLATFORM/lib/$(MACH64)/$(DYNLIBPSR)
LDLIBS +=	-lelf -lc -lz

CPPFLAGS = -D_KMEMUSER -D_LARGEFILE64_SOURCE=1 -I.. $(CPPFLAGS.master)

CERRWARN +=	-_gcc=-Wno-uninitialized

.KEEP_STATE:

lint: lintcheck

# include library targets
include ../../Makefile.targ

objs/%.o pics/%.o: ../common/%.c ../lkd.h
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# install rule for lint library target
$(ROOTLINTDIR)/%:	../common/%
	$(INS.file)
