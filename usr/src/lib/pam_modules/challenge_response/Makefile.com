#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#
#
#
# Copyright (c) 2014 by Delphix. All rights reserved.
#

LIBRARY=	pam_challenge_response.a
VERS=		.1
OBJECTS=	challenge_response.o

include		../../Makefile.pam_modules

LDLIBS +=	-lpam -lc -lm -lsmbios -luuid
# Don't depend on crypto lint libraries
$(LIBS) := LDLIBS +=	-lcrypto

all: $(LIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
