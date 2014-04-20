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
# Copyright 2014 Delphix.  All rights reserved.
#

include		../../Makefile.lib

TEXT_DOMAIN=	SUNW_OST_SYSOSPAM
POFILE=		challenge_response.po
MSGFILES=	challenge_response.c

SUBDIRS=	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include		$(SRC)/Makefile.msg.targ
include		../../Makefile.targ
