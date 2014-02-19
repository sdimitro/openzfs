#
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# BSD 3 Clause License
#
# Copyright (c) 2007, The Storage Networking Industry Association.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#	- Redistributions of source code must retain the above copyright
#	  notice, this list of conditions and the following disclaimer.
#
#	- Redistributions in binary form must reproduce the above copyright
#	  notice, this list of conditions and the following disclaimer in
#	  the documentation and/or other materials provided with the
#	  distribution.
#
#	- Neither the name of The Storage Networking Industry Association (SNIA)
#	  nor the names of its contributors may be used to endorse or promote
#	  products derived from this software without specific prior written
#	  permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

#
# Copyright (c) 2012 by Delphix. All rights reserved.
#

LIBRARY= libndmp.a
VERS= .1

NDMP_OBJ = \
	ndmp_client.o \
	ndmp_comm.o \
	ndmp_config.o \
	ndmp_connect.o \
	ndmp_device.o \
	ndmp_data.o \
	ndmp_handler.o \
	ndmp_log.o \
	ndmp_mover.o \
	ndmp_notify.o \
	ndmp_prop.o \
	ndmp_scsi.o \
	ndmp_server.o \
	ndmp_session.o \
	ndmp_tape.o \
	ndmp_util.o

XDR_OBJ = ndmp_xdr.o

XDR_SRC = \
	ndmp.h \
	ndmp_xdr.c

OBJECTS= $(NDMP_OBJ) $(XDR_OBJ)

include ../../Makefile.lib

LIBS=		$(DYNLIB)
C99MODE=	$(C99_ENABLE)

SRCDIR=		../common

INCS +=		-I$(SRCDIR)

CPPFLAGS +=	$(INCS) -D_LARGEFILE64_SOURCE=1 -D_REENTRANT
CPPFLAGS +=	-D_FILE_OFFSET_BITS=64

CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-variable

LDLIBS   += -lsocket -lnsl -lmd5 -lumem -lc

SRCS= $(NDMP_OBJ:%.o=$(SRCDIR)/%.c)
XDR_GEN= $(XDR_SRC:%=$(SRCDIR)/%)

CLEANFILES += $(XDR_GEN)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

$(PICS): $(XDR_GEN)

$(SRCDIR)/ndmp.h: $(SRCDIR)/ndmp.x
	$(RPCGEN) -C -h -o $(SRCDIR)/ndmp.h $(SRCDIR)/ndmp.x

$(SRCDIR)/ndmp_xdr.c: $(SRCDIR)/ndmp.x
	$(RPCGEN) -c -o $(SRCDIR)/ndmp_xdr.c $(SRCDIR)/ndmp.x

include ../../Makefile.targ
