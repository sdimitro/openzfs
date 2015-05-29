/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/tihdr.h>
#include "connstat.h"

int
mibopen(const char *proto)
{
	int fd;

	fd = open("/dev/arp", O_RDWR);
	if (fd == -1) {
		return (-1);
	}

	if (ioctl(fd, I_PUSH, proto) == -1) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

void
conn_walk(int fd, connstat_proto_t *proto, conn_walk_state_t *state)
{
	struct strbuf cbuf, dbuf;
	struct opthdr *hdr;
	int flags, r;
	struct {
		struct T_optmgmt_req req;
		struct opthdr hdr;
	} req;
	union {
		struct T_optmgmt_ack ack;
		uint8_t space[sizeof (struct T_optmgmt_ack) +
		    sizeof (struct opthdr) * 2];
	} ack;

	req.req.PRIM_type = T_OPTMGMT_REQ;
	req.req.OPT_offset = (caddr_t)&req.hdr - (caddr_t)&req;
	req.req.OPT_length = sizeof (req.hdr);
	req.req.MGMT_flags = T_CURRENT;

	req.hdr.level = proto->csp_miblevel;
	req.hdr.name = 0;
	req.hdr.len = 0;

	cbuf.buf = (caddr_t)&req;
	cbuf.len = sizeof (req);

	if (putmsg(fd, &cbuf, NULL, 0) == -1) {
		perror("putmsg");
		return;
	}

	/*
	 * Each reply consists of a control part for one fixed structure or
	 * table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK
	 * containing an opthdr structure.  The level and name identify the
	 * entry, and len is the size of the data part of the message.
	 */
	for (;;) {
		cbuf.buf = (caddr_t)&ack;
		cbuf.maxlen = sizeof (ack);
		flags = 0;

		/*
		 * We first do a getmsg() for the control part so that we
		 * can allocate a properly sized buffer to read the data
		 * part.
		 */
		if ((r = getmsg(fd, &cbuf, NULL, &flags)) < 0) {
			perror("getmsg");
			break;
		}
		if (r == 0) {
			break;
		}

		if (cbuf.len < sizeof (struct T_optmgmt_ack) ||
		    ack.ack.PRIM_type != T_OPTMGMT_ACK ||
		    ack.ack.MGMT_flags != T_SUCCESS ||
		    ack.ack.OPT_length < sizeof (struct opthdr)) {
			(void) fprintf(stderr, "invalid message\n");
			break;
		}

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		hdr = (struct opthdr *)((caddr_t)&ack + ack.ack.OPT_offset);
		if (hdr->level == 0 && hdr->name == 0)
			break;

		/* Allocate a buffer to hold the data portion of the message */
		if ((dbuf.buf = malloc(hdr->len)) == NULL) {
			perror("malloc");
			break;
		}
		dbuf.maxlen = hdr->len;
		dbuf.len = 0;
		flags = 0;
		r = getmsg(fd, NULL, &dbuf, &flags);

		if ((state->cws_flags & CS_IPV4) &&
		    hdr->name == proto->csp_mibv4name) {
			proto->csp_v4walk(&dbuf, state);
		} else if ((state->cws_flags & CS_IPV6) &&
		    hdr->name == proto->csp_mibv6name) {
			proto->csp_v6walk(&dbuf, state);
		}

		free(dbuf.buf);
	}
}
