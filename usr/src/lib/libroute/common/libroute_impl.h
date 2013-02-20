/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef	_LIBROUTE_IMPL_H
#define	_LIBROUTE_IMPL_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <libroute.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	RTMSG_BUF_SPACE	(10 * sizeof (struct sockaddr_storage))

typedef union sockaddr_union_s {
	struct sockaddr		su_sa;
	struct sockaddr_in	su_sin;
	struct sockaddr_dl	su_sdl;
	struct sockaddr_in6	su_sin6;
} sockaddr_union_t;

#define	su_family	su_sa.sa_family

typedef struct rtmsg_buf_s {
	struct	rt_msghdr	rb_rtm;
	uint8_t			rb_space[RTMSG_BUF_SPACE];
} rtmsg_buf_t;

/* Private structure that holds the contents of the opaque route handle. */
typedef struct __route_handle {
	libroute_version_t	ri_vers;
	int			ri_rtsock;	/* routing socket */
	int			ri_seq;
	route_rts_tracefunc_t	*ri_rts_tracefunc;
	void			*ri_rts_tracearg;
} route_impl_t;

/* Private structure that holds the contents of a routing table entry. */
typedef struct __route_entry_handle {
	route_impl_t		*rei_rip;
	uint_t			rei_fields;	/* fields set */
	int			rei_rtmflags;	/* <route.h> RTF_* flags */
	sockaddr_union_t	rei_dstu;
	uint_t			rei_plen;
	sockaddr_union_t	rei_netmasku;
	sockaddr_union_t	rei_gwu;
	uint_t			rei_flags;	/* ROUTE_* flags below */
	sockaddr_union_t	rei_outifu;
	char			rei_outifname[LIFNAMSIZ];
} route_entry_impl_t;

#define	rei_family	rei_dstu.su_family
#define	rei_outif	rei_outifu.su_sdl

/* rei_fields */
#define	REI_DST		0x01
#define	REI_PLEN	0x02
#define	REI_NETMASK	0x04
#define	REI_GATEWAY	0x08
#define	REI_OUTIF	0x10

#ifdef __cplusplus
}
#endif

#endif /* _LIBROUTE_IMPL_H */
