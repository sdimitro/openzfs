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

#ifndef _LIBROUTE_H
#define	_LIBROUTE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { LIBROUTE_VERSION_1 = 1 } libroute_version_t;

#define	LIBROUTE_VERSION	LIBROUTE_VERSION_1

/* Returned by route_entry_get_flags() */
#define	ROUTE_ENTRY_GATEWAY	0x1 /* Offlink destination */
#define	ROUTE_ENTRY_STATIC	0x2 /* Manually added */

/*
 * Only the following flags may be toggled by the caller using
 * route_entry_set_flags() or route_entry_clear_flags().  All other flags are
 * read-only.
 */
#define	ROUTE_ENTRY_MODIFYABLE (ROUTE_ENTRY_STATIC)

/* Flags for the last argument to route_entry_walk() */
#define	ROUTE_WALK_IPV4		0x1
#define	ROUTE_WALK_IPV6		0x2
#define	ROUTE_WALK_REDIRECT	0x4 /* Include entries learned via redirect */

typedef struct __route_handle *route_handle_t;
typedef struct __route_entry_handle *route_entry_handle_t;

typedef boolean_t route_entry_walkfunc_t(route_handle_t, route_entry_handle_t,
    void *);
typedef void route_rts_tracefunc_t(route_handle_t, struct rt_msghdr *, void *);

extern int route_open(libroute_version_t, route_handle_t *);
extern void route_close(route_handle_t);
extern int route_entry_create(route_handle_t, route_entry_handle_t *);
extern void route_entry_destroy(route_entry_handle_t);
extern int route_entry_set_destination(route_entry_handle_t, struct sockaddr *,
    uint_t);
extern int route_entry_get_destination(route_entry_handle_t, struct sockaddr **,
    uint_t *);
extern int route_entry_set_host(route_entry_handle_t, struct sockaddr *);
extern int route_entry_set_gateway(route_entry_handle_t, struct sockaddr *);
extern int route_entry_get_gateway(route_entry_handle_t, struct sockaddr **);
extern int route_entry_set_outifname(route_entry_handle_t, const char *);
extern int route_entry_get_outifname(route_entry_handle_t, char *, size_t);
extern int route_entry_set_outifindex(route_entry_handle_t, uint_t);
extern int route_entry_get_outifindex(route_entry_handle_t, uint_t *);
extern uint_t route_entry_get_flags(route_entry_handle_t);
extern int route_entry_set_flags(route_entry_handle_t, uint_t);
extern int route_entry_clear_flags(route_entry_handle_t, uint_t);
extern int route_entry_add(route_entry_handle_t);
extern int route_entry_delete(route_entry_handle_t);
extern int route_entry_walk(route_handle_t, route_entry_walkfunc_t *, void *,
    uint_t);
extern int route_entry_lookup(route_handle_t, struct sockaddr *,
    route_entry_handle_t *);
extern void route_rts_trace(route_handle_t, route_rts_tracefunc_t *, void *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBROUTE_H */
