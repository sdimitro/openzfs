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

/*
 * Libroute provides an API for manipulating the system's IP forwarding table
 * in an OS-independent way.  It provides the ability to add, delete, and walk
 * routes, as well as perform routing table lookups.
 *
 * The API is designed to be extensible by only exposing opaque object handles
 * to the caller, and providing access to object data through getter and setter
 * functions.  API versioning is also provided and enforced in route_open().
 *
 * The two main objects handled by the caller are:
 *
 * route_handle_t
 *
 * An opaque handle used by the library to store caller-specific state.  It is
 * acquired by calling route_open(), and and released by calling route_close().
 * Internally, this is a pointer to a route_impl_t structure.
 *
 * route_entry_handle_t
 *
 * An opaque handle representing a routing table entry.  A handle is created by
 * calling either route_entry_create() or route_entry_lookup(), and destroyed
 * by route_entry_destroy().  Properties associated with a route are accessed
 * by using getter and setter functions (route_entry_get_*() and
 * route_entry_set_*()).  Internally, this is a pointer to a route_entry_impl_t
 * structure.
 *
 * An example workflow for adding or deleting a route to the routing table
 * would be:
 *
 *   route_open()
 *   route_entry_create()
 *   route_entry_set_destination()
 *   route_entry_set_gateway()
 *   route_entry_set_outifname() or route_entry_set_outifindex()
 *   route_entry_add() or route_entry_delete()
 *   route_entry_destroy()
 *   route_close()
 *
 * An example workflow for a routing table lookup would be:
 *
 *   route_open()
 *   route_entry_lookup()
 *   route_entry_get_destination()
 *   route_entry_get_gateway()
 *   route_entry_get_outifname()
 *   route_entry_destroy()
 *   route_close()
 *
 * Multithreading
 *
 * The library is thread safe (it keeps no global state), but access to
 * a given route_handle_t or route_entry_handle_t is not MT-Safe.  Applications
 * wishing to use this API from multiple threads should either open one
 * route_handle_t per thread, or implement their own synchronization to
 * prevent simultaneous access to a given handle.
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <strings.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/tihdr.h>
#include <stropts.h>
#include <inet/ip.h>
#include <libroute.h>
#include "libroute_impl.h"

/* The types of ire's that route_entry_walk() will return by default */
#define	DEFAULT_IRE_TYPES \
	(IRE_DEFAULT | IRE_LOOPBACK | IRE_PREFIX | IRE_INTERFACE | IRE_HOST)

#define	ROUNDUP_LONG(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof (long) - 1))) : sizeof (long))

typedef struct walk_state_s {
	int	ws_ire_types;	/* Types of ire's that the walk will return */
	void	*ws_arg;	/* The callback argument */
} walk_state_t;

static size_t
salen(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (sizeof (struct sockaddr_in));
	case AF_LINK:
		return (sizeof (struct sockaddr_dl));
	case AF_INET6:
		return (sizeof (struct sockaddr_in6));
	default:
		return (0);
	}
}

static void
next_seq(route_impl_t *rip)
{
	rip->ri_seq++;
	if (rip->ri_seq < 0)
		rip->ri_seq = 0;
}

static boolean_t
is_unspecified(struct sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (sa->sa_family) {
	case AF_INET:
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin = (struct sockaddr_in *)sa;
		return (sin->sin_addr.s_addr == INADDR_ANY);
		break;
	case AF_INET6:
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6 = (struct sockaddr_in6 *)sa;
		return (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr));
		break;
	default:
		return (B_FALSE);
	}
}

static int
route_set_sockaddr(struct sockaddr *src, sockaddr_union_t *su)
{
	if (salen(src) == 0)
		return (EINVAL);
	bcopy(src, &su->su_sa, salen(src));
	return (0);
}

static int
plen_to_netmask(sa_family_t family, uint_t plen, sockaddr_union_t *su)
{
	uint8_t *maskp;

	switch (family) {
	case AF_INET:
		if (plen > IP_ABITS)
			return (EINVAL);
		maskp = (uint8_t *)&su->su_sin.sin_addr;
		break;
	case AF_INET6:
		if (plen > IPV6_ABITS)
			return (EINVAL);
		maskp = (uint8_t *)&su->su_sin6.sin6_addr;
		break;
	default:
		return (EINVAL);
	}

	while (plen > 0) {
		if (plen >= 8) {
			*maskp++ = 0xFF;
			plen -= 8;
		} else {
			*maskp |= 1 << (8 - plen);
			plen--;
		}
	}

	su->su_family = family;
	return (0);
}

static int
netmask_to_plen(sockaddr_union_t *su, uint_t *plen)
{
	uint8_t *maskp, value;
	size_t masksize;
	int i;

	switch (su->su_family) {
	case AF_INET:
		maskp = (uint8_t *)&su->su_sin.sin_addr;
		masksize = sizeof (su->su_sin.sin_addr);
		break;
	case AF_INET6:
		maskp = (uint8_t *)&su->su_sin6.sin6_addr;
		masksize = sizeof (su->su_sin6.sin6_addr);
		break;
	default:
		return (EINVAL);
	}

	*plen = 0;
	for (i = 0; i < masksize; i++) {
		value = maskp[i];
		if (value == 0)
			break;
		while (value > 0) {
			if (!(value & 0x80))
				break;
			value <<= 1;
			(*plen)++;
		}
	}

	return (0);
}

static int
route_entry_set_dstonly(route_entry_impl_t *reip, struct sockaddr *dst)
{
	int err;

	if ((err = route_set_sockaddr(dst, &reip->rei_dstu)) == 0)
		reip->rei_fields |= REI_DST;
	return (err);
}

static int
route_entry_set_netmask(route_entry_impl_t *reip, struct sockaddr *netmask)
{
	int err;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	err = netmask_to_plen((sockaddr_union_t *)netmask, &reip->rei_plen);
	if (err != 0)
		return (err);

	if ((err = route_set_sockaddr(netmask, &reip->rei_netmasku)) == 0) {
		reip->rei_fields |= REI_PLEN;
		reip->rei_fields |= REI_NETMASK;
	}
	return (err);
}

static uint8_t *
rtm_addaddr(struct rt_msghdr *rtm, uint_t rtm_addr, sockaddr_union_t *su,
    uint8_t *addrp)
{
	size_t addrlen = ROUNDUP_LONG(salen(&su->su_sa));

	bcopy(&su->su_sa, addrp, salen(&su->su_sa));
	rtm->rtm_addrs |= rtm_addr;
	rtm->rtm_msglen += addrlen;
	return (addrp + addrlen);
}

/*
 * Convert a route_entry_impl_t to a buffer that will ultimately be used
 * as the data for a routing socket message.  The structure of this data
 * is of the following form:
 *
 * struct rt_msghdr {
 *	...
 *	int rtm_addrs;
 *	...
 * }
 * <series of sockaddr structures>
 *
 * The RTA_* flags set in the rtm_addrs field describes which structures are
 * appended to the end of the rt_msghdr structure.  These structures must be in
 * assending order of RTA_* values.
 */
static int
entry2rtmbuf(route_entry_impl_t *reip, rtmsg_buf_t *rtmbuf)
{
	struct rt_msghdr *rtm;
	uint8_t *addrp;

	if (!(reip->rei_fields & REI_DST))
		return (EINVAL);

	rtm = &rtmbuf->rb_rtm;
	rtm->rtm_flags = reip->rei_rtmflags;
	if (reip->rei_flags & ROUTE_ENTRY_STATIC)
		rtm->rtm_flags |= RTF_STATIC;

	addrp = rtmbuf->rb_space;
	addrp = rtm_addaddr(rtm, RTA_DST, &reip->rei_dstu, addrp);
	if (reip->rei_fields & REI_GATEWAY)
		addrp = rtm_addaddr(rtm, RTA_GATEWAY, &reip->rei_gwu, addrp);
	if (reip->rei_fields & REI_NETMASK) {
		addrp = rtm_addaddr(rtm, RTA_NETMASK, &reip->rei_netmasku,
		    addrp);
	}
	if (reip->rei_fields & REI_OUTIF)
		addrp = rtm_addaddr(rtm, RTA_IFP, &reip->rei_outifu, addrp);

	return (0);
}

/*
 * Convert a routing socket message read from the kernel into a
 * route_entry_impl_t structure.
 */
static int
rtmbuf2entry(rtmsg_buf_t *rtmbuf, route_entry_impl_t *reip)
{
	struct rt_msghdr *rtm = &rtmbuf->rb_rtm;
	struct sockaddr *sa, *dst = NULL, *gw = NULL, *mask = NULL;
	struct sockaddr_dl *ifp = NULL;
	char ifname[LIFNAMSIZ];
	int addr, err;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	sa = (struct sockaddr *)rtmbuf->rb_space;
	for (addr = 1; addr != 0; addr <<= 1) {
		if (addr & rtm->rtm_addrs) {
			switch (addr) {
			case RTA_DST:
				dst = sa;
				break;
			case RTA_GATEWAY:
				/*
				 * We ignore the gateway address for interface
				 * routes added by the kernel (the gateway
				 * address is our local address in that case).
				 */
				if (!(rtm->rtm_flags & RTF_KERNEL))
					gw = sa;
				break;
			case RTA_NETMASK:
				mask = sa;
				break;
			case RTA_IFP:
				ifp = (struct sockaddr_dl *)sa;
				break;
			}
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			sa = (struct sockaddr *)((uint8_t *)sa +
			    ROUNDUP_LONG(salen(sa)));
		}
	}

	if (dst != NULL && ((err = route_entry_set_dstonly(reip, dst)) != 0))
		return (err);

	if (mask != NULL && ((err = route_entry_set_netmask(reip, mask)) != 0))
		return (err);

	if (gw != NULL && ((err = route_entry_set_gateway(reip, gw)) != 0))
		return (err);

	ifname[0] = '\0';
	if (ifp != NULL) {
		(void) strncpy(ifname, ifp->sdl_data, ifp->sdl_nlen);
		ifname[ifp->sdl_nlen] = '\0';
	} else if (gw != NULL) {
		route_entry_impl_t *gwentry;

		/*
		 * If the route wasn't added with an explicit output
		 * interface, we can infer it from the interface route
		 * used to reach the gateway.
		 */
		if (route_entry_lookup(reip->rei_rip, gw, &gwentry) == 0) {
			(void) route_entry_get_outifname(gwentry, ifname,
			    sizeof (ifname));
		}
	}
	if (ifname[0] != '\0' &&
	    ((err = route_entry_set_outifname(reip, ifname)) != 0))
			return (err);
	return (0);
}

rtmsg_buf_t *
rtmsg_alloc(route_impl_t *rip, uchar_t type)
{
	rtmsg_buf_t *rtmbuf;

	if ((rtmbuf = calloc(1, sizeof (rtmsg_buf_t))) == NULL)
		return (NULL);
	rtmbuf->rb_rtm.rtm_msglen = sizeof (struct rt_msghdr);
	rtmbuf->rb_rtm.rtm_type = type;
	rtmbuf->rb_rtm.rtm_seq = rip->ri_seq;
	rtmbuf->rb_rtm.rtm_version = RTM_VERSION;
	return (rtmbuf);
}

static int
write_rtmsg(route_impl_t *rip, route_entry_impl_t *reip, uchar_t type)
{
	rtmsg_buf_t *rtmbuf = NULL;
	ssize_t written;
	boolean_t needclose = B_FALSE;
	int err = 0;

	if (rip->ri_rtsock == -1) {
		if ((rip->ri_rtsock = socket(PF_ROUTE, SOCK_RAW, 0)) == -1)
			return (errno);
		needclose = B_TRUE;
	}

	next_seq(rip);
	if ((rtmbuf = rtmsg_alloc(rip, type)) == NULL) {
		err = errno;
		goto done;
	}

	if ((err = entry2rtmbuf(reip, rtmbuf)) != 0)
		goto done;

	written = write(rip->ri_rtsock, rtmbuf, rtmbuf->rb_rtm.rtm_msglen);
	if (written == -1)
		err = errno;
	else if (written != rtmbuf->rb_rtm.rtm_msglen)
		err = EINVAL;

	if (err == 0 && rip->ri_rts_tracefunc != NULL) {
		rip->ri_rts_tracefunc(rip, &rtmbuf->rb_rtm,
		    rip->ri_rts_tracearg);
	}

done:
	if (needclose) {
		(void) close(rip->ri_rtsock);
		rip->ri_rtsock = -1;
	}
	free(rtmbuf);
	return (err);
}

/*
 * Read a routing socket message and convert it to a route_entry_impl_t
 * structure.  The read message must match the specified pid and/or seq if
 * specified to allow the caller to receive a reply to a specific previous
 * routing socket command.
 */
static int
read_rtmsg(route_impl_t *rip, route_entry_impl_t *reip, pid_t pid, int seq)
{
	rtmsg_buf_t *rtmbuf = NULL;
	struct rt_msghdr *rtm;
	ssize_t rsize;
	boolean_t done;
	boolean_t needclose = B_FALSE;
	int err;

	if (rip->ri_rtsock == -1) {
		if ((rip->ri_rtsock = socket(PF_ROUTE, SOCK_RAW, 0)) == -1)
			return (errno);
		needclose = B_TRUE;
	}

	if ((rtmbuf = rtmsg_alloc(rip, 0)) == NULL) {
		err = errno;
		goto done;
	}
	rtm = &rtmbuf->rb_rtm;

	do {
		rsize = read(rip->ri_rtsock, rtmbuf, sizeof (*rtmbuf));
		if (rsize <= 0) {
			done = B_TRUE;
		} else {
			done = (pid == -1 || rtm->rtm_pid == pid) &&
			    (seq == -1 || rtm->rtm_seq == seq);
		}
	} while (!done);
	if (rsize < 0)
		err = errno;
	else if (rtm->rtm_errno != 0)
		err = rtm->rtm_errno;
	else
		err = rtmbuf2entry(rtmbuf, reip);

done:
	if (needclose) {
		(void) close(rip->ri_rtsock);
		rip->ri_rtsock = -1;
	}
	free(rtmbuf);
	return (err);
}

static boolean_t
process_ipv4_route(route_impl_t *rip, mib2_ipRouteEntry_t *rp,
    route_entry_walkfunc_t *fn, walk_state_t *ws)
{
	route_entry_impl_t rei;
	char *ifname = NULL;
	char ifnamebuf[LIFNAMSIZ];
	int err;

	bzero(&rei, sizeof (rei));

	rei.rei_rip = rip;
	rei.rei_dstu.su_family = AF_INET;
	bcopy(&rp->ipRouteDest, &rei.rei_dstu.su_sin.sin_addr,
	    sizeof (in_addr_t));
	rei.rei_fields |= REI_DST;

	rei.rei_netmasku.su_family = AF_INET;
	bcopy(&rp->ipRouteMask, &rei.rei_netmasku.su_sin.sin_addr,
	    sizeof (in_addr_t));
	rei.rei_fields |= REI_NETMASK;

	err = netmask_to_plen(&rei.rei_netmasku, &rei.rei_plen);
	assert(err == 0);
	rei.rei_fields |= REI_PLEN;

	if (rp->ipRouteInfo.re_flags & RTF_GATEWAY) {
		rei.rei_gwu.su_family = AF_INET;
		bcopy(&rp->ipRouteNextHop, &rei.rei_gwu.su_sin.sin_addr,
		    sizeof (in_addr_t));
		rei.rei_flags |= ROUTE_ENTRY_GATEWAY;
		rei.rei_fields |= REI_GATEWAY;
	}

	if (rp->ipRouteIfIndex.o_length != 0) {
		ifname = rp->ipRouteIfIndex.o_bytes;
	} else if (rei.rei_fields & REI_GATEWAY) {
		route_entry_impl_t *gwentry;

		/*
		 * If the route wasn't added with an explicit output interface,
		 * we can infer it from the interface route used to reach the
		 * gateway.
		 */
		if (route_entry_lookup(rei.rei_rip, &rei.rei_gwu.su_sa,
		    &gwentry) == 0) {
			if (route_entry_get_outifname(gwentry, ifnamebuf,
			    sizeof (ifnamebuf)) == 0)
				ifname = ifnamebuf;
		}
	}
	if (ifname != NULL) {
		size_t ifnamelen;

		ifnamelen = strlcpy(rei.rei_outifname, ifname,
		    sizeof (rei.rei_outifname));
		assert(ifnamelen < sizeof (rei.rei_outifname));

		rei.rei_outif.sdl_family = AF_LINK;
		rei.rei_outif.sdl_index = if_nametoindex(rei.rei_outifname);
		rei.rei_fields |= REI_OUTIF;
	}

	rei.rei_rtmflags = rp->ipRouteInfo.re_flags;

	return (fn(rip, &rei, ws->ws_arg));
}

static boolean_t
process_ipv6_route(route_impl_t *rip, mib2_ipv6RouteEntry_t *rp,
    route_entry_walkfunc_t *fn, walk_state_t *ws)
{
	char *ifname = NULL;
	char ifnamebuf[LIFNAMSIZ];
	route_entry_impl_t rei;

	bzero(&rei, sizeof (rei));

	rei.rei_rip = rip;
	rei.rei_dstu.su_family = AF_INET6;
	bcopy(&rp->ipv6RouteDest, &rei.rei_dstu.su_sin6.sin6_addr,
	    sizeof (in6_addr_t));
	rei.rei_fields |= REI_DST;

	rei.rei_plen = rp->ipv6RoutePfxLength;
	rei.rei_fields |= REI_PLEN;

	if (rp->ipv6RouteInfo.re_flags & RTF_GATEWAY) {
		rei.rei_gwu.su_family = AF_INET6;
		bcopy(&rp->ipv6RouteNextHop, &rei.rei_gwu.su_sin6.sin6_addr,
		    sizeof (in6_addr_t));
		rei.rei_flags |= ROUTE_ENTRY_GATEWAY;
		rei.rei_fields |= REI_GATEWAY;
	}

	if (rp->ipv6RouteIfIndex.o_length != 0) {
		ifname = rp->ipv6RouteIfIndex.o_bytes;
	} else if (rei.rei_fields & REI_GATEWAY) {
		route_entry_impl_t *gwentry;

		/*
		 * If the route wasn't added with an explicit output interface,
		 * we can infer it from the interface route used to reach the
		 * gateway.
		 */
		if (route_entry_lookup(rei.rei_rip, &rei.rei_gwu.su_sa,
		    &gwentry) == 0) {
			if (route_entry_get_outifname(gwentry, ifnamebuf,
			    sizeof (ifnamebuf)) == 0)
				ifname = ifnamebuf;
		}
	}
	if (ifname != NULL) {
		(void) strlcpy(rei.rei_outifname, ifname,
		    sizeof (rei.rei_outifname));
		rei.rei_outif.sdl_family = AF_LINK;
		rei.rei_outif.sdl_index = if_nametoindex(rei.rei_outifname);
		rei.rei_fields |= REI_OUTIF;
	}

	rei.rei_rtmflags = rp->ipv6RouteInfo.re_flags;

	return (fn(rip, &rei, ws->ws_arg));
}

static boolean_t
ire_match(int ire_type, int ire_types_wanted)
{
	return ((ire_types_wanted & ire_type) != 0);
}

static boolean_t
walk_ipv4_routes(route_impl_t *rip, struct strbuf *dbuf,
    route_entry_walkfunc_t *fn, walk_state_t *ws)
{
	uint_t nroutes = (dbuf->len / sizeof (mib2_ipRouteEntry_t));
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	mib2_ipRouteEntry_t *rp = (mib2_ipRouteEntry_t *)dbuf->buf;
	boolean_t ret = B_TRUE;

	for (; nroutes > 0; rp++, nroutes--) {
		if (!ire_match(rp->ipRouteInfo.re_ire_type, ws->ws_ire_types))
			continue;
		if (!(ret = process_ipv4_route(rip, rp, fn, ws)))
			break;
	}

	return (ret);
}

static boolean_t
walk_ipv6_routes(route_impl_t *rip, struct strbuf *dbuf,
    route_entry_walkfunc_t *fn, walk_state_t *ws)
{
	uint_t nroutes = (dbuf->len / sizeof (mib2_ipv6RouteEntry_t));
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	mib2_ipv6RouteEntry_t *rp = (mib2_ipv6RouteEntry_t *)dbuf->buf;
	boolean_t ret = B_TRUE;

	for (; nroutes > 0; rp++, nroutes--) {
		if (!ire_match(rp->ipv6RouteInfo.re_ire_type, ws->ws_ire_types))
			continue;
		if (!(ret = process_ipv6_route(rip, rp, fn, ws)))
			break;
	}

	return (ret);
}

/*
 * Public API entry points below.
 */

int
route_open(libroute_version_t vers, route_handle_t *rhp)
{
	route_impl_t *rip;

	if (vers != LIBROUTE_VERSION_1)
		return (ENOTSUP);

	if ((rip = calloc(1, sizeof (route_impl_t))) == NULL)
		return (errno);
	rip->ri_vers = vers;
	rip->ri_rtsock = -1;
	rip->ri_seq = -1;
	*rhp = rip;
	return (0);
}

void
route_close(route_handle_t rh)
{
	route_impl_t *rip = rh;

	if (rip->ri_rtsock != -1)
		(void) close(rip->ri_rtsock);
	free(rip);
}

int
route_entry_create(route_handle_t rh, route_entry_handle_t *rehp)
{
	route_entry_impl_t *reip;

	if ((reip = calloc(1, sizeof (route_entry_impl_t))) == NULL)
		return (errno);
	reip->rei_rip = rh;
	reip->rei_outif.sdl_family = AF_LINK;
	*rehp = reip;
	return (0);
}

void
route_entry_destroy(route_entry_handle_t reh)
{
	route_entry_impl_t *reip = reh;
	free(reip);
}

int
route_entry_set_destination(route_entry_handle_t reh, struct sockaddr *dst,
    uint_t plen)
{
	route_entry_impl_t *reip = reh;
	route_entry_impl_t orig = *reip;
	int err = 0;

	switch (dst->sa_family) {
	case AF_INET:
		if (plen > IP_ABITS)
			return (EINVAL);
		if (plen == IP_ABITS)
			reip->rei_rtmflags |= RTF_HOST;
		break;
	case AF_INET6:
		if (plen > IPV6_ABITS)
			return (EINVAL);
		if (plen == IPV6_ABITS)
			reip->rei_rtmflags |= RTF_HOST;
		break;
	default:
		return (EINVAL);
	}

	if (!(reip->rei_rtmflags & RTF_HOST)) {
		if ((err = plen_to_netmask(dst->sa_family, plen,
		    &reip->rei_netmasku)) == 0)
			reip->rei_fields |= REI_NETMASK;
	}

	if (err == 0) {
		reip->rei_plen = plen;
		reip->rei_fields |= REI_PLEN;
		err = route_entry_set_dstonly(reip, dst);
	}

	if (err != 0)
		*reip = orig;
	return (err);
}

/*
 * Convenience function for setting a host route destination.
 */
int
route_entry_set_host(route_entry_handle_t reh, struct sockaddr *dst)
{
	if (dst->sa_family != AF_INET && dst->sa_family != AF_INET6)
		return (EINVAL);
	return (route_entry_set_destination(reh, dst,
	    dst->sa_family == AF_INET ? IP_ABITS : IPV6_ABITS));
}

int
route_entry_get_destination(route_entry_handle_t reh, struct sockaddr **dst,
    uint_t *plen)
{
	route_entry_impl_t *reip = reh;

	if (!(reip->rei_fields & REI_DST))
		return (EINVAL);

	*dst = &reip->rei_dstu.su_sa;
	*plen = reip->rei_plen;
	return (0);
}

int
route_entry_set_gateway(route_entry_handle_t reh, struct sockaddr *gateway)
{
	route_entry_impl_t *reip = reh;
	int err;

	if ((err = route_set_sockaddr(gateway, &reip->rei_gwu)) == 0) {
		reip->rei_fields |= REI_GATEWAY;
		reip->rei_rtmflags |= RTF_GATEWAY;
		reip->rei_flags |= ROUTE_ENTRY_GATEWAY;
	}
	return (err);
}

int
route_entry_get_gateway(route_entry_handle_t reh, struct sockaddr **gateway)
{
	route_entry_impl_t *reip = reh;

	if (!(reip->rei_fields & REI_GATEWAY))
		return (EINVAL);

	*gateway = &reip->rei_gwu.su_sa;
	return (0);
}

int
route_entry_set_outifname(route_entry_handle_t reh, const char *outifname)
{
	route_entry_impl_t *reip = reh;

	if ((reip->rei_outif.sdl_index = if_nametoindex(outifname)) == 0)
		return (errno);

	if (strlcpy(reip->rei_outifname, outifname, sizeof (reip->rei_outif)) >=
	    sizeof (reip->rei_outifname))
		return (EINVAL);

	reip->rei_fields |= REI_OUTIF;
	return (0);
}

int
route_entry_get_outifname(route_entry_handle_t reh, char *outifname,
    size_t outifsize)
{
	route_entry_impl_t *reip = reh;

	if (!(reip->rei_fields & REI_OUTIF) ||
	    (strlcpy(outifname, reip->rei_outifname, outifsize) >= outifsize))
		return (EINVAL);
	return (0);
}

int
route_entry_set_outifindex(route_entry_handle_t reh, uint_t ifindex)
{
	route_entry_impl_t *reip = reh;

	/*
	 * Index 0 is a special case and is not associated with any
	 * interface.  It is used in the route_entry_lookup() logic to
	 * indicate that the output interface should be returned by the
	 * kernel in an RTM_GET reply.
	 */
	if (ifindex != 0 &&
	    if_indextoname(ifindex, reip->rei_outifname) == NULL)
		return (errno);

	reip->rei_outif.sdl_index = ifindex;
	reip->rei_fields |= REI_OUTIF;
	return (0);
}

int
route_entry_get_outifindex(route_entry_handle_t reh, uint_t *ifindex)
{
	route_entry_impl_t *reip = reh;

	if (!(reip->rei_fields & REI_OUTIF))
		return (EINVAL);
	*ifindex = reip->rei_outif.sdl_index;
	return (0);
}

uint_t
route_entry_get_flags(route_entry_handle_t reh)
{
	return (((route_entry_impl_t *)reh)->rei_flags);
}

int
route_entry_set_flags(route_entry_handle_t reh, uint_t flags)
{
	route_entry_impl_t *reip = reh;

	if ((flags & (~ROUTE_ENTRY_MODIFYABLE)) != 0)
		return (EINVAL);

	reip->rei_flags |= flags;
	return (0);
}

int
route_entry_clear_flags(route_entry_handle_t reh, uint_t flags)
{
	route_entry_impl_t *reip = reh;

	if ((flags & (~ROUTE_ENTRY_MODIFYABLE)) != 0)
		return (EINVAL);

	reip->rei_flags &= ~flags;
	return (0);
}

int
route_entry_add(route_entry_handle_t reh)
{
	route_entry_impl_t *reip = reh;

	return (write_rtmsg(reip->rei_rip, reip, RTM_ADD));
}

int
route_entry_delete(route_entry_handle_t reh)
{
	route_entry_impl_t *reip = reh;
	int err;

	if ((err = write_rtmsg(reip->rei_rip, reip, RTM_DELETE)) == ESRCH &&
	    (reip->rei_fields & REI_OUTIF)) {
		/*
		 * If the output interface was specified, try again without
		 * specifying it.  This will allow us to delete routes that
		 * were added without the output iterface specified.
		 */
		reip->rei_fields &= ~REI_OUTIF;
		err = write_rtmsg(reip->rei_rip, reip, RTM_DELETE);
		reip->rei_fields |= REI_OUTIF;
	}
	return (err);
}

int
route_entry_walk(route_handle_t rh, route_entry_walkfunc_t *fn, void *arg,
    uint_t walk_flags)
{
	route_impl_t *rip = rh;
	walk_state_t ws;
	struct strbuf cbuf, dbuf;
	struct opthdr *hdr;
	int flags, r, err = 0;
	boolean_t cont = B_TRUE;
	int ipfd;
	struct {
		struct T_optmgmt_req req;
		struct opthdr hdr;
	} req;
	union {
		struct T_optmgmt_ack ack;
		uint8_t space[64];
	} ack;

	ws.ws_ire_types = DEFAULT_IRE_TYPES;
	if (walk_flags & ROUTE_WALK_REDIRECT)
		ws.ws_ire_types |= IRE_HOST_REDIRECT;
	ws.ws_arg = arg;

	req.req.PRIM_type = T_OPTMGMT_REQ;
	req.req.OPT_offset = (caddr_t)&req.hdr - (caddr_t)&req;
	req.req.OPT_length = sizeof (req.hdr);
	req.req.MGMT_flags = T_CURRENT;

	req.hdr.level = MIB2_IP;
	req.hdr.name = 0;
	req.hdr.len = 0;

	cbuf.buf = (caddr_t)&req;
	cbuf.len = sizeof (req);

	if ((ipfd = open(IP_DEV_NAME, O_RDWR)) == -1)
		return (errno);

	if (putmsg(ipfd, &cbuf, NULL, 0) == -1) {
		(void) close(ipfd);
		return (errno);
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
		if ((r = getmsg(ipfd, &cbuf, NULL, &flags)) < 0) {
			err = errno;
			break;
		}
		if (r == 0)
			break;

		if (cbuf.len < sizeof (struct T_optmgmt_ack) ||
		    ack.ack.PRIM_type != T_OPTMGMT_ACK ||
		    ack.ack.MGMT_flags != T_SUCCESS ||
		    ack.ack.OPT_length < sizeof (struct opthdr)) {
			err = EINVAL;
			break;
		}

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		hdr = (struct opthdr *)((caddr_t)&ack + ack.ack.OPT_offset);
		if (hdr->level == 0 && hdr->name == 0)
			break;

		/* Allocate a buffer to hold the data portion of the message */
		if ((dbuf.buf = malloc(hdr->len)) == NULL) {
			err = errno;
			break;
		}
		dbuf.maxlen = hdr->len;
		dbuf.len = 0;
		flags = 0;

		r = getmsg(ipfd, NULL, &dbuf, &flags);

		if (cont) {
			if ((walk_flags & ROUTE_WALK_IPV4) &&
			    hdr->level == MIB2_IP &&
			    hdr->name == MIB2_IP_ROUTE) {
				cont = walk_ipv4_routes(rip, &dbuf, fn, &ws);
			} else if ((walk_flags & ROUTE_WALK_IPV6) &&
			    hdr->level == MIB2_IP6 &&
			    hdr->name == MIB2_IP6_ROUTE) {
				cont = walk_ipv6_routes(rip, &dbuf, fn, &ws);
			}
		}

		free(dbuf.buf);
	}

	(void) close(ipfd);
	return (err);
}

int
route_entry_lookup(route_handle_t rh, struct sockaddr *dst,
    route_entry_handle_t *rehp)
{
	route_impl_t *rip = rh;
	route_entry_impl_t req;
	int err;

	if ((rip->ri_rtsock = socket(PF_ROUTE, SOCK_RAW, 0)) == -1)
		return (errno);

	bzero(&req, sizeof (req));
	req.rei_outif.sdl_family = AF_LINK;

	/*
	 * We signal to the kernel that we want the output interface
	 * to be included in the reply by including an RTA_IFP address
	 * in our request with an index of 0.
	 */
	(void) route_entry_set_outifindex(&req, 0);

	/*
	 * There is a special case for looking up the default route, for which
	 * we must specify an all-zeros netmask.  Any other address lookup
	 * is done by specifying a host route.
	 */
	if (is_unspecified(dst))
		err = route_entry_set_destination(&req, dst, 0);
	else
		err = route_entry_set_host(&req, dst);

	if (err == 0 && (err = write_rtmsg(rip, &req, RTM_GET)) == 0 &&
	    (err = route_entry_create(rh, rehp)) == 0) {
		err = read_rtmsg(rip, *rehp, getpid(), rip->ri_seq);
		if (err != 0)
			route_entry_destroy(*rehp);
	}

	(void) close(rip->ri_rtsock);
	rip->ri_rtsock = -1;
	return (err);
}

/*
 * This is a hack for the route command, which, in verbose mode,  prints out
 * the contents of routing socket messages that it writes.
 */
void
route_rts_trace(route_handle_t rh, route_rts_tracefunc_t *fn, void *arg)
{
	route_impl_t *rip = rh;

	rip->ri_rts_tracefunc = fn;
	rip->ri_rts_tracearg = arg;
}
