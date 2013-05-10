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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <netinet/in.h>
#include <sys/socket.h>

#include <mdb/mdb_ctf.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>


/*
 * nlm_host dcmd implementation
 */

typedef struct mdb_sockaddr_in { /* IPv4 struct */
	sa_family_t	sin_family;
	struct {
		union { /* MUST specify all fields in the union */
			struct {
				uint8_t s_b1;
				uint8_t s_b2;
				uint8_t s_b3;
				uint8_t s_b4;
			} S_un_b;
			struct {
				uint16_t s_w1;
				uint16_t s_w2;
			} S_un_w;
			uint32_t S_addr;
		} S_un;
	} sin_addr;
} mdb_sockaddr_in_t;

typedef struct mdb_sockaddr_in6 { /* IPv6 struct */
	in6_addr_t sin6_addr;
} mdb_sockaddr_in6_t;

typedef struct mdb_nlm_host {
	uint_t		nh_refs;
	uintptr_t	nh_name;
	struct { /* struct netbuf in the os src code */
		/*
		 * ptr to struct sockaddr_in/mdb_sockaddr_in_t
		 * or to struct sockaddr_in6/mdb_sockaddr_in6_t
		 */
		uintptr_t	buf;
	} nh_addr;
	sysid_t		nh_sysid;
	uint8_t		nh_flags;
} mdb_nlm_host_t;

/*
 * Output looks like:
 * > ::nlm_host
 * NLM_HOST         IP ADDR               HOST             REFCNT  SYSID  FLAGS
 * ffffff01d80f7b48 172.16.203.114        delphix               0     14    0x5
 * ffffff01d80f7968 fe80::dc:ff:fe01:fdbf charleston.talisker   0     31    0x5
 */
static int
nlm_host_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_nlm_host_t nlm_host;
	char nh_name[1024];
	mdb_sockaddr_in_t sockaddr;
	mdb_sockaddr_in6_t sockaddr6;
	boolean_t ipv4;

	if (argc != 0) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("nlm_host", "nlm_host", argc, argv) == -1) {
			mdb_warn("can't walk all nlm_hosts");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	if (mdb_ctf_vread(&nlm_host, "struct nlm_host", "mdb_nlm_host_t",
	    addr, 0) == -1) {
		return (DCMD_ERR);
	}

	if (mdb_readstr(nh_name, sizeof (nh_name), nlm_host.nh_name) == -1) {
		mdb_warn("failed to read nh_name at %p\n", nlm_host.nh_name);
		(void) strcpy(nh_name, "<unknown>");
	}

	/*
	 * We expect to primarily encounter IPv4 addresses, so use an IPv4
	 * struct for the initial read.
	 */
	if (mdb_ctf_vread(&sockaddr, "struct sockaddr_in", "mdb_sockaddr_in_t",
	    nlm_host.nh_addr.buf, 0) == -1) {
		return (DCMD_ERR);
	}
	if (sockaddr.sin_family == AF_INET) { /* IPv4 */
		ipv4 = B_TRUE;
	} else { /* AF_INET6 == IPv6 */
		ipv4 = B_FALSE;
		if (mdb_ctf_vread(&sockaddr6, "struct sockaddr_in6",
		    "mdb_sockaddr_in6_t", nlm_host.nh_addr.buf, 0) == -1) {
			return (DCMD_ERR);
		}
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-16s %-24s %-16s %6s %6s %6s%</u>\n",
		    "NLM_HOST", "IP ADDR", "HOST", "REFCNT",
		    "SYSID", "FLAGS");
	}

	mdb_printf("%-16p ", addr);
	if (ipv4) {
		mdb_printf("%-24I", sockaddr.sin_addr.S_un.S_addr);
	} else {
		mdb_printf("%-24N", &sockaddr6.sin6_addr);
	}
	mdb_printf(" %-20s %2u %6u %6#x\n",
	    nh_name, nlm_host.nh_refs, nlm_host.nh_sysid, nlm_host.nh_flags);

	return (DCMD_OK);
}

/*
 * nlm_host walker implementation
 */

typedef struct mdb_nlm_globals_list {
	uintptr_t tqh_first; /* first element */
} mdb_nlm_globals_list_t;

typedef struct mdb_nlm_globals {
	struct {
		uintptr_t tqe_next; /* next element */
	} nlm_link;
} mdb_nlm_globals_t;

static int
nlm_host_walk_init(mdb_walk_state_t *wsp)
{
	mdb_nlm_globals_list_t globals_list;
	GElf_Sym sym;
	mdb_nlm_globals_t nlm_global;

	/*
	 * 1. Find the global list of zones.
	 * 2. Read the first element in the list. Should be the only element
	 *    since we operate w/a single global zone.
	 * 3. Read the AVL tree field and call ::walk avl.
	 */
	if (mdb_lookup_by_name("nlm_zones_list", &sym) != 0) {
		return (WALK_ERR);
	}

	if (mdb_ctf_vread(&globals_list, "struct nlm_globals_list",
	    "mdb_nlm_globals_list_t", sym.st_value, 0) == -1) {
		return (WALK_ERR);
	}

	if (globals_list.tqh_first == 0) {
		mdb_warn("empty zones list!\n");
		return (WALK_ERR);
	}

	/* This walk works for a single zone. Warn if there is > 1 zone. */
	if (mdb_ctf_vread(&nlm_global, "struct nlm_globals",
	    "mdb_nlm_globals_t", globals_list.tqh_first, 0) == -1) {
		return (WALK_ERR);
	}
	if (nlm_global.nlm_link.tqe_next != 0) {
		mdb_warn("2+ zones present -- info for only the "
		    "first zone in the data structure will be printed.\n");
	}

	wsp->walk_addr = globals_list.tqh_first
	    + mdb_ctf_offsetof_by_name("struct nlm_globals", "nlm_hosts_tree");
	if (mdb_layered_walk("avl", wsp) == -1) {
		mdb_warn("failed to walk 'avl'\n");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
nlm_host_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}


static const mdb_dcmd_t dcmds[] = {
	{ "nlm_host", "", "dump an nlm_host structure",
	    nlm_host_dcmd, NULL },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "nlm_host", "dump all nlm_host structures",
	    nlm_host_walk_init, nlm_host_walk_step, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
