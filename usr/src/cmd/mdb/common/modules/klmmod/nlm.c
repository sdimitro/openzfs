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

#include <sys/fcntl.h>
#include <nfs/lm.h>
#include <sys/flock_impl.h>
#include <sys/queue.h>
#include <limits.h>
#include <netdb.h>

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
	struct {
		uintptr_t tqh_first;
		uintptr_t tqh_last;
	} nh_vholds_list;
} mdb_nlm_host_t;

typedef struct mdb_nlm_vhold {
	uintptr_t nv_vp;
	int	nv_refcnt;
	struct {
		uintptr_t tqe_next;
		uintptr_t tqe_prev;
	} nv_link;
} mdb_nlm_vhold_t;

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

/*
 * Compare the local string with a string from the target.  This
 * returns 0 on success and -1 if there is an error reading in the
 * string.  The result of strcmp is put into the outparam.
 */
static int
targ_strcmp(uintptr_t addr, const char *s, int *outparam)
{
	char *s2;
	size_t sz;
	/*
	 * We add two extra characters because we need one for the
	 * null terminator, and one to make sure the local string
	 * isn't a prefix of the target's string.  This is necessary
	 * because readstr always puts a null terminator at the end,
	 * even if the string hasn't ended.
	 */
	sz = strlen(s) + 2;
	s2 = mdb_alloc(sz, UM_SLEEP | UM_GC);
	if (mdb_readstr(s2, sz, addr) == -1) {
		return (-1);
	}
	*outparam = strcmp(s2, s);
	return (0);
}

static int
vholds_cb(uintptr_t addr, const void *holdp, void *cb_data)
{
	uintptr_t hostaddr = (uintptr_t)cb_data;
	mdb_nlm_vhold_t *hold = (mdb_nlm_vhold_t *)holdp;
	char nh_name[MAXHOSTNAMELEN];
	char filename[MAXPATHLEN];
	mdb_nlm_host_t nlm_host;

	if (mdb_ctf_vread(&nlm_host, "struct nlm_host", "mdb_nlm_host_t",
	    (uintptr_t) hostaddr, 0) == -1) {
		return (WALK_ERR);
	}

	if (mdb_readstr(nh_name, sizeof (nh_name), nlm_host.nh_name) == -1) {
	    mdb_warn("failed to read nh_name at %p\n", nlm_host.nh_name);
		(void) strcpy(nh_name, "<unknown>");
	}

	if (mdb_vnode2path(hold->nv_vp, filename, sizeof (filename)) == -1) {
	    mdb_warn("failed to read filename at %p\n", hold->nv_vp);
		(void) strcpy(filename, "<unknown>");
	}

	mdb_printf("%-16p ", hostaddr);
	mdb_printf("%-16s %-16p %6u %-16p %-16s\n",
	    nh_name, addr, hold->nv_refcnt, hold->nv_vp, filename);

	return (WALK_NEXT);
}

static int
nlm_vholds_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_nlm_host_t nlm_host;

	if (argc > 1) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("nlm_host", "nlm_vholds", argc, argv) == -1) {
		    mdb_warn("can't walk nlm_host");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-16s %-16s %-16s %6s %-16s %-16s%</u>\n",
		    "NLM_HOST", "HOST", "NLM_HOLD", "REFCNT",
		    "VNODE", "FILENAME");
	}

	if (mdb_ctf_vread(&nlm_host, "struct nlm_host", "mdb_nlm_host_t",
	    (uintptr_t) addr, 0) == -1) {
		return (DCMD_ERR);
	}

	if (argc == 1) {
		int cmp;

		switch (argv->a_type) {
		case MDB_TYPE_STRING:
			if (targ_strcmp(nlm_host.nh_name, argv->a_un.a_str,
			    &cmp) == -1) {
				mdb_warn("unable to read sysid name");
				return (DCMD_ERR);
			}
			if (cmp != 0)
				return (DCMD_OK);
			break;
		default:
			mdb_warn("invalid host specified\n");
			return (DCMD_ERR);
		}
	}

	if (mdb_pwalk("nlm_vholds", vholds_cb, (void *)addr, addr) != 0) {
		mdb_warn("Can't walk nlm_vholds");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

static int
nlm_vholds_walk_init(mdb_walk_state_t *wsp)
{
	mdb_nlm_host_t nlm_host;
	if (wsp->walk_addr == NULL) {
		mdb_warn("Must supply a host to walk\n");
		return (WALK_ERR);
	}
	if (mdb_ctf_vread(&nlm_host, "struct nlm_host", "mdb_nlm_host_t",
		    wsp->walk_addr, 0) == -1) {
		return (WALK_ERR);
	}

	wsp->walk_addr = TAILQ_FIRST(&nlm_host.nh_vholds_list);
	return (WALK_NEXT);
}

static int
nlm_vholds_walk_step(mdb_walk_state_t *wsp)
{
	mdb_nlm_vhold_t hold;
	int status;
	if (wsp->walk_addr == NULL) {
		return (WALK_DONE);
	}

	if (mdb_ctf_vread(&hold, "struct nlm_vhold", "mdb_nlm_vhold_t",
	    wsp->walk_addr, 0) == -1) {
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &hold,
	    wsp->walk_cbdata);
	if (status == WALK_NEXT) {
		wsp->walk_addr = TAILQ_NEXT(&hold, nv_link);
	}
	return (status);
}

typedef struct nlm_lockson_arg {
	uint_t opt_v;
	const mdb_arg_t *spec_host;
	const mdb_nlm_host_t *cur_host;
} nlm_lockson_arg_t;

static int
nlm_lockson_cb(uintptr_t addr, const void *lockp, void *cb_data) {
	nlm_lockson_arg_t *arg = cb_data;
	const lock_descriptor_t *ld = lockp;
	int local;
	char hostname[MAXHOSTNAMELEN];
	proc_t p;
	char *s;

	if ((ld->l_flock.l_sysid & LM_SYSID_MAX) != arg->cur_host->nh_sysid) {
		return (WALK_NEXT);
	}

	if (mdb_readstr(hostname, sizeof (hostname),
	    (uintptr_t)(arg->cur_host->nh_name)) == -1) {
		mdb_warn("Unable to read host name");
		return (WALK_ERR);
	}
	local = ld->l_flock.l_sysid & LM_SYSID_CLIENT;

	mdb_printf("%-*s%?p %5hi(%c) %?p %-6d %-*s ", sizeof (hostname),
	    hostname, addr,	ld->l_flock.l_sysid & LM_SYSID_MAX,
	    local ? 'L' : 'R', ld->l_vnode, ld->l_flock.l_pid, MAXCOMLEN,
	    ld->l_flock.l_pid == 0 ? "<kernel>" : !local ? "<remote>" :
	    mdb_pid2proc(ld->l_flock.l_pid, &p) == NULL ? "<defunct>" :
	    p.p_user.u_comm);

	if (arg->opt_v) {
		switch (ld->l_status) {
		case FLK_INITIAL_STATE:
			s = "init";
			break;
		case FLK_START_STATE:
			s = "execute";
			break;
		case FLK_ACTIVE_STATE:
			s = "active";
			break;
		case FLK_SLEEPING_STATE:
			s = "blocked";
			break;
		case FLK_GRANTED_STATE:
			s = "granted";
			break;
		case FLK_INTERRUPTED_STATE:
			s = "interrupt";
			break;
		case FLK_CANCELLED_STATE:
			s = "cancel";
			break;
		case FLK_DEAD_STATE:
			s = "done";
			break;
		default:
			s = "<invalid>";
			break;
		}
		mdb_printf("%-9s", s);
	} else {
		mdb_printf("%-5d", ld->l_status);
	}

	mdb_printf(" %-2s", ld->l_type == F_RDLCK ? "RD"
	    : ld->l_type == F_WRLCK ? "WR" : "??");

	if (!arg->opt_v) {
		mdb_printf("\n");
		return (WALK_NEXT);
	}

	switch (GET_NLM_STATE(ld)) {
	case FLK_NLM_UP:
		s = "up";
		break;
	case FLK_NLM_SHUTTING_DOWN:
		s = "halting";
		break;
	case FLK_NLM_DOWN:
		s = "down";
		break;
	case FLK_NLM_UNKNOWN:
		s = "unknown";
		break;
	default:
		s = "<invalid>";
		break;
	}

	mdb_printf("(%5d:%-5d) %-7s ", ld->l_start, ld->l_len, s);
	s = mdb_alloc(PATH_MAX, UM_SLEEP | UM_GC);
	if (mdb_vnode2path((uintptr_t)ld->l_vnode, s, PATH_MAX) == -1) {
		s = "<unknown path>";
	}
	mdb_printf("%s\n", s);

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
nlm_lockson_vhold_cb(uintptr_t addr, const void *holdp, void *cb_data) {
	uintptr_t vnode_addr = ((mdb_nlm_vhold_t *)holdp)->nv_vp;
	if (mdb_pwalk("lock_graph", nlm_lockson_cb, cb_data, vnode_addr)
	    == -1) {
		mdb_warn("failed to walk lock_graph");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
nlm_lockson_host_cb(uintptr_t addr, const void *hostp, void *cb_data) {
	nlm_lockson_arg_t *arg = cb_data;
	mdb_nlm_host_t nlm_host;

	if (mdb_ctf_vread(&nlm_host, "struct nlm_host", "mdb_nlm_host_t",
	    addr, 0) == -1) {
		return (WALK_ERR);
	}
	arg->cur_host = &nlm_host;

	if (arg->spec_host) {
		int cmp;

		switch (arg->spec_host->a_type) {
		case MDB_TYPE_STRING:
			if (targ_strcmp(nlm_host.nh_name,
			    arg->spec_host->a_un.a_str, &cmp) == -1) {
				mdb_warn("unable to read sysid name");
				return (WALK_ERR);
			}
			if (cmp != 0)
				return (WALK_NEXT);
			break;
		case MDB_TYPE_IMMEDIATE:
			if (nlm_host.nh_sysid != arg->spec_host->a_un.a_val)
				return (WALK_NEXT);
			break;
		default:
			mdb_warn("invalid host specified\n");
			return (WALK_ERR);
		}
	}

	if (mdb_pwalk("nlm_vholds", nlm_lockson_vhold_cb, arg, addr) == -1) {
		mdb_warn("failed to walk vholds");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/* ARGSUSED */
static int
nlm_lockson_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nlm_lockson_arg_t cb_args = {FALSE, NULL, NULL};
	int count;

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	count = mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &cb_args.opt_v, NULL);

	if (argc - count > 1)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<b>%<u>%-*s%-?s %5s(x) %-?s %-6s %-*s %-*s TYPE",
		    16, "HOST", "LOCK ADDR", "SYSID", "VNODE", "PID",
		    MAXCOMLEN, "CMD", cb_args.opt_v ? 9 : 5, "STATE");

		if (cb_args.opt_v)
			mdb_printf("%-11s SRVSTAT %-10s", "(WIDTH)", "PATH");

		mdb_printf("%</u>%</b>\n");
	}
	if (argc > count)
		cb_args.spec_host = &argv[count];

	if (mdb_walk("nlm_host", nlm_lockson_host_cb, &cb_args) == -1) {
		mdb_warn("failed to walk nlm_host");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

void
nlm_lockson_help(void)
{
	mdb_printf("-v       verbose information about the locks\n"
	    "host     limit the output for the host specified\n"
	    "         by either $[sysid] or hostname\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "nlm_host", "", "dump an nlm_host structure",
	    nlm_host_dcmd, NULL },
	{ "nlm_vholds", "?", "dumps vholds in the system or one host",
	    nlm_vholds_dcmd, NULL },
	{ "nlm_lockson", "[-v] [host]", "Dumps all the held locks in nlm",
	    nlm_lockson_dcmd, nlm_lockson_help},
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "nlm_host", "dump all nlm_host structures",
	    nlm_host_walk_init, nlm_host_walk_step, NULL },
	{ "nlm_vholds", "walk the vholds in an nlm_host",
	    nlm_vholds_walk_init, nlm_vholds_walk_step, NULL },
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
