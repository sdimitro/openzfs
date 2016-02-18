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
 * Copyright (c) 2015, 2016 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <stddef.h>
#include <strings.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <langinfo.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/varargs.h>
#include <ofmt.h>
#include <netinet/in.h>
#include <inet/mib2.h>
#include "connstat.h"
#include "connstat_mib.h"
#include "connstat_tcp.h"

#define	DEFAULT_PROTO	"tcp"

static const char *invalid_v4v6_msg =
	"Invalid combination of IPv4 and IPv6 arguments\n";

static const struct option longopts[] = {
	{ "count",	required_argument,	0, 'c'	},
	{ "established",	no_argument,	0, 'e'	},
	{ "filter",	required_argument,	0, 'F'	},
	{ "help",	no_argument,		0, 'h'	},
	{ "interval",	required_argument,	0, 'i'	},
	{ "ipv4",	no_argument,		0, '4'	},
	{ "ipv6",	no_argument,		0, '6'	},
	{ "no-loopback",	no_argument,	0, 'L'	},
	{ "output",	required_argument,	0, 'o'	},
	{ "parsable",	no_argument,		0, 'P'	},
	{ "protocol",	required_argument,	0, 'p'	},
	{ "timestamp",	required_argument,	0, 'T'	},
	{ NULL, 0, 0, 0 }
};

static connstat_proto_t connstat_protos[] = {
	CONNSTAT_TCP_PROTO,
	{ NULL, 0, 0, 0, NULL }
};

typedef enum { NOTIMESTAMP, UTIMESTAMP, DTIMESTAMP } timestamp_fmt_t;

static char *progname;

static void	die(const char *, ...);
static void	process_filter(char *, connstat_conn_attr_t *, uint_t *);
static void	show_stats(connstat_proto_t *, ofmt_handle_t, uint_t,
    connstat_conn_attr_t *, timestamp_fmt_t, uint_t, uint_t);

static void
usage(int code)
{
	static const char *opts[] = {
		"-4, --ipv4             Only display IPv4 connections",
		"-6, --ipv6             Only display IPv6 connections",
		"-c, --count=COUNT      Only print COUNT reports",
		"-e, --established      Only display established connections",
		"-F, --filter=FILTER    Only display connection that match "
		    "FILTER",
		"-h, --help             Print this help",
		"-i, --interval=SECONDS Report once every SECONDS seconds",
		"-L, --no-loopback      Omit loopback connections",
		"-o, --output=FIELDS    Restrict output to the comma-separated "
		    "list of fields\n"
		    "                         specified",
		"-p, --protocol=PROTO   Display connection for PROTO "
		    "(currently only tcp is\n"
		    "                         supported)",
		"-P, --parsable         Parsable output mode",
		"-T, --timestamp=TYPE   Display a timestamp for each iteration",
		NULL
	};

	(void) fprintf(stderr, gettext("usage: "));
	(void) fprintf(stderr,
	    gettext("%s [-p <proto>] [-eLP] [-4|-6] [-T d|u] [-F <filter>]\n"
	    "               [-i <interval> [-c <count>]] [-o <field>[,...]]\n"),
	    progname);

	(void) fprintf(stderr, gettext("\nOptions:\n"));
	for (const char **optp = opts; *optp != NULL; optp++) {
		(void) fprintf(stderr, "  %s\n", gettext(*optp));
	}

	(void) fprintf(stderr, gettext("\nFilter:\n"));
	(void) fprintf(stderr, gettext("  The FILTER argument for the -F "
	    "option is of the form:\n"
	    "    <attr>=<value>,[<attr>=<value>,...]\n"));
	(void) fprintf(stderr, gettext("  Filter attributes:\n"));
	(void) fprintf(stderr, gettext(
	    "  laddr  Local IP address\n"
	    "  lport  Local port\n"
	    "  raddr  Remote IP address\n"
	    "  rport  Remote port\n"));

	(void) fprintf(stderr, gettext("\nFields:\n"));
	(void) fprintf(stderr, gettext(
	    "  laddr           Local IP address\n"
	    "  raddr           Remote IP address\n"
	    "  lport           Local port\n"
	    "  rport           Remote port\n"
	    "  inbytes         Total bytes received\n"
	    "  insegs          Total segments received\n"
	    "  inunorderbytes  Bytes received out of order\n"
	    "  inunordersegs   Segments received out of order\n"
	    "  outbytes        Total bytes sent\n"
	    "  outsegs         Total segments sent\n"
	    "  retransbytes    Bytes retransmitted\n"
	    "  retranssegs     Segments retransmitted\n"
	    "  suna            Current unacknowledged bytes sent\n"
	    "  swnd            Send window size (peer's receive window)\n"
	    "  cwnd            Congestion window size\n"
	    "  rwnd            Receive window size\n"
	    "  mss             Maximum segment size\n"
	    "  rto             Retransmission timeout (ms)\n"
	    "  rtt             Smoothed round-trip time (us)\n"
	    "  state           Connection state\n"));
	exit(code);
}

static connstat_proto_t *
getproto(const char *proto)
{
	for (connstat_proto_t *current = &connstat_protos[0];
	    current->csp_proto != NULL; current++) {
		if (strcasecmp(proto, current->csp_proto) == 0) {
			return (current);
		}
	}
	return (NULL);
}

int
main(int argc, char *argv[])
{
	int option;
	int count = 0;
	int interval = 0;
	char *fields = NULL;
	char *filterstr = NULL;
	connstat_conn_attr_t filter;
	char *protostr = DEFAULT_PROTO;
	connstat_proto_t *proto;
	ofmt_handle_t ofmt;
	ofmt_status_t oferr;
	char oferrbuf[OFMT_BUFSIZE];
	uint_t ofmtflags = OFMT_RIGHTJUST|OFMT_NOHEADER;
	uint_t flags = CS_LOOPBACK | CS_IPV4 | CS_IPV6;
	timestamp_fmt_t timestamp_fmt = NOTIMESTAMP;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];

	while ((option = getopt_long(argc, argv, "c:eF:hi:Lo:Pp:T:46",
	    longopts, NULL)) != -1) {
		errno = 0;
		switch (option) {
		case 'c':
			count = strtol(optarg, NULL, 10);
			if (count == 0 && errno != 0) {
				(void) fprintf(stderr, gettext(
				    "error parsing -c argument (%s): %s\n"),
				    optarg, strerror(errno));
				usage(1);
			}
			if (count <= 0) {
				die("count must be >= 0");
			}
			break;
		case 'e':
			flags |= CS_ESTABLISHED;
			break;
		case 'F':
			filterstr = optarg;
			break;
		case 'i':
			interval = strtol(optarg, NULL, 10);
			if (interval == 0 && errno != 0) {
				(void) fprintf(stderr, gettext(
				    "error parsing -i argument (%s): %s\n"),
				    optarg, strerror(errno));
				usage(1);
			}
			if (interval <= 0) {
				die("interval must be >= 0");
			}
			break;
		case 'L':
			flags &= ~CS_LOOPBACK;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'P':
			ofmtflags |= OFMT_PARSABLE;
			flags |= CS_PARSABLE;
			break;
		case 'p':
			protostr = optarg;
			break;
		case 'T':
			if (*optarg == 'u') {
				timestamp_fmt = UTIMESTAMP;
			} else if (*optarg == 'd') {
				timestamp_fmt = DTIMESTAMP;
			} else {
				usage(1);
			}
			break;
		case '4':
			if (!(flags & CS_IPV4)) {
				(void) fprintf(stderr, gettext(
				    invalid_v4v6_msg));
				usage(1);
			}
			flags &= ~CS_IPV6;
			break;
		case '6':
			if (!(flags & CS_IPV6)) {
				(void) fprintf(stderr, gettext(
				    invalid_v4v6_msg));
				usage(1);
			}
			flags &= ~CS_IPV4;
			break;
		case '?':
		default:
			usage(1);
			break;
		}
	}

	if ((proto = getproto(protostr)) == NULL) {
		(void) fprintf(stderr, gettext("unknown protocol: %s\n"),
		    protostr);
		usage(1);
	}

	if ((ofmtflags & OFMT_PARSABLE) && fields == NULL) {
		die("parsable output requires \"-o\"");
	}

	if ((ofmtflags & OFMT_PARSABLE) && fields != NULL &&
	    strcasecmp(fields, "all") == 0) {
		die("\"-o all\" is invalid with parsable output");
	}

	if (fields == NULL) {
		fields = proto->csp_default_fields;
	}

	/* If count is specified, then interval must also be specified. */
	if (count != 0 && interval == 0) {
		usage(1);
	}

	/* If interval is not specified, then the default count is 1. */
	if (interval == 0 && count == 0) {
		count = 1;
	}

	bzero(&filter, sizeof (filter));
	if (filterstr != NULL) {
		process_filter(filterstr, &filter, &flags);
	}

	oferr = ofmt_open(fields, proto->csp_getfields(), ofmtflags, 0, &ofmt);
	if (oferr != OFMT_SUCCESS) {
		(void) ofmt_strerror(ofmt, oferr, oferrbuf, sizeof (oferrbuf));
		die(oferrbuf);
	}
	ofmt_set_fs(ofmt, ',');

	show_stats(proto, ofmt, flags, &filter, timestamp_fmt, interval, count);

	ofmt_close(ofmt);
	return (0);
}

static void
str2sockaddr(const char *addr, struct sockaddr_storage *ss)
{
	struct addrinfo hints, *res;

	bzero(&hints, sizeof (hints));
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(addr, NULL, &hints, &res) != 0) {
		die("invalid literal IP address: %s", addr);
	}
	bcopy(res->ai_addr, ss, res->ai_addrlen);
	freeaddrinfo(res);
}

/*
 * The filterstr argument is of the form: <attr>=<value>[,...]
 * Possible attributes are laddr, raddr, lport, and rport. Parse this
 * filter and store the results into the provided attribute structure.
 */
static void
process_filter(char *filterstr, connstat_conn_attr_t *filter, uint_t *flags)
{
	int option;
	char *val;
	enum { F_LADDR, F_RADDR, F_LPORT, F_RPORT };
	static char *filter_optstr[] = { "laddr", "raddr", "lport", "rport" };
	int addrflag = 0, portflag = 0;
	struct sockaddr_storage *addrp = NULL;
	uint16_t port;

	while (*filterstr != '\0') {
		option = getsubopt(&filterstr, filter_optstr, &val);
		errno = 0;

		switch (option) {
		case F_LADDR:
			addrflag = CS_LADDR;
			addrp = &filter->ca_laddr;
			break;
		case F_RADDR:
			addrflag = CS_RADDR;
			addrp = &filter->ca_raddr;
			break;
		case F_LPORT:
			portflag = CS_LPORT;
			addrp = &filter->ca_laddr;
			break;
		case F_RPORT:
			portflag = CS_RPORT;
			addrp = &filter->ca_raddr;
			break;
		default:
			usage(1);
		}

		switch (option) {
		case F_LADDR:
		case F_RADDR:
			str2sockaddr(val, addrp);
			*flags |= addrflag;
			if (addrp->ss_family == AF_INET) {
				if (!(*flags & CS_IPV4)) {
					(void) fprintf(stderr, gettext(
					    invalid_v4v6_msg));
					usage(1);
				}
				*flags &= ~CS_IPV6;
			} else {
				if (!(*flags & CS_IPV6)) {
					(void) fprintf(stderr, gettext(
					    invalid_v4v6_msg));
					usage(1);
				}
				*flags &= ~CS_IPV4;
			}
			break;
		case F_LPORT:
		case F_RPORT:
			port = strtol(val, NULL, 10);
			if (port == 0 && errno != 0) {
				(void) fprintf(stderr, gettext(
				    "error parsing port (%s): %s\n"),
				    val, strerror(errno));
				usage(1);
			}
			((struct sockaddr_in *)addrp)->sin_port = htons(port);
			*flags |= portflag;
			break;
		}
	}

	/* Make sure that laddr and raddr are at least in the same family. */
	if ((*flags & (CS_LADDR|CS_RADDR)) == (CS_LADDR|CS_RADDR)) {
		if (filter->ca_laddr.ss_family != filter->ca_raddr.ss_family) {
			die("laddr and raddr must be of the same family.");
		}
	}
}

/*
 * Print timestamp as decimal representation of time_t value (-T u was
 * specified) or in date(1) format (-T d was specified).
 */
static void
print_timestamp(timestamp_fmt_t timestamp_fmt, boolean_t parsable)
{
	time_t t = time(NULL);
	char *pfx = parsable ? "= " : "";
	static char *fmt = NULL;

	/* We only need to retrieve this once per invocation */
	if (fmt == NULL) {
		fmt = nl_langinfo(_DATE_FMT);
	}

	if (timestamp_fmt == UTIMESTAMP) {
		(void) printf("%s%ld\n", pfx, t);
	} else if (timestamp_fmt == DTIMESTAMP) {
		char dstr[64];
		int len;

		len = strftime(dstr, sizeof (dstr), fmt, localtime(&t));
		if (len > 0) {
			(void) printf("%s%s\n", pfx, dstr);
		}
	}
}

static void
show_stats(connstat_proto_t *proto, ofmt_handle_t ofmt, uint_t flags,
    connstat_conn_attr_t *filter, timestamp_fmt_t timestamp_fmt,
    uint_t interval, uint_t count)
{
	boolean_t done = B_FALSE;
	uint_t i = 0;
	int mibfd;
	conn_walk_state_t state;

	state.cws_ofmt = ofmt;
	state.cws_flags = flags;
	state.cws_filter = *filter;

	if ((mibfd = mibopen(proto->csp_proto)) == -1) {
		die(strerror(errno));
	}

	do {
		if (timestamp_fmt != NOTIMESTAMP) {
			print_timestamp(timestamp_fmt, flags & CS_PARSABLE);
		}
		if (!(flags & CS_PARSABLE)) {
			ofmt_print_header(ofmt);
		}

		conn_walk(mibfd, proto, &state);

		if (count != 0 && ++i == count) {
			done = B_TRUE;
		} else {
			(void) sleep(interval);
		}
	} while (!done);
}

/*
 * ofmt callbacks for printing individual fields of various types.
 */
boolean_t
print_string(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	char *value;

	value = (char *)ofarg->ofmt_cbarg + ofarg->ofmt_id;
	(void) strlcpy(buf, value, bufsize);
	return (B_TRUE);
}

boolean_t
print_uint16(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	uint16_t value;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	value = *(uint16_t *)((char *)ofarg->ofmt_cbarg + ofarg->ofmt_id);
	(void) snprintf(buf, bufsize, "%hu", value);
	return (B_TRUE);
}

boolean_t
print_uint32(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	uint32_t value;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	value = *(uint32_t *)((char *)ofarg->ofmt_cbarg + ofarg->ofmt_id);
	(void) snprintf(buf, bufsize, "%u", value);
	return (B_TRUE);
}

boolean_t
print_uint64(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	uint64_t value;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	value = *(uint64_t *)((char *)ofarg->ofmt_cbarg + ofarg->ofmt_id);
	(void) snprintf(buf, bufsize, "%llu", value);
	return (B_TRUE);
}

/* PRINTFLIKE1 */
static void
die(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) putc('\n', stderr);

	exit(1);
}
