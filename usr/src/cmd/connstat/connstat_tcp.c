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
#include <string.h>
#include <stdlib.h>
#include <inet/mib2.h>
#include <sys/stropts.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inet/tcp.h>
#include <arpa/inet.h>
#include <ofmt.h>
#include <sys/time.h>
#include "connstat_mib.h"
#include "connstat_tcp.h"

typedef struct tcp_fields_buf_s {
	char t_laddr[INET6_ADDRSTRLEN];
	char t_raddr[INET6_ADDRSTRLEN];
	uint16_t t_lport;
	uint16_t t_rport;
	uint64_t t_inbytes;
	uint64_t t_insegs;
	uint64_t t_inunorderbytes;
	uint64_t t_inunordersegs;
	uint64_t t_outbytes;
	uint64_t t_outsegs;
	uint64_t t_retransbytes;
	uint64_t t_retranssegs;
	uint32_t t_suna;
	uint32_t t_swnd;
	uint32_t t_cwnd;
	uint32_t t_rwnd;
	uint32_t t_mss;
	uint32_t t_rto;
	int t_state;
	uint64_t t_rtt;
} tcp_fields_buf_t;

static boolean_t print_tcp_state(ofmt_arg_t *, char *, uint_t);

static ofmt_field_t tcp_fields[] = {
	{ "LADDR",	15,
		offsetof(tcp_fields_buf_t, t_laddr),	print_string },
	{ "RADDR",	15,
		offsetof(tcp_fields_buf_t, t_raddr),	print_string },
	{ "LPORT",	6,
		offsetof(tcp_fields_buf_t, t_lport),	print_uint16 },
	{ "RPORT",	6,
		offsetof(tcp_fields_buf_t, t_rport),	print_uint16 },
	{ "INBYTES",	11,
		offsetof(tcp_fields_buf_t, t_inbytes),	print_uint64 },
	{ "INSEGS",	11,
		offsetof(tcp_fields_buf_t, t_insegs),	print_uint64 },
	{ "INUNORDERBYTES",	15,
		offsetof(tcp_fields_buf_t, t_inunorderbytes),	print_uint64 },
	{ "INUNORDERSEGS",	14,
		offsetof(tcp_fields_buf_t, t_inunordersegs),	print_uint64 },
	{ "OUTBYTES",	11,
		offsetof(tcp_fields_buf_t, t_outbytes),	print_uint64 },
	{ "OUTSEGS",	11,
		offsetof(tcp_fields_buf_t, t_outsegs),	print_uint64 },
	{ "RETRANSBYTES",	13,
		offsetof(tcp_fields_buf_t, t_retransbytes),	print_uint64 },
	{ "RETRANSSEGS",	12,
		offsetof(tcp_fields_buf_t, t_retranssegs),	print_uint64 },
	{ "SUNA",	11,
		offsetof(tcp_fields_buf_t, t_suna),	print_uint32 },
	{ "SWND",	11,
		offsetof(tcp_fields_buf_t, t_swnd),	print_uint32 },
	{ "CWND",	11,
		offsetof(tcp_fields_buf_t, t_cwnd),	print_uint32 },
	{ "RWND",	11,
		offsetof(tcp_fields_buf_t, t_rwnd),	print_uint32 },
	{ "MSS",	6,
		offsetof(tcp_fields_buf_t, t_mss),	print_uint32 },
	{ "RTO",	8,
		offsetof(tcp_fields_buf_t, t_rto),	print_uint32 },
	{ "RTT",	8,
		offsetof(tcp_fields_buf_t, t_rtt),	print_uint64 },
	{ "STATE",	12,
		offsetof(tcp_fields_buf_t, t_state),	print_tcp_state },
	{ NULL, 0, 0, NULL}
};

static tcp_fields_buf_t fields_buf;

ofmt_field_t *
tcp_get_fields()
{
	return (tcp_fields);
}

/*
 * Extract information from the connection info structure into the global
 * output buffer.
 */
static void
tcp_ci2buf(struct tcpConnEntryInfo_s *ci)
{
	fields_buf.t_inbytes =
	    ci->ce_in_data_inorder_bytes + ci->ce_in_data_unorder_bytes;
	fields_buf.t_insegs =
	    ci->ce_in_data_inorder_segs + ci->ce_in_data_unorder_segs;
	fields_buf.t_inunorderbytes = ci->ce_in_data_unorder_bytes;
	fields_buf.t_inunordersegs = ci->ce_in_data_unorder_segs;
	fields_buf.t_outbytes = ci->ce_out_data_bytes;
	fields_buf.t_outsegs = ci->ce_out_data_segs;
	fields_buf.t_retransbytes = ci->ce_out_retrans_bytes;
	fields_buf.t_retranssegs = ci->ce_out_retrans_segs;
	fields_buf.t_suna = ci->ce_snxt - ci->ce_suna;
	fields_buf.t_swnd = ci->ce_swnd;
	fields_buf.t_cwnd = ci->ce_cwnd;
	fields_buf.t_rwnd = ci->ce_rwnd;
	fields_buf.t_mss = ci->ce_mss;
	fields_buf.t_rto = ci->ce_rto;
	fields_buf.t_rtt = ci->ce_rtt_sa;
	fields_buf.t_state = ci->ce_state;
}

/*
 * Extract information from the connection entry into the global output
 * buffer.
 */
static void
tcp_ipv4_ce2buf(mib2_tcpConnEntry_t *ce)
{
	(void) inet_ntop(AF_INET, (void *)&ce->tcpConnLocalAddress,
	    fields_buf.t_laddr, sizeof (fields_buf.t_laddr));
	(void) inet_ntop(AF_INET, (void *)&ce->tcpConnRemAddress,
	    fields_buf.t_raddr, sizeof (fields_buf.t_raddr));

	fields_buf.t_lport = ce->tcpConnLocalPort;
	fields_buf.t_rport = ce->tcpConnRemPort;

	tcp_ci2buf(&ce->tcpConnEntryInfo);
}

static void
tcp_ipv6_ce2buf(mib2_tcp6ConnEntry_t *ce)
{
	(void) inet_ntop(AF_INET6, (void *)&ce->tcp6ConnLocalAddress,
	    fields_buf.t_laddr, sizeof (fields_buf.t_laddr));
	(void) inet_ntop(AF_INET6, (void *)&ce->tcp6ConnRemAddress,
	    fields_buf.t_raddr, sizeof (fields_buf.t_raddr));

	fields_buf.t_lport = ce->tcp6ConnLocalPort;
	fields_buf.t_rport = ce->tcp6ConnRemPort;

	tcp_ci2buf(&ce->tcp6ConnEntryInfo);
}

/*
 * Print a single IPv4 connection entry, taking into account possible
 * filters that have been set in state.
 */
static void
tcp_ipv4_print(mib2_tcpConnEntry_t *ce, conn_walk_state_t *state)
{
	if (!(state->cws_flags & CS_LOOPBACK) &&
	    ntohl(ce->tcpConnLocalAddress) == INADDR_LOOPBACK) {
		return;
	}

	if (state->cws_flags & CS_LADDR) {
		struct sockaddr_in *sin =
		    (struct sockaddr_in *)&state->cws_filter.ca_laddr;
		if (ce->tcpConnLocalAddress != sin->sin_addr.s_addr) {
			return;
		}
	}
	if (state->cws_flags & CS_RADDR) {
		struct sockaddr_in *sin =
		    (struct sockaddr_in *)&state->cws_filter.ca_raddr;
		if (ce->tcpConnRemAddress != sin->sin_addr.s_addr) {
			return;
		}
	}
	if (state->cws_flags & CS_LPORT) {
		struct sockaddr_in *sin =
		    (struct sockaddr_in *)&state->cws_filter.ca_laddr;
		if (ce->tcpConnLocalPort != ntohs(sin->sin_port)) {
			return;
		}
	}
	if (state->cws_flags & CS_RPORT) {
		struct sockaddr_in *sin =
		    (struct sockaddr_in *)&state->cws_filter.ca_raddr;
		if (ce->tcpConnRemPort != ntohs(sin->sin_port)) {
			return;
		}
	}

	if ((state->cws_flags & CS_ESTABLISHED) &&
	    ce->tcpConnState != MIB2_TCP_established) {
		return;
	}

	tcp_ipv4_ce2buf(ce);
	ofmt_print(state->cws_ofmt, &fields_buf);
}

/*
 * Print a single IPv6 connection entry, taking into account possible
 * filters that have been set in state.
 */
static void
tcp_ipv6_print(mib2_tcp6ConnEntry_t *ce, conn_walk_state_t *state)
{
	if (!(state->cws_flags & CS_LOOPBACK) &&
	    IN6_IS_ADDR_LOOPBACK(
	    (struct in6_addr *)&ce->tcp6ConnLocalAddress)) {
		return;
	}

	if (state->cws_flags & CS_LADDR) {
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)&state->cws_filter.ca_laddr;
		if (!IN6_ARE_ADDR_EQUAL(
		    (struct in6_addr *)&ce->tcp6ConnLocalAddress,
		    &sin6->sin6_addr)) {
			return;
		}
	}
	if (state->cws_flags & CS_RADDR) {
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)&state->cws_filter.ca_raddr;
		if (!IN6_ARE_ADDR_EQUAL(
		    (struct in6_addr *)&ce->tcp6ConnRemAddress,
		    &sin6->sin6_addr)) {
			return;
		}
	}
	if (state->cws_flags & CS_LPORT) {
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)&state->cws_filter.ca_laddr;
		if (ce->tcp6ConnLocalPort != ntohs(sin6->sin6_port)) {
			return;
		}
	}
	if (state->cws_flags & CS_RPORT) {
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)&state->cws_filter.ca_raddr;
		if (ce->tcp6ConnRemPort != ntohs(sin6->sin6_port)) {
			return;
		}
	}

	if ((state->cws_flags & CS_ESTABLISHED) &&
	    ce->tcp6ConnState != MIB2_TCP_established) {
		return;
	}

	tcp_ipv6_ce2buf(ce);
	ofmt_print(state->cws_ofmt, &fields_buf);
}

void
tcp_walk_ipv4(struct strbuf *dbuf, conn_walk_state_t *state)
{
	uint_t nconns = (dbuf->len / sizeof (mib2_tcpConnEntry_t));
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	mib2_tcpConnEntry_t *ce = (mib2_tcpConnEntry_t *)dbuf->buf;

	for (; nconns > 0; ce++, nconns--) {
		tcp_ipv4_print(ce, state);
	}
}

void
tcp_walk_ipv6(struct strbuf *dbuf, conn_walk_state_t *state)
{
	uint_t nconns = (dbuf->len / sizeof (mib2_tcp6ConnEntry_t));
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	mib2_tcp6ConnEntry_t *ce = (mib2_tcp6ConnEntry_t *)dbuf->buf;

	for (; nconns > 0; ce++, nconns--) {
		tcp_ipv6_print(ce, state);
	}
}

static boolean_t
print_tcp_state(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	int state;
	char *statestr = NULL;
	struct tcp_state_info_s {
		int tsi_state;
		char *tsi_string;
	} tcp_state_info[] = {
		{ TCPS_CLOSED, "CLOSED" },
		{ TCPS_IDLE, "IDLE" },
		{ TCPS_BOUND, "BOUND" },
		{ TCPS_LISTEN, "LISTEN" },
		{ TCPS_SYN_SENT, "SYN_SENT" },
		{ TCPS_SYN_RCVD, "SYN_RCVD" },
		{ TCPS_ESTABLISHED, "ESTABLISHED" },
		{ TCPS_CLOSE_WAIT, "CLOSE_WAIT" },
		{ TCPS_FIN_WAIT_1, "FIN_WAIT_1" },
		{ TCPS_CLOSING, "CLOSING" },
		{ TCPS_LAST_ACK, "LAST_ACK" },
		{ TCPS_FIN_WAIT_2, "FIN_WAIT_2" },
		{ TCPS_TIME_WAIT, "TIME_WAIT" },
		{ TCPS_CLOSED - 1, NULL }
	};
	struct tcp_state_info_s *sip;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	state = *(int *)((char *)ofarg->ofmt_cbarg + ofarg->ofmt_id);

	for (sip = tcp_state_info; sip->tsi_string != NULL; sip++) {
		if (sip->tsi_state == state) {
			statestr = sip->tsi_string;
		}
	}
	if (statestr != NULL) {
		(void) strlcpy(buf, statestr, bufsize);
	} else {
		(void) snprintf(buf, bufsize, "UNKNOWN(%d)", state);
	}

	return (B_TRUE);
}
