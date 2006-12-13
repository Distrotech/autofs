/* ----------------------------------------------------------------------- *
 *   
 *  rpc_subs.c - routines for rpc discovery
 *
 *   Copyright 2004 Ian Kent <raven@themaw.net> - All Rights Reserved
 *   Copyright 2004 Jeff Moyer <jmoyer@redaht.com> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <rpc/types.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <rpcsvc/ypclnt.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "mount.h"
#include "rpc_subs.h"

/* #define STANDALONE */
#ifdef STANDALONE
#define error(logopt, msg, args...)	fprintf(stderr, msg "\n", ##args)
#else
#include "log.h"
#endif

#define MAX_ERR_BUF	512

static char *ypdomain = NULL;

/*
 * Create a UDP RPC client
 */
static CLIENT *create_udp_client(struct conn_info *info)
{
	int fd, cl_flags, ret, ghn_errno;
	CLIENT *client;
	struct sockaddr_in laddr, raddr;
	struct hostent hp;
	struct hostent *php = &hp;
	struct hostent *result;
	char buf[HOST_ENT_BUF_SIZE];
	size_t len;

	if (info->proto->p_proto != IPPROTO_UDP)
		return NULL;

	if (info->client) {
		if (!clnt_control(info->client, CLGET_FD, (char *) &fd)) {
			fd = -1;
			clnt_destroy(info->client);
			info->client = NULL;
		} else {
			clnt_control(info->client, CLSET_FD_NCLOSE, NULL);
			clnt_destroy(info->client);
		}
	}

	memset(&laddr, 0, sizeof(laddr));
	memset(&raddr, 0, sizeof(raddr));

	raddr.sin_family = AF_INET;
	if (inet_aton(info->host, &raddr.sin_addr))
		goto got_addr;

	memset(&hp, 0, sizeof(struct hostent));

	ret = gethostbyname_r(info->host, php,
			buf, HOST_ENT_BUF_SIZE, &result, &ghn_errno);
	if (ret || !result) {
		int err = ghn_errno == -1 ? errno : ghn_errno;
		char *estr = strerror_r(err, buf, HOST_ENT_BUF_SIZE);
		error(LOGOPT_ANY, "hostname lookup failed: %s", estr);
		goto out_close;
	}
	memcpy(&raddr.sin_addr.s_addr, php->h_addr, php->h_length);

got_addr:
	raddr.sin_port = htons(info->port);

	if (!info->client) {
		/*
		 * bind to any unused port.  If we left this up to the rpc
		 * layer, it would bind to a reserved port, which has been shown
		 * to exhaust the reserved port range in some situations.
		 */
		fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0)
			return NULL;

		if ((cl_flags = fcntl(fd, F_GETFD, 0)) != -1) {
			cl_flags |= FD_CLOEXEC;
			fcntl(fd, F_SETFD, cl_flags);
		}

		laddr.sin_family = AF_INET;
		laddr.sin_port = 0;
		laddr.sin_addr.s_addr = htonl(INADDR_ANY);

		len = sizeof(struct sockaddr_in);
		if (bind(fd, (struct sockaddr *)&laddr, len) < 0) {
			close(fd);
			fd = RPC_ANYSOCK;
			/* FALLTHROUGH */
		}
	}

	client = clntudp_bufcreate(&raddr,
				   info->program, info->version,
				   info->timeout, &fd,
				   info->send_sz, info->recv_sz);

	if (!client) {
		info->client = NULL;
		goto out_close;
	}

	/* Close socket fd on destroy, as is default for rpcowned fds */
	if  (!clnt_control(client, CLSET_FD_CLOSE, NULL)) {
		clnt_destroy(client);
		info->client = NULL;
		goto out_close;
	}

	return client;

out_close:
	if (fd != -1)
		close(fd);
	return NULL;
}

int rpc_udp_getclient(struct conn_info *info,
		      unsigned int program, unsigned int version)
{
	struct protoent *pe_proto;
	CLIENT *client;

	if (!info->client) {
		pe_proto = getprotobyname("udp");
		if (!pe_proto)
			return 0;

		info->proto = pe_proto;
		info->send_sz = UDPMSGSIZE;
		info->recv_sz = UDPMSGSIZE;
	}

	info->program = program;
	info->version = version;

	client = create_udp_client(info);

	if (!client)
		return 0;

	info->client = client;

	return 1;
}

void rpc_destroy_udp_client(struct conn_info *info)
{
	if (!info->client)
		return;

	clnt_destroy(info->client);
	info->client = NULL;
	return;
}

/*
 *  Perform a non-blocking connect on the socket fd.
 *
 *  tout contains the timeout.  It will be modified to contain the time
 *  remaining (i.e. time provided - time elasped).
 */
static int connect_nb(int fd, struct sockaddr_in *addr, struct timeval *tout)
{
	int flags, ret;
	socklen_t len;
	fd_set wset, rset;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;

	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (ret < 0)
		return -1;

	/* 
	 * From here on subsequent sys calls could change errno so
	 * we set ret = -errno to capture it in case we decide to
	 * use it later.
	 */
	len = sizeof(struct sockaddr);
	ret = connect(fd, (struct sockaddr *)addr, len);
	if (ret < 0 && errno != EINPROGRESS) {
		ret = -errno;
		goto done;
	}

	if (ret == 0)
		goto done;

	/* now wait */
	FD_ZERO(&rset);
	FD_SET(fd, &rset);
	wset = rset;

	ret = select(fd + 1, &rset, &wset, NULL, tout);
	if (ret <= 0) {
		if (ret == 0)
			ret = -ETIMEDOUT;
		else
			ret = -errno;
		goto done;
	}

	if (FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
		int status;

		len = sizeof(ret);
		status = getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len);
		if (status < 0) {
			ret = -errno;
			goto done;
		}

		/* Oops - something wrong with connect */
		if (ret)
			ret = -ret;
	}

done:
	fcntl(fd, F_SETFL, flags);
	return ret;
}

/*
 * Create a TCP RPC client using non-blocking connect
 */
static CLIENT *create_tcp_client(struct conn_info *info)
{
	int fd, cl_flags, ghn_errno;
	CLIENT *client;
	struct sockaddr_in addr;
	struct hostent hp;
	struct hostent *php = &hp;
	struct hostent *result;
	char buf[HOST_ENT_BUF_SIZE];
	int ret;

	if (info->proto->p_proto != IPPROTO_TCP)
		return NULL;

	if (info->client) {
		if (!clnt_control(info->client, CLGET_FD, (char *) &fd)) {
			fd = -1;
			clnt_destroy(info->client);
			info->client = NULL;
		} else {
			clnt_control(info->client, CLSET_FD_NCLOSE, NULL);
			clnt_destroy(info->client);
		}
	}

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	if (inet_aton(info->host, &addr.sin_addr))
		goto got_addr;

	memset(&hp, 0, sizeof(struct hostent));

	ret = gethostbyname_r(info->host, php,
			buf, HOST_ENT_BUF_SIZE, &result, &ghn_errno);
	if (ret || !result) {
		int err = ghn_errno == -1 ? errno : ghn_errno;
		char *estr =  strerror_r(err, buf, HOST_ENT_BUF_SIZE);
		error(LOGOPT_ANY, "hostname lookup failed: %s", estr);
		goto out_close;
	}
	memcpy(&addr.sin_addr.s_addr, php->h_addr, php->h_length);

got_addr:
	addr.sin_port = htons(info->port);

	if (!info->client) {
		fd = socket(PF_INET, SOCK_STREAM, info->proto->p_proto);
		if (fd < 0)
			return NULL;

		if ((cl_flags = fcntl(fd, F_GETFD, 0)) != -1) {
			cl_flags |= FD_CLOEXEC;
			fcntl(fd, F_SETFD, cl_flags);
		}

		ret = connect_nb(fd, &addr, &info->timeout);
		if (ret < 0)
			goto out_close;
	}

	client = clnttcp_create(&addr,
				info->program, info->version, &fd,
				info->send_sz, info->recv_sz);

	if (!client) {
		info->client = NULL;
		goto out_close;
	}

	/* Close socket fd on destroy, as is default for rpcowned fds */
	if  (!clnt_control(client, CLSET_FD_CLOSE, NULL)) {
		clnt_destroy(client);
		info->client = NULL;
		goto out_close;
	}

	return client;

out_close:
	if (fd != -1)
		close(fd);
	return NULL;
}

int rpc_tcp_getclient(struct conn_info *info,
		      unsigned int program, unsigned int version)
{
	struct protoent *pe_proto;
	CLIENT *client;

	if (!info->client) {
		pe_proto = getprotobyname("tcp");
		if (!pe_proto)
			return 0;

		info->proto = pe_proto;
		info->send_sz = 0;
		info->recv_sz = 0;
	}

	info->program = program;
	info->version = version;

	client = create_tcp_client(info);

	if (!client)
		return 0;

	info->client = client;

	return 1;
}

void rpc_destroy_tcp_client(struct conn_info *info)
{
	struct linger lin = { 1, 0 };
	socklen_t lin_len = sizeof(struct linger);
	int fd;

	if (!info->client)
		return;

	if (!clnt_control(info->client, CLGET_FD, (char *) &fd))
		fd = -1;

	switch (info->close_option) {
	case RPC_CLOSE_NOLINGER:
		if (fd >= 0)
			setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
		break;
	}

	clnt_destroy(info->client);
	info->client = NULL;

	return;
}

int rpc_portmap_getclient(struct conn_info *info,
			  const char *host, const char *proto,
			  unsigned int option)
{
	struct protoent *pe_proto;
	CLIENT *client;

	pe_proto = getprotobyname(proto);
	if (!pe_proto)
		return 0;

	info->host = host;
	info->program = PMAPPROG;
	info->port = PMAPPORT;
	info->version = PMAPVERS;
	info->proto = pe_proto;
	info->send_sz = RPCSMALLMSGSIZE;
	info->recv_sz = RPCSMALLMSGSIZE;
	info->timeout.tv_sec = PMAP_TOUT_UDP;
	info->timeout.tv_usec = 0;
	info->close_option = option;
	info->client = NULL;

	if (pe_proto->p_proto == IPPROTO_TCP) {
		info->timeout.tv_sec = PMAP_TOUT_TCP;
		client = create_tcp_client(info);
	} else
		client = create_udp_client(info);

	if (!client)
		return 0;

	info->client = client;

	return 1;
}

unsigned short rpc_portmap_getport(struct conn_info *info, struct pmap *parms)
{
	struct conn_info pmap_info;
	unsigned short port = 0;
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto->p_proto;

	memset(&pmap_info, 0, sizeof(struct conn_info));

	if (proto == IPPROTO_TCP)
		pmap_info.timeout.tv_sec = PMAP_TOUT_TCP;
	else
		pmap_info.timeout.tv_sec = PMAP_TOUT_UDP;

	if (info->client)
		client = info->client;
	else {
		pmap_info.host = info->host;
		pmap_info.port = PMAPPORT;
		pmap_info.program = PMAPPROG;
		pmap_info.version = PMAPVERS;
		pmap_info.proto = info->proto;
		pmap_info.send_sz = RPCSMALLMSGSIZE;
		pmap_info.recv_sz = RPCSMALLMSGSIZE;

		if (proto == IPPROTO_TCP)
			client = create_tcp_client(&pmap_info);
		else
			client = create_udp_client(&pmap_info);

		if (!client)
			return 0;
	}

	/*
	 * Check to see if server is up otherwise a getport will take
	 * forever to timeout.
	 */
	status = clnt_call(client, PMAPPROC_NULL,
			 (xdrproc_t) xdr_void, 0, (xdrproc_t) xdr_void, 0,
			 pmap_info.timeout);

	if (status == RPC_SUCCESS) {
		status = clnt_call(client, PMAPPROC_GETPORT,
				 (xdrproc_t) xdr_pmap, (caddr_t) parms,
				 (xdrproc_t) xdr_u_short, (caddr_t) &port,
				 pmap_info.timeout);
	}

	if (!info->client) {
		/*
		 * Only play with the close options if we think it
		 * completed OK
		 */
		if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
			struct linger lin = { 1, 0 };
			socklen_t lin_len = sizeof(struct linger);
			int fd;

			if (!clnt_control(client, CLGET_FD, (char *) &fd))
				fd = -1;

			switch (info->close_option) {
			case RPC_CLOSE_NOLINGER:
				if (fd >= 0)
					setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
				break;
			}
		}
		clnt_destroy(client);
	}

	if (status != RPC_SUCCESS)
		return 0;

	return port;
}

int rpc_ping_proto(struct conn_info *info)
{
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto->p_proto;

	if (info->client)
		client = info->client;
	else {
		if (info->proto->p_proto == IPPROTO_UDP) {
			info->send_sz = UDPMSGSIZE;
			info->recv_sz = UDPMSGSIZE;
			client = create_udp_client(info);
		} else
			client = create_tcp_client(info);

		if (!client)
			return 0;
	}

	clnt_control(client, CLSET_TIMEOUT, (char *) &info->timeout);
	clnt_control(client, CLSET_RETRY_TIMEOUT, (char *) &info->timeout);

	status = clnt_call(client, NFSPROC_NULL,
			 (xdrproc_t) xdr_void, 0, (xdrproc_t) xdr_void, 0,
			 info->timeout);

	if (!info->client) {
		/*
		 * Only play with the close options if we think it
		 * completed OK
		 */
		if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
			struct linger lin = { 1, 0 };
			socklen_t lin_len = sizeof(struct linger);
			int fd;

			if (!clnt_control(client, CLGET_FD, (char *) &fd))
				fd = -1;

			switch (info->close_option) {
			case RPC_CLOSE_NOLINGER:
				if (fd >= 0)
					setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
				break;
			}
		}
		clnt_destroy(client);
	}

	if (status != RPC_SUCCESS)
		return 0;

	return 1;
}

static unsigned int __rpc_ping(const char *host,
				unsigned long version,
				char *proto,
				long seconds, long micros,
				unsigned int option)
{
	unsigned int status;
	struct conn_info info;
	struct pmap parms;

	info.host = host;
	info.program = NFS_PROGRAM;
	info.version = version;
	info.send_sz = 0;
	info.recv_sz = 0;
	info.timeout.tv_sec = seconds;
	info.timeout.tv_usec = micros;
	info.close_option = option;
	info.client = NULL;

	status = RPC_PING_FAIL;

	info.proto = getprotobyname(proto);
	if (!info.proto)
		return status;

	parms.pm_prog = NFS_PROGRAM;
	parms.pm_vers = version;
	parms.pm_prot = info.proto->p_proto;
	parms.pm_port = 0;

	info.port = rpc_portmap_getport(&info, &parms);
	if (!info.port)
		return status;

	status = rpc_ping_proto(&info);

	return status;
}

int rpc_ping(const char *host, long seconds, long micros, unsigned int option)
{
	unsigned long vers3 = NFS3_VERSION;
	unsigned long vers2 = NFS2_VERSION;
	unsigned int status;

	status = __rpc_ping(host, vers2, "udp", seconds, micros, option);
	if (status)
		return RPC_PING_V2 | RPC_PING_UDP;

	status = __rpc_ping(host, vers3, "udp", seconds, micros, option);
	if (status)
		return RPC_PING_V3 | RPC_PING_UDP;

	status = __rpc_ping(host, vers2, "tcp", seconds, micros, option);
	if (status)
		return RPC_PING_V2 | RPC_PING_TCP;

	status = __rpc_ping(host, vers3, "tcp", seconds, micros, option);
	if (status)
		return RPC_PING_V3 | RPC_PING_TCP;

	return status;
}

double elapsed(struct timeval start, struct timeval end)
{
	double t1, t2;
	t1 =  (double)start.tv_sec + (double)start.tv_usec/(1000*1000);
	t2 =  (double)end.tv_sec + (double)end.tv_usec/(1000*1000);
	return t2-t1;
}

int rpc_time(const char *host,
	     unsigned int ping_vers, unsigned int ping_proto,
	     long seconds, long micros, unsigned int option, double *result)
{
	int status;
	double taken;
	struct timeval start, end;
	struct timezone tz;
	char *proto = (ping_proto & RPC_PING_UDP) ? "udp" : "tcp";
	unsigned long vers = ping_vers;

	gettimeofday(&start, &tz);
	status = __rpc_ping(host, vers, proto, seconds, micros, option);
	gettimeofday(&end, &tz);

	if (!status) {
		return 0;
	}

	taken = elapsed(start, end);

	if (result != NULL)
		*result = taken;

	return status;
}

static int rpc_get_exports_proto(struct conn_info *info, exports *exp)
{
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto->p_proto;
	unsigned int option = info->close_option;

	if (info->proto->p_proto == IPPROTO_UDP) {
		info->send_sz = UDPMSGSIZE;
		info->recv_sz = UDPMSGSIZE;
		client = create_udp_client(info);
	} else
		client = create_tcp_client(info);

	if (!client)
		return 0;

	clnt_control(client, CLSET_TIMEOUT, (char *) &info->timeout);
	clnt_control(client, CLSET_RETRY_TIMEOUT, (char *) &info->timeout);

	client->cl_auth = authunix_create_default();

	status = clnt_call(client, MOUNTPROC_EXPORT,
			 (xdrproc_t) xdr_void, NULL,
			 (xdrproc_t) xdr_exports, (caddr_t) exp,
			 info->timeout);

	/* Only play with the close options if we think it completed OK */
	if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
		struct linger lin = { 1, 0 };
		socklen_t lin_len = sizeof(struct linger);
		int fd;

		if (!clnt_control(client, CLGET_FD, (char *) &fd))
			fd = -1;

		switch (option) {
		case RPC_CLOSE_NOLINGER:
			if (fd >= 0)
				setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
			break;
		}
	}
	auth_destroy(client->cl_auth);
	clnt_destroy(client);

	if (status != RPC_SUCCESS)
		return 0;

	return 1;
}

static void rpc_export_free(exports item)
{
	groups grp;
	groups tmp;

	if (item->ex_dir)
		free(item->ex_dir);

	grp = item->ex_groups;
	while (grp) {
		if (grp->gr_name)
			free(grp->gr_name);
		tmp = grp;
		grp = grp->gr_next;
		free(tmp);
	}
	free(item);
}

void rpc_exports_free(exports list)
{
	exports tmp;

	while (list) {
		tmp = list;
		list = list->ex_next;
		rpc_export_free(tmp);
	}
	return;
}

static int masked_match(const char *addr, const char *mask)
{
	char buf[MAX_ERR_BUF], *ptr;
	struct sockaddr_in saddr;
	struct sockaddr_in6 saddr6;
	struct ifconf ifc;
	struct ifreq *ifr;
	int sock, cl_flags, ret, i, is_ipv4, is_ipv6;
	unsigned int msize;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(LOGOPT_ANY, "socket creation failed: %s", estr);
		return 0;
	}

	if ((cl_flags = fcntl(sock, F_GETFD, 0)) != -1) {
		cl_flags |= FD_CLOEXEC;
		fcntl(sock, F_SETFD, cl_flags);
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_req = (struct ifreq *) buf;
	ret = ioctl(sock, SIOCGIFCONF, &ifc);
	if (ret == -1) {
		close(sock);
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(LOGOPT_ANY, "ioctl: %s", estr);
		return 0;
	}

	is_ipv4 = is_ipv6 = 0;
	is_ipv4 = inet_pton(AF_INET, addr, &saddr.sin_addr);
	if (!is_ipv4)
		is_ipv6 = inet_pton(AF_INET6, addr, &saddr6.sin6_addr);

	if (strchr(mask, '.')) {
		struct sockaddr_in maddr;
		uint32_t ma;
		int i = 0;

		ret = inet_aton(mask, &maddr.sin_addr);
		if (!ret) {
			close(sock);
			return 0;
		}

		ma = ntohl((uint32_t) maddr.sin_addr.s_addr);
		while (!(ma & 1)) {
			i++;
			ma = ma >> 1;
		}

		msize = i;
	} else
		msize = atoi(mask);

	i = 0;
	ptr = (char *) &ifc.ifc_buf[0];

	while (ptr < buf + ifc.ifc_len) {
		ifr = (struct ifreq *) ptr;

		switch (ifr->ifr_addr.sa_family) {
		case AF_INET:
		{
			struct sockaddr_in *if_addr;
			uint32_t m, ia, ha;

			if (!is_ipv4 || msize > 32)
				break;

			m = -1;
			m = m << (32 - msize);
			ha = ntohl((uint32_t) saddr.sin_addr.s_addr);

			if_addr = (struct sockaddr_in *) &ifr->ifr_addr;
			ia = ntohl((uint32_t) if_addr->sin_addr.s_addr);

			if ((ia & m) == (ha & m)) {
				close(sock);
				return 1;
			}
			break;
		}

		/* glibc rpc only understands IPv4 atm */
		case AF_INET6:
			break;

		default:
			break;
		}

		i++;
		ptr = (char *) &ifc.ifc_req[i];
	}

	close(sock);
	return 0;
}

/*
 * This function has been adapted from the match_patern function
 * found in OpenSSH and is used in accordance with the copyright
 * notice found their.
 *
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland.
 */
/*
 * Returns true if the given string matches the pattern (which
 * may contain ? and * as wildcards), and zero if it does not
 * match.
 */
static int pattern_match(const char *s, const char *pattern)
{
	for (;;) {
		/* If at end of pattern, accept if also at end of string. */
		if (!*pattern)
			return !*s;

		if (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			if (!*pattern)
				return 1;

			/* If next character in pattern is known, optimize. */
			if (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				for (; *s; s++)
					if (*s == *pattern &&
					    pattern_match(s + 1, pattern + 1))
						return 1;

				/* Failed. */
				return 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			for (; *s; s++)
				if (pattern_match(s, pattern))
					return 1;
			/* Failed. */
			return 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		if (!*s)
			return 0;

		/* Check if the next character of the string is acceptable. */
		if (*pattern != '?' && *pattern != *s)
			return 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

static int string_match(const char *myname, const char *pattern)
{
	struct addrinfo hints, *ni;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = 0;
	hints.ai_socktype = 0;

	ret = getaddrinfo(myname, NULL, &hints, &ni);
	if (ret) {
		error(LOGOPT_ANY, "name lookup failed: %s", gai_strerror(ret));
		return 0;
	}

	if (strchr(pattern, '*') || strchr(pattern, '?')) {
		ret = pattern_match(myname, pattern);
		if (!ret)
			ret = pattern_match(ni->ai_canonname, pattern);
	} else {
		/* Match simple nane or FQDN */
		ret = !memcmp(myname, pattern, strlen(pattern));
		if (!ret)
			ret = !memcmp(ni->ai_canonname, pattern, strlen(pattern));

		/* Name could still be a netgroup (Solaris) */
		if (!ret && ypdomain) {
			ret = innetgr(pattern, myname, NULL, ypdomain);
			if (!ret)
				ret = innetgr(pattern,
					 ni->ai_canonname, NULL, ypdomain);
		}

	}
	freeaddrinfo(ni);
	return ret;
}

static int host_match(char *pattern)
{
	unsigned int negate = (*pattern == '-');
	const char *m_pattern = (negate ? pattern + 1 : pattern);
	char myname[MAXHOSTNAMELEN + 1] = "\0";
	struct in_addr tmp;
	int ret = 0;

	if (gethostname(myname, MAXHOSTNAMELEN))
		return 0;

	if (yp_get_default_domain(&ypdomain))
		ypdomain = NULL;

	if (*m_pattern == '@') {
		if (ypdomain)
			ret = innetgr(m_pattern + 1, myname, NULL, ypdomain);
	} else if (inet_aton(m_pattern, &tmp) || strchr(m_pattern, '/')) {
		size_t len = strlen(m_pattern) + 1;
		char *addr, *mask;

		addr = alloca(len);
		if (!addr)
			return 0;

		memset(addr, 0, len);
		memcpy(addr, m_pattern, len - 1);
		mask = strchr(addr, '/');
		if (mask) {
			*mask++ = '\0';
			ret = masked_match(addr, mask);
		} else
			ret = masked_match(addr, "32");
	} else if (!strcmp(m_pattern, "gss/krb5")) {
		/* Leave this to the GSS layer */
		ret = 1;
	} else
		ret = string_match(myname, m_pattern);

	if (negate)
		ret = !ret;

	return ret;
}

static int rpc_export_allowed(groups grouplist)
{
	groups grp = grouplist;

	/* NULL group list => everyone */
	if (!grp)
		return 1;

	while (grp) {
		if (host_match(grp->gr_name))
			return 1;
		grp = grp->gr_next;
	}
	return 0;
}

exports rpc_exports_prune(exports list)
{
	exports head = list;
	exports exp;
	exports last;
	int res;

	exp = list;
	last = NULL;
	while (exp) {
		res = rpc_export_allowed(exp->ex_groups);
		if (!res) {
			if (last == NULL) {
				head = exp->ex_next;
				rpc_export_free(exp);
				exp = head;
			} else {
				last->ex_next = exp->ex_next;
				rpc_export_free(exp);
				exp = last->ex_next;
			}
			continue;
		}
		last = exp;
		exp = exp->ex_next;
	}
	return head;
}

exports rpc_get_exports(const char *host, long seconds, long micros, unsigned int option)
{
	struct conn_info info;
	exports exportlist;
	struct pmap parms;
	int status;

	info.host = host;
	info.program = MOUNTPROG;
	info.version = MOUNTVERS;
	info.send_sz = 0;
	info.recv_sz = 0;
	info.timeout.tv_sec = seconds;
	info.timeout.tv_usec = micros;
	info.close_option = option;
	info.client = NULL;

	parms.pm_prog = info.program;
	parms.pm_vers = info.version;
	parms.pm_port = 0;

	/* Try UDP first */
	info.proto = getprotobyname("udp");
	if (!info.proto)
		goto try_tcp;

	parms.pm_prot = info.proto->p_proto;

	info.port = rpc_portmap_getport(&info, &parms);
	if (!info.port)
		goto try_tcp;

	memset(&exportlist, '\0', sizeof(exportlist));

	status = rpc_get_exports_proto(&info, &exportlist);
	if (status)
		return exportlist;

try_tcp:
	info.proto = getprotobyname("tcp");
	if (!info.proto)
		return NULL;

	parms.pm_prot = info.proto->p_proto;

	info.port = rpc_portmap_getport(&info, &parms);
	if (!info.port)
		return NULL;

	memset(&exportlist, '\0', sizeof(exportlist));

	status = rpc_get_exports_proto(&info, &exportlist);
	if (!status)
		return NULL;

	return exportlist;
}

#if 0
#include <stdio.h>

int main(int argc, char **argv)
{
	int ret;
	double res = 0.0;
	exports exportlist, tmp;
	groups grouplist;
	int n, maxlen;

/*
	ret = rpc_ping("budgie", 10, 0, RPC_CLOSE_DEFAULT);
	printf("ret = %d\n", ret);

	res = 0.0;
	ret = rpc_time("budgie", NFS2_VERSION, RPC_PING_TCP, 10, 0, RPC_CLOSE_DEFAULT, &res);
	printf("v2 tcp ret = %d, res = %f\n", ret, res);

	res = 0.0;
	ret = rpc_time("budgie", NFS3_VERSION, RPC_PING_TCP, 10, 0, RPC_CLOSE_DEFAULT, &res);
	printf("v3 tcp ret = %d, res = %f\n", ret, res);

	res = 0.0;
	ret = rpc_time("budgie", NFS2_VERSION, RPC_PING_UDP, 10, 0, RPC_CLOSE_DEFAULT, &res);
	printf("v2 udp ret = %d, res = %f\n", ret, res);

	res = 0.0;
	ret = rpc_time("budgie", NFS3_VERSION, RPC_PING_UDP, 10, 0, RPC_CLOSE_DEFAULT, &res);
	printf("v3 udp ret = %d, res = %f\n", ret, res);
*/
	exportlist = rpc_get_exports("budgie", 10, 0, RPC_CLOSE_NOLINGER);
	exportlist = rpc_exports_prune(exportlist);

	maxlen = 0;
	for (tmp = exportlist; tmp; tmp = tmp->ex_next) {
		if ((n = strlen(tmp->ex_dir)) > maxlen)
			maxlen = n;
	}

	if (exportlist) {
		while (exportlist) {
			printf("%-*s ", maxlen, exportlist->ex_dir);
			grouplist = exportlist->ex_groups;
			if (grouplist) {
				while (grouplist) {
					printf("%s%s", grouplist->gr_name,
						grouplist->gr_next ? "," : "");
					grouplist = grouplist->gr_next;
				}
			}
			printf("\n");
			exportlist = exportlist->ex_next;
		}
	}
	rpc_exports_free(exportlist);

	exit(0);
}
#endif
