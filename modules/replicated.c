/* ----------------------------------------------------------------------- *
 *
 *  repl_list.h - routines for replicated mount server selection
 *
 *   Copyright 2004 Jeff Moyer <jmoyer@redaht.com> - All Rights Reserved
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * A priority ordered list of hosts is created by using the following
 * selection rules.
 *
 *   1) Highest priority in selection is proximity.
 *      Proximity, in order of precedence is:
 *        - PROXIMITY_LOCAL, host corresponds to a local interface.
 *        - PROXIMITY_SUBNET, host is located in a subnet reachable
 *          through a local interface.
 *        - PROXIMITY_NETWORK, host is located in a network reachable
 *          through a local interface.
 *        - PROXIMITY_OTHER, host is on a network not directlty
 *          reachable through a local interface.
 *
 *   2) NFS version and protocol is selected by caclculating the largest
 *      number of hosts supporting an NFS version and protocol that
 *      have the closest proximity. These hosts are added to the list
 *      in response time order. Hosts may have a corresponding weight
 *      which essentially increaes response time and so influences the
 *      host order.
 *
 *   3) Hosts at further proximity that support the selected NFS version
 *      and protocol are also added to the list in response time order as
 *      in 2 above.
 *
 * ----------------------------------------------------------------------- */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>

#include "rpc_subs.h"
#include "replicated.h"
#include "automount.h"

#ifndef MAX_ERR_BUF
#define MAX_ERR_BUF		512
#endif
#define MAX_IFC_BUF		2048

#define MASK_A  0x7F000000
#define MASK_B  0xBFFF0000
#define MASK_C  0xDFFFFF00

/* Get numeric value of the n bits starting at position p */
#define getbits(x, p, n)	((x >> (p + 1 - n)) & ~(~0 << n))

#define max(x, y)	(x >= y ? x : y)
#define mmax(x, y, z)	(max(x, y) == x ? max(x, z) : max(y, z))

static unsigned int get_proximity(const char *host_addr, int addr_len)
{
	struct sockaddr_in *msk_addr, *if_addr;
	struct in_addr *hst_addr;
	char tmp[20], buf[MAX_ERR_BUF], *ptr;
	struct ifconf ifc;
	struct ifreq *ifr, nmptr;
	int sock, ret, i;
	uint32_t mask, ha, ia;

	memcpy(tmp, host_addr, addr_len);
	hst_addr = (struct in_addr *) tmp;

	ha = ntohl((uint32_t) hst_addr->s_addr);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(LOGOPT_ANY, "socket creation failed: %s", estr);
		return PROXIMITY_ERROR;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_req = (struct ifreq *) buf;
	ret = ioctl(sock, SIOCGIFCONF, &ifc);
	if (ret == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(LOGOPT_ANY, "ioctl: %s", estr);
		close(sock);
		return PROXIMITY_ERROR;
	}

	/* For each interface */

	/* Is the address a local interface */
	i = 0;
	ptr = (char *) &ifc.ifc_buf[0];

	while (ptr < buf + ifc.ifc_len) {
		ifr = (struct ifreq *) ptr;

		switch (ifr->ifr_addr.sa_family) {
		case AF_INET:
			if_addr = (struct sockaddr_in *) &ifr->ifr_addr;
			ret = memcmp(&if_addr->sin_addr, hst_addr, addr_len);
			if (!ret) {
				close(sock);
				return PROXIMITY_LOCAL;
			}
			break;

		default:
			break;
		}

		i++;
		ptr = (char *) &ifc.ifc_req[i];
	}

	i = 0;
	ptr = (char *) &ifc.ifc_buf[0];

	while (ptr < buf + ifc.ifc_len) {
		ifr = (struct ifreq *) ptr;

		switch (ifr->ifr_addr.sa_family) {
		case AF_INET:
			if_addr = (struct sockaddr_in *) &ifr->ifr_addr;
			ia =  ntohl((uint32_t) if_addr->sin_addr.s_addr);

			/* Is the address within a localiy attached subnet */

			nmptr = *ifr;
			ret = ioctl(sock, SIOCGIFNETMASK, &nmptr);
			if (ret == -1) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(LOGOPT_ANY, "ioctl: %s", estr);
				close(sock);
				return PROXIMITY_ERROR;
			}

			msk_addr = (struct sockaddr_in *) &nmptr.ifr_netmask;
			mask = ntohl((uint32_t) msk_addr->sin_addr.s_addr);

			if ((ia & mask) == (ha & mask)) {
				close(sock);
				return PROXIMITY_SUBNET;
			}

			/*
			 * Is the address within a local ipv4 network.
			 *
			 * Bit position 31 == 0 => class A.
			 * Bit position 30 == 0 => class B.
			 * Bit position 29 == 0 => class C.
			 */

			if (!getbits(ia, 31, 1))
				mask = MASK_A;
			else if (!getbits(ia, 30, 1))
				mask = MASK_B;
			else if (!getbits(ia, 29, 1))
				mask = MASK_C;
			else
				break;

			if ((ia & mask) == (ha & mask)) {
				close(sock);
				return PROXIMITY_NET;
			}
			break;

		default:
			break;
		}

		i++;
		ptr = (char *) &ifc.ifc_req[i];
	}

	close(sock);

	return PROXIMITY_OTHER;
}

static struct host *new_host(const char *name, const char *addr, unsigned int proximity, unsigned int weight)
{
	struct host *new;
	char *tmp1, *tmp2;

	if (!name || !addr)
		return NULL;

	tmp1 = strdup(name);
	if (!tmp1)
		return NULL;

	tmp2 = strdup(addr);
	if (!tmp2) {
		free(tmp1);
		return NULL;
	}

	new = malloc(sizeof(struct host));
	if (!new) {
		free(tmp1);
		free(tmp2);
		return NULL;
	}

	memset(new, 0, sizeof(struct host));

	new->name = tmp1;
	new->addr = tmp2;
	new->proximity = proximity;
	new->weight = weight;

	return new;
}

static int add_host(struct host **list, struct host *host)
{
	struct host *this, *last;

	if (!list) {
		*list = host;
		return 1;
	}

	this = *list;
	last = this;
	while (this) {
		if (this->proximity >= host->proximity)
			break;
		last = this;
		this = this->next;
	}

	if (host->cost) {
		while (this) {
			if (this->proximity != host->proximity)
				break;
			if (this->cost >= host->cost)
				break;
			last = this;
			this = this->next;
		}
	}

	if (last == this) {
		host->next = last;
		*list = host;
		return 1;
	}

	last->next = host;
	host->next = this;

	return 1;
}

static void free_host(struct host *host)
{
	free(host->name);
	free(host->addr);
	free(host->path);
	free(host);
}

static void remove_host(struct host **hosts, struct host *host)
{
	struct host *last, *this;

	if (host == *hosts) {
		*hosts = (*hosts)->next;
		host->next = NULL;
		return;
	}

	this = *hosts;
	last = NULL;
	while (this) {
		if (this == host)
			break;
		last = this;
		this = this->next;
	}

	if (!last || !this)
		return;

	last->next = this->next;
	host->next = NULL;

	return;
}

static void delete_host(struct host **hosts, struct host *host)
{
	remove_host(hosts, host);
	free_host(host);
	return;
}

void free_host_list(struct host **list)
{
	struct host *this;

	this = *list;
	while (this) {
		struct host *next = this->next;
		free_host(this);
		this = next;
	}
	*list = NULL;
}

static unsigned int get_nfs_info(struct host *host,
			 struct conn_info *pm_info, struct conn_info *rpc_info,
			 const char *proto, unsigned int version)
{
	struct pmap parms;
	struct timeval start, end;
	struct timezone tz;
	unsigned int supported = 0;
	double taken = 0;
	int status, count = 0;

	memset(&parms, 0, sizeof(struct pmap));

	parms.pm_prog = NFS_PROGRAM;

	/* Try to prode UDP first to conserve socket space */
	rpc_info->proto = getprotobyname(proto);
	if (!rpc_info->proto)
		return 0;

	status = rpc_portmap_getclient(pm_info,
				 host->name, proto, RPC_CLOSE_DEFAULT);
	if (!status)
		return 0;

	parms.pm_prot = rpc_info->proto->p_proto;
#if 0
	if (!(version & NFS4_REQUESTED))
		goto v3_ver;

	parms.pm_vers = NFS4_VERSION;
	rpc_info->port = rpc_portmap_getport(pm_info, &parms);
	if (rpc_info->port) {
		status = rpc_udp_getclient(rpc_info, NFS_PROGRAM, NFS4_VERSION);
		if (status) {
			gettimeofday(&start, &tz);
			status = rpc_ping_proto(rpc_info);
			gettimeofday(&end, &tz);
			if (status) {
				taken += elapsed(start, end);
				count++;
				supported = NFS4_SUPPORTED;
			}
		}
	}

v3_ver:
#endif
	if (!(version & NFS3_REQUESTED))
		goto v2_ver;

	parms.pm_vers = NFS3_VERSION;
	rpc_info->port = rpc_portmap_getport(pm_info, &parms);
	if (rpc_info->port) {
		status = rpc_udp_getclient(rpc_info, NFS_PROGRAM, NFS3_VERSION);
		if (status) {
			gettimeofday(&start, &tz);
			status = rpc_ping_proto(rpc_info);
			gettimeofday(&end, &tz);
			if (status) {
				taken += elapsed(start, end);
				count++;
				supported |= NFS3_SUPPORTED;
			}
		}
	}

v2_ver:
	if (!(version & NFS2_REQUESTED))
		goto done_ver;

	parms.pm_vers = NFS2_VERSION;
	rpc_info->port = rpc_portmap_getport(pm_info, &parms);
	if (rpc_info->port) {
		status = rpc_udp_getclient(rpc_info, NFS_PROGRAM, NFS2_VERSION);
		if (status) {
			gettimeofday(&start, &tz);
			status = rpc_ping_proto(rpc_info);
			gettimeofday(&end, &tz);
			if (status) {
				taken += elapsed(start, end);
				count++;
				supported |= NFS2_SUPPORTED;
			}
		}
	}

done_ver:
	if (rpc_info->proto->p_proto == IPPROTO_UDP) {
		rpc_destroy_udp_client(rpc_info);
		rpc_destroy_udp_client(pm_info);
	} else {
		rpc_destroy_tcp_client(rpc_info);
		rpc_destroy_tcp_client(pm_info);
	}

	if (count) {
		/*
		 * Average response time to 7 significant places as
		 * integral type.
		 */
		host->cost = (unsigned long) ((taken * 1000000) / count);

		/* Allow for user bias */
		if (host->weight)
			host->cost *= (host->weight + 1);
	}

	return supported;
}

static int get_vers_and_cost(struct host *host, unsigned int version)
{
	struct conn_info pm_info, rpc_info;
	time_t timeout = RPC_TIMEOUT;
	unsigned int supported, vers = NFS_VERS_MASK;
	int ret = 0;

	memset(&pm_info, 0, sizeof(struct conn_info));
	memset(&rpc_info, 0, sizeof(struct conn_info));

	if (host->proximity == PROXIMITY_NET)
		timeout = RPC_TIMEOUT * 2;
	else if (host->proximity == PROXIMITY_NET)
		timeout = RPC_TIMEOUT * 8;

	rpc_info.host = host->name;
	rpc_info.program = NFS_PROGRAM;
	rpc_info.timeout.tv_sec = timeout;
	rpc_info.close_option = RPC_CLOSE_DEFAULT;
	rpc_info.client = NULL;

	vers &= version;

	if (version & UDP_REQUESTED) {
		supported = get_nfs_info(host, &pm_info, &rpc_info, "udp", vers);
		if (supported) {
			ret = 1;
			host->version |= (supported << 8);
		}
	}

	if (version & TCP_REQUESTED) {
		supported = get_nfs_info(host, &pm_info, &rpc_info, "tcp", vers);
		if (supported) {
			ret = 1;
			host->version |= supported;
		}
	}

	return ret;
}

static int get_supported_ver_and_cost(struct host *host, unsigned int version)
{
	struct conn_info pm_info, rpc_info;
	struct pmap parms;
	const char *proto;
	unsigned int vers;
	struct timeval start, end;
	struct timezone tz;
	double taken = 0;
	time_t timeout = RPC_TIMEOUT;
	int status;

	memset(&pm_info, 0, sizeof(struct conn_info));
	memset(&rpc_info, 0, sizeof(struct conn_info));
	memset(&parms, 0, sizeof(struct pmap));

	if (host->proximity == PROXIMITY_NET)
		timeout = RPC_TIMEOUT * 2;
	else if (host->proximity == PROXIMITY_NET)
		timeout = RPC_TIMEOUT * 8;

	rpc_info.host = host->name;
	rpc_info.program = NFS_PROGRAM;
	rpc_info.timeout.tv_sec = timeout;
	rpc_info.close_option = RPC_CLOSE_DEFAULT;
	rpc_info.client = NULL;

	parms.pm_prog = NFS_PROGRAM;

	if (version & UDP_SELECTED_MASK) {
		proto = "udp";
		vers = (version << 8);
	} else {
		proto = "tcp";
		vers = version;
	}

	rpc_info.proto = getprotobyname(proto);
	if (!rpc_info.proto)
		return 0;

	status = rpc_portmap_getclient(&pm_info,
				 host->name, proto, RPC_CLOSE_DEFAULT);
	if (!status)
		return 0;

	parms.pm_prot = rpc_info.proto->p_proto;

	status = 0;
	parms.pm_vers = vers;
	rpc_info.port = rpc_portmap_getport(&pm_info, &parms);
	if (rpc_info.port) {
		status = rpc_udp_getclient(&rpc_info, NFS_PROGRAM, parms.pm_vers);
		if (status) {
			gettimeofday(&start, &tz);
			status = rpc_ping_proto(&rpc_info);
			gettimeofday(&end, &tz);
			if (status)
				taken = elapsed(start, end);
		}
	}

	if (rpc_info.proto->p_proto == IPPROTO_UDP) {
		rpc_destroy_udp_client(&rpc_info);
		rpc_destroy_udp_client(&pm_info);
	} else {
		rpc_destroy_tcp_client(&rpc_info);
		rpc_destroy_tcp_client(&pm_info);
	}

	if (status) {
		/* Response time to 7 significant places as integral type. */
		host->cost = (unsigned long) (taken * 1000000);

		/* Allow for user bias */
		if (host->weight)
			host->cost *= (host->weight + 1);

		return 1;
	}

	return 0;
}

int prune_host_list(struct host **list, unsigned int vers)
{
	struct host *this, *last, *first;
	struct host *new = NULL;
	unsigned int proximity, selected_version = 0;
	unsigned int v2_tcp_count, v3_tcp_count, v4_tcp_count;
	unsigned int v2_udp_count, v3_udp_count, v4_udp_count;
	unsigned int max_udp_count, max_tcp_count, max_count;
	int status;

	if (!*list)
		return 0;

	/* Use closest hosts to choose NFS version */

	first = *list;
	this = first;
	proximity = this->proximity;

	while (this && this->proximity == proximity) {
		struct host *next = this->next;

		if (this->name) {
			status = get_vers_and_cost(this, vers);
			if (!status) {
				if (this == first) {
					first = next;
					if (next)
						proximity = next->proximity;
				}
				delete_host(list, this);
			}
		}
		this = next;
	}

	last = this;

	if (!first)
		return 0;

	/* Select NFS version of highest number of closest servers */

	v4_tcp_count = v3_tcp_count = v2_tcp_count = 0;
	v4_udp_count = v3_udp_count = v2_udp_count = 0;

	this = first;
	do {
		if (this->version & NFS4_TCP_SUPPORTED)
			v4_tcp_count++;

		if (this->version & NFS3_TCP_SUPPORTED)
			v3_tcp_count++;

		if (this->version & NFS2_TCP_SUPPORTED)
			v2_tcp_count++;

		if (this->version & NFS4_UDP_SUPPORTED)
			v4_udp_count++;

		if (this->version & NFS3_UDP_SUPPORTED)
			v3_udp_count++;

		if (this->version & NFS2_UDP_SUPPORTED)
			v2_udp_count++;

		this = this->next; 
	} while (this && this != last);

	max_tcp_count = mmax(v4_tcp_count, v3_tcp_count, v2_tcp_count);
	max_udp_count = mmax(v4_udp_count, v3_udp_count, v2_udp_count);
	max_count = max(max_tcp_count, max_udp_count);

	if (max_count == v4_tcp_count)
		selected_version = NFS4_TCP_SUPPORTED;
	else if (max_count == v3_tcp_count)
		selected_version = NFS3_TCP_SUPPORTED;
	else if (max_count == v2_tcp_count)
		selected_version = NFS2_TCP_SUPPORTED;
	else if (max_count == v4_udp_count)
		selected_version = NFS4_UDP_SUPPORTED;
	else if (max_count == v3_udp_count)
		selected_version = NFS3_UDP_SUPPORTED;
	else if (max_count == v2_udp_count)
		selected_version = NFS2_UDP_SUPPORTED;

	if (!selected_version)
		return 0;

	/* Add hosts with selected version to new list */

	this = first;
	do {
		struct host *next = this->next;
		if (this->version & selected_version) {
			this->version = selected_version;
			remove_host(list, this);
			add_host(&new, this);
		}
		this = next;
	} while (this && this != last);

	/*
	 * Now go through rest of list and check for chosen version
	 * and add to new list if supported.
	 */ 

	first = last;
	this = first;
	while (this) {
		struct host *next = this->next;
		if (!this->name)
			add_host(&new, this);
		else {
			status = get_supported_ver_and_cost(this, selected_version);
			if (status) {
				this->version = selected_version;
				remove_host(list, this);
				add_host(&new, this);
			}
		}
		this = next;
	}

	free_host_list(list);
	*list = new;

	return 1;
}

static int add_host_addrs(struct host **list, const char *host, unsigned int weight)
{
	struct hostent he;
	struct hostent *phe = &he;
	struct hostent *result;
	struct sockaddr_in saddr;
	char buf[MAX_IFC_BUF], **haddr;
	int ghn_errno, ret;
	struct host *new;
	unsigned int prx;

	saddr.sin_family = AF_INET;
	if (inet_aton(host, &saddr.sin_addr)) {
		const char *thost = (const char *) &saddr.sin_addr;

		prx = get_proximity(thost, sizeof(saddr.sin_addr));
		if (prx == PROXIMITY_ERROR)
			return 0;

		if (!(new = new_host(host, thost, prx, weight)))
			return 0;

		if (!add_host(list, new))
			free_host(new);

		return 1;
	}

	memset(buf, 0, MAX_IFC_BUF);
	memset(&he, 0, sizeof(struct hostent));

	ret = gethostbyname_r(host, phe,
			buf, MAX_IFC_BUF, &result, &ghn_errno);
	if (ret || !result) {
		if (ghn_errno == -1)
			error(LOGOPT_ANY,
			      "host %s: lookup failure %d", host, errno);
		else
			error(LOGOPT_ANY,
			      "host %s: lookup failure %d", host, ghn_errno);
		return 0;
	}

	for (haddr = phe->h_addr_list; *haddr; haddr++) {
		prx = get_proximity(*haddr, phe->h_length);
		if (prx == PROXIMITY_ERROR)
			return 0;

		if (!(new = new_host(host, *haddr, prx, weight)))
			return 0;

		if (!add_host(list, new)) {
			free_host(new);
			continue;
		}
	}

	return 1;
}

static int add_path(struct host *hosts, const char *path, int len)
{
	struct host *this;
	char *tmp, *tmp2;

	tmp = alloca(len + 1);
	if (!tmp)
		return 0;

	strncpy(tmp, path, len);
	tmp[len] = '\0';

	this = hosts;
	while (this) {
		if (!this->path) {
			tmp2 = strdup(tmp);
			if (!tmp2)
				return 0;
			this->path = tmp2;
		}
		this = this->next;
	}

	return 1;
}

static int add_local_path(struct host **hosts, const char *path)
{
	struct host *new;
	char *tmp;

	tmp = strdup(path);
	if (!tmp)
		return 0;

	new = malloc(sizeof(struct host));
	if (!new) {
		free(tmp);
		return 0;
	}

	memset(new, 0, sizeof(struct host));

	new->path = tmp;
	new->proximity = PROXIMITY_LOCAL;
	new->version = NFS_VERS_MASK;
	new->name = new->addr = NULL;
	new->weight = new->cost = 0;

	add_host(hosts, new);

	return 1;
}

int parse_location(struct host **hosts, const char *list)
{
	char *str, *p, *delim;
	unsigned int empty = 1;

	if (!list)
		return 0;

	str = strdup(list);
	if (!str)
		return 0;

	p = str;

	while (p && *p) {
		char *next = NULL;
		int weight = 0;

		p += strspn(p, " \t,");
		delim = strpbrk(p, "(, \t:");

		if (delim) {
			if (*delim == '(') {
				char *w = delim + 1;

				*delim = '\0';

				delim = strchr(w, ')');
				if (delim) {
					*delim = '\0';
					weight = atoi(w);
				}
				delim++;
			}

			if (*delim == ':') {
				char *path;

				*delim = '\0';
				path = delim + 1;

				/* Oh boy - might have spaces in the path */
				next = path;
				while (*next && *next != ':')
					next++;

				/* No spaces in host names at least */
				if (*next == ':') {
					while (*next &&
					      (*next != ' ' && *next != '\t'))
						next--;
					*next++ = '\0';
				}

				if (p != delim) {
					if (!add_host_addrs(hosts, p, weight)) {
						if (empty) {
							p = next;
							continue;
						}
					}

					if (!add_path(*hosts, path, strlen(path))) {
						free_host_list(hosts);
						free(str);
						return 0;
					}
				} else {
					if (!add_local_path(hosts, path)) {
						p = next;
						continue;
					}
				}
			} else if (*delim != '\0') {
				*delim = '\0';
				next = delim + 1;

				if (!add_host_addrs(hosts, p, weight)) {
					p = next;
					continue;
				}

				empty = 0;
			}
		} else {
			/* syntax error - no mount path */
			free_host_list(hosts);
			free(str);
			return 0;
		}

		p = next;
	}

	free(str);
	return 1;
}

void dump_host_list(struct host *hosts)
{
	struct host *this;

	if (!hosts)
		return;

	this = hosts;
	while (this) {
		debug(LOGOPT_ANY,
		      "name %s path %s version %x proximity %u weight %u cost %u",
		      this->name, this->path, this->version,
		      this->proximity, this->weight, this->cost);
		this = this->next;
	}
	return;
}

