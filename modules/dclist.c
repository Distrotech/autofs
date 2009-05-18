/*
 * Copyright 2009 Ian Kent <raven@themaw.net>
 * Copyright 2009 Red Hat, Inc.
 *
 * This module was apapted from code contained in the Samba distribution
 * file source/libads/dns.c which contained the following copyright
 * information:
 *
 * Unix SMB/CIFS implementation.
 * DNS utility library
 * Copyright (C) Gerald (Jerry) Carter           2006.
 * Copyright (C) Jeremy Allison                  2007.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <ldap.h>
#include <sys/param.h>
#include <errno.h>

#include "automount.h"
#include "dclist.h"

#define	MAX_DNS_PACKET_SIZE	0xffff
#define	MAX_DNS_NAME_LENGTH	MAXHOSTNAMELEN
/* The longest time we will cache dns srv records */
#define MAX_TTL			(60*60*1) /* 1 hours */

#ifdef NS_HFIXEDSZ	/* Bind 8/9 interface */
#if !defined(C_IN)	/* AIX 5.3 already defines C_IN */
#  define C_IN		ns_c_in
#endif
#if !defined(T_A)	/* AIX 5.3 already defines T_A */
#  define T_A   	ns_t_a
#endif

#  define T_SRV 	ns_t_srv
#if !defined(T_NS)	/* AIX 5.3 already defines T_NS */
#  define T_NS 		ns_t_ns
#endif
#else
#  ifdef HFIXEDSZ
#    define NS_HFIXEDSZ HFIXEDSZ
#  else
#    define NS_HFIXEDSZ sizeof(HEADER)
#  endif	/* HFIXEDSZ */
#  ifdef PACKETSZ
#    define NS_PACKETSZ	PACKETSZ
#  else	/* 512 is usually the default */
#    define NS_PACKETSZ	512
#  endif	/* PACKETSZ */
#  define T_SRV 	33
#endif

#define SVAL(buf, pos) (*(const uint16_t *)((const char *)(buf) + (pos)))
#define IVAL(buf, pos) (*(const uint32_t *)((const char *)(buf) + (pos)))

#define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
#define IREV(x) ((SREV(x)<<16) | (SREV((x)>>16)))

#define RSVAL(buf, pos) SREV(SVAL(buf, pos))
#define RIVAL(buf, pos) IREV(IVAL(buf, pos))

#define QSORT_CAST	(int (*)(const void *, const void *))

/* DNS query section in replies */

struct dns_query {
	const char *hostname;
	uint16_t type;
	uint16_t in_class;
};

/* DNS RR record in reply */

struct dns_rr {
	const char *hostname;
	uint16_t type;
	uint16_t in_class;
	uint32_t ttl;
	uint16_t rdatalen;
	uint8_t *rdata;
};

/* SRV records */

struct dns_rr_srv {
	const char *hostname;
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	uint32_t ttl;
};

static pthread_mutex_t dclist_mutex = PTHREAD_MUTEX_INITIALIZER;

static void dclist_mutex_lock(void)
{
	int status = pthread_mutex_lock(&dclist_mutex);
	if (status)
		fatal(status);
	return;
}

static void dclist_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&dclist_mutex);
	if (status)
		fatal(status);
	return;
}

static int dns_parse_query(unsigned int logopt,
			   uint8_t *start, uint8_t *end,
			   uint8_t **ptr, struct dns_query *q)
{
	uint8_t *p = *ptr;
	char hostname[MAX_DNS_NAME_LENGTH];
	char buf[MAX_ERR_BUF];
	int namelen;

	if (!start || !end || !q || !*ptr)
		return 0;

	memset(q, 0, sizeof(*q));

	/* See RFC 1035 for details. If this fails, then return. */

	namelen = dn_expand(start, end, p, hostname, sizeof(hostname));
	if (namelen < 0) {
		error(logopt, "failed to expand query hostname");
		return 0;
	}

	p += namelen;
	q->hostname = strdup(hostname);
	if (!q) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, "strdup: %s", estr);
		return 0;
	}

	/* check that we have space remaining */

	if (p + 4 > end) {
		error(logopt, "insufficient buffer space for result");
		free((void *) q->hostname);
		return 0;
	}

	q->type     = RSVAL(p, 0);
	q->in_class = RSVAL(p, 2);
	p += 4;

	*ptr = p;

	return 1;
}

static int dns_parse_rr(unsigned int logopt,
			uint8_t *start, uint8_t *end,
			uint8_t **ptr, struct dns_rr *rr)
{
	uint8_t *p = *ptr;
	char hostname[MAX_DNS_NAME_LENGTH];
	char buf[MAX_ERR_BUF];
	int namelen;

	if (!start || !end || !rr || !*ptr)
		return 0;

	memset(rr, 0, sizeof(*rr));

	/* pull the name from the answer */

	namelen = dn_expand(start, end, p, hostname, sizeof(hostname));
	if (namelen < 0) {
		error(logopt, "failed to expand query hostname");
		return 0;
	}
	p += namelen;
	rr->hostname = strdup(hostname);
	if (!rr->hostname) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, "strdup: %s", estr);
		return 0;
	}

	/* check that we have space remaining */

	if (p + 10 > end) {
		error(logopt, "insufficient buffer space for result");
		free((void *) rr->hostname);
		return 0;
	}

	/* pull some values and then skip onto the string */

	rr->type     = RSVAL(p, 0);
	rr->in_class = RSVAL(p, 2);
	rr->ttl      = RIVAL(p, 4);
	rr->rdatalen = RSVAL(p, 8);

	p += 10;

	/* sanity check the available space */

	if (p + rr->rdatalen > end) {
		error(logopt, "insufficient buffer space for data");
		free((void *) rr->hostname);
		return 0;
	}

	/* save a point to the rdata for this section */

	rr->rdata = p;
	p += rr->rdatalen;

	*ptr = p;

	return 1;
}

static int dns_parse_rr_srv(unsigned int logopt,
			    uint8_t *start, uint8_t *end,
			    uint8_t **ptr, struct dns_rr_srv *srv)
{
	struct dns_rr rr;
	uint8_t *p;
	char dcname[MAX_DNS_NAME_LENGTH];
	char buf[MAX_ERR_BUF];
	int namelen;

	if (!start || !end || !srv || !*ptr)
		return 0;

	/* Parse the RR entry.  Coming out of the this, ptr is at the beginning
	   of the next record */

	if (!dns_parse_rr(logopt, start, end, ptr, &rr)) {
		error(logopt, "Failed to parse RR record");
		return 0;
	}

	if (rr.type != T_SRV) {
		error(logopt, "Bad answer type (%d)", rr.type);
		return 0;
	}

	p = rr.rdata;

	srv->priority = RSVAL(p, 0);
	srv->weight   = RSVAL(p, 2);
	srv->port     = RSVAL(p, 4);
	srv->ttl      = rr.ttl;

	p += 6;

	namelen = dn_expand(start, end, p, dcname, sizeof(dcname));
	if (namelen < 0) {
		error(logopt, "Failed to expand dcname");
		return 0;
	}

	srv->hostname = strdup(dcname);
	if (!srv->hostname) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, "strdup: %s", estr);
		return 0;
	}

	debug(logopt, "Parsed %s [%u, %u, %u]",
	      srv->hostname, srv->priority, srv->weight, srv->port);

	return 1;
}

/*********************************************************************
 Sort SRV record list based on weight and priority.  See RFC 2782.
*********************************************************************/

static int dnssrvcmp(struct dns_rr_srv *a, struct dns_rr_srv *b)
{
	if (a->priority == b->priority) {
		/* randomize entries with an equal weight and priority */
		if (a->weight == b->weight)
			return 0;

		/* higher weights should be sorted lower */
		if (a->weight > b->weight)
			return -1;
		else
			return 1;
	}

	if (a->priority < b->priority)
		return -1;

	return 1;
}

#define DNS_FAILED_WAITTIME          30

static int dns_send_req(unsigned int logopt,
			const char *name, int q_type, uint8_t **rbuf,
			int *resp_length)
{
	uint8_t *buffer = NULL;
	size_t buf_len = 0;
	int resp_len = NS_PACKETSZ;
	static time_t last_dns_check = 0;
	static unsigned int last_dns_status = 0;
	time_t now = time(NULL);
	char buf[MAX_ERR_BUF];

	/* Try to prevent bursts of DNS lookups if the server is down */

	/* Protect against large clock changes */

	if (last_dns_check > now)
		last_dns_check = 0;

	/* IF we had a DNS timeout or a bad server and we are still
	   in the 30 second cache window, just return the previous
	   status and save the network timeout. */

	if ((last_dns_status == ETIMEDOUT ||
	     last_dns_status == ECONNREFUSED) &&
	     ((last_dns_check + DNS_FAILED_WAITTIME) > now)) {
		char *estr = strerror_r(last_dns_status, buf, MAX_ERR_BUF);
		debug(logopt, "Returning cached status (%s)", estr);
		return last_dns_status;
	}

	/* Send the Query */
	do {
		if (buffer)
			free(buffer);

		buf_len = resp_len * sizeof(uint8_t);

		if (buf_len) {
			buffer = malloc(buf_len);
			if (!buffer) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(logopt, "malloc: %s", estr);
				last_dns_status = ENOMEM;
				last_dns_check = time(NULL);
				return last_dns_status;
			}
		}

		resp_len = res_query(name, C_IN, q_type, buffer, buf_len);
		if (resp_len < 0) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "Failed to resolve %s (%s)", name, estr);
			free(buffer);
			last_dns_status = ENOENT;
			last_dns_check = time(NULL);
			return last_dns_status;
		}

		/* On AIX, Solaris, and possibly some older glibc systems (e.g. SLES8)
		   truncated replies never give back a resp_len > buflen
		   which ends up causing DNS resolve failures on large tcp DNS replies */

		if (buf_len == resp_len) {
			if (resp_len == MAX_DNS_PACKET_SIZE) {
				error(logopt,
				      "DNS reply too large when resolving %s",
				      name);
				free(buffer);
				last_dns_status = EMSGSIZE;
				last_dns_check = time(NULL);
				return last_dns_status;
			}

			resp_len = MIN(resp_len * 2, MAX_DNS_PACKET_SIZE);
		}
	} while (buf_len < resp_len && resp_len <= MAX_DNS_PACKET_SIZE);

	*rbuf = buffer;
	*resp_length = resp_len;

	last_dns_check = time(NULL);
	last_dns_status = 0;

	return 0;
}

static int dns_lookup_srv(unsigned int logopt, const char *name,
			  struct dns_rr_srv **dclist, int *numdcs)
{
	uint8_t *buffer = NULL;
	int resp_len = 0;
	struct dns_rr_srv *dcs = NULL;
	int query_count, answer_count;
	uint8_t *p = buffer;
	int rrnum;
	int idx = 0;
	char buf[MAX_ERR_BUF];
	int ret;

	if (!name || !dclist)
		return -EINVAL;

	/* Send the request.  May have to loop several times in case
	   of large replies */

	ret = dns_send_req(logopt, name, T_SRV, &buffer, &resp_len);
	if (ret) {
		error(logopt, "Failed to send DNS query");
		return ret;
	}
	p = buffer;

	/* For some insane reason, the ns_initparse() et. al. routines are only
	   available in libresolv.a, and not the shared lib.  Who knows why....
	   So we have to parse the DNS reply ourselves */

	/* Pull the answer RR's count from the header.
	 * Use the NMB ordering macros */

	query_count      = RSVAL(p, 4);
	answer_count     = RSVAL(p, 6);

	debug(logopt,
	      "%d records returned in the answer section.",
	       answer_count);

	if (answer_count) {
		dcs = malloc(sizeof(struct dns_rr_srv) * answer_count);
		if (!dcs) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "malloc: %s", estr);
			free(buffer);
			return ENOMEM;
		}
	}

	/* now skip the header */

	p += NS_HFIXEDSZ;

	/* parse the query section */

	for (rrnum = 0; rrnum < query_count; rrnum++) {
		struct dns_query q;

		ret = dns_parse_query(logopt, buffer, buffer+resp_len, &p, &q);
		if (!ret) {
			error(logopt,
			      "Failed to parse query record [%d]", rrnum);
			free(buffer);
			free(dcs);
			return EBADMSG;
		}
	}

	/* now we are at the answer section */

	for (rrnum = 0; rrnum < answer_count; rrnum++) {
		ret = dns_parse_rr_srv(logopt,
				       buffer, buffer+resp_len,
				       &p, &dcs[rrnum]);
		if (!ret) {
			error(logopt,
			      "Failed to parse answer record [%d]", rrnum);
			free(buffer);
			free(dcs);
			return EBADMSG;
		}
	}
	idx = rrnum;

	qsort(dcs, idx, sizeof(struct dns_rr_srv), QSORT_CAST dnssrvcmp);

	*dclist = dcs;
	*numdcs = idx;

	return 0;
}

static char *escape_dn_commas(const char *uri)
{
	size_t len = strlen(uri);
	char *new, *tmp, *ptr;

	ptr = (char *) uri;
	while (*ptr) {
		if (*ptr == '\\')
			ptr += 2;
		if (*ptr == ',')
			len += 2;
		ptr++;
	}

	new = malloc(len + 1);
	if (!new)
		return NULL;
	memset(new, 0, len + 1);

	ptr = (char *) uri;
	tmp = new;
	while (*ptr) {
		if (*ptr == '\\') {
			ptr++;
			*tmp++ = *ptr++;
			continue;
		}
		if (*ptr == ',') {
			strcpy(tmp, "%2c");
			ptr++;
			tmp += 3;
			continue;
		}
		*tmp++ = *ptr++;
	}

	return new;
}

void free_dclist(struct dclist *dclist)
{
	if (dclist->uri)
		free((void *) dclist->uri);
	free(dclist);
}

static char *getdnsdomainname(unsigned int logopt)
{
	struct addrinfo hints, *ni;
	char name[MAX_DNS_NAME_LENGTH + 1];
	char buf[MAX_ERR_BUF];
	char *dnsdomain = NULL;
	char *ptr;
	int ret;

	memset(name, 0, sizeof(name));
	if (gethostname(name, MAX_DNS_NAME_LENGTH) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, "gethostname: %s", estr);
		return NULL;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(name, NULL, &hints, &ni);
	if (ret) {
		error(logopt, "hostname lookup failed: %s", gai_strerror(ret));
		return NULL;
	}

	ptr = ni->ai_canonname;
	while (*ptr && *ptr != '.')
		ptr++;

	if (*++ptr)
		dnsdomain = strdup(ptr);

	freeaddrinfo(ni);

	return dnsdomain;
}

struct dclist *get_dc_list(unsigned int logopt, const char *uri)
{
	LDAPURLDesc *ludlist = NULL;
	LDAPURLDesc **ludp;
	struct dns_rr_srv *dcs;
	unsigned int min_ttl = MAX_TTL;
	struct dclist *dclist = NULL;;
	char buf[MAX_ERR_BUF];
	char *dn_uri, *esc_uri;
	char *domain;
	char *list;
	int numdcs;
	int ret;

	if (strcmp(uri, "ldap:///") && strcmp(uri, "ldaps:///")) {
		dn_uri = strdup(uri);
		if (!dn_uri) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "strdup: %s", estr);
			return NULL;
		}
	} else {
		char *dnsdomain;
		char *hdn;

		dnsdomain = getdnsdomainname(logopt);
		if (!dnsdomain) {
			error(logopt, "failed to get dns domainname");
			return NULL;
		}

		if (ldap_domain2dn(dnsdomain, &hdn) || hdn == NULL) {
			error(logopt,
			      "Could not turn domain \"%s\" into a dn\n",
			      dnsdomain);
			free(dnsdomain);
			return NULL;
		}
		free(dnsdomain);

		dn_uri = malloc(strlen(uri) + strlen(hdn) + 1);
		if (!dn_uri) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "malloc: %s", estr);
			ber_memfree(hdn);
			return NULL;
		}

		strcpy(dn_uri, uri);
		strcat(dn_uri, hdn);
		ber_memfree(hdn);
	}

	esc_uri = escape_dn_commas(dn_uri);
	if (!esc_uri) {
		error(logopt, "Could not escape commas in uri %s", dn_uri);
		free(dn_uri);
		return NULL;
	}

	ret = ldap_url_parse(esc_uri, &ludlist);
	if (ret != LDAP_URL_SUCCESS) {
		error(logopt, "Could not parse uri %s (%d)", dn_uri, ret);
		free(esc_uri);
		free(dn_uri);
		return NULL;
	}

	free(esc_uri);

	if (!ludlist) {
		error(logopt, "No dn found in uri %s", dn_uri);
		free(dn_uri);
		return NULL;
	}

	free(dn_uri);

	dclist = malloc(sizeof(struct dclist));
	if (!dclist) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, "malloc: %s", estr);
		ldap_free_urldesc(ludlist);
		return NULL;
	}
	memset(dclist, 0, sizeof(struct dclist));

	list = NULL;
	for (ludp = &ludlist; *ludp != NULL;) {
		LDAPURLDesc *lud = *ludp;
		size_t req_len, len;
		char *request = NULL;
		char *tmp;
		int i;

		if (!lud->lud_dn && !lud->lud_dn[0] &&
		   (!lud->lud_host || !lud->lud_host[0])) {
			*ludp = lud->lud_next;
			continue;
		}

		domain = NULL;
		if (ldap_dn2domain(lud->lud_dn, &domain) || domain == NULL) {
			error(logopt,
			      "Could not turn dn \"%s\" into a domain",
			      lud->lud_dn);
			*ludp = lud->lud_next;
			continue;
		}

		debug(logopt, "doing lookup of SRV RRs for domain %s", domain);

		req_len = sizeof("_ldap._tcp.") + strlen(domain);
		request = malloc(req_len);
		if (!request) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "malloc: %s", estr);
			goto out_error;
		}

		ret = snprintf(request, req_len, "_ldap._tcp.%s", domain);
		if (ret >= req_len) {
			free(request);
			goto out_error;
		}

		dclist_mutex_lock();
		if (dns_lookup_srv(logopt, request, &dcs, &numdcs)) {
			error(logopt,
			      "DNS SRV query failed for domain %s", domain);
			dclist_mutex_unlock();
			free(request);
			goto out_error;
		}
		dclist_mutex_unlock();
		free(request);

		len = strlen(lud->lud_scheme);
		len += sizeof("://");
		len *= numdcs;

		for (i = 0; i < numdcs; i++) {
			if (dcs[i].ttl > 0 && dcs[i].ttl < min_ttl)
				min_ttl = dcs[i].ttl;
			len += strlen(dcs[i].hostname);
			if (dcs[i].port > 0)
				len += sizeof(":65535");
		}

		tmp = realloc(list, len);
		if (!tmp) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "realloc: %s", estr);
			goto out_error;
		}

		if (!list)
			memset(tmp, 0, len);
		else
			strcat(tmp, " ");

		for (i = 0; i < numdcs; i++) {
			if (i > 0)
				strcat(tmp, " ");
			strcat(tmp, lud->lud_scheme);
			strcat(tmp, "://");
			strcat(tmp, dcs[i].hostname);
			if (dcs[i].port > 0) {
				char port[7];
				ret = snprintf(port, 7, ":%d", dcs[i].port);
				if (ret > 6) {
					error(logopt,
					      "invalid port: %u", dcs[i].port);
					goto out_error;
				}
				strcat(tmp, port);
			}
		}
		list = tmp;

		*ludp = lud->lud_next;
		ber_memfree(domain);
	}

	ldap_free_urldesc(ludlist);

	dclist->expire = time(NULL) + min_ttl;
	dclist->uri = list;

	return dclist;

out_error:
	if (list)
		free(list);
	if (domain)
		ber_memfree(domain);
	ldap_free_urldesc(ludlist);
	free_dclist(dclist);
	return NULL;
}
