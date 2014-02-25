/* ----------------------------------------------------------------------- *
 *   
 *  parse_subs.c - misc parser subroutines
 *                automounter map
 * 
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "automount.h"

#define MAX_NETWORK_LEN		255

#define MAX_IFC_BUF		2048
static int volatile ifc_buf_len = MAX_IFC_BUF;
static int volatile ifc_last_len = 0;

#define MASK_A  0x7F000000
#define MASK_B  0xBFFF0000
#define MASK_C  0xDFFFFF00

/* Get numeric value of the n bits starting at position p */
#define getbits(x, p, n)	((x >> (p + 1 - n)) & ~(~0 << n))

struct types {
	char *type;
	unsigned int len;
};

static struct types map_type[] = {
	{ "file", 4 },
	{ "program", 7 },
	{ "yp", 2 },
	{ "nis", 3 },
	{ "nisplus", 7 },
	{ "ldap", 4 },
	{ "ldaps", 5 },
	{ "hesiod", 6 },
	{ "userdir", 7 },
	{ "hosts", 5 },
};
static unsigned int map_type_count = sizeof(map_type)/sizeof(struct types);

static struct types format_type[] = {
	{ "sun", 3 },
	{ "hesiod", 6 },
};
static unsigned int format_type_count = sizeof(format_type)/sizeof(struct types);

static unsigned int ipv6_mask_cmp(uint32_t *host, uint32_t *iface, uint32_t *mask)
{
	unsigned int ret = 1;
	unsigned int i;

	for (i = 0; i < 4; i++) {
		if ((host[i] & mask[i]) != (iface[i] & mask[i])) {
			ret = 0;
			break;
		}
	}
	return ret;
}

unsigned int get_proximity(struct sockaddr *host_addr)
{
	struct ifaddrs *ifa = NULL;
	struct ifaddrs *this;
	struct sockaddr_in *addr, *msk_addr, *if_addr;
	struct sockaddr_in6 *addr6, *msk6_addr, *if6_addr;
	struct in_addr *hst_addr;
	struct in6_addr *hst6_addr;
	int addr_len;
	char buf[MAX_ERR_BUF];
	uint32_t mask, ha, ia, *mask6, *ha6, *ia6;
	int ret;

	addr = NULL;
	addr6 = NULL;
	hst_addr = NULL;
	hst6_addr = NULL;
	mask6 = NULL;
	ha6 = NULL;
	ia6 = NULL;
	ha = 0;

	switch (host_addr->sa_family) {
	case AF_INET:
		addr = (struct sockaddr_in *) host_addr;
		hst_addr = (struct in_addr *) &addr->sin_addr;
		ha = ntohl((uint32_t) hst_addr->s_addr);
		addr_len = sizeof(*hst_addr);
		break;

	case AF_INET6:
#ifndef WITH_LIBTIRPC
		return PROXIMITY_UNSUPPORTED;
#else
		addr6 = (struct sockaddr_in6 *) host_addr;
		hst6_addr = (struct in6_addr *) &addr6->sin6_addr;
		ha6 = &hst6_addr->s6_addr32[0];
		addr_len = sizeof(*hst6_addr);
		break;
#endif

	default:
		return PROXIMITY_ERROR;
	}

	ret = getifaddrs(&ifa);
	if (ret) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("getifaddrs: %s", estr);
		return PROXIMITY_ERROR;
	}

	this = ifa;
	while (this) {
		if (!(this->ifa_flags & IFF_UP) ||
		    this->ifa_flags & IFF_POINTOPOINT ||
		    this->ifa_addr == NULL) {
			this = this->ifa_next;
			continue;
		}

		switch (this->ifa_addr->sa_family) {
		case AF_INET:
			if (host_addr->sa_family == AF_INET6)
				break;
			if_addr = (struct sockaddr_in *) this->ifa_addr;
			ret = memcmp(&if_addr->sin_addr, hst_addr, addr_len);
			if (!ret) {
				freeifaddrs(ifa);
				return PROXIMITY_LOCAL;
			}
			break;

		case AF_INET6:
#ifdef WITH_LIBTIRPC
			if (host_addr->sa_family == AF_INET)
				break;
			if6_addr = (struct sockaddr_in6 *) this->ifa_addr;
			ret = memcmp(&if6_addr->sin6_addr, hst6_addr, addr_len);
			if (!ret) {
				freeifaddrs(ifa);
				return PROXIMITY_LOCAL;
			}
#endif
		default:
			break;
		}
		this = this->ifa_next;
	}

	this = ifa;
	while (this) {
		if (!(this->ifa_flags & IFF_UP) ||
		    this->ifa_flags & IFF_POINTOPOINT ||
		    this->ifa_addr == NULL) {
			this = this->ifa_next;
			continue;
		}

		switch (this->ifa_addr->sa_family) {
		case AF_INET:
			if (host_addr->sa_family == AF_INET6)
				break;
			if_addr = (struct sockaddr_in *) this->ifa_addr;
			ia =  ntohl((uint32_t) if_addr->sin_addr.s_addr);

			/* Is the address within a localy attached subnet */

			msk_addr = (struct sockaddr_in *) this->ifa_netmask;
			mask = ntohl((uint32_t) msk_addr->sin_addr.s_addr);

			if ((ia & mask) == (ha & mask)) {
				freeifaddrs(ifa);
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
				freeifaddrs(ifa);
				return PROXIMITY_NET;
			}
			break;

		case AF_INET6:
#ifdef WITH_LIBTIRPC
			if (host_addr->sa_family == AF_INET)
				break;
			if6_addr = (struct sockaddr_in6 *) this->ifa_addr;
			ia6 = &if6_addr->sin6_addr.s6_addr32[0];

			/* Is the address within the network of the interface */

			msk6_addr = (struct sockaddr_in6 *) this->ifa_netmask;
			mask6 = &msk6_addr->sin6_addr.s6_addr32[0];

			if (ipv6_mask_cmp(ha6, ia6, mask6)) {
				freeifaddrs(ifa);
				return PROXIMITY_SUBNET;
			}

			/* How do we define "local network" in ipv6? */
#endif
		default:
			break;
		}
		this = this->ifa_next;
	}

	freeifaddrs(ifa);

	return PROXIMITY_OTHER;
}

/*
 * Skip whitespace in a string; if we hit a #, consider the rest of the
 * entry a comment.
 */
const char *skipspace(const char *whence)
{
	while (1) {
		switch (*whence) {
		case ' ':
		case '\b':
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
			whence++;
			break;
		case '#':	/* comment: skip to end of string */
			while (*whence != '\0')
				whence++;
			/* FALLTHROUGH */

		default:
			return whence;
		}
	}
}

/*
 * Check a string to see if a colon appears before the next '/'.
 */
int check_colon(const char *str)
{
	char *ptr = (char *) str;

	/* Colon escape */
	if (!strncmp(ptr, ":/", 2))
		return 1;

	while (*ptr && strncmp(ptr, ":/", 2))
		ptr++;

	if (!*ptr)
		return 0;

	return 1;
}

/* Get the length of a chunk delimitered by whitespace */
int chunklen(const char *whence, int expect_colon)
{
	char *str = (char *) whence;
	int n = 0;
	int quote = 0;

	for (; *str; str++, n++) {
		switch (*str) {
		case '\\':
			if( quote ) {
				break;
			} else {
				quote = 1;
				continue;
			}
		case '"':
			if (quote)
				break;
			while (*str) {
				str++;
				n++;
				if (*str == '"')
					break;
				if (!strncmp(str, ":/", 2))
					expect_colon = 0;
			}
			break;
		case ':':
			if (expect_colon && !strncmp(str, ":/", 2))
				expect_colon = 0;
			continue;
		case ' ':
		case '\t':
			/* Skip space or tab if we expect a colon */
			if (expect_colon)
				continue;
		case '\b':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case '\0':
			if (!quote)
				return n;
			/* FALLTHROUGH */
		default:
			break;
		}
		quote = 0;
	}

	return n;
}

/*
 * Compare str with pat.  Return 0 if compare equal or
 * str is an abbreviation of pat of no less than mchr characters.
 */
int strmcmp(const char *str, const char *pat, int mchr)
{
	int nchr = 0;

	while (*str == *pat) {
		if (!*str)
			return 0;
		str++;
		pat++;
		nchr++;
	}

	if (!*str && nchr > mchr)
		return 0;

	return *pat - *str;
}

char *dequote(const char *str, int origlen, unsigned int logopt)
{
	char *ret = malloc(origlen + 1);
	char *cp = ret;
	const char *scp;
	int len = origlen;
	int quote = 0, dquote = 0;
	int i, j;

	if (ret == NULL)
		return NULL;

	/* first thing to do is strip white space from the end */
	i = len - 1;
	while (isspace(str[i])) {
		/* of course, we have to keep escaped white-space */
		j = i - 1;
		if (j > 0 && (str[j] == '\\' || str[j] == '"'))
			break;
		i--;
		len--;
	}

	for (scp = str; len > 0 && *scp; scp++, len--) {
		if (!quote) {
			if (*scp == '"') {
				if (dquote)
					dquote = 0;
				else
					dquote = 1;
				continue;
			}

			if (!dquote) {
				if (*scp == '\\') {
					quote = 1;
					continue;
				}
			}
		}
		quote = 0;
		*cp++ = *scp;
	}
	*cp = '\0';

	if (dquote) {
		debug(logopt, "unmatched quote in %.*s", origlen, str);
		free(ret);
		return NULL;
	}

	return ret;
}

int span_space(const char *str, unsigned int maxlen)
{
	const char *p = str;
	unsigned int len = 0;

	while (*p && !isblank(*p) && len < maxlen) {
		if (*p == '"') {
			while (*p++ && len++ < maxlen) {
				if (*p == '"')
					break;
			}
		} else if (*p == '\\') {
			p += 2;
			len += 2;
			continue;
		}
		p++;
		len++;
	}
	return len;
}

char *sanitize_path(const char *path, int origlen, unsigned int type, unsigned int logopt)
{
	char *slash, *cp, *s_path;
	const char *scp;
	int len = origlen;
	unsigned int seen_slash = 0, quote = 0, dquote = 0;

	if (type & (LKP_INDIRECT | LKP_DIRECT)) {
		slash = strchr(path, '/');
		if (slash) {
			if (type == LKP_INDIRECT)
				return NULL;
			if (*path != '/')
				return NULL;
		} else {
			if (type == LKP_DIRECT)
				return NULL;
		}
	}

	s_path = malloc(origlen + 1);
	if (!s_path)
		return NULL;

	for (cp = s_path, scp = path; len > 0; scp++, len--) {
		if (!quote) {
			if (*scp == '"') {
				if (dquote)
					dquote = 0;
				else
					dquote = 1;
				continue;
			}

			if (!dquote) {
				/* Badness in string - go away */
				if (*scp < 32) {
					free(s_path);
					return NULL;
				}

				if (*scp == '\\') {
					quote = 1;
					continue;
				} 
			}

			/*
			 * Not really proper but we get problems with
			 * paths with multiple slashes. The kernel
			 * compresses them so when we get a query there
			 * should be only single slashes.
			 */
			if (*scp == '/') {
				if (seen_slash)
					continue;
				seen_slash = 1;
			} else
				seen_slash = 0;
		}
		quote = 0;
		*cp++ = *scp;
	}
	*cp = '\0';

	if (dquote) {
		debug(logopt, "unmatched quote in %.*s", origlen, path);
		free(s_path);
		return NULL;
	}

	/* Remove trailing / but watch out for a quoted / alone */
	if (strlen(cp) > 1 && origlen > 1 && *(cp - 1) == '/')
		*(cp - 1) = '\0';

	return s_path;
}

void free_map_type_info(struct map_type_info *info)
{
	if (info->type)
		free(info->type);
	if (info->format)
		free(info->format);
	if (info->map)
		free(info->map);
	free(info);
	return;
}

struct map_type_info *parse_map_type_info(const char *str)
{
	struct map_type_info *info;
	char *buf, *type, *fmt, *map, *tmp;
	char *pos;

	buf = strdup(str);
	if (!buf)
		return NULL;

	info = malloc(sizeof(struct map_type_info));
	if (!info) {
		free(buf);
		return NULL;
	}
	memset(info, 0, sizeof(struct map_type_info));

	type = fmt = map = NULL;

	tmp = strchr(buf, ':');
	if (!tmp) {
		pos = buf;
		while (*pos == ' ')
			*pos++ = '\0';
		map = pos;
	} else {
		int i, j;

		for (i = 0; i < map_type_count; i++) {
			char *m_type = map_type[i].type;
			unsigned int m_len = map_type[i].len;

			pos = buf;

			if (strncmp(m_type, pos, m_len))
				continue;

			type = pos;
			pos += m_len;

			if (*pos == ' ' || *pos == ':') {
				while (*pos == ' ')
					*pos++ = '\0';
				if (*pos != ':') {
					free(buf);
					free(info);
					return NULL;
				} else {
					*pos++ = '\0';
					while (*pos && *pos == ' ')
						*pos++ = '\0';
					map = pos;
					break;
				}
			}

			if (*pos == ',') {
				*pos++ = '\0';
				for (j = 0; j < format_type_count; j++) {
					char *f_type = format_type[j].type;
					unsigned int f_len = format_type[j].len;
				
					if (strncmp(f_type, pos, f_len))
						continue;

					fmt = pos;
					pos += f_len;

					if (*pos == ' ' || *pos == ':') {
						while (*pos == ' ')
							*pos++ = '\0';
						if (*pos != ':') {
							free(buf);
							free(info);
							return NULL;
						} else {
							*pos++ = '\0';
							while (*pos && *pos == ' ')
								*pos++ = '\0';
							map = pos;
							break;
						}
					}
				}
			}
		}

		if (!type) {
			pos = buf;
			while (*pos == ' ')
				*pos++ = '\0';
			map = pos;
		}
	}

	/* Look for space terminator - ignore local options */
	for (tmp = buf; *tmp; tmp++) {
		if (*tmp == ' ') {
			*tmp = '\0';
			break;
		}
		if (*tmp == '\\')
			tmp++;
	}

	if (type) {
		info->type = strdup(type);
		if (!info->type) {
			free(buf);
			free_map_type_info(info);
			return NULL;
		}
	}

	if (fmt) {
		info->format = strdup(fmt);
		if (!info->format) {
			free(buf);
			free_map_type_info(info);
			return NULL;
		}
	}

	if (map) {
		info->map = strdup(map);
		if (!info->map) {
			free(buf);
			free_map_type_info(info);
			return NULL;
		}
	}

	free(buf);

	return info;
}

