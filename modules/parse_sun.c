#ident "$Id: parse_sun.c,v 1.5 2003/11/10 12:10:21 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  parse_sun.c - module for Linux automountd to parse a Sun-format
 *                automounter map
 * 
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <netinet/in.h>

#define MODULE_PARSE
#include "automount.h"

#ifdef DEBUG
#define DB(x)           do { x; } while(0)
#else
#define DB(x)           do { } while(0)
#endif

#define MODPREFIX "parse(sun): "
int parse_version = AUTOFS_PARSE_VERSION;	/* Required by protocol */

static struct mount_mod *mount_nfs = NULL;
static int init_ctr = 0;

struct substvar {
	char *def;		/* Define variable */
	char *val;		/* Value to replace with */
	struct substvar *next;
};

struct parse_context {
	char *optstr;		/* Mount options */
	struct substvar *subst;	/* $-substitutions */
	int slashify_colons;	/* Change colons to slashes? */
};

struct utsname un;
char processor[65];		/* Not defined on Linux, so we make our own */

/* Predefined variables: tail of link chain */
static struct substvar
	sv_arch   = {"ARCH",   un.machine,  NULL },
	sv_cpu    = {"CPU",    processor,   &sv_arch},
	sv_host   = {"HOST",   un.nodename, &sv_cpu},
	sv_osname = {"OSNAME", un.sysname,  &sv_host},
	sv_osrel  = {"OSREL",  un.release,  &sv_osname},
	sv_osvers = {"OSVERS", un.version,  &sv_osrel
};

/* Default context pattern */

static struct parse_context default_context = {
	NULL,			/* No mount options */
	&sv_osvers,		/* The substvar predefined variables */
	1			/* Do slashify_colons */
};

/* Free all storage associated with this context */
static void kill_context(struct parse_context *ctxt)
{
	struct substvar *sv, *nsv;

	sv = ctxt->subst;

	while (sv != &sv_osvers) {
		nsv = sv->next;
		free(sv);
		sv = nsv;
	}

	if (ctxt->optstr)
		free(ctxt->optstr);

	free(ctxt);
}

/* Find the $-variable matching a certain string fragment */
static const struct substvar *findvar(const struct substvar *sv, const char *str, int len)
{
	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0')
			return sv;
		sv = sv->next;
	}
	return NULL;
}

/* $- and &-expand a Sun-style map entry and return the length of the entry.
   If "dst" is NULL, just count the length. */
int expandsunent(const char *src, char *dst, const char *key,
		 const struct substvar *svc, int slashify_colons)
{
	const struct substvar *sv;
	int len, l, seen_colons;
	const char *p;
	char ch;

	len = 0;
	seen_colons = 0;

	while ((ch = *src++)) {
		switch (ch) {
		case '&':
			l = strlen(key);
			if (dst) {
				strcpy(dst, key);
				dst += l;
			}
			len += l;
			break;

		case '$':
			if (*src == '{') {
				p = strchr(++src, '}');
				if (!p) {
					/* Ignore rest of string */
					if (dst)
						*dst = '\0';
					return len;
				}
				sv = findvar(svc, src, p - src);
				if (sv) {
					l = strlen(sv->val);
					if (dst) {
						strcpy(dst, sv->val);
						dst += l;
					}
					len += l;
				}
				src = p + 1;
			} else {
				p = src;
				while (isalnum(*p) || *p == '_')
					p++;
				sv = findvar(svc, src, p - src);
				if (sv) {
					l = strlen(sv->val);
					if (dst) {
						strcpy(dst, sv->val);
						dst += l;
					}
					len += l;
				}
				src = p;
			}
			break;

		case '\\':
			len++;
			if (dst)
				*dst++ = ch;

			if (*src) {
				len++;
				if (dst)
					*dst++ = *src;
				src++;
			}
			break;

		case ':':
			if (dst)
				*(dst++) = (seen_colons && slashify_colons) ? '/' : ':';
			len++;
			seen_colons = 1;
			break;

		default:
			if (isspace(ch))
				seen_colons = 0;

			if (dst)
				*(dst++) = ch;
			len++;
			break;
		}
	}
	if (dst)
		*dst = '\0';
	return len;
}

/* Skip whitespace in a string; if we hit a #, consider the rest of the
   entry a comment */
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

/* Get the length of a chunk delimitered by whitespace */
int chunklen(const char *whence)
{
	int n = 0;
	int quote = 0;

	for (; *whence; whence++, n++) {
		switch (*whence) {
		case '\\':
			quote = 1;
			continue;

		case ' ':
		case '\b':
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case '#':
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

int parse_init(int argc, const char *const *argv, void **context)
{
	struct parse_context *ctxt;
	struct substvar *sv;
	char *noptstr;
	const char *xopt;
	int optlen, len;
	int i, bval;

	/* Get processor information for predefined escapes */

	if (!init_ctr) {
		uname(&un);
		/* uname -p is not defined on Linux.  Make it the same as uname -m,
		   except make it return i386 on all x86 (x >= 3) */
		strcpy(processor, un.machine);
		if (processor[0] == 'i' && processor[1] >= '3' &&
		    !strcmp(processor + 2, "86"))
			processor[1] = '3';
	}

	/* Set up context and escape chain */

	if (!(ctxt = (struct parse_context *) malloc(sizeof(struct parse_context)))) {
		syslog(LOG_CRIT, MODPREFIX "malloc: %m");
		return 1;
	}
	*context = (void *) ctxt;

	*ctxt = default_context;
	optlen = 0;

	/* Look for options and capture, and create new defines if we need to */

	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
			case 'D':
				sv = malloc(sizeof(struct substvar));
				if (!sv) {
					syslog(LOG_ERR, MODPREFIX "malloc: %m");
					break;
				}
				if (argv[i][2])
					sv->def = strdup(argv[i] + 2);
				else if (++i < argc)
					sv->def = strdup(argv[i]);
				else {
					free(sv);
					break;
				}

				if (!sv->def) {
					syslog(LOG_ERR, MODPREFIX "strdup: %m");
					free(sv);
				} else {
					sv->val = strchr(sv->def, '=');
					if (sv->val)
						*(sv->val++) = '\0';
					else
						sv->val = "";

					sv->next = ctxt->subst;
					ctxt->subst = sv;
				}
				break;

			case '-':
				if (!strncmp(argv[i] + 2, "no-", 3)) {
					xopt = argv[i] + 5;
					bval = 0;
				} else {
					xopt = argv[i] + 2;
					bval = 1;
				}

				if (strmcmp(xopt, "slashify-colons", 1))
					ctxt->slashify_colons = bval;
				else
					syslog(LOG_ERR, MODPREFIX "unknown option: %s",
					       argv[i]);

				break;

			default:
				syslog(LOG_ERR, MODPREFIX "unknown option: %s", argv[i]);
				break;
			}
		} else {
			len = strlen(argv[i]);
			if (ctxt->optstr) {
				noptstr =
				    (char *) realloc(ctxt->optstr, optlen + len + 2);
				if (!noptstr)
					break;
				noptstr[optlen] = ',';
				strcpy(noptstr + optlen + 1, argv[i]);
				optlen += len + 1;
			} else {
				noptstr = (char *) malloc(len + 1);
				strcpy(noptstr, argv[i]);
				optlen = len;
			}
			if (!noptstr) {
				kill_context(ctxt);
				syslog(LOG_CRIT, MODPREFIX "%m");
				return 1;
			}
			ctxt->optstr = noptstr;
			DB(syslog
			   (LOG_DEBUG, MODPREFIX "init gathered options: %s",
			    ctxt->optstr));
		}
	}

	/* We only need this once.  NFS mounts are so common that we cache
	   this module. */
	if (!mount_nfs)
		if ((mount_nfs = open_mount("nfs", MODPREFIX))) {
			init_ctr++;
			return 0;
		} else {
			kill_context(ctxt);
			return 1;
	} else {
		init_ctr++;
		return 0;
	}
}

static char *dequote(const char *str, int strlen)
{
	char *ret = malloc(strlen + 1);
	char *cp = ret;
	const char *scp;
	int origlen = strlen;

	if (ret == NULL)
		return NULL;

	for (scp = str; strlen > 0 && *scp; scp++, strlen--) {
		if (*scp == '\\')
			continue;
		*cp++ = *scp;
	}
	*cp = '\0';

	DB(syslog(LOG_DEBUG, MODPREFIX "dequote(\"%.*s\") -> %s", origlen, str, ret));

	return ret;
}

static const char *parse_options(const char *str, char **ret)
{
	const char *cp = str;
	int len;

	if (*cp++ != '-')
		return str;

	if (*ret != NULL)
		free(*ret);

	*ret = dequote(cp, len = chunklen(cp));

	return cp + len;
}

static char *concat_options(char *left, char *right)
{
	char *ret;

	if (left == NULL || *left == '\0') {
		free(left);
		ret = strdup(right);
		return ret;
	}

	if (right == NULL || *right == '\0') {
		free(right);
		return strdup(left);
	}

	ret = malloc(strlen(left) + strlen(right) + 2);

	if (ret == NULL) {
		syslog(LOG_ERR, MODPREFIX "concat_options malloc: %m");
		return NULL;
	}

	sprintf(ret, "%s,%s", left, right);

	free(left);
	free(right);

	return ret;
}

static int sun_mount(const char *root, const char *name, int namelen,
		     const char *path, int pathlen,
		     const char *loc, int loclen, const char *options)
{
	char *fstype = "nfs";	/* Default filesystem type */
	int nonstrict = 0;
	int rv;
	char *mountpoint;
	char *what;

	if (*options == '\0')
		options = NULL;

	if (options) {
		char *noptions;
		const char *comma;
		char *np;
		int len = strlen(options) + 1;

		noptions = np = alloca(len);
		*np = '\0';

		/* Extract fstype= pseudo option */
		for (comma = options; *comma != '\0';) {
			const char *cp;

			while (*comma == ',')
				comma++;

			cp = comma;

			while (*comma != '\0' && *comma != ',')
				comma++;

			if (strncmp("fstype=", cp, 7) == 0) {
				int typelen = comma - (cp + 7);
				fstype = alloca(typelen + 1);
				memcpy(fstype, cp + 7, typelen);
				fstype[typelen] = '\0';
			} else if (strncmp("nonstrict", cp, 9) == 0) {
				nonstrict = 1;
			} else {
				memcpy(np, cp, comma - cp + 1);
				np += comma - cp + 1;
			}
		}
		if (np > noptions)
			np[-1] = '\0';

		options = noptions;
	}

	while (*path == '/') {
		path++;
		pathlen--;
	}

	mountpoint = alloca(namelen + pathlen + 2);

	if (pathlen)
		sprintf(mountpoint, "%.*s/%.*s", namelen, name, pathlen, path);
	else
		sprintf(mountpoint, "%.*s", namelen, name);

	what = alloca(loclen + 1);
	memcpy(what, loc, loclen);
	what[loclen] = '\0';

	DB(syslog(LOG_DEBUG,
		  MODPREFIX
		  "mounting root %s, mountpoint %s, what %s, fstype %s, options %s\n",
		  root, mountpoint, what, fstype, options));

	if (!strcmp(fstype, "nfs")) {
		rv = mount_nfs->mount_mount(root, mountpoint, strlen(mountpoint),
					    what, fstype, options, mount_nfs->context);
	} else {
		/* Generic mount routine */
		rv = do_mount(root, mountpoint, strlen(mountpoint), what, fstype,
			      options);
	}

	if (nonstrict && rv) {
		DB(syslog(LOG_DEBUG, "ignoring failure of non-strict mount"));
		return 0;
	}

	return rv;
}

/*
 * syntax is:
 *	[-options] location
 *	[-options] [mountpoint [-options] location]...
 */
int parse_mount(const char *root, const char *name,
		int name_len, const char *mapent, void *context)
{
	struct parse_context *ctxt = (struct parse_context *) context;
	char *pmapent, *options;
	const char *p;
	int mapent_len, rv;
	int optlen;

	mapent_len = expandsunent(mapent, NULL, name, ctxt->subst, ctxt->slashify_colons);
	pmapent = alloca(mapent_len + 1);
	if (!pmapent) {
		syslog(LOG_ERR, MODPREFIX "alloca: %m");
		return 1;
	}
	expandsunent(mapent, pmapent, name, ctxt->subst, ctxt->slashify_colons);

	DB(syslog(LOG_DEBUG, MODPREFIX "expanded entry: %s", pmapent));

	options = strdup(ctxt->optstr ? ctxt->optstr : "");
	if (!options) {
		syslog(LOG_ERR, MODPREFIX "strdup: %m");
		return 1;
	}
	optlen = strlen(options);

	p = skipspace(pmapent);

	/* Deal with 0 or more options */
	if (*p == '-') {
		do {
			char *noptions = NULL;

			p = parse_options(p, &noptions);
			options = concat_options(options, noptions);

			if (options == NULL) {
				syslog(LOG_ERR, MODPREFIX "concat_options: %m");
				return 1;
			}
			p = skipspace(p);
		} while (*p == '-');
	}

	DB(syslog(LOG_DEBUG, MODPREFIX "gathered options: %s", options));

	if (*p == '/') {
		int l;
		int atleast1 = 0;

		/* It's a multi-mount; deal with it */
		do {
			char *myoptions = strdup(options);
			char *path, *loc;
			int pathlen, loclen;

			if (myoptions == NULL) {
				syslog(LOG_ERR, MODPREFIX "multi strdup: %m");
				free(options);
				return 1;
			}

			path = dequote(p, l = chunklen(p));
			pathlen = strlen(path);

			p += l;
			p = skipspace(p);

			/* Local options are appended to per-map options */
			if (*p == '-') {
				do {
					char *newopt = NULL;

					p = parse_options(p, &newopt);
					myoptions = concat_options(myoptions, newopt);

					if (myoptions == NULL) {
						syslog(LOG_ERR,
						       MODPREFIX
						       "multi concat_options: %m");
						free(options);
						free(path);
						return 1;
					}
					p = skipspace(p);
				} while (*p == '-');
			}

			loc = dequote(p, l = chunklen(p));
			loclen = strlen(loc);

			if (loc == NULL || path == NULL) {
				syslog(LOG_ERR, MODPREFIX "out of memory");
				free(loc);
				free(path);
				free(options);
				return 1;
			}

			p += l;
			p = skipspace(p);

			DB(syslog
			   (LOG_DEBUG,
			    MODPREFIX "multimount: %.*s on %.*s with options %s", loclen,
			    loc, pathlen, path, myoptions));

			rv = sun_mount(root, name, name_len, path, pathlen, loc, loclen,
				       myoptions);
			free(path);
			free(loc);
			free(myoptions);

			if (!rv)
				atleast1 = 1;

		} while (*p == '/');

		free(options);
		return !atleast1;
	} else {
		/* Normal (non-multi) entries */
		char *loc;
		int loclen;

		if (*p == ':')
			p++;	/* Sun escape for entries starting with / */

		loc = dequote(p, chunklen(p));
		loclen = strlen(loc);

		if (loc == NULL) {
			syslog(LOG_ERR, MODPREFIX "out of memory");
			free(loc);
			free(options);
			return 1;
		}

		if (loclen == 0) {
			syslog(LOG_ERR, MODPREFIX "entry %s is empty!", name);
			free(options);
			return 1;
		}

		DB(syslog(LOG_DEBUG, MODPREFIX "core of entry: options=%s, loc=%.*s",
			  options, loclen, loc));

		rv = sun_mount(root, name, name_len, "/", 1, loc, loclen, options);
		free(loc);
		free(options);
	}

	return rv;
}

int parse_done(void *context)
{
	int rv = 0;
	struct parse_context *ctxt = (struct parse_context *) context;

	if (--init_ctr == 0) {
		rv = close_mount(mount_nfs);
		mount_nfs = NULL;
	}
	kill_context(ctxt);
	return rv;
}
