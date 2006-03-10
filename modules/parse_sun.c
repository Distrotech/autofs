#ident "$Id: parse_sun.c,v 1.45 2006/03/10 20:54:53 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  parse_sun.c - module for Linux automountd to parse a Sun-format
 *                automounter map
 * 
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2004, 2005 Ian Kent <raven@themaw.net>
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
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <netinet/in.h>

#define MODULE_PARSE
#include "automount.h"
#include "macros.h"

#define MODPREFIX "parse(sun): "

int parse_version = AUTOFS_PARSE_VERSION;	/* Required by protocol */

static struct mount_mod *mount_nfs = NULL;
static int init_ctr = 0;

struct parse_context {
	char *optstr;		/* Mount options */
	char *macros;		/* Map wide macro defines */
	struct substvar *subst;	/* $-substitutions */
	int slashify_colons;	/* Change colons to slashes? */
};

struct multi_mnt {
	char *path;
	char *options;
	char *location;
	struct multi_mnt *next;
};

/* Default context */

static struct parse_context default_context = {
	NULL,			/* No mount options */
	NULL,			/* No map wide macros */
	NULL,			/* The substvar local vars table */
	1			/* Do slashify_colons */
};

/* Free all storage associated with this context */
static void kill_context(struct parse_context *ctxt)
{
	macro_free_table(ctxt->subst);
	if (ctxt->optstr)
		free(ctxt->optstr);
	if (ctxt->macros)
		free(ctxt->macros);
	free(ctxt);
}

static struct substvar *addstdenv(struct substvar *sv)
{
	struct substvar *list = sv;
	struct thread_stdenv_vars *tsv;
	char numbuf[16];

	tsv = pthread_getspecific(key_thread_stdenv_vars);
	if (tsv) {
		int ret;
		long num;

		num = (long) tsv->uid;
		ret = sprintf(numbuf, "%ld", num);
		if (ret > 0)
			list = macro_addvar(list, "UID", 3, numbuf);
		num = (long) tsv->gid;
		ret = sprintf(numbuf, "%ld", num);
		if (ret > 0)
			list = macro_addvar(list, "GID", 3, numbuf);
		list = macro_addvar(list, "USER", 4, tsv->user);
		list = macro_addvar(list, "GROUP", 5, tsv->group);
		list = macro_addvar(list, "HOME", 4, tsv->home);
	}
	return list;
}

static struct substvar *removestdenv(struct substvar *sv)
{
	struct substvar *list = sv;

	list = macro_removevar(list, "UID", 3);
	list = macro_removevar(list, "USER", 4);
	list = macro_removevar(list, "HOME", 4);
	list = macro_removevar(list, "GID", 3);
	list = macro_removevar(list, "GROUP", 5);
	return list;
}

/* 
 * $- and &-expand a Sun-style map entry and return the length of the entry.
 * If "dst" is NULL, just count the length.
 */
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
				sv = macro_findvar(svc, src, p - src);
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
				sv = macro_findvar(svc, src, p - src);
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
				*(dst++) = 
				  (seen_colons && slashify_colons) ? '/' : ':';
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

	while (*ptr && *ptr != ':' && *ptr != '/') {
		ptr++;
	}

	if (!*ptr || *ptr == '/')
		return 0;

	return 1;
}

/* Get the length of a chunk delimitered by whitespace */
int chunklen(const char *whence, int expect_colon)
{
	int n = 0;
	int quote = 0;

	for (; *whence; whence++, n++) {
		switch (*whence) {
		case '\\':
			if( quote ) {
				break;
			} else {
				quote = 1;
				continue;
			}
		case ':':
			if (expect_colon)
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
	char buf[MAX_ERR_BUF];
	char *noptstr, *def, *val, *macros;
	const char *xopt;
	int optlen, len, offset;
	int i, bval;

	/* Get processor information for predefined escapes */

	if (!init_ctr)
		macro_init();

	/* Set up context and escape chain */

	if (!(ctxt = (struct parse_context *) malloc(sizeof(struct parse_context)))) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(MODPREFIX "malloc: %s", estr);
		return 1;
	}
	*context = (void *) ctxt;

	*ctxt = default_context;
	optlen = 0;

	/* Look for options and capture, and create new defines if we need to */

	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-' &&
		   (argv[i][1] == 'D' || argv[i][1] == '-') ) {
			switch (argv[i][1]) {
			case 'D':
				if (argv[i][2])
					def = strdup(argv[i] + 2);
				else if (++i < argc)
					def = strdup(argv[i]);
				else
					break;

				if (!def) {
					char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error(MODPREFIX "strdup: %s", estr);
					break;
				}

				val = strchr(def, '=');
				if (val)
					*(val++) = '\0';
				else
					val = "";

				ctxt->subst = macro_addvar(ctxt->subst,
							def, strlen(def), val);

				/* we use 5 for the "-D", "=", "," and the null */
				if (ctxt->macros) {
					len = strlen(ctxt->macros) + strlen(def) + strlen(val);
					macros = realloc(ctxt->macros, len + 5);
					if (!macros) {
						free(def);
						break;
					}
					strcat(macros, ",");
				} else { /* No comma, so only +4 */
					len = strlen(def) + strlen(val);
					macros = malloc(len + 4);
					if (!macros) {
						free(def);
						break;
					}
					*macros = '\0';
				}
				ctxt->macros = macros;

				strcat(ctxt->macros, "-D");
				strcat(ctxt->macros, def);
				strcat(ctxt->macros, "=");
				strcat(ctxt->macros, val);
				free(def);
				break;

			case '-':
				if (!strncmp(argv[i] + 2, "no-", 3)) {
					xopt = argv[i] + 5;
					bval = 0;
				} else {
					xopt = argv[i] + 2;
					bval = 1;
				}

				if (!strmcmp(xopt, "slashify-colons", 1))
					ctxt->slashify_colons = bval;
				else
					error(MODPREFIX "unknown option: %s",
					      argv[i]);
				break;

			default:
				error(MODPREFIX "unknown option: %s", argv[i]);
				break;
			}
		} else {
			offset = (argv[i][0] == '-' ? 1 : 0);
			len = strlen(argv[i] + offset);
			if (ctxt->optstr) {
				noptstr =
				    (char *) realloc(ctxt->optstr, optlen + len + 2);
				if (!noptstr)
					break;
				noptstr[optlen] = ',';
				strcpy(noptstr + optlen + 1, argv[i] + offset);
				optlen += len + 1;
			} else {
				noptstr = (char *) malloc(len + 1);
				strcpy(noptstr, argv[i] + offset);
				optlen = len;
			}
			if (!noptstr) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				kill_context(ctxt);
				crit(MODPREFIX "%s", estr);
				return 1;
			}
			ctxt->optstr = noptstr;
			debug(MODPREFIX "init gathered options: %s",
			      ctxt->optstr);
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
			*context = NULL;
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
	int quote = 0;

	if (ret == NULL)
		return NULL;

	for (scp = str; strlen > 0 && *scp; scp++, strlen--) {
		if (*scp == '\\' && !quote ) {
			quote = 1;
			continue;
		}
		quote = 0;
		*cp++ = *scp;
	}
	*cp = '\0';

	debug(MODPREFIX "dequote(\"%.*s\") -> %s", origlen, str, ret);

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

	*ret = dequote(cp, len = chunklen(cp, 0));

	return cp + len;
}

static char *concat_options(char *left, char *right)
{
	char buf[MAX_ERR_BUF];
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
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(MODPREFIX "concat_options malloc: %s", estr);
		return NULL;
	}

	sprintf(ret, "%s,%s", left, right);

	free(left);
	free(right);

	return ret;
}

static int sun_mount(struct autofs_point *ap, const char *root,
			const char *name, int namelen,
			const char *loc, int loclen, const char *options,
			struct parse_context *ctxt)
{
	char *fstype = "nfs";	/* Default filesystem type */
	int nonstrict = 1;
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
			} else if (strncmp("strict", cp, 6) == 0) {
				nonstrict = 0;
			} else if (strncmp("nonstrict", cp, 9) == 0) {
				nonstrict = 1;
			} else {
				memcpy(np, cp, comma - cp + 1);
				np += comma - cp + 1;
			}
		}

		if (np > noptions + len) {
			warn(MODPREFIX "options string truncated");
			np[len] = '\0';
		} else
			*(np - 1) = '\0';

		options = noptions;
	}


	if (!strcmp(fstype, "autofs") && ctxt->macros) {
		char *noptions = NULL;

		if (!options) {
			noptions = alloca(strlen(ctxt->macros) + 1);
			*noptions = '\0';
		} else {
			int len = strlen(options) + strlen(ctxt->macros) + 2;
			noptions = alloca(len);

			if (noptions) {
				strcpy(noptions, options);
				strcat(noptions, ",");
			}
		}

		if (noptions) {
			strcat(noptions, ctxt->macros);
			options = noptions;
		} else {
			error(MODPREFIX "alloca failed for options");
		}
	}

	mountpoint = alloca(namelen + 1);
	sprintf(mountpoint, "%.*s", namelen, name);

	what = alloca(loclen + 1);
	memcpy(what, loc, loclen);
	what[loclen] = '\0';

	if (!strcmp(fstype, "autofs") && strchr(loc, ':') == NULL) {
		char mtype[7];
		int mtype_len;

		if (loc[0] == '/') {
			mtype_len = 5;
			if (loc[1] == '/')
				strcpy(mtype, "ldap:");
			else
				strcpy(mtype, "file:");
		} else {
			mtype_len = 3;
			strcpy(mtype, "yp:");
		}

		what = alloca(loclen + mtype_len + 1);
		memcpy(what, mtype, mtype_len);
		memcpy(what + mtype_len, loc, loclen);
		what[loclen + mtype_len] = '\0';
	} else {
		what = alloca(loclen + 1);
		memcpy(what, loc, loclen);
		what[loclen] = '\0';
	}

	debug(MODPREFIX
	    "mounting root %s, mountpoint %s, what %s, fstype %s, options %s\n",
	    root, mountpoint, what, fstype, options);

	if (!strcmp(fstype, "nfs")) {
		rv = mount_nfs->mount_mount(ap, root, mountpoint, strlen(mountpoint),
					    what, fstype, options, mount_nfs->context);
	} else {
		/* Generic mount routine */
		rv = do_mount(ap, root, mountpoint, strlen(mountpoint), what, fstype,
			      options);
	}

	if (nonstrict && rv)
		return -rv;

	return rv;
}

/*
 * Scan map entry looking for evidence it has multiple key/mapent
 * pairs.
 */
static int check_is_multi(const char *mapent)
{
	const char *p = (char *) mapent;
	int multi = 0;
	int not_first_chunk = 0;

	if (!p) {
		crit("check_is_multi: unexpected NULL map entry pointer");
		return 0;
	}
	
	/* If first character is "/" it's a multi-mount */
	if (*p == '/')
		return 1;

	while (*p) {
		p = skipspace(p);

		/*
		 * After the first chunk there can be additional
		 * locations (possibly not multi) or possibly an
		 * options string if the first entry includes the
		 * optional '/' (is multi). Following this any
		 * path that begins with '/' indicates a mutil-mount
		 * entry.
		 */
		if (not_first_chunk) {
			if (*p == '/' || *p == '-') {
				multi = 1;
				break;
			}
		}

		while (*p == '-') {
			p += chunklen(p, 0);
			p = skipspace(p);
		}

		/*
		 * Expect either a path or location
		 * after which it's a multi mount.
		 */
		p += chunklen(p, check_colon(p));
		not_first_chunk++;
	}

	return multi;
}

static int
add_offset_entry(struct mapent_cache *mc, const char *name,
		 const char *m_root, int m_root_len,
		 const char *path, const char *myoptions, const char *loc,
		 time_t age)
{
	char m_key[PATH_MAX + 1];
	char m_mapent[MAPENT_MAX_LEN + 1];
	int m_key_len, m_mapent_len;
	int ret;

	m_key_len = m_root_len + strlen(path) + 1;
	if (m_key_len > PATH_MAX) {
		error(MODPREFIX "multi mount key too long - ignored");
		return CHE_FAIL;
	}
	strcpy(m_key, m_root);
	strcat(m_key, path);

	m_mapent_len = strlen(myoptions) + strlen(loc) + 3;
	if (m_mapent_len > MAPENT_MAX_LEN) {
		error(MODPREFIX "multi mount mapent too long - ignored");
		return CHE_FAIL;
	}
	strcpy(m_mapent, "-");
	strcat(m_mapent, myoptions);
	strcat(m_mapent, " ");
	strcat(m_mapent, loc);

	debug("adding multi-mount offset %s -> %s", path, m_mapent);

	cache_writelock(mc);
	ret = cache_add_offset(mc, name, m_key, m_mapent, age);
	cache_unlock(mc);

	return ret;
}

#define AUTOFS_SUPER_MAGIC 0x0187L

static int mount_multi_triggers(struct autofs_point *ap, char *root, struct mapent *me, const char *base)
{
	char path[PATH_MAX + 1];
	char *offset = path;
	struct mapent *oe;
	struct list_head *pos = NULL;
	unsigned int fs_path_len;
	struct statfs fs;
	struct stat st;
	unsigned int is_autofs_fs;
	int ret, start;
	int count = 0, at_least_one = 0;

	fs_path_len = strlen(root) + strlen(base);
	if (fs_path_len > PATH_MAX)
		return 0;

	strcpy(path, root);
	strcat(path, base);
	ret = statfs(path, &fs);
	if (ret == -1)
		return 0;

	is_autofs_fs = fs.f_type == AUTOFS_SUPER_MAGIC ? 1 : 0;

	start = strlen(root);
	offset = cache_get_offset(base, offset, start, &me->multi_list, &pos);
	while (offset) {
		int plen = fs_path_len + strlen(offset);

		count++;

		if (plen > PATH_MAX) {
			warn("path loo long");
			goto cont;
		}

		oe = cache_lookup_offset(base, offset, start, &me->multi_list);
		if (!oe)
			goto cont;

		/*
		 * If the host filesystem is not an autofs fs
		 * we require the mount point directory exist
		 * and that permissions are OK.
		 */
		if (!is_autofs_fs) {
			ret = stat(oe->key, &st);
			if (ret == -1)
				goto cont;
		}

		debug("mount offset %s", oe->key);

		if (mount_autofs_offset(ap, oe, is_autofs_fs) < 0)
			warn("failed to mount offset");
		else
			at_least_one++;
cont:
		offset = cache_get_offset(base,
				offset, start, &me->multi_list, &pos);
	}

	return count ? at_least_one : 1;
}

static void parse_sun_cleanup(struct mapent_cache *mc, const char *name,
			 char *options, char *path, char *myoptions)
{
	cache_writelock(mc);
	cache_delete_offset_list(mc, name);
	cache_unlock(mc);

	if (options)
		free(options);

	if (path)
		free(path);

	if (myoptions)
		free(myoptions);
}

/*
 * syntax is:
 *	[-options] location [location] ...
 *	[-options] [mountpoint [-options] location [location] ... ]...
 *
 * There are three ways this routine can be called. One where we parse
 * offsets in a multi-mount entry adding them to the cache for later lookups.
 * Another where we parse a multi-mount entry looking for a root offset mount
 * and mount it if it exists and also mount its offsets down to the first
 * level nexting point. Finally to mount non multi-mounts and to mount a
 * lower level multi-mount nesting point and its offsets.
 */
int parse_mount(struct autofs_point *ap, const char *name,
		int name_len, const char *mapent, void *context)
{
	struct parse_context *ctxt = (struct parse_context *) context;
	char buf[MAX_ERR_BUF];
	struct mapent_cache *mc = ap->mc;
	struct mapent *me;
	char *pmapent, *options;
	const char *p;
	int mapent_len, rv = 0;
	int optlen;
	int slashify = ctxt->slashify_colons;

	if (!mapent) {
		error(MODPREFIX "error: empty map entry");
		return 1;
	}

	ctxt->subst = addstdenv(ctxt->subst);
	mapent_len = expandsunent(mapent, NULL, name, ctxt->subst, slashify);
	pmapent = alloca(mapent_len + 1);
	if (!pmapent) {	
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(MODPREFIX "alloca: %s", estr);
		return 1;
	}
	pmapent[mapent_len] = '\0';

	expandsunent(mapent, pmapent, name, ctxt->subst, slashify);
	ctxt->subst = removestdenv(ctxt->subst);

	debug(MODPREFIX "expanded entry: %s", pmapent);

	options = strdup(ctxt->optstr ? ctxt->optstr : "");
	if (!options) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(MODPREFIX "strdup: %s", estr);
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
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(MODPREFIX "concat_options: %s", estr);
				return 1;
			}
			p = skipspace(p);
		} while (*p == '-');
	}

	debug(MODPREFIX "gathered options: %s", options);

	if (check_is_multi(p)) {
		char *m_root = NULL;
		int m_root_len;
		char *root_path = NULL;
		char *root_loc = NULL;
		char *root_options = NULL;
		time_t age = time(NULL);
		int l;

		/* If name starts with "/" it's a direct mount */
		if (*name == '/') {
			m_root_len = name_len;
			m_root = alloca(m_root_len + 1);
			if (!m_root) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(MODPREFIX "alloca: %s", estr);
				free(options);
				return 1;
			}
			strcpy(m_root, name);
		} else {
			m_root_len = strlen(ap->path) + name_len + 1;
			m_root = alloca(m_root_len + 1);
			if (!m_root) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(MODPREFIX "alloca: %s", estr);
				free(options);
				return 1;
			}
			strcpy(m_root, ap->path);
			strcat(m_root, "/");
			strcat(m_root, name);
		}

		cache_writelock(mc);
		me = cache_lookup(mc, name);
		if (me) {
			/* So we know we're the multi-mount root */
			if (!me->multi)
				me->multi = me;
		}
		cache_unlock(mc);

		if (!me) {
			error(MODPREFIX "can't find multi root");
			free(options);
			return 1;
		}

		/* It's a multi-mount; deal with it */
		do {
			char *myoptions = strdup(options);
			char *path, *loc;
			int status;

			if (myoptions == NULL) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(MODPREFIX "multi strdup: %s", estr);
				parse_sun_cleanup(mc, name, options, NULL, NULL);
				return 1;
			}

			if (*p != '/') {
				l = 0;
				path = dequote("/", 1);
			} else
				path = dequote(p, l = chunklen(p, 0));

			if (!path) {
				error(MODPREFIX "out of memory");
				parse_sun_cleanup(mc, name, options, NULL, myoptions);
				return 1;
			}

			p += l;
			p = skipspace(p);

			/* Local options are appended to per-map options */
			if (*p == '-') {
				do {
					char *newopt = NULL;

					p = parse_options(p, &newopt);
					myoptions = concat_options(myoptions, newopt);

					if (myoptions == NULL) {
						char *estr;
						estr = strerror_r(errno, buf, MAX_ERR_BUF);
						error(MODPREFIX
						    "multi concat_options: %s", estr);
						parse_sun_cleanup(mc, name,
							options, NULL, NULL);
						return 1;
					}
					p = skipspace(p);
				} while (*p == '-');
			}

			/* Skip over colon escape */
			if (*p == ':')
				p++;

			loc = dequote(p, l = chunklen(p, check_colon(p)));
			if (!loc) {
				error(MODPREFIX "out of memory");
				parse_sun_cleanup(mc, name, options, path, myoptions);
				return 1;
			}

			p += l;
			p = skipspace(p);

			while (*p && *p != '/') {
				char *ent;

				ent = dequote(p, l = chunklen(p, check_colon(p)));
				if (!ent) {
					error(MODPREFIX "out of memory");
					parse_sun_cleanup(mc, name,
						options, path, myoptions);
					return 1;
				}

				loc = realloc(loc, strlen(loc) + l + 2);
				if (!loc) {
					error(MODPREFIX "out of memory");
					parse_sun_cleanup(mc, name,
						options, path, myoptions);
					free(ent);
					return 1;
				}

				strcat(loc, " ");
				strcat(loc, ent);

				free(ent);

				p += l;
				p = skipspace(p);
			}

			status = add_offset_entry(mc, name,
						m_root, m_root_len,
						path, myoptions, loc, age);

			if (!strcmp(path, "/")) {
				root_path = strdup(path);
				if (!root_path) {
					error(MODPREFIX "out of memory");
					parse_sun_cleanup(mc, name,
						options, path, myoptions);
					return 1;
				}
				root_loc = strdup(loc);
				if (!root_loc) {
					error(MODPREFIX "out of memory");
					parse_sun_cleanup(mc, name,
						options, path, myoptions);
					free(root_path);
					return 1;
				}
				root_options = strdup(myoptions);
				if (!root_options) {
					error(MODPREFIX "out of memory");
					parse_sun_cleanup(mc, name,
						options, path, myoptions);
					free(root_loc);
					free(root_path);
					return 1;
				}
			}
			free(loc);
			free(path);
			free(myoptions);
		} while (*p == '/');

		if (root_path) {
			rv = sun_mount(ap, m_root, root_path, strlen(root_path),
				root_loc, strlen(root_loc), root_options, ctxt);

			free(root_path);
			free(root_loc);
			free(root_options);

			if (rv < 0) {
				error("mount multi-mount root %s failed", name);
				cache_writelock(mc);
				cache_delete_offset_list(mc, name);
				cache_unlock(mc);
				return rv;
			}
		}

		cache_readlock(mc);
		if (!mount_multi_triggers(ap, m_root, me, "/")) {
			error("failed to mount offset triggers");
			rv = 1;
		}
		cache_unlock(mc);

		free(options);

		return rv;
	} else {
		/* Normal (and non-root multi-mount) entries */
		char *loc;
		int loclen;
		int l;

		if (*p == ':')
			p++;	/* Sun escape for entries starting with / */

		loc = dequote(p, l = chunklen(p, check_colon(p)));
		if (!loc) {
			error(MODPREFIX "out of memory");
			free(options);
			return 1;
		}

		p += l;
		p = skipspace(p);

		while (*p) {
			char *ent;

			ent = dequote(p, l = chunklen(p, check_colon(p)));
			if (!ent) {
				error(MODPREFIX "out of memory");
				free(options);
				return 1;
			}

			loc = realloc(loc, strlen(loc) + l + 2);
			if (!loc) {
				error(MODPREFIX "out of memory");
				free(ent);
				free(options);
				return 1;
			}

			strcat(loc, " ");
			strcat(loc, ent);

			free(ent);

			p += l;
			p = skipspace(p);
		}

		loclen = strlen(loc);
		if (loclen == 0) {
			error(MODPREFIX "entry %s is empty!", name);
			free(loc);
			free(options);
			return 1;
		}

		debug(MODPREFIX "core of entry: options=%s, loc=%.*s",
		      options, loclen, loc);

		rv = sun_mount(ap, ap->path, name, name_len, loc, loclen, options, ctxt);

		/* non-strict failure to normal failure for ordinary mount */
		if (rv < 0)
			rv = -rv;
			
		free(loc);
		free(options);

		/*
		 * If it's a multi-mount insert the triggers
		 * These are always direct mount triggers so root = ""
		 */
		cache_readlock(mc);
		me = cache_lookup(mc, name);
		if (me && me->multi) {
			char *m_key = me->multi->key;
			int start;
			char *base, *m_root;

			if (*m_key == '/') {
				m_root = m_key;
				start = strlen(m_key);
			} else {
				start = strlen(ap->path) + strlen(m_key) + 1;
				pthread_cleanup_push(cache_lock_cleanup, mc);
				m_root = alloca(start + 1);
				pthread_cleanup_pop(0);
				if (!m_root) {
					char *estr;
					estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error(MODPREFIX "alloca: %s", estr);
					return 1;
				}
				strcpy(m_root, ap->path);
				strcat(m_root, "/");
				strcat(m_root, m_key);
			}

			base = &me->key[start];

			if (!mount_multi_triggers(ap, m_root, me->multi, base)) {
				error("failed to mount offset triggers");
				rv = 1;
			}
		}
		cache_unlock(mc);
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
	if (ctxt)
		kill_context(ctxt);

	return rv;
}
