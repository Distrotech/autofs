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
				} else
					return 0;
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
				} else
					return 0;
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
		crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
		*context = NULL;
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
					error(LOGOPT_ANY, MODPREFIX "strdup: %s", estr);
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
					error(LOGOPT_ANY,
					      MODPREFIX "unknown option: %s",
					      argv[i]);
				break;

			default:
				error(LOGOPT_ANY,
				      MODPREFIX "unknown option: %s", argv[i]);
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
				crit(LOGOPT_ANY, MODPREFIX "%s", estr);
				*context = NULL;
				return 1;
			}
			ctxt->optstr = noptstr;
			debug(LOGOPT_NONE,
			      MODPREFIX "init gathered options: %s",
			      ctxt->optstr);
		}
	}

	/* We only need this once.  NFS mounts are so common that we cache
	   this module. */
	if (!mount_nfs) {
		if ((mount_nfs = open_mount("nfs", MODPREFIX))) {
			init_ctr++;
			return 0;
		} else {
			kill_context(ctxt);
			*context = NULL;
			return 1;
		}
	} else {
		init_ctr++;
		return 0;
	}
}

static const char *parse_options(const char *str, char **ret, unsigned int logopt)
{
	const char *cp = str;
	int len;

	if (*cp++ != '-')
		return str;

	if (*ret != NULL)
		free(*ret);

	len = chunklen(cp, 0);
	*ret = dequote(cp, len, logopt);

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
		error(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
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
			} else if (strncmp("bg", cp, 2) == 0 ||
				   strncmp("nofg", cp, 4) == 0) {
				continue;
			} else {
				memcpy(np, cp, comma - cp + 1);
				np += comma - cp + 1;
			}
		}

		if (np > noptions + len) {
			warn(ap->logopt, MODPREFIX "options string truncated");
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
			error(ap->logopt,
			      MODPREFIX "alloca failed for options");
		}
	}

	mountpoint = alloca(namelen + 1);
	sprintf(mountpoint, "%.*s", namelen, name);

	what = alloca(loclen + 1);
	memcpy(what, loc, loclen);
	what[loclen] = '\0';
/*
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
*/
		what = alloca(loclen + 1);
		memcpy(what, loc, loclen);
		what[loclen] = '\0';
/*	} */

	debug(ap->logopt,
	    MODPREFIX
	    "mounting root %s, mountpoint %s, what %s, fstype %s, options %s",
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
	const char *p = mapent;
	int multi = 0;
	int not_first_chunk = 0;

	if (!p) {
		crit(LOGOPT_ANY,
		     MODPREFIX "unexpected NULL map entry pointer");
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
add_offset_entry(struct autofs_point *ap, const char *name,
		 const char *m_root, int m_root_len,
		 const char *path, const char *myoptions, const char *loc,
		 time_t age)
{
	struct map_source *source;
	struct mapent_cache *mc;
	char m_key[PATH_MAX + 1];
	char m_mapent[MAPENT_MAX_LEN + 1];
	int p_len, m_key_len, m_options_len, m_mapent_len;
	int ret;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	if (!*path || !*loc) {
		error(ap->logopt,
		      MODPREFIX "syntax error in offset %s -> %s", path, loc);
		return CHE_FAIL;
	}

	p_len = strlen(path);
	/* Trailing '/' causes us pain */
	if (path[p_len - 1] == '/')
		p_len--;
	m_key_len = m_root_len + p_len;
	if (m_key_len > PATH_MAX) {
		error(ap->logopt, MODPREFIX "multi mount key too long");
		return CHE_FAIL;
	}
	strcpy(m_key, m_root);
	strncat(m_key, path, p_len);
	m_key[m_key_len] = '\0';

	m_options_len = 0;
	if (*myoptions)
		m_options_len = strlen(myoptions) + 2;

	m_mapent_len = strlen(loc);
	if (m_mapent_len + m_options_len > MAPENT_MAX_LEN) {
		error(ap->logopt, MODPREFIX "multi mount mapent too long");
		return CHE_FAIL;
	}

	if (*myoptions) {
		strcpy(m_mapent, "-");
		strcat(m_mapent, myoptions);
		strcat(m_mapent, " ");
		strcat(m_mapent, loc);
	} else
		strcpy(m_mapent, loc);

	cache_readlock(mc);
	cache_multi_lock(mc);
	ret = cache_add_offset(mc, name, m_key, m_mapent, age);
	cache_multi_unlock(mc);
	cache_unlock(mc);

	if (ret == CHE_OK)
		debug(ap->logopt, MODPREFIX
		      "added multi-mount offset %s -> %s", path, m_mapent);
	else
		debug(ap->logopt, MODPREFIX
		      "syntax error or dupliate offset %s -> %s", path, loc);

	return ret;
}

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

	fs_path_len = strlen(root) + strlen(base);
	if (fs_path_len > PATH_MAX)
		return 0;

	strcpy(path, root);
	strcat(path, base);
	ret = statfs(path, &fs);
	if (ret == -1) {
		/* There's no mount yet - it must be autofs */
		if (errno == ENOENT)
			is_autofs_fs = 1;
		else
			return 0;
	} else
		is_autofs_fs = fs.f_type == AUTOFS_SUPER_MAGIC ? 1 : 0;

	start = strlen(root);
	offset = cache_get_offset(base, offset, start, &me->multi_list, &pos);
	while (offset) {
		int plen = fs_path_len + strlen(offset);

		if (plen > PATH_MAX) {
			warn(ap->logopt, MODPREFIX "path loo long");
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

		debug(ap->logopt, MODPREFIX "mount offset %s", oe->key);

		if (mount_autofs_offset(ap, oe, is_autofs_fs) < 0)
			warn(ap->logopt, MODPREFIX "failed to mount offset");
cont:
		offset = cache_get_offset(base,
				offset, start, &me->multi_list, &pos);
	}

	return 1;
}

static int validate_location(char *loc)
{
	char *ptr = loc;

	/* We don't know much about these */
	if (*ptr == '/')
		return 1;

	/* If a ':' is present now it must be a host name */
	if (check_colon(ptr)) {
		if (!isalpha(*ptr++))
			return 0;

		while (*ptr && *ptr != ':') {
			if (!(isalnum(*ptr) ||
			    *ptr == '-' || *ptr == '.' || *ptr == ','))
				return 0;
			ptr++;
		}

		if (*ptr && *ptr == ':')
			ptr++;
	}

	/* Must always be something following */
	if (!*ptr)
		return 0;

	return 1;
}

static int parse_mapent(const char *ent, char *g_options, char **options, char **location, int logopt)
{
	char buf[MAX_ERR_BUF];
	const char *p;
	char *tmp, *myoptions, *loc;
	int l;

	p = ent;

	myoptions = strdup(g_options);
	if (!myoptions) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, MODPREFIX "strdup: %s", estr);
		return 0;
	}

	/* Local options are appended to per-map options */
	if (*p == '-') {
		do {
			char *tmp, *newopt = NULL;

			p = parse_options(p, &newopt, logopt);

			tmp = concat_options(myoptions, newopt);
			if (!tmp) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(logopt, MODPREFIX
				      "concat_options: %s", estr);
				free(myoptions);
				return 0;
			}
			myoptions = tmp;

			p = skipspace(p);
		} while (*p == '-');
	}

	/* Location can't begin with a '/' */
	if (*p == '/') {
		error(logopt, MODPREFIX "error location begins with \"/\"");
		free(myoptions);
		return 0;
	}

	/* Skip ':' escape */
	if (*p == ':')
		p++;

	l = chunklen(p, check_colon(p));
	loc = dequote(p, l, logopt);
	if (!loc) {
		error(logopt, MODPREFIX "out of memory");
		free(myoptions);
		return 0;
	}

	if (!validate_location(loc)) {
		error(logopt, MODPREFIX "invalid location");
		free(myoptions);
		free(loc);
		return 0;
	}

	debug(logopt, MODPREFIX "dequote(\"%.*s\") -> %s", l, p, loc);

	p += l;
	p = skipspace(p);

	while (*p && *p != '/') {
		char *ent;

		/* Location can't begin with a '/' */
		if (*p == '/') {
			error(logopt,
			      MODPREFIX "error location begins with \"/\"");
			free(myoptions);
			free(loc);
			return 0;
		}

		/* Skip ':' escape */
		if (*p == ':')
			p++;

		l = chunklen(p, check_colon(p));
		ent = dequote(p, l, logopt);
		if (!ent) {
			error(logopt, MODPREFIX "out of memory");
			free(myoptions);
			free(loc);
			return 0;
		}

		if (!validate_location(ent)) {
			error(logopt,
			      MODPREFIX "invalid location %s", ent);
			free(ent);
			free(myoptions);
			free(loc);
			return 0;
		}

		debug(logopt, MODPREFIX "dequote(\"%.*s\") -> %s", l, p, ent);

		loc = realloc(loc, strlen(loc) + l + 2);
		if (!loc) {
			error(logopt, MODPREFIX "out of memory");
			free(ent);
			free(myoptions);
			free(loc);
			return 0;
		}

		strcat(loc, " ");
		strcat(loc, ent);

		free(ent);

		p += l;
		p = skipspace(p);
	}

	*options = myoptions;
	*location = loc;

	return (p - ent);
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
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me, *ro;
	char *pmapent, *options;
	const char *p;
	int mapent_len, rv = 0;
	int optlen;
	int slashify = ctxt->slashify_colons;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	if (!mapent) {
		error(ap->logopt, MODPREFIX "error: empty map entry");
		return 1;
	}

	ctxt->subst = addstdenv(ctxt->subst);

	mapent_len = expandsunent(mapent, NULL, name, ctxt->subst, slashify);
	if (mapent_len == 0) {
		error(ap->logopt, MODPREFIX "failed to expand map entry");
		return 1;
	}

	pmapent = alloca(mapent_len + 1);
	if (!pmapent) {	
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "alloca: %s", estr);
		return 1;
	}
	pmapent[mapent_len] = '\0';

	expandsunent(mapent, pmapent, name, ctxt->subst, slashify);
	ctxt->subst = removestdenv(ctxt->subst);

	debug(ap->logopt, MODPREFIX "expanded entry: %s", pmapent);

	options = strdup(ctxt->optstr ? ctxt->optstr : "");
	if (!options) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "strdup: %s", estr);
		return 1;
	}
	optlen = strlen(options);

	p = skipspace(pmapent);

	/* Deal with 0 or more options */
	if (*p == '-') {
		char *mnt_options = NULL;

		do {
			char *noptions = NULL;

			p = parse_options(p, &noptions, ap->logopt);
			mnt_options = concat_options(mnt_options, noptions);

			if (mnt_options == NULL) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(ap->logopt,
				      MODPREFIX "concat_options: %s", estr);
				return 1;
			}
			p = skipspace(p);
		} while (*p == '-');

		if (options)
			free(options);

		options = mnt_options;
	}

	debug(ap->logopt, MODPREFIX "gathered options: %s", options);

	if (check_is_multi(p)) {
		char *m_root = NULL;
		int m_root_len;
		time_t age = time(NULL);
		int l;

		/* If name starts with "/" it's a direct mount */
		if (*name == '/') {
			m_root_len = name_len;
			m_root = alloca(m_root_len + 1);
			if (!m_root) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(ap->logopt, MODPREFIX "alloca: %s", estr);
				free(options);
				return 1;
			}
			strcpy(m_root, name);
		} else {
			m_root_len = strlen(ap->path) + name_len + 1;
			m_root = alloca(m_root_len + 1);
			if (!m_root) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(ap->logopt, MODPREFIX "alloca: %s", estr);
				free(options);
				return 1;
			}
			strcpy(m_root, ap->path);
			strcat(m_root, "/");
			strcat(m_root, name);
		}

		cache_writelock(mc);
		me = cache_lookup_distinct(mc, name);
		if (!me) {
			int ret;
			/*
			 * Not in the cache, perhaps it's a program map
			 * or one that doesn't support enumeration
			 */
			ret = cache_add(mc, source, name, mapent, time(NULL));
			if (ret == CHE_FAIL) {
				cache_unlock(mc);
				free(options);
				return 1;
			}
		}

		me = cache_lookup_distinct(mc, name);
		if (me) {
			/* So we know we're the multi-mount root */
			if (!me->multi)
				me->multi = me;
		}
		cache_unlock(mc);

		if (!me) {
			error(ap->logopt,
			      MODPREFIX "can't find multi root %s", name);
			free(options);
			return 1;
		}

		/* It's a multi-mount; deal with it */
		do {
			char *tmp, *path, *myoptions, *loc;
			int status;

			if (*p != '/') {
				l = 0;
				tmp = dequote("/", 1, ap->logopt);
				debug(ap->logopt,
				      MODPREFIX "dequote(\"/\") -> %s", tmp);
			} else {
				l = chunklen(p, 0);
				tmp = dequote(p, l, ap->logopt);
				debug(ap->logopt, MODPREFIX
				      "dequote(\"%.*s\") -> %s", l, p, tmp);
			}

			if (!tmp) {
				error(ap->logopt, MODPREFIX "out of memory");
				cache_readlock(mc);
				cache_multi_lock(mc);
				cache_delete_offset_list(mc, name);
				cache_multi_unlock(mc);
				cache_unlock(mc);
				free(options);
				return 1;
			}

			path = sanitize_path(tmp, strlen(tmp));
			if (!path) {
				error(ap->logopt, MODPREFIX "invalid path");
				cache_readlock(mc);
				cache_multi_lock(mc);
				cache_delete_offset_list(mc, name);
				cache_multi_unlock(mc);
				cache_unlock(mc);
				free(tmp);
				free(options);
				return 1;
			}
			free(tmp);

			p += l;
			p = skipspace(p);

			l = parse_mapent(p, options, &myoptions, &loc, ap->logopt);
			if (!l) {
				cache_readlock(mc);
				cache_multi_lock(mc);
				cache_delete_offset_list(mc, name);
				cache_multi_unlock(mc);
				cache_unlock(mc);
				free(path);
				free(options);
				return 1;
			}

			p += l;
			p = skipspace(p);

			master_source_current_wait(ap->entry);
			ap->entry->current = source;

			status = add_offset_entry(ap, name,
						m_root, m_root_len,
						path, myoptions, loc, age);

			if (status != CHE_OK) {
				error(ap->logopt, MODPREFIX "error adding multi-mount");
				cache_readlock(mc);
				cache_multi_lock(mc);
				cache_delete_offset_list(mc, name);
				cache_multi_unlock(mc);
				cache_unlock(mc);
				free(path);
				free(options);
				free(myoptions);
				free(loc);
				return 1;
			}

			free(loc);
			free(path);
			free(myoptions);
		} while (*p == '/');

		cache_readlock(mc);
		if (!me) {
			error(ap->logopt,
			      MODPREFIX
			      "failed to find cache entry for %s", name);
			cache_multi_lock(mc);
			cache_delete_offset_list(mc, name);
			cache_multi_unlock(mc);
			cache_unlock(mc);
			free(options);
			return 1;
		}

		/* Mount root offset if it exists */
		ro = cache_lookup_offset("/", "/", strlen(m_root), &me->multi_list);
		if (ro) {
			char *myoptions, *loc;

			rv = parse_mapent(ro->mapent,
				options, &myoptions, &loc, ap->logopt);
			if (!rv) {
				error(ap->logopt,
				      MODPREFIX "mount of root offset failed");
				cache_multi_lock(mc);
				cache_delete_offset_list(mc, name);
				cache_multi_unlock(mc);
				cache_unlock(mc);
				free(options);
				return 1;
			}

			rv = sun_mount(ap, m_root,
				"/", 1, loc, strlen(loc), myoptions, ctxt);

			free(myoptions);
			free(loc);

			if (rv < 0) {
				error(ap->logopt,
				      MODPREFIX
				      "mount multi-mount root %s failed", name);
				cache_multi_lock(mc);
				cache_delete_offset_list(mc, name);
				cache_multi_unlock(mc);
				cache_unlock(mc);
				free(options);
				return rv;
			}
		}

		if (!mount_multi_triggers(ap, m_root, me, "/")) {
			error(ap->logopt,
			      MODPREFIX "failed to mount offset triggers");
			free(options);
			return 1;
		}
		cache_unlock(mc);

		free(options);

		return rv;
	} else {
		/* Normal (and non-root multi-mount) entries */
		char *loc;
		int loclen;
		int l;

		/* Location can't begin with a '/' */
		if (*p == '/') {
			error(ap->logopt,
			      MODPREFIX "error location begins with \"/\"");
			free(options);
			return 1;
		}

		if (*p == ':')
			p++;	/* Sun escape for entries starting with / */

		l = chunklen(p, check_colon(p));
		loc = dequote(p, l, ap->logopt);
		if (!loc) {
			error(ap->logopt, MODPREFIX "out of memory");
			free(options);
			return 1;
		}

		if (!*loc) {
			error(ap->logopt, MODPREFIX "invalid location");
			free(loc);
			free(options);
			return 1;
		}

		if (!validate_location(loc)) {
			error(ap->logopt, MODPREFIX "invalid location");
			free(loc);
			free(options);
			return 1;
		}

		debug(ap->logopt,
		      MODPREFIX "dequote(\"%.*s\") -> %s", l, p, loc);

		p += l;
		p = skipspace(p);

		while (*p) {
			char *ent;

			l = chunklen(p, check_colon(p));
			ent = dequote(p, l, ap->logopt);
			if (!ent) {
				error(ap->logopt, MODPREFIX "out of memory");
				free(loc);
				free(options);
				return 1;
			}

			if (!validate_location(ent)) {
				error(ap->logopt, MODPREFIX "invalid location");
				free(ent);
				free(loc);
				free(options);
				return 1;
			}

			debug(ap->logopt,
			      MODPREFIX "dequote(\"%.*s\") -> %s", l, p, ent);

			loc = realloc(loc, strlen(loc) + l + 2);
			if (!loc) {
				error(ap->logopt, MODPREFIX "out of memory");
				free(ent);
				free(loc);
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
			error(ap->logopt,
			      MODPREFIX "entry %s is empty!", name);
			free(loc);
			free(options);
			return 1;
		}

		debug(ap->logopt,
		      MODPREFIX "core of entry: options=%s, loc=%.*s",
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
		me = cache_lookup_distinct(mc, name);
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
					cache_unlock(mc);
					estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error(ap->logopt,
					      MODPREFIX "alloca: %s", estr);
					return 1;
				}
				strcpy(m_root, ap->path);
				strcat(m_root, "/");
				strcat(m_root, m_key);
			}

			base = &me->key[start];

			cache_multi_lock(mc);
			if (!mount_multi_triggers(ap, m_root, me->multi, base)) {
				error(ap->logopt,
				      MODPREFIX "failed to mount offset triggers");
				rv = 1;
			}
			cache_multi_unlock(mc);
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
