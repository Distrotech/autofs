#ident "$Id: lookup_file.c,v 1.26 2006/03/01 23:51:13 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  lookup_file.c - module for Linux automount to query a flat file map
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2001-2003 Ian Kent <raven@themaw.net>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <syslog.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(file): "

typedef enum {
	st_begin, st_compare, st_star, st_badent, st_entspc, st_getent
} LOOKUP_STATE;

typedef enum { got_nothing, got_star, got_real, got_plus } FOUND_STATE;
typedef enum { esc_none, esc_char, esc_val } ESCAPES;


struct lookup_context {
	const char *mapname;
	time_t mtime;
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	struct stat st;

	if (!(*context = ctxt = malloc(sizeof(struct lookup_context)))) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	if (argc < 1) {
		crit(MODPREFIX "No map name");
		free(ctxt);
		return 1;
	}

	ctxt->mapname = argv[0];

	if (ctxt->mapname[0] != '/') {
		crit(MODPREFIX "file map %s is not an absolute pathname",
		       ctxt->mapname);
		free(ctxt);
		return 1;
	}

	if (access(ctxt->mapname, R_OK)) {
		warn(MODPREFIX "file map %s missing or not readable",
		       ctxt->mapname);
		free(ctxt);
		return 1;
	}

	if (stat(ctxt->mapname, &st)) {
		crit(MODPREFIX "file map %s, could not stat",
		       ctxt->mapname);
		free(ctxt);
		return 1;
	}
		
	ctxt->mtime = st.st_mtime;

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	return !(ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1));
}

static int read_one(FILE *f, char *key, char *mapent)
{
	char *kptr, *p;
	int mapent_len;
	int ch, nch;
	LOOKUP_STATE state;
	FOUND_STATE getting, gotten;
	ESCAPES escape;

	kptr = key;
	p = NULL;
	mapent_len = 0;
	state = st_begin;
	memset(key, 0, KEY_MAX_LEN + 1);
	memset(mapent, 0, MAPENT_MAX_LEN + 1);
	getting = gotten = got_nothing;
	escape = esc_none;

	/* This is ugly.  We can't just remove \ escape sequences in the value
	   portion of an entry, because the parsing routine may need it. */

	while ((ch = getc(f)) != EOF) {
		switch (escape) {
		case esc_none:
			if (ch == '\\') {
				/* Handle continuation lines */
				if ((nch = getc(f)) == '\n')
					continue;
				ungetc(nch, f);
				escape = esc_char;
			}
			break;

		case esc_char:
			escape = esc_val;
			break;

		case esc_val:
			escape = esc_none;
			break;
		}

		switch (state) {
		case st_begin:
			if (!escape) {
				if (isspace(ch));
				else if (ch == '#')
					state = st_badent;
				else if (ch == '*') {
					state = st_star;
					*(kptr++) = ch;
				} else {
					if (ch == '+')
						gotten = got_plus;
					state = st_compare;
					*(kptr++) = ch;
				}
			} else if (escape == esc_char);
			else
				state = st_badent;
			break;

		case st_compare:
			if (ch == '\n') {
				state = st_begin;
				if (gotten == got_plus)
					goto got_it;
			} else if (isspace(ch) && !escape) {
				getting = got_real;
				state = st_entspc;
				if (gotten == got_plus)
					goto got_it;
			} else if (escape == esc_char);
			else
				*(kptr++) = ch;
			break;

		case st_star:
			if (ch == '\n')
				state = st_begin;
			else if (isspace(ch) && gotten < got_star && !escape) {
				getting = got_star;
				state = st_entspc;
			} else if (escape != esc_char)
				state = st_badent;
			break;

		case st_badent:
			if (ch == '\n')
				state = st_begin;
			break;

		case st_entspc:
			if (ch == '\n')
				state = st_begin;
			else if (!isspace(ch) || escape) {
				state = st_getent;
				p = mapent;
				gotten = getting;
				*(p++) = ch;
				mapent_len = 1;
			}
			break;

		case st_getent:
			if (ch == '\n') {
				state = st_begin;
				if (gotten == got_real || gotten == getting)
					goto got_it;
			} else if (mapent_len < MAPENT_MAX_LEN) {
				mapent_len++;
				*(p++) = ch;
				nch = getc(f);
				if (nch == EOF &&
				   (gotten == got_real || gotten == getting))
				   	goto got_it;
				ungetc(nch, f);
			}
			break;
		}
		continue;

	      got_it:
		if (gotten == got_nothing)
			goto next;

		return 1;

	      next:
		kptr = key;
		p = NULL;
		mapent_len = 0;
		memset(key, 0, KEY_MAX_LEN + 1);
		memset(mapent, 0, MAPENT_MAX_LEN + 1);
		getting = gotten = got_nothing;
		escape = esc_none;
	}

	return 0;
}

static struct autofs_point *prepare_plus_include(struct autofs_point *ap, char *key)
{
	struct autofs_point *iap;
	char *type, *map, *fmt;
	char *buf;
	char *tmp;

	iap = malloc(sizeof(struct autofs_point));
	if (!iap) {
		error(MODPREFIX "could not malloc storage for included map");
		return NULL;
	}
	memcpy(iap, ap, sizeof(struct autofs_point));

	/*
	 * TODO:
	 * Initially just consider the passed in key to be a simple map
	 * name (and possible source) and use the global map options in
	 * the given autofs_point. ie. global options override.
	 *
	 * Later we might want to parse this and fill in the autofs_point
	 * options fields.
	 */
	/* skip plus */
	buf = strdup(key + 1);
	if (!buf) {
		error(MODPREFIX "failed to strdup key");
		free(iap);
		return NULL;
	}

	type = fmt = NULL;

	/* Look for space terminator - ignore local options */
	map = buf;
	for (tmp = buf; *tmp; tmp++) {
		if (*tmp == ' ') {
			*tmp = '\0';
			break;
		} else if (*tmp == ',') {
			type = buf;
			*tmp++ = '\0';
			fmt = tmp;
		} else if (*tmp == ':') {
			if (!fmt)
				type = buf;
			*tmp++ = '\0';
			map = tmp;
		}
		if (*tmp == '\\')
			tmp++;
	}

	iap->maptype = NULL;
	if (type) {
		iap->maptype = strdup(type);
		if (!iap->maptype) {
			error(MODPREFIX "failed to strdup key");
			free(iap);
			free(buf);
			return NULL;
		}
	}

	iap->mapfmt = NULL;
	if (fmt) {
		iap->mapfmt = strdup(fmt);
		if (!iap->mapfmt) {
			error(MODPREFIX "failed to strdup key");
			free(iap->maptype);
			free(iap);
			free(buf);
			return NULL;
		}
	}

	if (ap->mapargc >= 1) {
		iap->mapargv = copy_argv(ap->mapargc, ap->mapargv);
		if (!iap->mapargv) {
			error(MODPREFIX "failed to copy args");
			free(iap->maptype);
			free(iap->mapfmt);
			free(iap);
			free(buf);
			return NULL;
		}
		if (iap->mapargv[0])
			free((char *) iap->mapargv[0]);
		iap->mapargv[0] = strdup(map);
		if (!iap->mapargv[0]) {
			error(MODPREFIX "failed to dup map name");
			free_argv(iap->mapargc, iap->mapargv);
			free(iap->maptype);
			free(iap->mapfmt);
			free(iap);
			free(buf);
			return NULL;
		}
	} else {
		error("invalid arguments for autofs_point");
		free(iap->maptype);
		free(iap->mapfmt);
		free(iap);
		free(buf);
		return NULL;
	}

	free(buf);

	return iap;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	char *key;
	char *mapent;
	struct stat st;
	FILE *f;
	int entry;

	key = malloc(KEY_MAX_LEN + 1);
	if (!key) {
		error(MODPREFIX "could not malloc storage for key");
		return NSS_STATUS_UNAVAIL;
	}

	mapent = malloc(MAPENT_MAX_LEN + 1);
	if (!mapent) {
		error(MODPREFIX "could not malloc storage for mapent");
		free(key);
		return NSS_STATUS_UNAVAIL;
	}

	f = fopen(ctxt->mapname, "r");
	if (!f) {
		error(MODPREFIX "could not open map file %s", ctxt->mapname);
		free(key);
		free(mapent);
		return NSS_STATUS_UNAVAIL;
	}

	while(1) {
		entry = read_one(f, key, mapent);
		if (entry) {
			/*
			 * If key starts with '+' it has to be an
			 * included map.
			 */
			if (*key == '+') {
				struct autofs_point *iap;
				int status;

				iap = prepare_plus_include(ap, key);
				if (!iap) {
					warn("failed to include map %s", key);
					continue;
				}

				/* Gim'ee some o' that 16k stack baby !! */
				status = lookup_nss_read_map(iap, age);
				if (!status)
					warn("failed to read included map %s", key);

				free_argv(iap->mapargc, iap->mapargv);
				free(iap->maptype);
				free(iap->mapfmt);
				free(iap);
			} else {
				cache_writelock();
				cache_update(key, mapent, age);
				cache_unlock();
			}
		}

		if (feof(f))
			break;
	}

	if (fstat(fileno(f), &st)) {
		crit(MODPREFIX "file map %s, could not stat",
		       ctxt->mapname);
		free(key);
		free(mapent);
		return NSS_STATUS_UNAVAIL;
	}
	ctxt->mtime = st.st_mtime;

	fclose(f);

	free(key);
	free(mapent);

	return NSS_STATUS_SUCCESS;
}

static int lookup_one(struct autofs_point *ap,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	char mkey[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	time_t age = time(NULL);
	FILE *f;
	int entry, ret;

	f = fopen(ctxt->mapname, "r");
	if (!f) {
		error(MODPREFIX "could not open map file %s", ctxt->mapname);
		return CHE_FAIL;
	}

	while(1) {
		entry = read_one(f, mkey, mapent);
		if (entry) {
			/*
			 * If key starts with '+' it has to be an
			 * included map.
			 */
			if (*mkey == '+') {
				struct autofs_point *iap;
				int status;

				iap = prepare_plus_include(ap, mkey);
				if (!iap) {
					warn("failed to select included map %s", mkey);
					continue;
				}

				/* Gim'ee some o' that 16k stack baby !! */
				status = lookup_nss_mount(iap, key, key_len);

				free_argv(iap->mapargc, iap->mapargv);
				free(iap->maptype);
				free(iap->mapfmt);
				free(iap);

				if (status)
					return CHE_COMPLETED;
			} else if (strncmp(mkey, key, key_len) == 0) {
				fclose(f);
				cache_writelock();
				ret = cache_update(key, mapent, age);
				cache_unlock();
				return ret;
			}
		}

		if (feof(f))
			break;
	}

	fclose(f);

	return CHE_MISSING;
}

static int lookup_wild(struct autofs_point *ap, struct lookup_context *ctxt)
{
	char mkey[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	time_t age = time(NULL);
	char *mapname;
	FILE *f;
	int entry, ret;

	mapname = alloca(strlen(ctxt->mapname) + 6);
	sprintf(mapname, "file:%s", ctxt->mapname);

	f = fopen(ctxt->mapname, "r");
	if (!f) {
		error(MODPREFIX "could not open map file %s", ctxt->mapname);
		return CHE_FAIL;
	}

	while(1) {
		entry = read_one(f, mkey, mapent);
		if (entry) {
			/*
			 * If key starts with '+' it has to be an
			 * included map.
			 */
			if (*mkey == '+') {
				struct autofs_point *iap;
				int status;

				iap = prepare_plus_include(ap, mkey);
				if (!iap) {
					warn("failed to select included map %s", mkey);
					continue;
				}

				/* Gim'ee some o' that 16k stack baby !! */
				status = lookup_nss_mount(iap, "*", 1);

				free_argv(iap->mapargc, iap->mapargv);
				free(iap->maptype);
				free(iap->mapfmt);
				free(iap);

				if (status)
					return CHE_COMPLETED;
			} else if (strncmp(mkey, "*", 1) == 0) {
				fclose(f);
				cache_writelock();
				ret = cache_update("*", mapent, age);
				cache_unlock();
				return ret;
			}
		}

		if (feof(f))
			break;
	}

	fclose(f);

	return CHE_MISSING;
}

static int check_map_indirect(struct autofs_point *ap,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct mapent_cache *me, *exists;
	time_t now = time(NULL);
	time_t t_last_read;
	int need_hup = 0;
	int ret = CHE_OK;

	cache_readlock();
	exists = cache_lookup(key);
	cache_unlock();

	ret = lookup_one(ap, key, key_len, ctxt);
	debug("ret=%d", ret);
	if (ret == CHE_FAIL || ret == CHE_COMPLETED)
		return ret;

	if ((ret & CHE_UPDATED) ||
	    (exists && (ret & CHE_MISSING)))
		need_hup = 1;

	if (ret == CHE_MISSING) {
		int wild = CHE_MISSING;

		wild = lookup_wild(ap, ctxt);
		if (wild == CHE_FAIL || wild == CHE_COMPLETED)
			return wild;

		cache_writelock();
		if (wild == CHE_MISSING)
			cache_delete("*");

		if (cache_delete(key) &&
			wild & (CHE_MISSING | CHE_FAIL))
			rmdir_path(key);
		cache_unlock();
	}

	/* Have parent update its map ? */
	if (need_hup)
		kill(getppid(), SIGHUP);

	return ret;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *me;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	int mapent_len;
	int status = 0;
	int ret = 1;

	debug(MODPREFIX "looking up %s", name);

	key_len = snprintf(key, KEY_MAX_LEN, "%s", name);
	if (key_len > KEY_MAX_LEN)
		return NSS_STATUS_NOTFOUND;

	/*
	 * We can't check the direct mount map as if it's not in
	 * the map cache already we never get a mount lookup, so
	 * we never know about it.
	 */
	if (ap->type == LKP_INDIRECT) {
		status = check_map_indirect(ap, key, key_len, ctxt);
		/* Found and mounted in nss lookup ? */
		if (status == CHE_COMPLETED)
			return NSS_STATUS_SUCCESS;

		if (status) {
			debug(MODPREFIX "check indirect map lookup failed");
			return status;
		}
	}

	cache_readlock();
	me = cache_lookup(key);
	if (me) {
		pthread_cleanup_push(cache_lock_cleanup, NULL);
		mapent = alloca(strlen(me->mapent) + 1);
		mapent_len = sprintf(mapent, me->mapent);
		pthread_cleanup_pop(0);
		mapent[mapent_len] = '\0';
	}
	cache_unlock();

	if (mapent) {
		debug(MODPREFIX "%s -> %s", key, mapent);
		ret = ctxt->parse->parse_mount(ap, key, key_len,
					mapent, ctxt->parse->context);
	}

	if (ret)
		return NSS_STATUS_TRYAGAIN;

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	return rv;
}
