#ident "$Id: lookup_file.c,v 1.23 2006/02/20 01:05:32 raven Exp $"
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

typedef enum { got_nothing, got_star, got_real } FOUND_STATE;
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
		return 1;
	}

	ctxt->mapname = argv[0];

	if (ctxt->mapname[0] != '/') {
		crit(MODPREFIX "file map %s is not an absolute pathname",
		       ctxt->mapname);
		return 1;
	}

	if (access(ctxt->mapname, R_OK)) {
		crit(MODPREFIX "file map %s missing or not readable",
		       ctxt->mapname);
		return 1;
	}

	if (stat(ctxt->mapname, &st)) {
		crit(MODPREFIX "file map %s, could not stat",
		       ctxt->mapname);
		return 1;
	}
		
	ctxt->mtime = st.st_mtime;

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

/*	cache_init(); */

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
					state = st_compare;
					*(kptr++) = ch;
				}
			} else if (escape == esc_char);
			else
				state = st_badent;
			break;

		case st_compare:
			if (ch == '\n')
				state = st_begin;
			else if (isspace(ch) && !escape) {
				getting = got_real;
				state = st_entspc;
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

/*
static int do_plus_include(struct autofs_point *ap, char *key)
{
	char *map = key;
	struct autofs_point *iap;

	iap = malloc(sizeof(struct autofs_point));
	if (!iap) {
		error(MODPREFIX "could not malloc storage for included map");
		return NSS_STATUS_UNAVAIL;
	}
	memcpy(iap, ap, sizeof(struct autofs_point));

	*
	 * TODO:
	 * Initially just consider the passed in key to be a simple map
	 * name (and possible source) and use the global map options in
	 * the passed in autofs_point.
	 * Later we might parse this and fill in the autofs_point fields.
	 *

	map++;


}
*/

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
		if (entry)
			cache_update(key, mapent, age);

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

static int lookup_one(const char *root,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	char mkey[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	FILE *f;
	int entry;
	time_t age = time(NULL);

	f = fopen(ctxt->mapname, "r");
	if (!f) {
		error(MODPREFIX "could not open map file %s", ctxt->mapname);
		return CHE_FAIL;
	}

	while(1) {
		entry = read_one(f, mkey, mapent);
		if (entry)
			if (strncmp(mkey, key, key_len) == 0) {
				fclose(f);
				return cache_update(key, mapent, age);
			}

		if (feof(f))
			break;
	}

	fclose(f);

	return CHE_MISSING;
}

static int lookup_wild(const char *root, struct lookup_context *ctxt)
{
	char mkey[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	char *mapname;
	FILE *f;
	int entry;
	time_t age = time(NULL);

	mapname = alloca(strlen(ctxt->mapname) + 6);
	sprintf(mapname, "file:%s", ctxt->mapname);

	f = fopen(ctxt->mapname, "r");
	if (!f) {
		error(MODPREFIX "could not open map file %s", ctxt->mapname);
		return CHE_FAIL;
	}

	while(1) {
		entry = read_one(f, mkey, mapent);
		if (entry)
			if (strncmp(mkey, "*", 1) == 0) {
				fclose(f);
				return cache_update("*", mapent, age);
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
	struct stat st;
	struct mapent_cache *me, *exists;
	time_t now = time(NULL);
	time_t t_last_read;
	int need_hup = 0;
	int ret = 0;

	if (stat(ctxt->mapname, &st)) {
		crit(MODPREFIX "file map %s, could not stat", ctxt->mapname);
		return NSS_STATUS_TRYAGAIN;
	}

	me = cache_lookup_first();
	t_last_read = me ? now - me->age : ap->exp_runfreq + 1;

	/* only if it has been modified */
	if (st.st_mtime > ctxt->mtime) {
		exists = cache_lookup(key);

		ret = lookup_one(ap->path, key, key_len, ctxt);
		if (ret == CHE_FAIL)
			return NSS_STATUS_UNAVAIL;

		if (t_last_read > ap->exp_runfreq)
			if ((ret & CHE_UPDATED) ||
			    (exists && (ret & CHE_MISSING)))
				need_hup = 1;

		if (ret == CHE_MISSING) {
			int wild = CHE_MISSING;

			wild = lookup_wild(ap->path, ctxt);
			if (wild == CHE_MISSING)
				cache_delete("*");

			if (cache_delete(key) &&
					wild & (CHE_MISSING | CHE_FAIL))
				rmdir_path(key);
		}
	}

	/* Have parent update its map ? */
	if (need_hup)
		kill(getppid(), SIGHUP);

	if (ret == CHE_MISSING)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *me;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char mapent[MAPENT_MAX_LEN + 1];
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
		if (status) {
			debug(MODPREFIX "check indirect map failure");
			return status;
		}
	}

	me = cache_lookup(key);
	if (me) {
		mapent_len = sprintf(mapent, me->mapent);
		mapent[mapent_len] = '\0';
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
/*	cache_release(); */
	return rv;
}
