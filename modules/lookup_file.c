#ident "$Id: lookup_file.c,v 1.4 2004/01/29 16:01:22 raven Exp $"
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <syslog.h>
#include <mntent.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(file): "

typedef enum {
	st_begin, st_compare, st_star, st_badent, st_entspc, st_getent
} LOOKUP_STATE;

typedef enum { got_nothing, got_star, got_real } FOUND_STATE;
typedef enum { esc_none, esc_char, esc_val } ESCAPES;


struct lookup_context {
	const char *mapname;
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;

	if (!(*context = ctxt = malloc(sizeof(struct lookup_context)))) {
		crit(MODPREFIX "malloc: %m");
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

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	cache_init();

	return !(ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1));
}

static int read_map(const char *root, struct lookup_context *ctxt)
{
	char key[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	char *kptr, *p;
	int mapent_len;
	char *mapname;
	FILE *f;
	int ch, nch;
	LOOKUP_STATE state;
	FOUND_STATE getting, gotten;
	ESCAPES escape;
	time_t age = time(NULL);

	chdir("/");

	mapname = alloca(strlen(ctxt->mapname) + 6);
	sprintf(mapname, "file:%s", ctxt->mapname);

	f = fopen(ctxt->mapname, "r");
	if (!f) {
		error(MODPREFIX "could not open map file %s", ctxt->mapname);
		return 0;
	}

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
				} else if (isprint((char) ch)) {
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
			else if (isprint((char) ch))
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
			}
			break;
		}
		continue;

	      got_it:
		if (gotten == got_nothing)
			goto next;

		cache_update(key, mapent, age);

	      next:
		kptr = key;
		p = NULL;
		mapent_len = 0;
		memset(key, 0, KEY_MAX_LEN + 1);
		memset(mapent, 0, MAPENT_MAX_LEN + 1);
		getting = gotten = got_nothing;
		escape = esc_none;
	}
	fclose(f);

	/* Clean stale entries from the cache */
	cache_clean(root, age);

	return 1;
}

int lookup_ghost(const char *root, int ghost, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *me;
	int status = 1;

	if (!read_map(root, ctxt))
		return LKP_FAIL;

	status = cache_ghost(root, ghost, ctxt->mapname, "file", ctxt->parse);

	me = cache_lookup_first();
	/* me NULL => empty map */
	if (me == NULL)
		return LKP_FAIL;

	if (*me->key == '/' && *(root + 1) != '-') {
		me = cache_partial_match(root);
		/* 
		 * me NULL => no entries for this direct mount
		 * root or indirect map
		 */
		if (me == NULL)
			return LKP_FAIL | LKP_INDIRECT;
	}

	return status;
}

static int lookup(const char *root, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	char key[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	struct mapent_cache *me = NULL;
	int status = -1;

	me = cache_lookup(name);
	if (me == NULL)
		if (sprintf(key, "%s/%s", root, name))
			me = cache_lookup(key);

	if (me == NULL) {
		/* path component, do submount */
		me = cache_partial_match(key);
		if (me)
			sprintf(mapent, "-fstype=autofs file:%s", ctxt->mapname);
	} else
		sprintf(mapent, me->mapent);

	if (me) {
		debug(MODPREFIX "%s -> %s", name, mapent);
		status = ctxt->parse->parse_mount(root, name, name_len,
						  mapent, ctxt->parse->context);
	}
	return status;
}

int lookup_mount(const char *root, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int status;

	status = lookup(root, name, name_len, ctxt);
	if (status == -1) {
		/* all else fails read entire map */
		if (!read_map(root, ctxt))
			return 1;

		status = lookup(root, name, name_len, ctxt);
	}
	return status;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	cache_release();
	return rv;
}
