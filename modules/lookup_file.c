#ident "$Id: lookup_file.c,v 1.36 2006/03/31 18:26:16 raven Exp $"
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
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(file): "

#define MAX_INCLUDE_DEPTH	16

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
		debug(MODPREFIX "file map %s is not an absolute pathname",
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

static int check_master_self_include(struct master *master, struct lookup_context *ctxt)
{
	char *m_path, *m_base, *i_path, *i_base;

	i_path = strdup(ctxt->mapname);
	if (!i_path)
		return 0;
	i_base = basename(i_path);

	m_path = strdup(master->name);
	if (!m_path) {
		free(i_path);
		return 0;
	}
	m_base = basename(m_path);

	if (!strcmp(m_base, i_base)) {
		free(i_path);
		free(m_path);
		return  1;
	}
	free(i_path);
	free(m_path);

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int timeout = master->default_timeout;
	unsigned int logging = master->default_logging;
	char *buffer;
	int blen;
	char *path;
	char *ent;
	struct stat st;
	FILE *f;
	int entry;

	if (master->recurse)
		return NSS_STATUS_UNAVAIL;

	if (master->depth > MAX_INCLUDE_DEPTH) {
		error("maximum include depth exceeded %s", master->name);
		return NSS_STATUS_UNAVAIL;
	}

	path = malloc(KEY_MAX_LEN + 1);
	if (!path) {
		error(MODPREFIX "could not malloc storage for path");
		return NSS_STATUS_UNAVAIL;
	}

	ent = malloc(MAPENT_MAX_LEN + 1);
	if (!ent) {
		error(MODPREFIX "could not malloc storage for mapent");
		free(path);
		return NSS_STATUS_UNAVAIL;
	}

	f = fopen(ctxt->mapname, "r");
	if (!f) {
		error(MODPREFIX "could not open master map file %s", ctxt->mapname);
		free(path);
		free(ent);
		return NSS_STATUS_UNAVAIL;
	}

	master_init_scan();
	while(1) {
		entry = read_one(f, path, ent);
		if (!entry) {
			if (feof(f))
				break;
			continue;
		}

		debug(MODPREFIX "read entry %s", path);

		/*
		 * If key starts with '+' it has to be an
		 * included map.
		 */
		if (*path == '+') {
			char *save_name;
			unsigned int inc;
			int status;

			save_name = master->name;
			master->name = path + 1;

			inc = check_master_self_include(master, ctxt);
			if (inc) 
				master->recurse = 1;;
			master->depth++;
			status = lookup_nss_read_master(master, age);
			if (!status)
				warn(MODPREFIX "failed to read included master map %s",
				     master->name);
			master->depth--;
			master->recurse = 0;

			master->name = save_name;
		} else {
			blen = strlen(path) + 1 + strlen(ent) + 1;
			buffer = malloc(blen);
			if (!buffer) {
				error(MODPREFIX "could not malloc parse buffer");
				free(path);
				free(ent);
				return NSS_STATUS_UNAVAIL;
			}
			memset(buffer, 0, blen);

			strcpy(buffer, path);
			strcat(buffer, " ");
			strcat(buffer, ent);

			master_parse_entry(buffer, timeout, logging, age);

			free(buffer);
		}

		if (feof(f))
			break;
	}

	if (fstat(fileno(f), &st)) {
		crit(MODPREFIX "file map %s, could not stat",
		       ctxt->mapname);
		free(path);
		free(ent);
		return NSS_STATUS_UNAVAIL;
	}
	ctxt->mtime = st.st_mtime;

	fclose(f);

	free(path);
	free(ent);

	return NSS_STATUS_SUCCESS;
}

static int check_self_include(const char *key, struct lookup_context *ctxt)
{
	char *m_key, *m_base, *i_key, *i_base;

	i_key = strdup(key + 1);
	if (!i_key)
		return 0;
	i_base = basename(i_key);

	m_key = strdup(ctxt->mapname);
	if (!m_key) {
		free(i_key);
		return 0;
	}
	m_base = basename(m_key);

	if (!strcmp(m_base, i_base)) {
		free(i_key);
		free(m_key);
		return 1;
	}
	free(i_key);
	free(m_key);

	return 0;
}

static struct autofs_point *
prepare_plus_include(struct autofs_point *ap, time_t age, char *key, unsigned int inc)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *current = ap->entry->current;
	struct map_source *source;
	struct autofs_point *iap;
	char *type, *map, *fmt;
	const char *argv[2];
	int ret, argc;
	unsigned int timeout = ap->exp_timeout;
	unsigned int logopt = ap->logopt;
	unsigned int ghost = ap->ghost;
	char *buf, *tmp;

	entry = master_new_mapent(ap->path, ap->entry->age);
	if (!entry) {
		error(MODPREFIX "malloc failed for entry");
		return NULL;
	}

	ret = master_add_autofs_point(entry, timeout, logopt, ghost, 0);
	if (!ret) {
		error(MODPREFIX "failed to add autofs_point to entry");
		master_free_mapent(entry);
		return NULL;
	}
	iap = entry->ap;

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
		master_free_mapent(entry);
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

	argc = 1;
	argv[0] = map;
	argv[1] = NULL;

	source = master_add_map_source(entry, type, fmt, age, argc, argv);
	if (!source) {
		error("failed to creat map_source");
		master_free_mapent(entry);
		free(buf);
		return NULL;
	}
	source->mc = current->mc;
	source->depth = current->depth + 1;
	if (inc)
		source->recurse = 1;

	free(buf);

	return iap;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	char *key;
	char *mapent;
	struct stat st;
	FILE *f;
	int entry;

	if (source->recurse)
		return NSS_STATUS_UNAVAIL;

	if (source->depth > MAX_INCLUDE_DEPTH) {
		error("maximum include depth exceeded %s", ctxt->mapname);
		return NSS_STATUS_UNAVAIL;
	}

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
		if (!entry) {
			if (feof(f))
				break;
			continue;
		}
			
		/*
		 * If key starts with '+' it has to be an
		 * included map.
		 */
		if (*key == '+') {
			struct autofs_point *iap;
			unsigned int inc;
			int status;

			debug("read included map %s", key);

			inc = check_self_include(key, ctxt);

			iap = prepare_plus_include(ap, age, key, inc);
			if (!iap) {
				debug("failed to select included map %s", key);
				continue;
			}

			/* Gim'ee some o' that 16k stack baby !! */
			status = lookup_nss_read_map(iap, age);
			if (!status)
				warn("failed to read included map %s", key);

			master_free_mapent_sources(iap->entry, 0);
			master_free_mapent(iap->entry);
		} else {
			if (ap->type == LKP_INDIRECT && *key == '/')
				continue;

			if (ap->type == LKP_DIRECT && *key != '/')
				continue;

			cache_writelock(mc);
			cache_update(mc, source, key, mapent, age);
			cache_unlock(mc);
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
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
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
				unsigned int inc;
				int status;

				debug("lookup included map %s", key);

				inc = check_self_include(mkey, ctxt);

				iap = prepare_plus_include(ap, age, mkey, inc);
				if (!iap) {
					debug("failed to select included map %s", key);
					continue;
				}

				/* Gim'ee some o' that 16k stack baby !! */
				status = lookup_nss_mount(iap, key, key_len);

				master_free_mapent_sources(iap->entry, 0);
				master_free_mapent(iap->entry);

				if (status)
					return CHE_COMPLETED;
			} else if (strncmp(mkey, key, key_len) == 0) {
				fclose(f);
				cache_writelock(mc);
				ret = cache_update(mc, source, key, mapent, age);
				cache_unlock(mc);
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
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
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
				unsigned int inc;
				int status;

				inc = check_self_include(mkey, ctxt);

				iap = prepare_plus_include(ap, age, mkey, inc);
				if (!iap) {
					debug("failed to select included map %s", mkey);
					continue;
				}

				/* Gim'ee some o' that 16k stack baby !! */
				status = lookup_nss_mount(iap, "*", 1);

				master_free_mapent_sources(iap->entry, 0);
				master_free_mapent(iap->entry);

				if (status)
					return CHE_COMPLETED;
			} else if (strncmp(mkey, "*", 1) == 0) {
				fclose(f);
				cache_writelock(mc);
				ret = cache_update(mc, source, "*", mapent, age);
				cache_unlock(mc);
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
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	struct mapent *exists;
	int need_map = 0;
	int ret = CHE_OK;

	cache_readlock(mc);
	exists = cache_lookup(mc, key);
	if (exists && exists->source != source)
		exists = NULL;
	cache_unlock(mc);

	ret = lookup_one(ap, key, key_len, ctxt);
	if (ret == CHE_COMPLETED)
		return NSS_STATUS_COMPLETED;

	if (ret == CHE_FAIL)
		return NSS_STATUS_NOTFOUND;

	if ((ret & CHE_UPDATED) ||
	    (exists && (ret & CHE_MISSING)))
		need_map = 1;

	if (ret == CHE_MISSING) {
		int wild = CHE_MISSING;

		wild = lookup_wild(ap, ctxt);
		if (wild == CHE_COMPLETED)
			return NSS_STATUS_SUCCESS;
/*
		if (wild == CHE_FAIL)
			return NSS_STATUS_NOTFOUND;
*/
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_writelock(mc);
		if (wild == CHE_MISSING)
			cache_delete(mc, "*");

		if (cache_delete(mc, key) && wild & (CHE_MISSING | CHE_FAIL))
			rmdir_path(ap, key);
		pthread_cleanup_pop(1);
	}

	/* Have parent update its map ? */
	/* TODO: update specific map */
	if (ap->ghost && need_map) {
		int status;

		source->stale = 1;

		status = pthread_mutex_lock(&ap->state_mutex);
		if (status)
			fatal(status);

		nextstate(ap->state_pipe[1], ST_READMAP);

		status = pthread_mutex_unlock(&ap->state_mutex);
		if (status)
			fatal(status);
	}

	if (ret == CHE_MISSING)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	struct mapent *me;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	int mapent_len;
	int status = 0;
	int ret = 1;

	if (source->recurse)
		return NSS_STATUS_UNAVAIL;

	if (source->depth > MAX_INCLUDE_DEPTH) {
		error("maximum include depth exceeded %s", ctxt->mapname);
		return NSS_STATUS_SUCCESS;
	}

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
		char *lkp_key;

		cache_readlock(mc);
		me = cache_lookup(mc, key);
		if (me && me->multi)
			lkp_key = strdup(me->multi->key);
		else
			lkp_key = strdup(key);
		cache_unlock(mc);

		if (!lkp_key)
			return NSS_STATUS_UNKNOWN;

		status = check_map_indirect(ap, lkp_key, strlen(lkp_key), ctxt);
		free(lkp_key);
		if (status) {
			if (status == NSS_STATUS_COMPLETED)
				return NSS_STATUS_SUCCESS;

			debug(MODPREFIX "check indirect map lookup failed");
			return NSS_STATUS_NOTFOUND;
		}
	}

	cache_readlock(mc);
	me = cache_lookup(mc, key);
	if (me) {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		mapent = alloca(strlen(me->mapent) + 1);
		mapent_len = sprintf(mapent, me->mapent);
		pthread_cleanup_pop(0);
		mapent[mapent_len] = '\0';
	}
	cache_unlock(mc);

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
