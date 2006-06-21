#ident "$Id: lookup_yp.c,v 1.30 2006/03/31 18:26:16 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  lookup_yp.c - module for Linux automountd to access a YP (NIS)
 *                automount map
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
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(yp): "

struct lookup_context {
	const char *domainname;
	const char *mapname;
	unsigned long order;
	struct parse_mod *parse;
};

struct callback_master_data {
	unsigned timeout;
	unsigned logging;
	time_t age;
};

struct callback_data {
	struct autofs_point *ap;
	time_t age;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

static unsigned int get_map_order(const char *domain, const char *map)
{
	char key[] = "YP_LAST_MODIFIED";
	int key_len = strlen(key);
	char *order;
	int order_len;
	char *mapname;
	long last_changed;
	int err;

	mapname = alloca(strlen(map) + 1);
	if (!mapname)
		return 0;

	strcpy(mapname, map);

	err = yp_match(domain, mapname, key, key_len, &order, &order_len);
	if (err != YPERR_SUCCESS) {
		if (err == YPERR_MAP) {
			char *usc;

			while ((usc = strchr(mapname, '_')))
				*usc = '.';

			err = yp_match(domain, mapname,
				       key, key_len, &order, &order_len);

			if (err != YPERR_SUCCESS)
				return 0;

			last_changed = atol(order);

			return (unsigned int) last_changed;
		}
		return 0;
	}

	last_changed = atol(order);
	free(order);

	return (unsigned int) last_changed;
}

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	int err;

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "%s", estr);
		return 1;
	}
	memset(ctxt, 0, sizeof(struct lookup_context));

	if (argc < 1) {
		crit(LOGOPT_ANY, MODPREFIX "no map name");
		free(ctxt);
		return 1;
	}
	ctxt->mapname = argv[0];

	debug(LOGOPT_NONE, MODPREFIX "ctxt->mapname=%s", ctxt->mapname);

	/* This should, but doesn't, take a const char ** */
	err = yp_get_default_domain((char **) &ctxt->domainname);
	if (err) {
		debug(LOGOPT_NONE, MODPREFIX "map %s: %s", ctxt->mapname,
		       yperr_string(err));
		free(ctxt);
		return 1;
	}

	ctxt->order = get_map_order(ctxt->domainname, ctxt->mapname);

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parse) {
		crit(LOGOPT_ANY, MODPREFIX "failed to open parse context");
		free(ctxt);
		return 1;
	}
	*context = ctxt;

	return 0;
}

int yp_all_master_callback(int status, char *ypkey, int ypkeylen,
		    char *val, int vallen, char *ypcb_data)
{
	struct callback_master_data *cbdata =
			(struct callback_master_data *) ypcb_data;
	unsigned int timeout = cbdata->timeout;
	unsigned int logging = cbdata->logging;
	time_t age = cbdata->age;
	char *buffer;
	unsigned int len;

	if (status != YP_TRUE)
		return status;

	/*
	 * Ignore keys beginning with '+' as plus map
	 * inclusion is only valid in file maps.
	 */
	if (*ypkey == '+')
		return 0;

	*(ypkey + ypkeylen) = '\0';
	*(val + vallen) = '\0';

	len = ypkeylen + 1 + vallen + 1;

	buffer = malloc(len);
	if (!buffer) {
		error(LOGOPT_ANY, MODPREFIX "could not malloc parse buffer");
		return 0;
	}
	memset(buffer, 0, len);

	strcat(buffer, ypkey);
	strcat(buffer, " ");
	strcat(buffer, val);

	master_parse_entry(buffer, timeout, logging, age);

	free(buffer);

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct ypall_callback ypcb;
	struct callback_master_data ypcb_data;
	char *mapname;
	int err;

	mapname = alloca(strlen(ctxt->mapname) + 1);
	if (!mapname)
		return 0;

	strcpy(mapname, ctxt->mapname);

	ypcb_data.timeout = master->default_timeout;
	ypcb_data.logging = master->default_logging;
	ypcb_data.age = age;

	ypcb.foreach = yp_all_master_callback;
	ypcb.data = (char *) &ypcb_data;

	err = yp_all((char *) ctxt->domainname, mapname, &ypcb);

	if (err != YPERR_SUCCESS) {
		if (err == YPERR_MAP) {
			char *usc;

			while ((usc = strchr(mapname, '_')))
				*usc = '.';

			err = yp_all((char *) ctxt->domainname, mapname, &ypcb);
		}

		if (err == YPERR_SUCCESS)
			return NSS_STATUS_SUCCESS;

		warn(LOGOPT_ANY,
		     MODPREFIX "read of master map %s failed: %s",
		     mapname, yperr_string(err));

		return NSS_STATUS_NOTFOUND;
	}

	return NSS_STATUS_SUCCESS;
}

int yp_all_callback(int status, char *ypkey, int ypkeylen,
		    char *val, int vallen, char *ypcb_data)
{
	struct callback_data *cbdata = (struct callback_data *) ypcb_data;
	struct autofs_point *ap = cbdata->ap;
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	time_t age = cbdata->age;
	char *key;
	char *mapent;
	int ret;

	if (status != YP_TRUE)
		return status;

	/*
	 * Ignore keys beginning with '+' as plus map
	 * inclusion is only valid in file maps.
	 */
	if (*ypkey == '+')
		return 0;

	if (ap->type == LKP_INDIRECT && *ypkey == '/')
		return 0;

	if (ap->type == LKP_DIRECT && *ypkey != '/')
		return 0;

	key = alloca(ypkeylen + 1);
	strncpy(key, ypkey, ypkeylen);
	*(key + ypkeylen) = '\0';

	mapent = alloca(vallen + 1);
	strncpy(mapent, val, vallen);
	*(mapent + vallen) = '\0';

	cache_writelock(mc);
	ret = cache_update(mc, source, key, mapent, age);
	cache_unlock(mc);
	if (ret == CHE_FAIL)
		return -1;

	return 0;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct ypall_callback ypcb;
	struct callback_data ypcb_data;
	char *mapname;
	int err;

	mapname = alloca(strlen(ctxt->mapname) + 1);
	if (!mapname)
		return 0;

	strcpy(mapname, ctxt->mapname);

	ypcb_data.ap = ap;
	ypcb_data.age = age;

	ypcb.foreach = yp_all_callback;
	ypcb.data = (char *) &ypcb_data;

	err = yp_all((char *) ctxt->domainname, mapname, &ypcb);

	if (err != YPERR_SUCCESS) {
		if (err == YPERR_MAP) {
			char *usc;

			while ((usc = strchr(mapname, '_')))
				*usc = '.';

			err = yp_all((char *) ctxt->domainname, mapname, &ypcb);
		}

		if (err == YPERR_SUCCESS)
			return NSS_STATUS_SUCCESS;

		warn(ap->logopt,
		     MODPREFIX "read of map %s failed: %s",
		     ap->path, yperr_string(err));

		return NSS_STATUS_NOTFOUND;
	}

	return NSS_STATUS_SUCCESS;
}

static int lookup_one(struct autofs_point *ap,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	char *mapname;
	char *mapent;
	int mapent_len;
	time_t age = time(NULL);
	int ret;

	mapname = alloca(strlen(ctxt->mapname) + 1);
	if (!mapname)
		return 0;

	strcpy(mapname, ctxt->mapname);

	mapent = alloca(MAPENT_MAX_LEN + 1);
	if (!mapent)
		return 0;

	/*
	 * For reasons unknown, the standard YP definitions doesn't
	 * define input strings as const char *.  However, my
	 * understanding is that they will not be modified by the
	 * library.
	 */
	ret = yp_match((char *) ctxt->domainname, mapname,
		       (char *) key, key_len, &mapent, &mapent_len);

	if (ret != YPERR_SUCCESS) {
		if (ret == YPERR_MAP) {
			char *usc;

			while ((usc = strchr(mapname, '_')))
				*usc = '.';

			ret = yp_match((char *) ctxt->domainname,
				mapname, key, key_len, &mapent, &mapent_len);
		}

		if (ret != YPERR_SUCCESS) {
			if (ret == YPERR_KEY)
				return CHE_MISSING;

			return -ret;
		}
	}

	cache_writelock(mc);
	ret = cache_update(mc, source, key, mapent, age);
	cache_unlock(mc);

	return ret;
}

static int lookup_wild(struct autofs_point *ap, struct lookup_context *ctxt)
{
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	char *mapname;
	char *mapent;
	int mapent_len;
	time_t age = time(NULL);
	int ret;

	mapname = alloca(strlen(ctxt->mapname) + 1);
	if (!mapname)
		return 0;

	strcpy(mapname, ctxt->mapname);

	mapent = alloca(MAPENT_MAX_LEN + 1);
	if (!mapent)
		return 0;

	ret = yp_match((char *) ctxt->domainname,
		       mapname, "*", 1, &mapent, &mapent_len);

	if (ret != YPERR_SUCCESS) {
		if (ret == YPERR_MAP) {
			char *usc;

			while ((usc = strchr(mapname, '_')))
				*usc = '.';

			ret = yp_match((char *) ctxt->domainname,
				mapname, "*", 1, &mapent, &mapent_len);
		}

		if (ret != YPERR_SUCCESS) {
			if (ret == YPERR_KEY)
				return CHE_MISSING;

			return -ret;
		}
	}

	cache_writelock(mc);
	ret = cache_update(mc, source, "*", mapent, age);
	cache_unlock(mc);

	return ret;
}

static int check_map_indirect(struct autofs_point *ap,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	struct mapent *me, *exists;
	unsigned int map_order;
	int need_map = 0;
	int ret = 0;

	cache_readlock(mc);
	exists = cache_lookup_distinct(mc, key);
	if (exists && exists->source != source)
		exists = NULL;
	cache_unlock(mc);

	/* check map and if change is detected re-read map */
	ret = lookup_one(ap, key, key_len, ctxt);
	if (ret == CHE_FAIL)
		return NSS_STATUS_NOTFOUND;

	if (ret < 0) {
		warn(ap->logopt,
		     MODPREFIX "lookup for %s failed: %s",
		     key, yperr_string(-ret));
		return NSS_STATUS_UNAVAIL;
	}

	/* Only read map if it has been modified */
	map_order = get_map_order(ctxt->domainname, ctxt->mapname);
	if (map_order > ctxt->order) {
		ctxt->order = map_order;
		need_map = 1;
	}

	if (ret == CHE_MISSING) {
		int wild = CHE_MISSING;

		wild = lookup_wild(ap, ctxt);
		if (wild == CHE_UPDATED || CHE_OK)
			return NSS_STATUS_SUCCESS;

		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_writelock(mc);
		if (wild == CHE_MISSING)
			cache_delete(mc, "*");

		if (cache_delete(mc, key) && wild & (CHE_MISSING | CHE_FAIL))
			rmdir_path(ap, key);
		pthread_cleanup_pop(1);
	}

	/* Have parent update its map if needed */
	if (ap->ghost && need_map) {
		int status;

		ap->entry->current->stale = 1;

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
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	int mapent_len;
	struct mapent *me;
	int status = 0;
	int ret = 1;

	debug(ap->logopt, MODPREFIX "looking up %s", name);

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
		me = cache_lookup_distinct(mc, key);
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
			debug(ap->logopt,
			      MODPREFIX "check indirect map lookup failed");
			return status;
		}
	}

	cache_readlock(mc);
	me = cache_lookup(mc, key);
	if (me) {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		mapent = alloca(strlen(me->mapent) + 1);
		mapent_len = sprintf(mapent, "%s", me->mapent);
		mapent[mapent_len] = '\0';
		pthread_cleanup_pop(0);
	}
	cache_unlock(mc);

	if (mapent) {
		debug(ap->logopt, MODPREFIX "%s -> %s", key, mapent);
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
