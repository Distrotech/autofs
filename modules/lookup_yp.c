#ident "$Id: lookup_yp.c,v 1.21 2006/02/24 17:20:55 raven Exp $"
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
#include <syslog.h>
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
	struct parse_mod *parse;
};

struct callback_data {
	const char *root;
	time_t age;
	struct lookup_context *ctxt;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	int err;

	if (!(*context = ctxt = malloc(sizeof(struct lookup_context)))) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(MODPREFIX "%s", estr);
		return 1;
	}

	if (argc < 1) {
		crit(MODPREFIX "No map name");
		free(ctxt);
		*context = NULL;
		return 1;
	}
	ctxt->mapname = argv[0];

	debug(MODPREFIX "ctxt->mapname=%s", ctxt->mapname);

	/* This should, but doesn't, take a const char ** */
	err = yp_get_default_domain((char **) &ctxt->domainname);
	if (err) {
		warn(MODPREFIX "map %s: %s\n", ctxt->mapname,
		       yperr_string(err));
		free(ctxt);
		*context = NULL;
		return 1;
	}

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	return !(ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1));
}

int yp_all_callback(int status, char *ypkey, int ypkeylen,
		    char *val, int vallen, char *ypcb_data)
{
	struct callback_data *cbdata = (struct callback_data *) ypcb_data;
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

	key = alloca(ypkeylen + 1);
	strncpy(key, ypkey, ypkeylen);
	*(key + ypkeylen) = '\0';

	mapent = alloca(vallen + 1);
	strncpy(mapent, val, vallen);
	*(mapent + vallen) = '\0';

	cache_writelock();
	ret = cache_update(key, mapent, age);
	cache_unlock();
	if (ret == CHE_FAIL)
		return -1;

	return 0;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct ypall_callback ypcb;
	struct callback_data ypcb_data;
	int err;

	ypcb_data.root = ap->path;
	ypcb_data.age = age;
	ypcb_data.ctxt = ctxt;

	ypcb.foreach = yp_all_callback;
	ypcb.data = (char *) &ypcb_data;

	err = yp_all((char *) ctxt->domainname, (char *) ctxt->mapname, &ypcb);

	if (err != YPERR_SUCCESS) {
		warn(MODPREFIX "lookup_ghost for map %s failed: %s",
		       ap->path, yperr_string(err));
		return NSS_STATUS_NOTFOUND;
	}

	return NSS_STATUS_SUCCESS;
}

static int lookup_one(const char *root,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	char *mapent;
	int mapent_len;
	time_t age = time(NULL);
	int ret;

	/*
	 * For reasons unknown, the standard YP definitions doesn't
	 * define input strings as const char *.  However, my
	 * understanding is that they will not be modified by the
	 * library.
	 */
	ret = yp_match((char *) ctxt->domainname, (char *) ctxt->mapname,
		       (char *) key, key_len, &mapent, &mapent_len);

	if (ret != YPERR_SUCCESS) {
		if (ret == YPERR_KEY)
			return CHE_MISSING;

		return -ret;
	}

	cache_writelock();
	ret = cache_update(key, mapent, age);
	cache_unlock();

	return ret;
}

static int lookup_wild(const char *root, struct lookup_context *ctxt)
{
	char *mapent;
	int mapent_len;
	time_t age = time(NULL);
	int ret;

	mapent = alloca(MAPENT_MAX_LEN + 1);
	if (!mapent)
		return 0;

	ret = yp_match((char *) ctxt->domainname,
		       (char *) ctxt->mapname, "*", 1, &mapent, &mapent_len);

	if (ret != YPERR_SUCCESS) {
		if (ret == YPERR_KEY)
			return CHE_MISSING;

		return -ret;
	}

	cache_writelock();
	ret = cache_update("*", mapent, age);
	cache_unlock();

	return ret;
}

static int check_map_indirect(struct autofs_point *ap,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct mapent_cache *me, *exists;
	time_t now = time(NULL);
	time_t t_last_read;
	int need_hup = 0;
	int ret = 0;

	cache_readlock();
	/* First check to see if this entry exists in the cache */
	exists = cache_lookup(key);
	cache_unlock();

	/* check map and if change is detected re-read map */
	ret = lookup_one(ap->path, key, key_len, ctxt);
	if (ret == CHE_FAIL)
		return NSS_STATUS_NOTFOUND;

	if (ret < 0) {
		warn(MODPREFIX 
		     "lookup for %s failed: %s", key, yperr_string(-ret));
		return NSS_STATUS_UNAVAIL;
	}

	cache_readlock();
	/* First check to see if this entry exists in the cache */
	exists = cache_lookup(key);

	me = cache_lookup_first();
	t_last_read = me ? now - me->age : ap->exp_runfreq + 1;
	cache_unlock();

	if (t_last_read > ap->exp_runfreq)
		if ((ret & CHE_UPDATED) ||
		    (exists && (ret & CHE_MISSING)))
			need_hup = 1;

	if (ret == CHE_MISSING) {
		int wild = CHE_MISSING;

		wild = lookup_wild(ap->path, ctxt);
		if (wild == CHE_MISSING)
			cache_delete("*");

		pthread_cleanup_push(cache_lock_cleanup, NULL);
		cache_writelock();
		if (cache_delete(key) &&
				wild & (CHE_MISSING | CHE_FAIL))
			rmdir_path(key);
		cache_unlock();
		pthread_cleanup_pop(0);
	}

	/* Have parent update its map */
	if (need_hup)
		kill(getppid(), SIGHUP);

	if (ret == CHE_MISSING)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	int mapent_len;
	struct mapent_cache *me;
	int status = 0;
	int ret;

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

	cache_readlock();
	me = cache_lookup(key);
	if (me) {
		pthread_cleanup_push(cache_lock_cleanup, NULL);
		mapent = alloca(strlen(me->mapent) + 1);
		mapent_len = sprintf(mapent, "%s", me->mapent);
		mapent[mapent_len] = '\0';
		pthread_cleanup_pop(0);
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
