#ident "$Id: lookup_yp.c,v 1.4 2004/05/10 12:44:30 raven Exp $"
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
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>

#define MODULE_LOOKUP
#include "automount.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(yp): "

struct lookup_context {
	const char *domainname;
	const char *mapname;
	struct parse_mod *parse;
};

struct callback_data {
	int status;
	int map;
	const char *root;
	char direct_base[KEY_MAX_LEN + 1];
	const char *name;
	int name_len;
	unsigned long type;
	const char *mapname;
	time_t age;
	struct lookup_context *context;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	int err;

	if (!(*context = ctxt = malloc(sizeof(struct lookup_context)))) {
		crit(MODPREFIX "%m");
		return 1;
	}

	if (argc < 1) {
		crit(MODPREFIX "No map name");
		return 1;
	}
	ctxt->mapname = argv[0];

	/* This should, but doesn't, take a const char ** */
	err = yp_get_default_domain((char **) &ctxt->domainname);
	if (err) {
		crit(MODPREFIX "map %s: %s\n", ctxt->mapname,
		       yperr_string(err));
		return 1;
	}

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	cache_init();

	return !(ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1));
}

int yp_all_callback(int status, char *ypkey, int ypkeylen,
		    char *val, int vallen, char *ypcb_data)
{
	time_t *age = (time_t *) ypcb_data;
	char *key;
	char *mapent;

	if (status != YP_TRUE)
		return status;

	key = alloca(ypkeylen + 1);
	strncpy(key, ypkey, ypkeylen);
	*(key + ypkeylen) = '\0';

	mapent = alloca(vallen + 1);
	strncpy(mapent, val, vallen);
	*(mapent + vallen) = '\0';

	cache_update(key, mapent, *age);

	return 0;
}

static int read_map(const char *root, struct lookup_context *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct ypall_callback ypcb;
	time_t age = time(NULL);
	int err;

	ypcb.foreach = yp_all_callback;
	ypcb.data = (char *) &age;

	err = yp_all((char *) ctxt->domainname, (char *) ctxt->mapname, &ypcb);

	if (err != YPERR_SUCCESS) {
		warn(MODPREFIX "lookup_ghost for %s failed: %s",
		       root, yperr_string(err));
		return 0;
	}

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

	status = cache_ghost(root, ghost, ctxt->mapname, "yp", ctxt->parse);

	me = cache_lookup_first();
	/* me NULL => empty map */
	if (me == NULL)
		return LKP_FAIL;

	if (*me->key == '/' && *(root + 1) != '-') {
		me = cache_partial_match(root);
		/* me NULL => no entries for this direct mount root or indirect map */
		if (me == NULL)
			return LKP_FAIL | LKP_INDIRECT;
	}

	return status;
}

int lookup_mount(const char *root, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	struct mapent_cache *me = NULL;
	time_t age = time(NULL);
	int mapent_len;
	int err, rv;

	debug(MODPREFIX "looking up %s", name);

	me = cache_lookup(name);
	if (me == NULL)
		if (sprintf(key, "%s/%s", root, name))
			me = cache_lookup(key);

	if (me == NULL) {
		/* path component, do submount */
		me = cache_partial_match(key);

		if (me) {
			mapent = malloc(strlen(ctxt->mapname) + 20);
			mapent_len =
			    sprintf(mapent, "-fstype=autofs yp:%s", ctxt->mapname);
		}
	} else {
		mapent = malloc(strlen(me->mapent) + 1);
		mapent_len = sprintf(mapent, me->mapent);
	}

	if (!me) {
		/* For reasons unknown, the standard YP definitions doesn't
		   define input strings as const char *.  However, my
		   understanding is that they will not be modified by the
		   library. */
		err = yp_match((char *) ctxt->domainname, (char *) ctxt->mapname,
			       (char *) name, name_len, &mapent, &mapent_len);

		if (err != YPERR_SUCCESS) {
			if (err != YPERR_KEY)
				goto out_err;

			/* See if there is an entry "root/name" */
			key_len = sprintf(key, "%s/%s", root, name);
			err = yp_match((char *) ctxt->domainname, 
				       (char *) ctxt->mapname,
				       key, key_len, &mapent, &mapent_len);

			if (err != YPERR_SUCCESS) {
				if (err != YPERR_KEY)
					goto out_err;
				/* 
				 * Try to get the "*" entry if there is one i
				 * - note that we *don't* modify "name" so
				 *   & -> the name we used, not "*"
				 */
				err =
				    yp_match((char *) ctxt->domainname,
					     (char *) ctxt->mapname, "*", 1, 
					     &mapent, &mapent_len);
			} else
				cache_update(key, mapent, age);

			if (err)
				goto out_err;
		} else
			cache_update(name, mapent, age);
	}

	mapent[mapent_len] = '\0';

	debug(MODPREFIX "%s -> %s", name, mapent);

	rv = ctxt->parse->parse_mount(root, name, name_len, mapent, ctxt->parse->context);
	free(mapent);
	return rv;

out_err:
	warn(MODPREFIX "lookup for %s failed: %s", name, yperr_string(err));
	if (mapent)
		free(mapent);
	return 1;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	cache_release();
	return rv;
}
