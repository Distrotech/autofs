/* ----------------------------------------------------------------------- *
 *   
 *  lookup_hosts.c - module for Linux automount to mount the exports
 *                      from a given host
 *
 *   Copyright 2005 Ian Kent <raven@themaw.net>
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>

/* 
 * Avoid annoying compiler noise by using an alternate name for
 * typedef name in mount.h
 */
#define name __dummy_type_name
#include "mount.h"
#undef name

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"
#define MODPREFIX "lookup(hosts): "

pthread_mutex_t hostent_mutex = PTHREAD_MUTEX_INITIALIZER;

struct lookup_context {
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

exports rpc_get_exports(const char *host, long seconds, long micros, unsigned int option);
void rpc_exports_free(exports list);

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	mapfmt = MAPFMT_DEFAULT;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc, argv);
	if (!ctxt->parse) {
		logerr(MODPREFIX "failed to open parse context");
		free(ctxt);
		return 1;
	}
	*context = ctxt;

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	return NSS_STATUS_UNKNOWN;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct map_source *source;
	struct mapent_cache *mc;
	struct hostent *host;
	int status;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	/*
	 * If we don't need to create directories then there's no use
	 * reading the map. We always need to read the whole map for
	 * direct mounts in order to mount the triggers.
	 */
	if (!(ap->flags & MOUNT_FLAG_GHOST) && ap->type != LKP_DIRECT)
		return NSS_STATUS_SUCCESS;

	mc = source->mc;

	status = pthread_mutex_lock(&hostent_mutex);
	if (status) {
		error(ap->logopt, MODPREFIX "failed to lock hostent mutex");
		return NSS_STATUS_UNAVAIL;
	}

	sethostent(0);
	while ((host = gethostent()) != NULL) {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_writelock(mc);
		cache_update(mc, source, host->h_name, NULL, age);
		cache_unlock(mc);
		pthread_cleanup_pop(0);
	}
	endhostent();

	status = pthread_mutex_unlock(&hostent_mutex);
	if (status)
		error(ap->logopt, MODPREFIX "failed to unlock hostent mutex");

	source->age = age;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me;
	char buf[MAX_ERR_BUF];
	char *mapent = NULL;
	int mapent_len;
	time_t now = time(NULL);
	exports exp;
	int ret;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, name, LKP_DISTINCT);
	if (me) {
		if (me->status >= time(NULL)) {
			cache_unlock(me->mc);
			return NSS_STATUS_NOTFOUND;
		} else {
			struct mapent_cache *smc = me->mc;
			struct mapent *sme;

			if (me->mapent)
				cache_unlock(smc);
			else {
				cache_unlock(smc);
				cache_writelock(smc);
				sme = cache_lookup_distinct(smc, name);
				/* Negative timeout expired for non-existent entry. */
				if (sme && !sme->mapent)
					cache_delete(smc, name);
				cache_unlock(smc);
			}
		}
	}

	cache_readlock(mc);
	me = cache_lookup_distinct(mc, name);
	if (!me) {
		cache_unlock(mc);
		/*
		 * We haven't read the list of hosts into the
		 * cache so go straight to the lookup.
		 */
		if (!(ap->flags & MOUNT_FLAG_GHOST)) {
			/*
			 * If name contains a '/' we're searching for an
			 * offset that doesn't exist in the export list
			 * so it's NOTFOUND otherwise this could be a
			 * lookup for a new host.
			 */
			if (*name != '/' && strchr(name, '/'))
				return NSS_STATUS_NOTFOUND;
			goto done;
		}

		if (*name == '/')
			info(ap->logopt, MODPREFIX
			      "can't find path in hosts map %s", name);
		else
			info(ap->logopt, MODPREFIX
			      "can't find path in hosts map %s/%s",
			      ap->path, name);

		debug(ap->logopt,
		      MODPREFIX "lookup failed - update exports list");
		goto done;
	}
	/*
	 * Host map export entries are added to the cache as
	 * direct mounts. If the name we seek starts with a slash
	 * it must be a mount request for one of the exports.
	 */
	if (*name == '/') {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		mapent_len = strlen(me->mapent);
		mapent = alloca(mapent_len + 1);
		if (mapent)
			strcpy(mapent, me->mapent);
		pthread_cleanup_pop(0);
	}
	cache_unlock(mc);

	if (mapent) {
		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		debug(ap->logopt, MODPREFIX "%s -> %s", name, me->mapent);

		ret = ctxt->parse->parse_mount(ap, name, name_len,
				 mapent, ctxt->parse->context);

		if (ret) {
			time_t now = time(NULL);
			int rv = CHE_OK;

			cache_writelock(mc);
			me = cache_lookup_distinct(mc, name);
			if (!me)
				rv = cache_update(mc, source, name, NULL, now);
			if (rv != CHE_FAIL) {
				me = cache_lookup_distinct(mc, name);
				me->status = now + ap->negative_timeout;
			}
			cache_unlock(mc);
			return NSS_STATUS_TRYAGAIN;
		}
		return NSS_STATUS_SUCCESS;
	}
done:
	/*
	 * Otherwise we need to get the exports list and add update
	 * the cache.
	 */
	debug(ap->logopt, MODPREFIX "fetchng export list for %s", name);

	exp = rpc_get_exports(name, 10, 0, RPC_CLOSE_NOLINGER);

	mapent = NULL;
	while (exp) {
		if (mapent) {
			int len = strlen(mapent) + 1;

			len += strlen(name) + 2*(strlen(exp->ex_dir) + 2) + 3;
			mapent = realloc(mapent, len);
			if (!mapent) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				logerr(MODPREFIX "malloc: %s", estr);
				rpc_exports_free(exp);
				return NSS_STATUS_UNAVAIL;
			}
			strcat(mapent, " \"");
			strcat(mapent, exp->ex_dir);
			strcat(mapent, "\"");
		} else {
			int len = 2*(strlen(exp->ex_dir) + 2) + strlen(name) + 3;

			mapent = malloc(len);
			if (!mapent) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				logerr(MODPREFIX "malloc: %s", estr);
				rpc_exports_free(exp);
				return NSS_STATUS_UNAVAIL;
			}
			strcpy(mapent, "\"");
			strcat(mapent, exp->ex_dir);
			strcat(mapent, "\"");
		}
		strcat(mapent, " \"");
		strcat(mapent, name);
		strcat(mapent, ":");
		strcat(mapent, exp->ex_dir);
		strcat(mapent, "\"");

		exp = exp->ex_next;
	}
	rpc_exports_free(exp);

	/* Exports lookup failed so we're outa here */
	if (!mapent) {
		error(ap->logopt, "exports lookup failed for %s", name);
		return NSS_STATUS_UNAVAIL;
	}

	debug(ap->logopt, MODPREFIX "%s -> %s", name, mapent);

	cache_writelock(mc);
	cache_update(mc, source, name, mapent, now);
	cache_unlock(mc);

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	ret = ctxt->parse->parse_mount(ap, name, name_len,
				 mapent, ctxt->parse->context);
	free(mapent);

	if (ret) {
		time_t now = time(NULL);
		int rv = CHE_OK;

		cache_writelock(mc);
		me = cache_lookup_distinct(mc, name);
		if (!me)
			rv = cache_update(mc, source, name, NULL, now);
		if (rv != CHE_FAIL) {
			me = cache_lookup_distinct(mc, name);
			me->status = now + ap->negative_timeout;
		}
		cache_unlock(mc);
		return NSS_STATUS_TRYAGAIN;
	}

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	return rv;
}
