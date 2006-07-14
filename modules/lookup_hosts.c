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
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>

#include "mount.h"

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
exports rpc_exports_prune(exports list);
void rpc_exports_free(exports list);

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
		return 1;
	}

	mapfmt = MAPFMT_DEFAULT;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc, argv);
	if (!ctxt->parse) {
		crit(LOGOPT_ANY, MODPREFIX "failed to open parse context");
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
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	struct hostent *host;
	int status;

	status = pthread_mutex_lock(&hostent_mutex);
	if (status) {
		error(LOGOPT_ANY, MODPREFIX "failed to lock hostent mutex");
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
		error(LOGOPT_ANY, MODPREFIX "failed to unlock hostent mutex");

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source = ap->entry->current;
	struct mapent_cache *mc = source->mc;
	struct mapent *me;
	char buf[MAX_ERR_BUF];
	char *mapent = NULL;
	int mapent_len;
	time_t now = time(NULL);
	exports exp;
	int status = NSS_STATUS_UNKNOWN;
	int ret;

	cache_readlock(mc);
	me = cache_lookup_distinct(mc, name);
	if (!me) {
		/*
		 * We haven't read the list of hosts into the
		 * cache so go straight to the lookup.
		 */
		if (!ap->ghost) {
			/*
			 * If name contains a '/' we're searching for an
			 * offset that doesn't exist in the export list
			 * so it's NOTFOUND otherwise this could be a
			 * lookup for a new host.
			 */
			if (strchr(name, '/'))
				status = NSS_STATUS_NOTFOUND;
			goto done;
		}

		pthread_cleanup_push(cache_lock_cleanup, mc);
		if (*name == '/')
			msg(MODPREFIX
			      "can't find path in hosts map %s", name);
		else
			msg(MODPREFIX
			      "can't find path in hosts map %s/%s",
			      ap->path, name);
		pthread_cleanup_pop(0);
		status = NSS_STATUS_NOTFOUND;
		goto done;
	}
	/*
	 * Host map export entries are added to the cache as
	 * direct mounts. If the name we seek starts with a slash
	 * it must be a mount request for one of the exports.
	 */
	if (*name == '/') {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		mapent = alloca(strlen(me->mapent) + 1);
		mapent_len = sprintf(mapent, me->mapent);
		pthread_cleanup_pop(0);
		mapent[mapent_len] = '\0';
	}
done:
	cache_unlock(mc);

	if (status != NSS_STATUS_UNKNOWN)
		return status;

	if (mapent) {
		debug(ap->logopt, MODPREFIX "%s -> %s", name, me->mapent);
		ret = ctxt->parse->parse_mount(ap, name, name_len,
				 mapent, ctxt->parse->context);

		if (ret)
			return NSS_STATUS_TRYAGAIN;

		return NSS_STATUS_SUCCESS;
	}

	/*
	 * Otherwise we need to get the exports list and add then
	 * the cache.
	 */
	debug(ap->logopt, MODPREFIX "fetchng export list for %s", name);

	exp = rpc_get_exports(name, 10, 0, RPC_CLOSE_NOLINGER);

	/* Check exports for obvious ones we don't have access to */
	exp = rpc_exports_prune(exp);

	while (exp) {
		if (mapent) {
			int len = strlen(mapent) + 1;

			len += strlen(name) + 2*strlen(exp->ex_dir) + 3;
			mapent = realloc(mapent, len);
			if (!mapent) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				crit(ap->logopt, MODPREFIX "malloc: %s", estr);
				rpc_exports_free(exp);
				return NSS_STATUS_UNAVAIL;
			}
			strcat(mapent, " ");
			strcat(mapent, exp->ex_dir);
		} else {
			int len = 2*strlen(exp->ex_dir) + strlen(name) + 3;

			mapent = malloc(len);
			if (!mapent) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				crit(ap->logopt, MODPREFIX "malloc: %s", estr);
				rpc_exports_free(exp);
				return NSS_STATUS_UNAVAIL;
			}
			strcpy(mapent, exp->ex_dir);
		}
		strcat(mapent, " ");
		strcat(mapent, name);
		strcat(mapent, ":");
		strcat(mapent, exp->ex_dir);

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

	ret = ctxt->parse->parse_mount(ap, name, name_len,
				 mapent, ctxt->parse->context);
	free(mapent);

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
