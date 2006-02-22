#ident "$Id: lookup_hosts.c,v 1.4 2006/02/22 02:23:41 raven Exp $"
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
#include <syslog.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"
#include "mount.h"

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

	if (!(*context = ctxt = malloc(sizeof(struct lookup_context)))) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	mapfmt = MAPFMT_DEFAULT;

	return !(ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1));
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct hostent *host;
	int status;

	status = pthread_mutex_lock(&hostent_mutex);
	if (status) {
		error("failed to lock hostent mutex");
		return NSS_STATUS_UNAVAIL;
	}

	sethostent(0);
	while ((host = gethostent()) != NULL) {
		cache_writelock();
		pthread_cleanup_push(cache_lock_cleanup, NULL);
		cache_update(host->h_name, NULL, age);
		pthread_cleanup_pop(0);
		cache_unlock();
	}
	endhostent();

	status = pthread_mutex_unlock(&hostent_mutex);
	if (status)
		error("failed to unlock hostent mutex");

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *me;
	char buf[MAX_ERR_BUF];
	char *mapent = NULL;
	int mapent_len;
	time_t now = time(NULL);
	exports exp;
	int status = NSS_STATUS_UNKNOWN;
	int ret;

	cache_readlock();
	me = cache_lookup(name);
	if (!me) {
		pthread_cleanup_push(cache_lock_cleanup, NULL);
		if (*name == '/')
			error(MODPREFIX
			      "can't find path in hosts map %s", name);
		else
			error(MODPREFIX
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
		pthread_cleanup_push(cache_lock_cleanup, NULL);
		mapent = alloca(strlen(me->mapent) + 1);
		mapent_len = sprintf(mapent, me->mapent);
		pthread_cleanup_pop(0);
		mapent[mapent_len] = '\0';
	}
done:
	cache_unlock();

	if (status != NSS_STATUS_UNKNOWN)
		return status;

	if (mapent) {
		debug(MODPREFIX "%s -> %s", name, me->mapent);
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
	debug(MODPREFIX "fetchng export list for %s", name);

	exp = rpc_get_exports(name, 10, 0, RPC_CLOSE_DEFAULT);

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
				crit(MODPREFIX "malloc: %s", estr);
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
				crit(MODPREFIX "malloc: %s", estr);
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
		error("exports lookup failed for %s", name);
		return NSS_STATUS_UNAVAIL;
	}

	debug(MODPREFIX "%s -> %s", name, mapent);

	cache_writelock();
	cache_update(name, mapent, now);
	cache_unlock();

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
