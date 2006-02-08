#ident "$Id: lookup_hosts.c,v 1.1 2006/02/08 16:50:32 raven Exp $"
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
#include "mount.h"

#define MAPFMT_DEFAULT "sun"
#define MODPREFIX "lookup(hosts): "

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
		if (strerror_r(errno, buf, MAX_ERR_BUF))
			strcpy(buf, "strerror_r failed");
		crit(MODPREFIX "malloc: %s", buf);
		return 1;
	}

	mapfmt = MAPFMT_DEFAULT;
	cache_init();

	return !(ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1));
}

/* host maps are always indirect maps */
int lookup_enumerate(const char *root, int (*fn)(struct mapent_cache *, int), time_t now, void *context)
{
	return LKP_NOTSUP;
}

int lookup_ghost(const char *root, int ghost, time_t now, void *context)
{
	struct hostent *host;
	time_t age = now ? now : time(NULL);

	sethostent(0);
	while ((host = gethostent()) != NULL)
		cache_update(host->h_name, NULL, age);
	endhostent();

	cache_ghost(root, ghost);

	return LKP_INDIRECT;
}

int lookup_mount(const char *root, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *me;
	char buf[MAX_ERR_BUF];
	char *mapent = NULL;
	time_t now = time(NULL);
	exports exp;
	int ret;

	me = cache_lookup(name);
	if (!me) {
		if (*name == '/')
			error(MODPREFIX
			      "can't find path in hosts map %s", name);
		else
			error(MODPREFIX
			      "can't find path in hosts map %s/%s",
			      root, name);
		return 1;
	}

	/*
	 * Host map export entries are added to the cache as
	 * direct mounts. If the name we seek starts with a slash
	 * it must be a mount request for one of the exports.
	 */
	if (*name == '/') {
		debug(MODPREFIX "%s -> %s", name, me->mapent);
		ret = ctxt->parse->parse_mount(root, name, name_len,
				 me->mapent, ctxt->parse->context);
		return ret;
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
				if (strerror_r(errno, buf, MAX_ERR_BUF))
					strcpy(buf, "strerror_r failed");
				crit(MODPREFIX "malloc: %s", buf);
				return 1;
			}
			strcat(mapent, " ");
			strcat(mapent, exp->ex_dir);
		} else {
			int len = 2*strlen(exp->ex_dir) + strlen(name) + 3;

			mapent = malloc(len);
			if (!mapent) {
				if (strerror_r(errno, buf, MAX_ERR_BUF))
					strcpy(buf, "strerror_r failed");
				crit(MODPREFIX "malloc: %s", buf);
				return 1;
			}
			strcpy(mapent, exp->ex_dir);
		}
		strcat(mapent, " ");
		strcat(mapent, name);
		strcat(mapent, ":");
		strcat(mapent, exp->ex_dir);

		exp = exp->ex_next;
	}

	/* Exports lookup failed so we're outa here */
	if (!mapent) {
		error("exports lookup failed for %s", name);
		return 1;
	}

	debug(MODPREFIX "%s -> %s", name, mapent);

	cache_update(name, mapent, now);

	ret = ctxt->parse->parse_mount(root, name, name_len,
				 mapent, ctxt->parse->context);
	free(mapent);

	return ret;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	cache_release();
	return rv;
}
