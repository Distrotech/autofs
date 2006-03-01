#ident "$Id: lookup.c,v 1.7 2006/03/01 23:51:13 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  lookup.c - API layer to implement nsswitch semantics for map reading
 *		and mount lookups.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "automount.h"
#include "nsswitch.h"

static int do_read_map(struct autofs_point *ap, char *type, time_t age)
{
	struct lookup_mod *lookup;
	int status;

	lookup = open_lookup(type, "",
			ap->mapfmt, ap->mapargc, ap->mapargv);
	if (!lookup)
		return NSS_STATUS_UNAVAIL;

	status = lookup->lookup_read_map(ap, age, lookup->context);

	close_lookup(lookup);

	/*
	 * For maps that don't support enumeration return success
	 * and do whatever we must to have autofs function with an
	 * empty map entry cache.
	 */
	if (status == NSS_STATUS_UNKNOWN)
		return NSS_STATUS_SUCCESS;

	return status;
}

int lookup_nss_read_map(struct autofs_point *ap, time_t age)
{
	struct list_head nsslist;
	struct list_head *head, *p;
	struct nss_source *this;
	int result;

	if (ap->maptype) {
		result = do_read_map(ap, ap->maptype, age);
		return !result;
	}

	/* If it starts with a '/' it has to be a file map */
	if (*ap->mapargv[0] == '/') {
		struct autofs_point tmp;
		char source[] = "file";

		memcpy(&tmp, ap, sizeof(struct autofs_point));

		result = do_read_map(&tmp, source, age);

		return !result;
	}

	INIT_LIST_HEAD(&nsslist);

	result = nsswitch_parse(&nsslist);
	if (result) {
		error("can't to read name service switch config.");
		return 0;
	}

	head = &nsslist;
	list_for_each(p, head) {
		enum nsswitch_status status;
		struct nss_action a;

		this = list_entry(p, struct nss_source, list);

		/* 
		 * autofs built-in map for nsswitch "files" is "file".
		 * This is a special case as we need to append the
		 * normal location to the map name.
		 * note: It's invalid to specify a relative path.
		 */
		if (!strcasecmp(this->source, "files")) {
			struct autofs_point *tap;
			char *path;

			if (strchr(ap->mapargv[0], '/')) {
				error("relative path invalid in files map name");
				continue;
			}

			this->source[4] = '\0';
			/* TODO: autoconf maps location */
			path = malloc(strlen("/etc/") + 
				      strlen(ap->mapargv[0]) + 1);
			if (!path) {
				free_sources(&nsslist);
				return 0;
			}

			strcpy(path, "/etc/");
			strcat(path, ap->mapargv[0]);

			tap = malloc(sizeof(struct autofs_point));
			if (!tap) {
				error("could not malloc storage for nss lookup");
				free(path);
				free_sources(&nsslist);
				return 0;
			}
			memcpy(tap, ap, sizeof(struct autofs_point));

			if (ap->mapargc >= 1) {
				tap->mapargv = copy_argv(ap->mapargc, ap->mapargv);
				if (!tap->mapargv) {
					error("failed to copy args");
					free(tap);
					free(path);
					free_sources(&nsslist);
					return 0;
				}
				if (tap->mapargv[0])
					free((char *) tap->mapargv[0]);
				tap->mapargv[0] = path;
			} else {
				error("invalid arguments for autofs_point");
				free(tap);
				free(path);
				free_sources(&nsslist);
				return 0;
			}

			result = do_read_map(tap, this->source, age);

			/* path is freed in free_argv */
			free_argv(tap->mapargc, tap->mapargv);
			free(tap);
		} else
			result = do_read_map(ap, this->source, age);

		/* Check if we have negated actions */
		for (status = 0; status < NSS_STATUS_MAX; status++) {
			a = this->action[status];
			if (a.action == NSS_ACTION_UNKNOWN)
				continue;

			if (a.negated && result != status) {
				if (a.action == NSS_ACTION_RETURN) {
					free_sources(&nsslist);
					if (result == NSS_STATUS_SUCCESS) {
						return 1;
					} else
						return 0;
				}
			}
		}

		a = this->action[result];

		/* Check if we have other actions for this status */
		switch (result) {
		case NSS_STATUS_SUCCESS:
			if (a.action == NSS_ACTION_CONTINUE)
				break;

			free_sources(&nsslist);
			return 1;
		case NSS_STATUS_NOTFOUND:
		case NSS_STATUS_UNAVAIL:
		case NSS_STATUS_TRYAGAIN:
			if (a.action == NSS_ACTION_RETURN) {
				free_sources(&nsslist);
				return 0;
			}
			break;
		}
	}

	if (!list_empty(&nsslist)) {
		free_sources(&nsslist);
		return 1;
	}

	warn("no sources found in nsswitch");
	return 0;
}

int lookup_enumerate(struct autofs_point *ap,
	int (*fn)(struct autofs_point *ap, struct mapent_cache *, int),
	time_t now)
{
	struct mapent_cache *me;

	/* TODO: more sensible status return */
	if (strcmp(ap->path, "/-"))
		return LKP_FAIL | LKP_INDIRECT;

	me = cache_enumerate(NULL);
	while (me) {
		/* TODO: check return */
		fn(ap, me, now);
		me = cache_enumerate(me);
	}

	return LKP_DIRECT;
}

int lookup_ghost(struct autofs_point *ap)
{
	struct mapent_cache *me;
	char buf[MAX_ERR_BUF];
	struct stat st;
	char *fullpath;
	int ret;

	if (!strcmp(ap->path, "/-"))
		return LKP_FAIL | LKP_DIRECT;

	if (!ap->ghost)
		return LKP_INDIRECT;

	me = cache_enumerate(NULL);
	while (me) {
		if (*me->key == '*')
			goto next;

		if (*me->key == '/') {
			/* It's a busy multi-mount - leave till next time */
			if (list_empty(&me->multi_list))
				error("invalid key %s", me->key);
			goto next;
		}

		fullpath = alloca(strlen(me->key) + strlen(ap->path) + 3);
		if (!fullpath) {
			warn("failed to allocate full path");
			goto next;
		}
		sprintf(fullpath, "%s/%s", ap->path, me->key);

		ret = stat(fullpath, &st);
		if (ret == -1 && errno != ENOENT) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn("stat error %s", estr);
			goto next;
		}

		ret = mkdir_path(fullpath, 0555);
		if (ret < 0 && errno != EEXIST) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn("mkdir_path %s failed: %s", fullpath, estr);
			goto next;
		}

		if (stat(fullpath, &st) != -1) {
			me->dev = st.st_dev;
			me->ino = st.st_ino;
		}
next:
		me = cache_enumerate(me);
	}

	return LKP_INDIRECT;
}

int do_lookup_mount(struct autofs_point *ap, const char *type, const char *name, int name_len)
{
	struct lookup_mod *lookup;
	int status;

	lookup = open_lookup(type, "", ap->mapfmt, ap->mapargc, ap->mapargv);
	if (!lookup) {
		debug("lookup module %s failed", type);
		return NSS_STATUS_UNAVAIL;
	}

	status = lookup->lookup_mount(ap, name, name_len, lookup->context);

	close_lookup(lookup);

	return status;
}

int lookup_nss_mount(struct autofs_point *ap, const char *name, int name_len)
{
	struct list_head nsslist;
	struct list_head *head, *p;
	struct nss_source *this;
	int ret;

	if (ap->maptype)
		return !do_lookup_mount(ap, ap->maptype, name, name_len);

	/* If it starts with a '/' it has to be a file map */
	if (*ap->mapargv[0] == '/') {
		struct autofs_point tmp;
		char source[] = "file";

		memcpy(&tmp, ap, sizeof(struct autofs_point));

		return !do_lookup_mount(&tmp, source, name, name_len);
	}

	INIT_LIST_HEAD(&nsslist);

	ret = nsswitch_parse(&nsslist);
	if (ret) {
		error("can't to read name service switch config.");
		return 0;
	}

	head = &nsslist;
	list_for_each(p, head) {
		enum nsswitch_status status;
		struct nss_action a;
		int result;

		this = list_entry(p, struct nss_source, list);

		/* 
		 * autofs build-in map for nsswitch "files" is "file".
		 * This is a special case as we need to append the
		 * normal location to the map name.
		 * note: we consider it invalid to specify a relative
		 *       path.
		 */
		if (!strcasecmp(this->source, "files")) {
			struct autofs_point *tap;
			char *path;

			if (strchr(ap->mapargv[0], '/')) {
				error("relative path invalid in files map name");
				return 0;
			}

			this->source[4] = '\0';
			/* TODO: autoconf maps location */
			path = malloc(strlen("/etc/") + 
				      strlen(ap->mapargv[0]) + 1);
			if (!path) {
				free_sources(&nsslist);
				return 0;
			}
			strcpy(path, "/etc/");
			strcat(path, ap->mapargv[0]);

			tap = malloc(sizeof(struct autofs_point));
			if (!tap) {
				error("could not malloc storage for nss lookup");
				free(path);
				free_sources(&nsslist);
				return 0;
			}
			memcpy(tap, ap, sizeof(struct autofs_point));

			if (ap->mapargc >= 1) {
				tap->mapargv = copy_argv(ap->mapargc, ap->mapargv);
				if (!tap->mapargv) {
					error("failed to copy args");
					free(tap);
					free(path);
					free_sources(&nsslist);
					return 0;
				}
				if (tap->mapargv[0])
					free((char *) tap->mapargv[0]);
				tap->mapargv[0] = path;
			} else {
				error("invalid arguments for autofs_point");
				free(tap);
				free(path);
				free_sources(&nsslist);
				return 0;
			}

			result = do_lookup_mount(tap,
					 this->source, name, name_len);

			/* path is freed in free_argv */
			free_argv(tap->mapargc, tap->mapargv);
			free(tap);
		} else
			result = do_lookup_mount(ap,
					 this->source, name, name_len);

		/* Check if we have negated actions */
		for (status = 0; status < NSS_STATUS_MAX; status++) {
			a = this->action[status];
			if (a.action == NSS_ACTION_UNKNOWN)
				continue;

			if (a.negated && result != status) {
				if (a.action == NSS_ACTION_RETURN) {
					free_sources(&nsslist);
					if (result == NSS_STATUS_SUCCESS)
						return 1;
					else
						return 0;
				}
			}
		}
			
		a = this->action[result];

		/* Check if we have other actions for this status */
		switch (result) {
		case NSS_STATUS_SUCCESS:
			/* Doesn't make much sense for a successful mount */
			if (a.action == NSS_ACTION_CONTINUE)
				break;

			free_sources(&nsslist);
			return 1;
		case NSS_STATUS_NOTFOUND:
		case NSS_STATUS_UNAVAIL:
		case NSS_STATUS_TRYAGAIN:
			if (a.action == NSS_ACTION_RETURN) {
				free_sources(&nsslist);
				return 0;
			}
			break;
		}
	}

	if (!list_empty(&nsslist))
		free_sources(&nsslist);

	return 0;
}

static char *make_fullpath(const char *root, const char *key)
{
	int l;
	char *path;

	if (*key == '/') {
		l = strlen(key) + 1;
		if (l > KEY_MAX_LEN)
			return NULL;
		path = malloc(l);
		strcpy(path, key);
	} else {
		l = strlen(key) + 1 + strlen(root) + 1;
		if (l > KEY_MAX_LEN)
			return NULL;
		path = malloc(l);
		sprintf(path, "%s/%s", root, key);
	}
	return path;
}

int lookup_prune_cache(struct autofs_point *ap, time_t age)
{
	struct mapent_cache *me, *this;
	char *key, *next_key;
	char *path;
	int status = CHE_FAIL;

	cache_readlock();

	me = cache_enumerate(NULL);
	while (me) {
		if (me->age >= age) {
			me = cache_enumerate(me);
			continue;
		}

		key = strdup(me->key);
		me = cache_enumerate(me);

		if (!key)
			continue;

		next_key = strdup(me->key);
		if (!next_key) {
			free(key);
			continue;
		}

		cache_unlock();

		cache_writelock();
		this = cache_lookup(key);
		if (!this) {
			cache_unlock();
			goto next;
		}
		status = cache_delete(key);
		cache_unlock();

		if (status != CHE_FAIL) {
			path = make_fullpath(ap->path, key);
			if (!path)
				warn("can't malloc storage for path"); 
			else {
				rmdir_path(path);
				free(path);
			}
		}
next:
		cache_readlock();
		me = cache_lookup(next_key);
		free(key);
		free(next_key);
	}

	cache_unlock();

	return 1;
}

