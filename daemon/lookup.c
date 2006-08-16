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

static int check_nss_result(struct nss_source *this, enum nsswitch_status result)
{
	enum nsswitch_status status;
	struct nss_action a;

	/* Check if we have negated actions */
	for (status = 0; status < NSS_STATUS_MAX; status++) {
		a = this->action[status];
		if (a.action == NSS_ACTION_UNKNOWN)
			continue;

		if (a.negated && result != status) {
			if (a.action == NSS_ACTION_RETURN) {
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
		if (a.action == NSS_ACTION_CONTINUE)
			break;
		return 1;

	case NSS_STATUS_NOTFOUND:
	case NSS_STATUS_UNAVAIL:
	case NSS_STATUS_TRYAGAIN:
		if (a.action == NSS_ACTION_RETURN) {
			return 0;
		}
		break;

	default:
		break;
	}

	return -1;
}

static int do_read_master(struct master *master, char *type, time_t age)
{
	struct lookup_mod *lookup;
	const char *argv[2];
	int argc;
	int status;

	argc = 1;
	argv[0] = master->name;
	argv[1] = NULL;

	lookup = open_lookup(type, "", NULL, argc, argv);
	if (!lookup)
		return NSS_STATUS_UNAVAIL;

	status = lookup->lookup_read_master(master, age, lookup->context);

	close_lookup(lookup);

	return status;
}

static int read_master_map(struct master *master, char *type, time_t age)
{
	char *path, *save_name;
	int result;

	if (strcasecmp(type, "files")) {
		return do_read_master(master, type, age);
	}

	/* 
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: It's invalid to specify a relative path.
	 */

	if (strchr(master->name, '/')) {
		error(LOGOPT_ANY, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	path = malloc(strlen(AUTOFS_MAP_DIR) + strlen(master->name) + 2);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	strcpy(path, AUTOFS_MAP_DIR);
	strcat(path, "/");
	strcat(path, master->name);

	save_name = master->name;
	master->name = path;

	result = do_read_master(master, type, age);

	master->name = save_name;
	free(path);

	return result;
}

int lookup_nss_read_master(struct master *master, time_t age)
{
	struct list_head nsslist;
	struct list_head *head, *p;
	int result = NSS_STATUS_UNKNOWN;

	/* If it starts with a '/' it has to be a file or LDAP map */
	if (*master->name == '/') {
		if (*(master->name + 1) == '/') {
			debug(LOGOPT_NONE,
			      "reading master ldap %s", master->name);
			result = do_read_master(master, "ldap", age);
		} else {
			debug(LOGOPT_NONE,
			      "reading master file %s", master->name);
			result = do_read_master(master, "file", age);
		}

		return !result;
	} else {
		char *name = master->name;
		char *tmp;

		/* Old style name specification will remain I think. */
		tmp = strchr(name, ':');
		if (tmp) {
			char source[10];

			memset(source, 0, 10);
			/* TODO: ldaps is not yet handled by ldap module */
			/* TODO: must tighten up this test */
			if (!strncmp(name, "file", 4) ||
			    !strncmp(name, "yp", 2) ||
			    !strncmp(name, "nis", 3) ||
			    !strncmp(name, "nisplus", 7) ||
			    !strncmp(name, "ldap", 4)) {
				strncpy(source, name, tmp - name);

				master->name = tmp + 1;

				debug(LOGOPT_NONE,
				      "reading master %s %s",
				      source, master->name);

				result = do_read_master(master, source, age);
				master->name = name;

				return !result;
			}
		}
	}

	INIT_LIST_HEAD(&nsslist);

	result = nsswitch_parse(&nsslist);
	if (result) {
		if (!list_empty(&nsslist))
			free_sources(&nsslist);
		error(LOGOPT_ANY, "can't to read name service switch config.");
		return 0;
	}

	/* First one gets it */
	head = &nsslist;
	list_for_each(p, head) {
		struct nss_source *this;
		int status;

		this = list_entry(p, struct nss_source, list);

		debug(LOGOPT_NONE,
		      "reading master %s %s", this->source, master->name);

		result = read_master_map(master, this->source, age);
		if (result == NSS_STATUS_UNKNOWN) {
			debug(LOGOPT_NONE,
			      "no map - continuing to next source");
			continue;
		}

		status = check_nss_result(this, result);
		if (status >= 0) {
			free_sources(&nsslist);
			return status;
		}
	}

	if (!list_empty(&nsslist))
		free_sources(&nsslist);

	return !result;
}

static int do_read_map(struct autofs_point *ap, struct map_source *map, time_t age)
{
	struct lookup_mod *lookup;
	int status;

	if (!map->lookup) {
		lookup = open_lookup(map->type, "",
				map->format, map->argc, map->argv);
		if (!lookup) {
			debug(ap->logopt, "lookup module %s failed", map->type);
			return NSS_STATUS_UNAVAIL;
		}
		map->lookup = lookup;
	}

	lookup = map->lookup;

	/* If we don't need to create directories then there's no use
	 * reading the map. We just need to test that the map is valid
	 * for the fail cases to function correctly and to cache the
	 * lookup handle.
	 *
	 * We always need to whole map for direct mounts in order to
	 * mount the triggers.
	 */
	if (!ap->ghost && ap->type != LKP_DIRECT)
		return NSS_STATUS_SUCCESS;

	master_source_current_wait(ap->entry);
	ap->entry->current = map;

	status = lookup->lookup_read_map(ap, age, lookup->context);

	/*
	 * For maps that don't support enumeration return success
	 * and do whatever we must to have autofs function with an
	 * empty map entry cache.
	 */
	if (status == NSS_STATUS_UNKNOWN)
		return NSS_STATUS_SUCCESS;

	return status;
}

static int read_file_source_instance(struct autofs_point *ap, struct map_source *map, time_t age)
{
	struct map_source *instance;
	char src_file[] = "file";
	char src_prog[] = "program";
	struct stat st;
	char *type, *format;

	if (stat(map->argv[0], &st) == -1) {
		warn(ap->logopt, "file map %s not found", map->argv[0]);
		return NSS_STATUS_NOTFOUND;
	}

	if (!S_ISREG(st.st_mode))
		return NSS_STATUS_NOTFOUND;

	if (st.st_mode & __S_IEXEC)
		type = src_prog;
	else
		type = src_file;

	format = map->format;

	instance = master_add_source_instance(map, type, format, age);
	if (!instance)
		return NSS_STATUS_UNAVAIL;

	return do_read_map(ap, instance, age);
}

static int read_source_instance(struct autofs_point *ap, struct map_source *map, const char *type, time_t age)
{
	struct map_source *instance;
	const char *format;

	format = map->format;

	instance = master_add_source_instance(map, type, format, age);
	if (!instance)
		return NSS_STATUS_UNAVAIL;

	return do_read_map(ap, instance, age);
}

static enum nsswitch_status read_map_source(struct nss_source *this,
		struct autofs_point *ap, struct map_source *map, time_t age)
{
	enum nsswitch_status result;
	struct map_source *instance;
	struct map_source tmap;
	char *path;

	if (strcasecmp(this->source, "files")) {
		return read_source_instance(ap, map, this->source, age);
	}

	/* 
	 * autofs built-in map for nsswitch "files" is "file".
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: It's invalid to specify a relative path.
	 */

	if (strchr(map->argv[0], '/')) {
		error(ap->logopt, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	instance = master_find_source_instance(map,
				"file", map->format, map->argc, map->argv);
	if (!instance)
		instance = master_find_source_instance(map,
				"program", map->format, map->argc, map->argv);

	if (instance)
		return read_file_source_instance(ap, map, age);

	this->source[4] = '\0';
	tmap.type = this->source;
	tmap.format = map->format;
	tmap.lookup = map->lookup;
	tmap.mc = map->mc;
	tmap.instance = map->instance;
	tmap.argc = 0;
	tmap.argv = NULL;

	path = malloc(strlen(AUTOFS_MAP_DIR) + strlen(map->argv[0]) + 2);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	strcpy(path, AUTOFS_MAP_DIR);
	strcat(path, "/");
	strcat(path, map->argv[0]);

	if (map->argc >= 1) {
		tmap.argc = map->argc;
		tmap.argv = copy_argv(map->argc, map->argv);
		if (!tmap.argv) {
			error(ap->logopt, "failed to copy args");
			free(path);
			return NSS_STATUS_UNKNOWN;
		}
		if (tmap.argv[0])
			free((char *) tmap.argv[0]);
		tmap.argv[0] = path;
	} else {
		error(ap->logopt, "invalid arguments for autofs_point");
		free(path);
		return NSS_STATUS_UNKNOWN;
	}

	result = read_file_source_instance(ap, &tmap, age);

	/* path is freed in free_argv */
	free_argv(tmap.argc, tmap.argv);

	return result;
}

int lookup_nss_read_map(struct autofs_point *ap, time_t age)
{
	struct master_mapent *entry = ap->entry;
	struct list_head nsslist;
	struct list_head *head, *p;
	struct nss_source *this;
	struct map_source *map;
	enum nsswitch_status status;
	int result = 0;

	/*
	 * For each map source (ie. each entry for the mount
	 * point in the master map) do the nss lookup to
	 * locate the map and read it.
	 */
	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	map = entry->first;
	while (map) {
		/* Is map source up to date or no longer valid */
		if (!map->stale || entry->age > map->age) {
			map = map->next;
			continue;
		}

		sched_yield();

		if (map->type) {
			debug(ap->logopt,
			      "reading map %s %s", map->type, map->argv[0]);
			result = do_read_map(ap, map, age);
			map = map->next;
			continue;
		}

		/* If it starts with a '/' it has to be a file or LDAP map */
		if (map->argv && *map->argv[0] == '/') {
			if (*(map->argv[0] + 1) == '/') {
				char *tmp = strdup("ldap");
				if (!tmp) {
					map = map->next;
					continue;
				}
				map->type = tmp;
				debug(ap->logopt,
				      "reading map %s %s", tmp, map->argv[0]);
				result = do_read_map(ap, map, age);
			} else {
				debug(ap->logopt,
				      "reading map file %s", map->argv[0]);
				result = read_file_source_instance(ap, map, age);
			}
			map = map->next;
			continue;
		}

		INIT_LIST_HEAD(&nsslist);

		status = nsswitch_parse(&nsslist);
		if (status) {
			error(ap->logopt,
			      "can't to read name service switch config.");
			result = 1;
			break;
		}

		head = &nsslist;
		list_for_each(p, head) {
			this = list_entry(p, struct nss_source, list);

			debug(ap->logopt,
			      "reading map %s %s", this->source, map->argv[0]);

			result = read_map_source(this, ap, map, age);
			if (result == NSS_STATUS_UNKNOWN)
				continue;

			status = check_nss_result(this, result);
			if (status >= 0) {
				result = !status;
				map = NULL;
				break;
			}
		}

		if (!list_empty(&nsslist))
			free_sources(&nsslist);

		if (!map)
			break;

		map = map->next;
	}
	pthread_cleanup_pop(1);

	return !result;
}

int lookup_ghost(struct autofs_point *ap)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me;
	char buf[MAX_ERR_BUF];
	struct stat st;
	char *fullpath;
	int ret;

	if (!strcmp(ap->path, "/-"))
		return LKP_FAIL | LKP_DIRECT;

	if (!ap->ghost)
		return LKP_INDIRECT;

	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	map = entry->first;
	while (map) {
		/*
		 * Only consider map sources that have been read since 
		 * the map entry was last updated.
		 */
		if (entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_readlock(mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			if (*me->key == '*')
				goto next;

			if (*me->key == '/') {
				/* It's a busy multi-mount - leave till next time */
				if (list_empty(&me->multi_list))
					error(ap->logopt,
					      "invalid key %s", me->key);
				goto next;
			}

			fullpath = alloca(strlen(me->key) + strlen(ap->path) + 3);
			if (!fullpath) {
				warn(ap->logopt, "failed to allocate full path");
				goto next;
			}
			sprintf(fullpath, "%s/%s", ap->path, me->key);

			ret = stat(fullpath, &st);
			if (ret == -1 && errno != ENOENT) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				warn(ap->logopt, "stat error %s", estr);
				goto next;
			}

			ret = mkdir_path(fullpath, 0555);
			if (ret < 0 && errno != EEXIST) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				warn(ap->logopt,
				     "mkdir_path %s failed: %s", fullpath, estr);
				goto next;
			}

			if (stat(fullpath, &st) != -1) {
				me->dev = st.st_dev;
				me->ino = st.st_ino;
			}
next:
			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);

	return LKP_INDIRECT;
}

int do_lookup_mount(struct autofs_point *ap, struct map_source *map, const char *name, int name_len)
{
	struct lookup_mod *lookup;
	int status;

	if (!map->lookup) {
		lookup = open_lookup(map->type, "",
				     map->format, map->argc, map->argv);
		if (!lookup) {
			debug(ap->logopt,
			      "lookup module %s failed", map->type);
			return NSS_STATUS_UNAVAIL;
		}
		map->lookup = lookup;
	}

	lookup = map->lookup;

	master_source_current_wait(ap->entry);
	ap->entry->current = map;

	status = lookup->lookup_mount(ap, name, name_len, lookup->context);

	return status;
}

static int lookup_name_file_source_instance(struct autofs_point *ap, struct map_source *map, const char *name, int name_len)
{
	struct map_source *instance;
	char src_file[] = "file";
	char src_prog[] = "program";
	time_t age = time(NULL);
	struct stat st;
	char *type, *format;

	if (stat(map->argv[0], &st) == -1) {
		warn(ap->logopt, "file map not found");
		return NSS_STATUS_NOTFOUND;
	}

	if (!S_ISREG(st.st_mode))
		return NSS_STATUS_NOTFOUND;

	if (st.st_mode & __S_IEXEC)
		type = src_prog;
	else
		type = src_file;

	format = map->format;

	instance = master_add_source_instance(map, type, format, age);
	if (!instance)
		return NSS_STATUS_NOTFOUND;

	return do_lookup_mount(ap, instance, name, name_len);
}

static int lookup_name_source_instance(struct autofs_point *ap, struct map_source *map, const char *type, const char *name, int name_len)
{
	struct map_source *instance;
	const char *format;
	time_t age = time(NULL);

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance)
		instance = master_add_source_instance(map, type, format, age);

	return do_lookup_mount(ap, instance, name, name_len);
}

static enum nsswitch_status lookup_map_name(struct nss_source *this,
			struct autofs_point *ap, struct map_source *map,
			const char *name, int name_len)
{
	enum nsswitch_status result;
	struct map_source *instance;
	struct map_source tmap;
	char *path;

	if (strcasecmp(this->source, "files"))
		return lookup_name_source_instance(ap, map,
					this->source, name, name_len);

	/* 
	 * autofs build-in map for nsswitch "files" is "file".
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: we consider it invalid to specify a relative
	 *       path.
	 */
	if (strchr(map->argv[0], '/')) {
		error(ap->logopt, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	instance = master_find_source_instance(map, "file", map->format, 0, NULL);
	if (!instance)
		instance = master_find_source_instance(map, "program", map->format, 0, NULL);

	if (instance)
		return lookup_name_file_source_instance(ap, map, name, name_len);

	this->source[4] = '\0';
	tmap.type = this->source;
	tmap.format = map->format;
	tmap.mc = map->mc;
	tmap.instance = map->instance;
	tmap.argc = 0;
	tmap.argv = NULL;

	path = malloc(strlen(AUTOFS_MAP_DIR) + strlen(map->argv[0]) + 2);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	strcpy(path, AUTOFS_MAP_DIR);
	strcat(path, "/");
	strcat(path, map->argv[0]);

	if (map->argc >= 1) {
		tmap.argc = map->argc;
		tmap.argv = copy_argv(map->argc, map->argv);
		if (!tmap.argv) {
			error(ap->logopt, "failed to copy args");
			free(path);
			return NSS_STATUS_UNKNOWN;
		}
		if (tmap.argv[0])
			free((char *) tmap.argv[0]);
		tmap.argv[0] = path;
	} else {
		error(ap->logopt, "invalid arguments for autofs_point");
		free(path);
		return NSS_STATUS_UNKNOWN;
	}

	result = lookup_name_file_source_instance(ap, &tmap, name, name_len);

	/* path is freed in free_argv */
	free_argv(tmap.argc, tmap.argv);

	return result;
}

int lookup_nss_mount(struct autofs_point *ap, const char *name, int name_len)
{
	struct master_mapent *entry = ap->entry;
	struct list_head nsslist;
	struct list_head *head, *p;
	struct nss_source *this;
	struct map_source *map;
	enum nsswitch_status status;
	int result = 0;

	/*
	 * For each map source (ie. each entry for the mount
	 * point in the master map) do the nss lookup to
	 * locate the map and lookup the name.
	 */
	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	map = entry->first;
	while (map) {
		/*
		 * Only consider map sources that have been read since 
		 * the map entry was last updated.
		 */
		if (entry->age > map->age) {
			map = map->next;
			continue;
		}

		sched_yield();

		if (map->type) {
			result = do_lookup_mount(ap, map, name, name_len);

			if (result == NSS_STATUS_SUCCESS)
				break;

			map = map->next;
			continue;
		}

		/* If it starts with a '/' it has to be a file or LDAP map */
		if (*map->argv[0] == '/') {
			if (*(map->argv[0] + 1) == '/') {
				char *tmp = strdup("ldap");
				if (!tmp) {
					map = map->next;
					continue;
				}
				map->type = tmp;
				result = do_lookup_mount(ap, map, name, name_len);
			} else
				result = lookup_name_file_source_instance(ap, map, name, name_len);

			if (result == NSS_STATUS_SUCCESS)
				break;

			map = map->next;
			continue;
		}

		INIT_LIST_HEAD(&nsslist);

		status = nsswitch_parse(&nsslist);
		if (status) {
			error(ap->logopt,
			      "can't to read name service switch config.");
			result = 1;
			break;
		}

		head = &nsslist;
		list_for_each(p, head) {
			enum nsswitch_status status;

			this = list_entry(p, struct nss_source, list);

			result = lookup_map_name(this, ap, map, name, name_len);

			if (result == NSS_STATUS_UNKNOWN) {
				map = map->next;
				continue;
			}

			status = check_nss_result(this, result);
			if (status >= 0) {
				map = NULL;
				break;
			}
		}

		if (!list_empty(&nsslist))
			free_sources(&nsslist);

		if (!map)
			break;

		map = map->next;
	}
	pthread_cleanup_pop(1);

	return !result;
}

void lookup_close_lookup(struct autofs_point *ap)
{
	struct map_source *map;

	map = ap->entry->first;
	if (!map)
		return;

	while (map) {
		struct map_source *instance;

		instance = map->instance;
		while (instance) {
			if (instance->lookup) {
				close_lookup(instance->lookup);
				instance->lookup = NULL;
			}
			instance = instance->next;
		}

		if (map->lookup) {
			close_lookup(map->lookup);
			map->lookup = NULL;
		}
		map = map->next;
	}
	return;
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
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me, *this;
	char *path;
	int status = CHE_FAIL;

	master_source_readlock(entry);

	map = entry->first;
	while (map) {
		if (!map->stale) {
			map = map->next;
			continue;
		}
		mc = map->mc;
		cache_readlock(mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			char *key = NULL, *next_key = NULL;

			if (me->age >= age) {
				me = cache_enumerate(mc, me);
				continue;
			}

			key = strdup(me->key);
			me = cache_enumerate(mc, me);
			if (!key)
				continue;

			path = make_fullpath(ap->path, key);
			if (!path) {
				warn(ap->logopt,
				     "can't malloc storage for path");
				free(key);
				continue;
			}

			if (is_mounted(_PATH_MOUNTED, path, MNTS_REAL)) {
				debug(ap->logopt,
				      "prune posponed, %s is mounted", path);
				free(key);
				free(path);
				continue;
			}

			if (me)
				next_key = strdup(me->key);

			cache_unlock(mc);

			cache_writelock(mc);
			this = cache_lookup_distinct(mc, key);
			if (!this) {
				cache_unlock(mc);
				free(key);
				if (next_key)
					free(next_key);
				free(path);
				goto next;
			}

			if (!is_mounted(_PROC_MOUNTS, path, MNTS_AUTOFS)) {
				status = CHE_FAIL;
				if (this->ioctlfd == -1)
					status = cache_delete(mc, key);
				if (status != CHE_FAIL) {
					if (ap->type == LKP_INDIRECT)
						rmdir_path(ap, path, ap->dev);
					else
						rmdir_path(ap, path, this->dev);
				}
			}
			cache_unlock(mc);

			if (!next_key) {
				free(key);
				free(path);
				cache_readlock(mc);
				continue;
			}
next:
			cache_readlock(mc);
			me = cache_lookup_distinct(mc, next_key);
			free(key);
			free(path);
			free(next_key);
		}
		cache_unlock(mc);
		map->stale = 0;
		map = map->next;
	}

	master_source_unlock(entry);

	return 1;
}

/* Return with cache readlock held */
struct mapent *lookup_source_valid_mapent(struct autofs_point *ap, const char *key, unsigned int type)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me = NULL;

	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	map = entry->first;
	while (map) {
		/*
		 * Only consider map sources that have been read since
		 * the map entry was last updated.
		 */
		if (ap->entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		cache_readlock(mc);
		if (type == LKP_DISTINCT)
			me = cache_lookup_distinct(mc, key);
		else
			me = cache_lookup(mc, key);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}
	pthread_cleanup_pop(1);

	return me;
}

/* Return with cache readlock held */
struct mapent *lookup_source_mapent(struct autofs_point *ap, const char *key, unsigned int type)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me = NULL;

	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	map = entry->first;
	while (map) {
		mc = map->mc;
		cache_readlock(mc);
		if (type == LKP_DISTINCT)
			me = cache_lookup_distinct(mc, key);
		else
			me = cache_lookup(mc, key);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}
	pthread_cleanup_pop(1);

	return me;
}

int lookup_source_close_ioctlfd(struct autofs_point *ap, const char *key)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me;
	int ret = 0;

	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	map = entry->first;
	while (map) {
		mc = map->mc;
		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me) {
			if (me->ioctlfd != -1) {
				close(me->ioctlfd);
				me->ioctlfd = -1;
			}
			cache_unlock(mc);
			ret = 1;
			break;
		}
		cache_unlock(mc);
		map = map->next;
	}
	pthread_cleanup_pop(1);

	return ret;
}

