/* ----------------------------------------------------------------------- *
 *   
 *  cache.c - mount entry cache management routines
 *
 *   Copyright 2002-2003 Ian Kent <raven@themaw.net> - All Rights Reserved
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>
#include <stdio.h>
#include <fcntl.h>
#include <mntent.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "automount.h"

extern int kproto_version;	/* Kernel protocol major version */
extern int kproto_sub_version;	/* Kernel protocol minor version */

#define HASHSIZE      27

struct ghost_context {
	const char *root;
	char *mapname;
	char direct_base[KEY_MAX_LEN + 1];
	char key[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
};

static struct mapent_cache *mapent_hash[HASHSIZE];

static unsigned long ent_check(struct ghost_context *gc, char **key, int ghost);

static unsigned int hash(const char *key)
{
	unsigned long hashval;
	char *s = (char *) key;

	for (hashval = 0; *s != '\0';)
		hashval += *s++;

	return hashval % HASHSIZE;
}

void cache_init(void)
{
	int i;

	cache_release();

	for (i = 0; i < HASHSIZE; i++)
		mapent_hash[i] = NULL;
}

struct mapent_cache *cache_lookup_first(void)
{
	struct mapent_cache *me = NULL;
	int i;

	for (i = 0; i < HASHSIZE; i++) {
		me = mapent_hash[i];
		if (me != NULL)
			break;
	}
	return me;
}

struct mapent_cache *cache_lookup(const char *key)
{
	struct mapent_cache *me = NULL;

	for (me = mapent_hash[hash(key)]; me != NULL; me = me->next)
		if (strcmp(key, me->key) == 0)
			return me;

	me = cache_lookup_first();
	if (me != NULL) {
		/* Can't have wildcard in direct map */
		if (*me->key == '/')
			return NULL;

		for (me = mapent_hash[hash("*")]; me != NULL; me = me->next)
			if (strcmp("*", me->key) == 0)
				return me;
	}
	return NULL;
}

struct mapent_cache *cache_lookup_next(struct mapent_cache *me)
{
	struct mapent_cache *next = me->next;

	while (next != NULL) {
		if (!strcmp(me->key, next->key))
			return next;

		next = next->next;
	}
	return NULL;
}

struct mapent_cache *cache_partial_match(const char *prefix)
{
	struct mapent_cache *me = NULL;
	int len = strlen(prefix);
	int i;

	for (i = 0; i < HASHSIZE; i++) {
		me = mapent_hash[i];
		if (me == NULL)
			continue;
		if (len < strlen(me->key) &&
		    (strncmp(prefix, me->key, len) == 0) && me->key[len] == '/')
			return me;

		me = me->next;
		while (me != NULL) {
			if (len < strlen(me->key) &&
			    strncmp(prefix, me->key, len) == 0 && me->key[len] == '/')
				return me;
			me = me->next;
		}
	}
	return NULL;
}

int cache_update(const char *key, const char *mapent, time_t age)
{
	struct mapent_cache *s, *me = NULL;
	char *pkey, *pent;
	unsigned int hashval;

	for (s = mapent_hash[hash(key)]; s != NULL; s = s->next)
		if (strcmp(key, s->key) == 0)
			me = s;

	if (me == NULL) {
		me = (struct mapent_cache *) malloc(sizeof(struct mapent_cache));
		if (me == NULL) {
			return 0;
		}

		pkey = malloc(strlen(key) + 1);
		if (pkey == NULL) {
			free(me);
			return 0;
		}

		pent = malloc(strlen(mapent) + 1);
		if (pent == NULL) {
			free(me);
			free(pkey);
			return 0;
		}

		me->key = strcpy(pkey, key);
		me->mapent = strcpy(pent, mapent);
		me->age = age;

		hashval = hash(pkey);
		me->next = mapent_hash[hashval];
		mapent_hash[hashval] = me;
	} else {
		if (strcmp(me->mapent, mapent) != 0) {
			pent = malloc(strlen(mapent) + 1);
			if (pent == NULL) {
				return 0;
			}
			free(me->mapent);
			me->mapent = strcpy(pent, mapent);
		}
		me->age = age;
	}
	return 1;
}

int cache_delete(const char *root, const char *key)
{
	struct mapent_cache *me = NULL, *pred;
	char path[KEY_MAX_LEN + 1];
	unsigned int hashval = hash(key);

	if (*key == '/')
		strcpy(path, key);
	else
		sprintf(path, "%s/%s", root, me->key);

	me = mapent_hash[hashval];
	if (me == NULL)
		return 0;

	if (strcmp(key, me->key) == 0) {
		if (is_mounted(path))
			return 0;
		mapent_hash[hashval] = me->next;
		goto found;
	}

	while (me->next != NULL) {
		pred = me;
		me = me->next;
		if (strcmp(key, me->key) == 0) {
			if (is_mounted(path))
				return 0;

			pred->next = me->next;
			goto found;
		}
	}
	return 0;

      found:
	rmdir_path(path);
	free(me->key);
	free(me->mapent);
	free(me);
	return 1;
}

void cache_clean(const char *root, time_t age)
{
	struct mapent_cache *me, *pred;
	char path[KEY_MAX_LEN + 1];
	int i;

	for (i = 0; i < HASHSIZE; i++) {
		me = mapent_hash[i];
		if (me == NULL)
			continue;

		while (me->next != NULL) {
			pred = me;
			me = me->next;
			if (*me->key == '/') {
				strcpy(path, me->key);
			} else {
				sprintf(path, "%s/%s", root, me->key);
			}

			if (is_mounted(path))
				continue;

			if (me->age < age) {
				pred->next = me->next;
				rmdir_path(path);
				free(me->key);
				free(me->mapent);
				free(me);
				me = pred;
			}
		}

		me = mapent_hash[i];
		if (*me->key == '/') {
			strcpy(path, me->key);
		} else {
			sprintf(path, "%s/%s", root, me->key);
		}

		if (is_mounted(path))
			continue;

		if (me->age < age) {
			mapent_hash[i] = me->next;
			rmdir_path(path);
			free(me->key);
			free(me->mapent);
			free(me);
		}
	}
}

void cache_release(void)
{
	struct mapent_cache *me, *next;
	int i;

	for (i = 0; i < HASHSIZE; i++) {
		me = mapent_hash[i];
		if (me == NULL)
			continue;
		next = me->next;
		free(me->key);
		free(me->mapent);
		free(me);

		while (next != NULL) {
			me = next;
			next = me->next;
			free(me->key);
			free(me->mapent);
			free(me);
		}
	}
}

int cache_ghost(const char *root, int ghosted,
		const char *mapname, const char *type, struct parse_mod *parse)
{
	struct mapent_cache *me;
	struct ghost_context gc;
	char *pkey = NULL;
	char *fullpath;
	struct stat st;
	unsigned long match = 0;
	unsigned long map = LKP_INDIRECT;
	int i;

	chdir("/");

	memset(&gc, 0, sizeof(struct ghost_context));
	gc.root = root;
	gc.mapname = alloca(strlen(mapname) + 6);
	sprintf(gc.mapname, "%s:%s", type, mapname);

	for (i = 0; i < HASHSIZE; i++) {
		me = mapent_hash[i];

		if (me == NULL)
			continue;

		while (me != NULL) {
			strcpy(gc.key, me->key);
			strcpy(gc.mapent, me->mapent);

			match = ent_check(&gc, &pkey, ghosted);

			if (match == LKP_ERR_FORMAT) {
				error("cache_ghost: entry in %s not valid map "
				      "format, key %s",
				       gc.mapname, gc.key);
			} else if (match == LKP_WILD) {
				if (*me->key == '/')
					error("cache_ghost: wildcard map key "
					      "not valid in direct map");
				me = me->next;
				continue;;
			}

			switch (match) {
			case LKP_MATCH:
				if (!ghosted)
					break;

				if (*gc.key == '/') {
					fullpath = alloca(strlen(gc.key) + 2);
					sprintf(fullpath, "%s", gc.key);
				} else {
					fullpath =
					    alloca(strlen(gc.key) + strlen(gc.root) + 3);
					sprintf(fullpath, "%s/%s", gc.root, gc.key);
				}

				if (stat(fullpath, &st) == -1 && errno == ENOENT) {
					if (mkdir_path(fullpath, 0555) < 0)
						warn("cache_ghost: mkdir_path %s "
						     "failed: %m",
						      fullpath);
				}
				break;

			case LKP_MOUNT:
				if (!is_mounted(gc.direct_base)) {
					debug("cache_ghost: attempting to mount map, "
					      "key %s",
					      gc.direct_base);
					parse->parse_mount("", gc.direct_base + 1,
							   strlen(gc.direct_base) - 1,
							   gc.mapent, parse->context);
				}
				break;
			}
			me = me->next;
		}
	}

	me = cache_lookup_first();
	if (!me)
		return LKP_FAIL;
	if (*me->key == '/')
		map = LKP_DIRECT;
	return map;
}

int is_mounted(const char *path)
{
	struct mntent *mnt;
	FILE *mtab;
	int pathlen = strlen(path);
	int ret = 0;

	if (!path || !pathlen)
		return ret;

	wait_for_lock();
	mtab = setmntent(_PATH_MOUNTED, "r");
	if (!mtab) {
		unlink(AUTOFS_LOCK);
		error("is_mounted: setmntent: %m");
		return -1;
	}

	while ((mnt = getmntent(mtab)) != NULL) {
		int len = strlen(mnt->mnt_dir);

		if (pathlen == len && !strncmp(path, mnt->mnt_dir, pathlen)) {
			ret = 1;
			break;
		}
	}

	endmntent(mtab);
	unlink(AUTOFS_LOCK);

	return ret;
}

static unsigned long ent_check(struct ghost_context *gc, char **pkey, int ghosted)
{
	char *proot = (char *) gc->root;
	char *slash, *pk;
	size_t len;

	*pkey = gc->key;

	if (*gc->key == '*') {
		return LKP_WILD;
	}

	/* Indirect map ghost, return key */
	if (*gc->key != '/')
		return LKP_MATCH;

	/* Base path of direct map, each new dir needs to be mounted */
	if (!strncmp(gc->root, "/-", 2)) {
		slash = strchr(gc->key + 1, '/');

		if (*gc->key != '/' || !slash) {
			return LKP_ERR_FORMAT;
		}

		*slash = '\0';
		len = strlen(gc->key);
		if (strncmp(gc->direct_base, gc->key, len)) {
			strncpy(gc->direct_base, gc->key, len);
			*(gc->direct_base + len) = '\0';
			sprintf(gc->mapent, "-fstype=autofs %s", gc->mapname);
			return LKP_MOUNT;
		}
		return LKP_NEXT;
	}

	/* Direct map entry, pick out component of path */
	if (*gc->key == '/') {
		pk = gc->key;
		len = strlen(gc->root);
		if (!strncmp(gc->root, gc->key, len)) {
			len--;
			while ((*proot++ == *pk++) && len)
				len--;
			if (len || *pk++ != '/')
				return LKP_NOMATCH;
			slash = strchr(pk, '/');
			*pkey = pk;
			/* Path component, internal mount for lookup_mount */
			if (slash && (!ghosted ||
				      (kproto_version >= 4 && kproto_sub_version < 2))) {
				*slash = '\0';
				sprintf(gc->mapent, "-fstype=autofs %s", gc->mapname);
			}
			return LKP_MATCH;
		}
	}
	return LKP_NOMATCH;
}
