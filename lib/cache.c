/* ----------------------------------------------------------------------- *
 *   
 *  cache.c - mount entry cache management routines
 *
 *   Copyright 2002-2005 Ian Kent <raven@themaw.net> - All Rights Reserved
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "automount.h"

void cache_dump_multi(struct list_head *list)
{
	struct list_head *p;
	struct mapent *me;

	list_for_each(p, list) {
		me = list_entry(p, struct mapent, multi_list);
		msg("key=%s", me->key);
	}
}

void cache_dump_cache(struct mapent_cache *mc)
{
	struct mapent *me;
	unsigned int i;

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (me == NULL)
			continue;
		while (me) {
			msg("me->key=%s me->multi=%p dev=%ld ino=%ld",
				me->key, me->multi, me->dev, me->ino);
			me = me->next;
		}
	}
}

void cache_readlock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_rdlock(&mc->rwlock);
	if (status) {
		error(LOGOPT_ANY, "mapent cache rwlock lock failed");
		fatal(status);
	}
	return;
}

void cache_writelock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_wrlock(&mc->rwlock);
	if (status) {
		error(LOGOPT_ANY, "mapent cache rwlock lock failed");
		fatal(status);
	}
	return;
}

int cache_try_writelock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_trywrlock(&mc->rwlock);
	if (status) {
		debug(LOGOPT_ANY, "mapent cache rwlock busy");
		return 0;
	}
	return 1;
}

void cache_unlock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_unlock(&mc->rwlock);
	if (status) {
		error(LOGOPT_ANY, "mapent cache rwlock unlock failed");
		fatal(status);
	}
	return;
}

void cache_lock_cleanup(void *arg)
{
	struct mapent_cache *mc = (struct mapent_cache *) arg;

	cache_unlock(mc);
	return;
}

void cache_multi_lock(struct mapent *me)
{
	int status;

	if (!me)
		return;

	status = pthread_mutex_lock(&me->multi_mutex);
	if (status) {
		error(LOGOPT_ANY, "mapent cache multi mutex lock failed");
		fatal(status);
	}
	return;
}

void cache_multi_unlock(struct mapent *me)
{
	int status;

	if (!me)
		return;

	status = pthread_mutex_unlock(&me->multi_mutex);
	if (status) {
		error(LOGOPT_ANY, "mapent cache multi mutex unlock failed");
		fatal(status);
	}
	return;
}

void cache_multi_lock_cleanup(void *arg)
{
	struct mapent *me = (struct mapent *) arg;
	cache_multi_unlock(me);
	return;
}

static inline void ino_index_lock(struct mapent_cache *mc)
{
	int status = pthread_mutex_lock(&mc->ino_index_mutex);
	if (status)
		fatal(status);
	return;
}

static inline void ino_index_unlock(struct mapent_cache *mc)
{
	int status = pthread_mutex_unlock(&mc->ino_index_mutex);
	if (status)
		fatal(status);
	return;
}

struct mapent_cache *cache_init(struct map_source *map)
{
	struct mapent_cache *mc;
	unsigned int i;
	int status;

	if (map->mc)
		cache_release(map);

	mc = malloc(sizeof(struct mapent_cache));
	if (!mc)
		return NULL;

	mc->size = HASHSIZE;

	mc->hash = malloc(mc->size * sizeof(struct entry *));
	if (!mc->hash) {
		free(mc);
		return NULL;
	}

	mc->ino_index = malloc(mc->size * sizeof(struct list_head));
	if (!mc->ino_index) {
		free(mc->hash);
		free(mc);
		return NULL;
	}

	status = pthread_mutex_init(&mc->ino_index_mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_rwlock_init(&mc->rwlock, NULL);
	if (status)
		fatal(status);

	cache_writelock(mc);

	for (i = 0; i < mc->size; i++) {
		mc->hash[i] = NULL;
		INIT_LIST_HEAD(&mc->ino_index[i]);
	}

	mc->map = map;

	cache_unlock(mc);

	return mc;
}

struct mapent_cache *cache_init_null_cache(struct master *master)
{
	struct mapent_cache *mc;
	unsigned int i;
	int status;

	if (master->nc)
		cache_release_null_cache(master);

	mc = malloc(sizeof(struct mapent_cache));
	if (!mc)
		return NULL;

	mc->size = HASHSIZE;

	mc->hash = malloc(mc->size * sizeof(struct entry *));
	if (!mc->hash) {
		free(mc);
		return NULL;
	}

	mc->ino_index = malloc(mc->size * sizeof(struct list_head));
	if (!mc->ino_index) {
		free(mc->hash);
		free(mc);
		return NULL;
	}

	status = pthread_mutex_init(&mc->ino_index_mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_rwlock_init(&mc->rwlock, NULL);
	if (status)
		fatal(status);

	cache_writelock(mc);

	for (i = 0; i < mc->size; i++) {
		mc->hash[i] = NULL;
		INIT_LIST_HEAD(&mc->ino_index[i]);
	}

	cache_unlock(mc);

	return mc;
}

static unsigned int hash(const char *key)
{
	unsigned long hashval;
	char *s = (char *) key;

	for (hashval = 0; *s != '\0';)
		hashval += *s++;

	return hashval % HASHSIZE;
}

static unsigned int ino_hash(dev_t dev, ino_t ino)
{
	unsigned long hashval;

	hashval = dev + ino;

	return hashval % HASHSIZE;
}

int cache_set_ino_index(struct mapent_cache *mc, const char *key, dev_t dev, ino_t ino)
{
	unsigned int ino_index = ino_hash(dev, ino);
	struct mapent *me;

	me = cache_lookup_distinct(mc, key);
	if (!me)
		return 0;

	ino_index_lock(mc);
	list_del_init(&me->ino_index);
	list_add(&me->ino_index, &mc->ino_index[ino_index]);
	me->dev = dev;
	me->ino = ino;
	ino_index_unlock(mc);

	return 1;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_ino(struct mapent_cache *mc, dev_t dev, ino_t ino)
{
	struct mapent *me = NULL;
	struct list_head *head, *p;
	unsigned int ino_index;

	ino_index_lock(mc);
	ino_index = ino_hash(dev, ino);
	head = &mc->ino_index[ino_index];

	list_for_each(p, head) {
		me = list_entry(p, struct mapent, ino_index);

		if (me->dev != dev || me->ino != ino)
			continue;

		ino_index_unlock(mc);
		return me;
	}
	ino_index_unlock(mc);
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_first(struct mapent_cache *mc)
{
	struct mapent *me = NULL;
	unsigned int i;

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (!me)
			continue;

		while (me) {
			/* Multi mount entries are not primary */
			if (me->multi && me->multi != me) {
				me = me->next;
				continue;
			}
			return me;
		}
	}
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_next(struct mapent_cache *mc, struct mapent *me)
{
	struct mapent *this;
	unsigned long hashval;
	unsigned int i;

	if (!me)
		return NULL;

	this = me->next;
	while (this) {
		/* Multi mount entries are not primary */
		if (this->multi && this->multi != this) {
			this = this->next;
			continue;
		}
		return this;
	}

	hashval = hash(me->key) + 1;
	if (hashval < mc->size) {
		for (i = (unsigned int) hashval; i < mc->size; i++) {
			this = mc->hash[i];
			if (!this)
				continue;

			while (this) {
				/* Multi mount entries are not primary */
				if (this->multi && this->multi != this) {
					this = this->next;
					continue;
				}
				return this;
			}
		}
	}
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_key_next(struct mapent *me)
{
	struct mapent *next;

	if (!me)
		return NULL;

	next = me->next;
	while (next) {
		/* Multi mount entries are not primary */
		if (me->multi && me->multi != me)
			continue;
		if (!strcmp(me->key, next->key))
			return next;
		next = next->next;
	}
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup(struct mapent_cache *mc, const char *key)
{
	struct mapent *me = NULL;

	if (!key)
		return NULL;

	for (me = mc->hash[hash(key)]; me != NULL; me = me->next) {
		if (strcmp(key, me->key) == 0)
			goto done;
	}

	me = cache_lookup_first(mc);
	if (me != NULL) {
		/* Can't have wildcard in direct map */
		if (*me->key == '/') {
			me = NULL;
			goto done;
		}

		for (me = mc->hash[hash("*")]; me != NULL; me = me->next)
			if (strcmp("*", me->key) == 0)
				goto done;
	}
done:
	return me;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_distinct(struct mapent_cache *mc, const char *key)
{
	struct mapent *me;

	if (!key)
		return NULL;

	for (me = mc->hash[hash(key)]; me != NULL; me = me->next) {
		if (strcmp(key, me->key) == 0)
			return me;
	}

	return NULL;
}

/* Lookup an offset within a multi-mount entry */
struct mapent *cache_lookup_offset(const char *prefix, const char *offset, int start, struct list_head *head)
{
	struct list_head *p;
	struct mapent *this;
	int plen = strlen(prefix);
	char *o_key;

	/* root offset duplicates "/" */
	if (plen > 1) {
		o_key = alloca(plen + strlen(offset) + 1);
		strcpy(o_key, prefix);
		strcat(o_key, offset);
	} else {
		o_key = alloca(strlen(offset) + 1);
		strcpy(o_key, offset);
	}

	list_for_each(p, head) {
		this = list_entry(p, struct mapent, multi_list);
		if (!strcmp(&this->key[start], o_key))
			goto done;
	}
	this = NULL;
done:
	return this;
}

/* cache must be read locked by caller */
struct mapent *cache_partial_match(struct mapent_cache *mc, const char *prefix)
{
	struct mapent *me = NULL;
	size_t len = strlen(prefix);
	unsigned int i;

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
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

/* cache must be write locked by caller */
int cache_add(struct mapent_cache *mc, const char *key, const char *mapent, time_t age)
{
	struct mapent *me, *existing = NULL;
	char *pkey, *pent;
	unsigned int hashval = hash(key);
	int status;

	me = (struct mapent *) malloc(sizeof(struct mapent));
	if (!me)
		return CHE_FAIL;

	pkey = malloc(strlen(key) + 1);
	if (!pkey) {
		free(me);
		return CHE_FAIL;
	}
	me->key = strcpy(pkey, key);

	if (mapent) {
		pent = malloc(strlen(mapent) + 1);
		if (!pent) {
			free(me);
			free(pkey);
			return CHE_FAIL;
		}
		me->mapent = strcpy(pent, mapent);
	} else
		me->mapent = NULL;

	me->age = age;
	me->status = 0;
	me->mc = mc;
	INIT_LIST_HEAD(&me->ino_index);
	INIT_LIST_HEAD(&me->multi_list);
	me->multi = NULL;
	me->parent = NULL;
	me->ioctlfd = -1;
	me->dev = (dev_t) -1;
	me->ino = (ino_t) -1;

	status = pthread_mutex_init(&me->multi_mutex, NULL);
	if (status)
		fatal(status);

	/* 
	 * We need to add to the end if values exist in order to
	 * preserve the order in which the map was read on lookup.
	 */
	existing = cache_lookup_distinct(mc, key);
	if (!existing) {
		me->next = mc->hash[hashval];
		mc->hash[hashval] = me;
	} else {
		while (1) {
			struct mapent *next;
		
			next = cache_lookup_key_next(existing);
			if (!next)
				break;

			existing = next;
		}
		me->next = existing->next;
		existing->next = me;
	}
	return CHE_OK;
}

/* cache must be write locked by caller */
static void cache_add_ordered_offset(struct mapent *me, struct list_head *head)
{
	struct list_head *p;
	struct mapent *this;

	list_for_each(p, head) {
		size_t tlen;
		int eq;

		this = list_entry(p, struct mapent, multi_list);
		tlen = strlen(this->key);

		eq = strncmp(this->key, me->key, tlen);
		if (!eq && tlen == strlen(me->key))
			return;

		if (eq > 0) {
			list_add_tail(&me->multi_list, p);
			return;
		}
	}
	list_add_tail(&me->multi_list, p);

	return;
}

/* cache must be write locked by caller */
int cache_add_offset(struct mapent_cache *mc, const char *mkey, const char *key, const char *mapent, time_t age)
{
	struct mapent *me, *owner;
	int ret = CHE_OK;

	owner = cache_lookup_distinct(mc, mkey);
	if (!owner)
		return CHE_FAIL;

	me = cache_lookup_distinct(mc, key);
	if (me && me != owner)
		return CHE_DUPLICATE;

	ret = cache_add(mc, key, mapent, age);
	if (ret == CHE_FAIL) {
		warn(LOGOPT_ANY, "failed to add key %s to cache", key);
		return CHE_FAIL;
	}

	me = cache_lookup_distinct(mc, key);
	if (me) {
		cache_add_ordered_offset(me, &owner->multi_list);
		me->multi = owner;
		goto done;
	}
	ret = CHE_FAIL;
done:
	return ret; 
}

static struct mapent *get_parent(const char *key, struct list_head *head, struct list_head **pos)
{
	struct list_head *next;
	struct mapent *this, *last;
	int eq;

	last = NULL;
	next = *pos ? (*pos)->next : head->next;

	list_for_each(next, head) {
		this = list_entry(next, struct mapent, multi_list);

		if (!strcmp(this->key, key))
			break;

		eq = strncmp(this->key, key, strlen(this->key));
		if (eq == 0) {
			*pos = next;
			last = this;
			continue;
		}
	}

	return last;
}

int cache_set_parents(struct mapent *mm)
{
	struct list_head *multi_head, *p, *pos;
	struct mapent *this;

	if (!mm->multi)
		return 0;

	pos = NULL;
	multi_head = &mm->multi->multi_list;

	list_for_each(p, multi_head) {
		struct mapent *parent;
		this = list_entry(p, struct mapent, multi_list);
		parent = get_parent(this->key, multi_head, &pos);
		if (parent)
			this->parent = parent;
		else
			this->parent = mm->multi;
	}

	return 1;
}

/* cache must be write locked by caller */
int cache_update(struct mapent_cache *mc, const char *key, const char *mapent, time_t age)
{
	struct mapent *me = NULL;
	char *pent;
	int ret = CHE_OK;

	me = cache_lookup(mc, key);
	if (!me || (*me->key == '*' && *key != '*')) {
		ret = cache_add(mc, key, mapent, age);
		if (!ret) {
			debug(LOGOPT_NONE, "failed for %s", key);
			return CHE_FAIL;
		}
		ret = CHE_UPDATED;
	} else {
		/* Already seen one of these */
		if (me->age == age)
			return CHE_OK;

		if (!mapent)
			me->mapent = NULL;
		else if (!me->mapent || strcmp(me->mapent, mapent) != 0) {
			pent = malloc(strlen(mapent) + 1);
			if (pent == NULL)
				return CHE_FAIL;
			if (me->mapent)
				free(me->mapent);
			me->mapent = strcpy(pent, mapent);
			ret = CHE_UPDATED;
		}
		me->age = age;
	}
	return ret;
}

/* cache must be write locked by caller */
int cache_delete(struct mapent_cache *mc, const char *key)
{
	struct mapent *me = NULL, *pred;
	unsigned int hashval = hash(key);
	int status, ret = CHE_OK;
	char *this;

	this = alloca(strlen(key) + 1);
	if (!this) {
		ret = CHE_FAIL;
		goto done;
	}
	strcpy(this, key);

	me = mc->hash[hashval];
	if (!me) {
		ret = CHE_FAIL;
		goto done;
	}

	while (me->next != NULL) {
		pred = me;
		me = me->next;
		if (strcmp(this, me->key) == 0) {
			if (me->multi && !list_empty(&me->multi_list)) {
				ret = CHE_FAIL;
				goto done;
			}
			pred->next = me->next;
			status = pthread_mutex_destroy(&me->multi_mutex);
			if (status)
				fatal(status);
			ino_index_lock(mc);
			list_del(&me->ino_index);
			ino_index_unlock(mc);
			free(me->key);
			if (me->mapent)
				free(me->mapent);
			free(me);
			me = pred;
		}
	}

	me = mc->hash[hashval];
	if (!me)
		goto done;

	if (strcmp(this, me->key) == 0) {
		if (me->multi && !list_empty(&me->multi_list)) {
			ret = CHE_FAIL;
			goto done;
		}
		mc->hash[hashval] = me->next;
		status = pthread_mutex_destroy(&me->multi_mutex);
		if (status)
			fatal(status);
		ino_index_lock(mc);
		list_del(&me->ino_index);
		ino_index_unlock(mc);
		free(me->key);
		if (me->mapent)
			free(me->mapent);
		free(me);
	}
done:
	return ret;
}

/* cache must be write locked by caller */
int cache_delete_offset_list(struct mapent_cache *mc, const char *key)
{
	struct mapent *me;
	struct mapent *this;
	struct list_head *head, *next;
	int remain = 0;
	int status;

	me = cache_lookup_distinct(mc, key);
	if (!me)
		return CHE_FAIL;

	/* Not offset list owner */
	if (me->multi != me)
		return CHE_FAIL;

	head = &me->multi_list;
	next = head->next;
	while (next != head) {
		this = list_entry(next, struct mapent, multi_list);
		next = next->next;
		if (this->ioctlfd != -1) {
			error(LOGOPT_ANY,
			      "active offset mount key %s", this->key);
			return CHE_FAIL;
		}
	}

	head = &me->multi_list;
	next = head->next;
	while (next != head) {
		this = list_entry(next, struct mapent, multi_list);
		next = next->next;
		list_del_init(&this->multi_list);
		this->multi = NULL;
		debug(LOGOPT_NONE, "deleting offset key %s", this->key);
		status = cache_delete(mc, this->key);
		if (status == CHE_FAIL) {
			warn(LOGOPT_ANY,
			     "failed to delete offset %s", this->key);
			this->multi = me;
			/* TODO: add list back in */
			remain++;
		}
	}

	if (!remain) {
		list_del_init(&me->multi_list);
		me->multi = NULL;
	}

	if (remain)
		return CHE_FAIL;

	return CHE_OK;
}

void cache_release(struct map_source *map)
{
	struct mapent_cache *mc;
	struct mapent *me, *next;
	int status;
	unsigned int i;

	mc = map->mc;

	cache_writelock(mc);

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (me == NULL)
			continue;
		next = me->next;
		free(me->key);
		if (me->mapent)
			free(me->mapent);
		free(me);

		while (next != NULL) {
			me = next;
			next = me->next;
			free(me->key);
			if (me->mapent)
				free(me->mapent);
			free(me);
		}
	}

	map->mc = NULL;

	cache_unlock(mc);

	status = pthread_mutex_destroy(&mc->ino_index_mutex);
	if (status)
		fatal(status);

	status = pthread_rwlock_destroy(&mc->rwlock);
	if (status)
		fatal(status);

	free(mc->hash);
	free(mc->ino_index);
	free(mc);
}

void cache_release_null_cache(struct master *master)
{
	struct mapent_cache *mc;
	struct mapent *me, *next;
	int status;
	unsigned int i;

	mc = master->nc;

	cache_writelock(mc);

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (me == NULL)
			continue;
		next = me->next;
		free(me->key);
		if (me->mapent)
			free(me->mapent);
		free(me);

		while (next != NULL) {
			me = next;
			next = me->next;
			free(me->key);
			free(me);
		}
	}

	master->nc = NULL;

	cache_unlock(mc);

	status = pthread_mutex_destroy(&mc->ino_index_mutex);
	if (status)
		fatal(status);

	status = pthread_rwlock_destroy(&mc->rwlock);
	if (status)
		fatal(status);

	free(mc->hash);
	free(mc->ino_index);
	free(mc);
}



/* cache must be read locked by caller */
struct mapent *cache_enumerate(struct mapent_cache *mc, struct mapent *me)
{
	if (!me)
		return cache_lookup_first(mc);

	return cache_lookup_next(mc, me);
}

/*
 * Get each offset from list head under prefix.
 * Maintain traversal current position in pos for subsequent calls. 
 * Return each offset into offset.
 * TODO: length check on offset.
 */
/* cache must be read locked by caller */
char *cache_get_offset(const char *prefix, char *offset, int start,
			struct list_head *head, struct list_head **pos)
{
	struct list_head *next;
	struct mapent *this;
	size_t plen = strlen(prefix);
	size_t len = 0;

	if (*pos == head)
		return NULL;

	/* Find an offset */
	*offset = '\0';
	next = *pos ? (*pos)->next : head->next;
	while (next != head) {
		char *offset_start, *pstart, *pend;

		this = list_entry(next, struct mapent, multi_list);
		*pos = next;
		next = next->next;

		offset_start = &this->key[start];
		if (strlen(offset_start) <= plen)
			continue;

		if (!strncmp(prefix, offset_start, plen)) {
			/* "/" doesn't count for root offset */
			if (plen == 1)
				pstart = &offset_start[plen - 1];
			else
				pstart = &offset_start[plen];

			/* not part of this sub-tree */
			if (*pstart != '/')
				continue;

			/* get next offset */
			pend = pstart;
			while (*pend++) ;
			len = pend - pstart - 1;
			strncpy(offset, pstart, len);
			offset[len] ='\0';
			break;
		}
	}

	/* Seek to next offset */
	while (next != head) {
		char *offset_start, *pstart;

		this = list_entry(next, struct mapent, multi_list);

		offset_start = &this->key[start];
		if (strlen(offset_start) <= plen + len)
			break;

		/* "/" doesn't count for root offset */
		if (plen == 1)
			pstart = &offset_start[plen - 1];
		else
			pstart = &offset_start[plen];

		/* not part of this sub-tree */
		if (*pstart != '/')
			break;

		/* new offset */
		if (!*(pstart + len + 1))
			break;

		/* compare offset */
		if (pstart[len] != '/' || strncmp(offset, pstart, len))
			break;

		*pos = next;
		next = next->next;
	}

	return *offset ? offset : NULL;
}

