#ident "$Id: cache.c,v 1.30 2006/03/31 18:26:16 raven Exp $"
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
		info("key=%s", me->key);
	}
}

void cache_dump_cache(struct mapent_cache *mc)
{
	struct mapent *me;
	int i;

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (me == NULL)
			continue;
		while (me) {
			info("me->key=%s me->multi=%p dev=%ld ino=%ld",
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
		error("mapent cache rwlock lock failed");
		fatal(status);
	}
	return;
}

void cache_writelock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_wrlock(&mc->rwlock);
	if (status) {
		error("mapent cache rwlock lock failed");
		fatal(status);
	}
	return;
}

void cache_unlock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_unlock(&mc->rwlock);
	if (status) {
		error("mapent cache rwlock unlock failed");
		fatal(status);
	}
	return;
}

void cache_lock_cleanup(void *arg)
{
	struct mapent_cache *mc = (struct mapent_cache *) arg;

	cache_unlock(mc);
}

struct mapent_cache *cache_init(struct autofs_point *ap)
{
	struct mapent_cache *mc;
	int i, status;

	if (ap->mc)
		cache_release(ap);

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

	me = cache_lookup(mc, key);
	if (!me)
		return 0;

	list_add(&me->ino_index, &mc->ino_index[ino_index]);

	me->dev = dev;
	me->ino = ino;

	return 1;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_ino(struct mapent_cache *mc, dev_t dev, ino_t ino)
{
	struct mapent *me = NULL;
	struct list_head *head, *p;
	unsigned int ino_index;

	ino_index = ino_hash(dev, ino);
	head = &mc->ino_index[ino_index];

	list_for_each(p, head) {
		me = list_entry(p, struct mapent, ino_index);

		if (me->dev != dev || me->ino != ino)
			continue;

		return me;
	}
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_first(struct mapent_cache *mc)
{
	struct mapent *me = NULL;
	int i;

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
	int i;

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
		for (i = hashval; i < mc->size; i++) {
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
	int len = strlen(prefix);
	int i;

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
int cache_add(struct mapent_cache *mc, struct map_source *source,
		const char *key, const char *mapent, time_t age)
{
	struct mapent *me, *existing = NULL;
	char *pkey, *pent;
	unsigned int hashval = hash(key);

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
	me->source = source;
	INIT_LIST_HEAD(&me->ino_index);
	INIT_LIST_HEAD(&me->multi_list);
	me->multi = NULL;
	me->ioctlfd = -1;
	me->dev = -1;
	me->ino = -1;

	/* 
	 * We need to add to the end if values exist in order to
	 * preserve the order in which the map was read on lookup.
	 */
	existing = cache_lookup(mc, key);
	if (!existing || *existing->key == '*') {
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
		int eq, tlen;

		this = list_entry(p, struct mapent, multi_list);
		tlen = strlen(this->key);

		eq = strncmp(this->key, me->key, tlen);
		if (!eq && tlen == strlen(me->key))
			goto done;

		if (eq > 0) {
			list_add_tail(&me->multi_list, p);
			goto done;
		}
	}
	list_add_tail(&me->multi_list, p);
done:
	return;
}

/* cache must be write locked by caller */
int cache_add_offset(struct mapent_cache *mc, const char *mkey, const char *key, const char *mapent, time_t age)
{
	struct mapent *me, *owner;
	int ret = CHE_OK;

	owner = cache_lookup(mc, mkey);
	if (!owner)
		return CHE_FAIL;

	ret = cache_update(mc, owner->source, key, mapent, age);
	if (ret == CHE_FAIL) {
		warn("failed to add key %s to cache", key);
		return CHE_FAIL;
	}

	me = cache_lookup(mc, key);
	if (me) {
		cache_add_ordered_offset(me, &owner->multi_list);
		me->multi = owner;
		goto done;
	}
	ret = CHE_FAIL;
done:
	return ret; 
}

/* cache must be write locked by caller */
int cache_update(struct mapent_cache *mc, struct map_source *source,
		 const char *key, const char *mapent, time_t age)
{
	struct mapent *me = NULL;
	char *pent;
	int ret = CHE_OK;

	me = cache_lookup(mc, key);
	if (!me || *me->key == '*') {
		ret = cache_add(mc, source, key, mapent, age);
		if (!ret) {
			debug("failed for %s", key);
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
	int ret = CHE_OK;

	me = mc->hash[hashval];
	if (!me) {
		ret = CHE_FAIL;
		goto done;
	}

	while (me->next != NULL) {
		pred = me;
		me = me->next;
		if (strcmp(key, me->key) == 0) {
			if (me->multi && !list_empty(&me->multi_list)) {
				ret = CHE_FAIL;
				goto done;
			}
			pred->next = me->next;
			if (!list_empty(&me->ino_index))
				list_del(&me->ino_index);
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

	if (strcmp(key, me->key) == 0) {
		if (me->multi && !list_empty(&me->multi_list)) {
			ret = CHE_FAIL;
			goto done;
		}
		mc->hash[hashval] = me->next;
		if (!list_empty(&me->ino_index))
			list_del(&me->ino_index);
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

	me = cache_lookup(mc, key);
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
		list_del_init(&this->multi_list);
		this->multi = NULL;
		debug("deleting offset key %s", this->key);
		status = cache_delete(mc, this->key);
		if (status == CHE_FAIL) {
			warn("failed to delete offset %s", this->key);
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

void cache_release(struct autofs_point *ap)
{
	struct mapent_cache *mc;
	struct mapent *me, *next;
	int status;
	int i;

	mc = ap->mc;

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

	ap->mc = NULL;

	cache_unlock(mc);

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
	int plen = strlen(prefix);
	int len = 0;

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

