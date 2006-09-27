/* ----------------------------------------------------------------------- *
 *   
 *  master.c - master map utility routines.
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
#include <string.h>
#include <memory.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include "automount.h"

/* The root of the map entry tree */
struct master *master_list = NULL;

/* Attribute to create detached thread */
extern pthread_attr_t thread_attr;

extern struct startup_cond suc;

static struct map_source *
__master_find_map_source(struct master_mapent *,
			 const char *, const char *, int, const char **);

pthread_mutex_t master_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t instance_mutex = PTHREAD_MUTEX_INITIALIZER;

int master_add_autofs_point(struct master_mapent *entry,
		time_t timeout, unsigned logopt, unsigned ghost, int submount) 
{
	struct autofs_point *ap;
	int status;

	ap = malloc(sizeof(struct autofs_point));
	if (!ap)
		return 0;

	ap->state = ST_INIT;
	ap->kver.major = 0;
	ap->kver.minor = 0;

	ap->state_pipe[0] = -1;
	ap->state_pipe[1] = -1;

	ap->path = strdup(entry->path);
	if (!ap->path) {
		free(ap);
		return 0;
	}

	ap->entry = entry;
	ap->exp_thread = 0;
	ap->readmap_thread = 0;
	ap->exp_timeout = timeout;
	ap->exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
	ap->ghost = ghost;

	if (ap->path[1] == '-')
		ap->type = LKP_DIRECT;
	else
		ap->type = LKP_INDIRECT;

	ap->dir_created = 0;
	ap->logopt = logopt;

	ap->parent = NULL;
	ap->submnt_count = 0;
	ap->submount = submount;
	INIT_LIST_HEAD(&ap->mounts);
	INIT_LIST_HEAD(&ap->submounts);

	status = pthread_mutex_init(&ap->state_mutex, NULL);
	if (status) {
		free(ap->path);
		free(ap);
		return 0;
	}

	status = pthread_mutex_init(&ap->mounts_mutex, NULL);
	if (status) {
		status = pthread_mutex_destroy(&ap->state_mutex);
		if (status)
			fatal(status);
		free(ap->path);
		free(ap);
		return 0;
	}

	status = pthread_cond_init(&ap->mounts_cond, NULL);
	if (status) {
		status = pthread_mutex_destroy(&ap->mounts_mutex);
		if (status)
			fatal(status);
		status = pthread_mutex_destroy(&ap->state_mutex);
		if (status)
			fatal(status);
		free(ap->path);
		free(ap);
		return 0;
	}
	entry->ap = ap;

	return 1;
}

void master_free_autofs_point(struct autofs_point *ap)
{
	int status;

	if (!ap)
		return;

	status = pthread_mutex_destroy(&ap->state_mutex);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&ap->mounts_mutex);
	if (status)
		fatal(status);

	status = pthread_cond_destroy(&ap->mounts_cond);
	if (status)
		fatal(status);

	free(ap->path);
	free(ap);
}

struct map_source *
master_add_map_source(struct master_mapent *entry,
		      char *type, char *format, time_t age,
		      int argc, const char **argv)
{
	struct map_source *source;
	char *ntype, *nformat;
	const char **tmpargv, *name = NULL;

	source = malloc(sizeof(struct map_source));
	if (!source)
		return NULL;
	memset(source, 0, sizeof(struct map_source));

	if (type) {
		ntype = strdup(type);
		if (!ntype) {
			master_free_map_source(source, 0);
			return NULL;
		}
		source->type = ntype;
	}

	if (format) {
		nformat = strdup(format);
		if (!nformat) {
			master_free_map_source(source, 0);
			return NULL;
		}
		source->format = nformat;
	}

	source->age = age;
	source->stale = 1;

	tmpargv = copy_argv(argc, argv);
	if (!tmpargv) {
		master_free_map_source(source, 0);
		return NULL;
	}
	source->argc = argc;
	source->argv = tmpargv;

	/* Can be NULL for "hosts" map */
	if (argv)
		name = argv[0];

	master_source_writelock(entry);

	if (!entry->maps) {
		entry->maps = source;
		entry->first = source;
	} else {
		struct map_source *this, *last, *next;

		/* Typically there only a few map sources */

		this = __master_find_map_source(entry, type, format, argc, tmpargv);
		if (this) {
			this->age = age;
			master_free_map_source(source, 0);
			master_source_unlock(entry);
			return this;
		}

		last = NULL;
		next = entry->maps;
		while (next) {
			last = next;
			next = next->next;
		}
		if (last)
			last->next = source;
		else
			entry->maps = source;
	}

	master_source_unlock(entry);

	return source;
}

static int compare_source_type_and_format(struct map_source *map, const char *type, const char *format)
{
	int res = 0;

	if (type) {
		if (!map->type)
			goto done;

		if (strcmp(map->type, type))
			goto done;
	} else if (map->type)
		goto done;

	if (format) {
		if (!map->format)
			goto done;

		if (strcmp(map->format, format))
			goto done;
	} else if (map->format)
		goto done;

	res = 1;
done:
	return res;
}

static struct map_source *
__master_find_map_source(struct master_mapent *entry,
			 const char *type, const char *format,
			 int argc, const char **argv)
{
	struct map_source *map;
	struct map_source *source = NULL;
	int res;

	map = entry->first;
	while (map) {
		res = compare_source_type_and_format(map, type, format);
		if (!res)
			goto next;

		res = compare_argv(map->argc, map->argv, argc, argv);
		if (!res)
			goto next;

		source = map;
		break;
next:
		map = map->next;
	}

	return source;
}

struct map_source *master_find_map_source(struct master_mapent *entry,
				const char *type, const char *format,
				int argc, const char **argv)
{
	struct map_source *source = NULL;

	master_mutex_lock();

	source = __master_find_map_source(entry, type, format, argc, argv);

	master_mutex_unlock();

	return source;
}

void master_free_map_source(struct map_source *source, unsigned int free_cache)
{
	int status;

	if (source->type)
		free(source->type);
	if (source->format)
		free(source->format);
	if (free_cache && source->mc)
		cache_release(source);
	if (source->lookup) {
		struct map_source *instance;

		instance = source->instance;
		while (instance) {
			if (instance->lookup)
			close_lookup(instance->lookup);
			instance = instance->next;
		}
		close_lookup(source->lookup);
	}
	if (source->argv)
		free_argv(source->argc, source->argv);
	if (source->instance) {
		struct map_source *instance, *next;

		status = pthread_mutex_lock(&instance_mutex);
		if (status)
			fatal(status);

		instance = source->instance;
		while (instance) {
			next = instance->next;
			master_free_map_source(instance, 0);
			instance = next;
		}

		status = pthread_mutex_unlock(&instance_mutex);
		if (status)
			fatal(status);
	}

	free(source);

	return;
}

struct map_source *master_find_source_instance(struct map_source *source, const char *type, const char *format, int argc, const char **argv)
{
	struct map_source *map;
	struct map_source *instance = NULL;
	int status, res;

	status = pthread_mutex_lock(&instance_mutex);
	if (status)
		fatal(status);

	map = source->instance;
	while (map) {
		res = compare_source_type_and_format(map, type, format);
		if (!res)
			goto next;

		if (!argv) {
			instance = map;
			break;
		}

		res = compare_argv(map->argc, map->argv, argc, argv);
		if (!res)
			goto next;

		instance = map;
		break;
next:
		map = map->next;
	}

	status = pthread_mutex_unlock(&instance_mutex);
	if (status)
		fatal(status);

	return instance;
}

struct map_source *
master_add_source_instance(struct map_source *source, const char *type, const char *format, time_t age)
{
	struct map_source *instance;
	struct map_source *new;
	char *ntype, *nformat;
	const char **tmpargv, *name;
	int status;

	if (!type)
		return NULL;

	instance = master_find_source_instance(source,
			type, format, source->argc, source->argv);
	if (instance)
		return instance;

	new = malloc(sizeof(struct map_source));
	if (!new)
		return NULL;
	memset(new, 0, sizeof(struct map_source));

	ntype = strdup(type);
	if (!ntype) {
		master_free_map_source(new, 0);
		return NULL;
	}
	new->type = ntype;

	if (format) {
		nformat = strdup(format);
		if (!nformat) {
			master_free_map_source(new, 0);
			return NULL;
		}
		new->format = nformat;
	}

	new->age = age;
	new->mc = source->mc;

	tmpargv = copy_argv(source->argc, source->argv);
	if (!tmpargv) {
		master_free_map_source(new, 0);
		return NULL;
	}
	new->argc = source->argc;
	new->argv = tmpargv;

	name = new->argv[0];

	status = pthread_mutex_lock(&instance_mutex);
	if (status)
		fatal(status);

	if (!source->instance)
		source->instance = new;
	else {
		/*
		 * We know there's no other instance of this
		 * type so just add to head of list
		 */
		new->next = source->instance;
		source->instance = new;
	}

	status = pthread_mutex_unlock(&instance_mutex);
	if (status)
		fatal(status);

	return new;
}

void master_source_writelock(struct master_mapent *entry)
{
	int status;

	status = pthread_rwlock_wrlock(&entry->source_lock);
	if (status) {
		error(LOGOPT_ANY,
		      "master_mapent source write lock failed");
		fatal(status);
	}
	return;
}

void master_source_readlock(struct master_mapent *entry)
{
	int status;

	status = pthread_rwlock_rdlock(&entry->source_lock);
	if (status) {
		error(LOGOPT_ANY,
		      "master_mapent source read lock failed");
		fatal(status);
	}
	return;
}

void master_source_unlock(struct master_mapent *entry)
{
	int status;

	status = pthread_rwlock_unlock(&entry->source_lock);
	if (status) {
		error(LOGOPT_ANY,
		      "master_mapent source unlock failed");
		fatal(status);
	}
	return;
}

void master_source_lock_cleanup(void *arg)
{
	struct master_mapent *entry = (struct master_mapent *) arg;

	master_source_unlock(entry);

	return;
}

void master_source_current_wait(struct master_mapent *entry)
{
	int status;

	status = pthread_mutex_lock(&entry->current_mutex);
	if (status) {
		error(LOGOPT_ANY, "entry current source lock failed");
		fatal(status);
	}

	while (entry->current != NULL) {
		status = pthread_cond_wait(
				&entry->current_cond, &entry->current_mutex);
		if (status) {
			error(LOGOPT_ANY,
			      "entry current source condition wait failed");
			fatal(status);
		}
	}

	return;
}

void master_source_current_signal(struct master_mapent *entry)
{
	int status;

	status = pthread_cond_signal(&entry->current_cond);
	if (status) {
		error(LOGOPT_ANY,
		      "entry current source condition signal failed");
		fatal(status);
	}

	status = pthread_mutex_unlock(&entry->current_mutex);
	if (status) {
		error(LOGOPT_ANY, "entry current source unlock failed");
		fatal(status);
	}

	return;
}

struct master_mapent *master_find_mapent(struct master *master, const char *path)
{
	struct list_head *head, *p;

	master_mutex_lock();

	head = &master->mounts;
	list_for_each(p, head) {
		struct master_mapent *entry;

		entry = list_entry(p, struct master_mapent, list);

		if (!strcmp(entry->path, path)) {
			master_mutex_unlock();
			return entry;
		}
	}

	master_mutex_unlock();

	return NULL;
}

struct master_mapent *master_new_mapent(const char *path, time_t age)
{
	struct master_mapent *entry;
	int status;
	char *tmp;

	entry = malloc(sizeof(struct master_mapent));
	if (!entry)
		return NULL;

	memset(entry, 0, sizeof(struct master_mapent));

	tmp = strdup(path);
	if (!tmp) {
		free(entry);
		return NULL;
	}
	entry->path = tmp;

	entry->thid = 0;
	entry->age = age;
	entry->first = NULL;
	entry->current = NULL;
	entry->maps = NULL;
	entry->ap = NULL;

	status = pthread_rwlock_init(&entry->source_lock, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_init(&entry->current_mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_cond_init(&entry->current_cond, NULL);
	if (status)
		fatal(status);

	INIT_LIST_HEAD(&entry->list);

	return entry;
}

void master_add_mapent(struct master *master, struct master_mapent *entry)
{
	master_mutex_lock();
	list_add_tail(&entry->list, &master->mounts);
	master_mutex_unlock();
	return;
}

void master_remove_mapent(struct master_mapent *entry)
{
	if (entry->ap->submount)
		return;

	master_mutex_lock();
	if (!list_empty(&entry->list))
		list_del_init(&entry->list);
	master_mutex_unlock();
	return;
}

void master_free_mapent_sources(struct master_mapent *entry, unsigned int free_cache)
{
	master_source_writelock(entry);

	if (entry->maps) {
		struct map_source *m, *n;

		m = entry->maps;
		while (m) {
			n = m->next;
			master_free_map_source(m, free_cache);
			m = n;
		}
		entry->maps = NULL;
		entry->first = NULL;
	}

	master_source_unlock(entry);

	return;
}

void master_free_mapent(struct master_mapent *entry)
{
	int status;

	if (entry->path)
		free(entry->path);

	master_free_autofs_point(entry->ap);

	status = pthread_rwlock_destroy(&entry->source_lock);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&entry->current_mutex);
	if (status)
		fatal(status);

	status = pthread_cond_destroy(&entry->current_cond);
	if (status)
		fatal(status);

	free(entry);

	return;
}

struct master *master_new(const char *name, unsigned int timeout, unsigned int ghost)
{
	struct master *master;
	char *tmp;

	master = malloc(sizeof(struct master));
	if (!master)
		return NULL;

	if (!name)
		tmp = (char *) defaults_get_master_map();
	else
		tmp = strdup(name);

	if (!tmp)
		return NULL;

	master->name = tmp;

	master->recurse = 0;
	master->depth = 0;
	master->default_ghost = ghost;
	master->default_timeout = timeout;
	master->default_logging = defaults_get_logging();

	INIT_LIST_HEAD(&master->mounts);

	return master;
}

int master_read_master(struct master *master, time_t age, int readall)
{
	if (!lookup_nss_read_master(master, age)) {
		error(LOGOPT_ANY,
		      "can't read master map %s", master->name);
		return 0;
	}

	master_mount_mounts(master, age, readall);

	master_mutex_lock();

	if (list_empty(&master->mounts)) {
		master_mutex_unlock();
		error(LOGOPT_ANY, "no mounts in table");
		return 0;
	}

	master_mutex_unlock();

	return 1;
}

int master_submount_list_empty(struct autofs_point *ap)
{
	int res = 0;

	mounts_mutex_lock(ap);
	if (list_empty(&ap->submounts))
		res = 1;
	mounts_mutex_unlock(ap);

	return res;
}

int master_notify_submount(struct autofs_point *ap, const char *path, enum states state)
{
	struct list_head *head, *p;
	struct autofs_point *this;
	pthread_t thid;
	size_t plen = strlen(path);
	int status, ret = 1;

	mounts_mutex_lock(ap);

	head = &ap->submounts;
	p = head->prev;
	while (p != head) {
		size_t len;

		this = list_entry(p, struct autofs_point, mounts);
		p = p->prev;

		if (!master_submount_list_empty(this)) {
			if (!master_notify_submount(this, path, state)) {
				ret = 0;
				break;
			}
		}

		len = strlen(this->path);

		/* Initial path not the same */
		if (strncmp(this->path, path, len))
			continue;

		/*
		 * Part of submount tree?
		 * We must wait till we get to submount itself.
		 * If it is tell caller by returning true.
		 */
		if (plen > len) {
			/* Not part of this directory tree */
			if (path[len] != '/')
				continue;
			break;
		}

		/* Now we have a submount to expire */

		state_mutex_lock(this);

		if (this->state == ST_SHUTDOWN) {
			state_mutex_unlock(this);
			break;
		}

		nextstate(this->state_pipe[1], state);

		state_mutex_unlock(this);

		thid = this->thid;
		ap->mounts_signaled = MASTER_SUBMNT_WAIT;
		while (ap->mounts_signaled == MASTER_SUBMNT_WAIT) {
			status = pthread_cond_wait(&ap->mounts_cond, &ap->mounts_mutex);
			if (status)
				fatal(status);
		}

		if (ap->mounts_signaled == MASTER_SUBMNT_JOIN) {
			status = pthread_join(thid, NULL);
			if (status)
				fatal(status);
		} else
			ret = 0;

		break;
	}

	mounts_mutex_unlock(ap);

	return ret;
}

void master_signal_submount(struct autofs_point *ap, unsigned int join)
{
	int status;

	if (!ap->parent || !ap->submount)
		return;

	mounts_mutex_lock(ap->parent);

	ap->parent->mounts_signaled = join;

	if (join == MASTER_SUBMNT_JOIN) {
		/* We are finishing up */
		ap->parent->submnt_count--;
		list_del(&ap->mounts);
	}

	status = pthread_cond_signal(&ap->parent->mounts_cond);
	if (status)
		fatal(status);

	mounts_mutex_unlock(ap->parent);

	return;
}

void master_notify_state_change(struct master *master, int sig)
{
	struct master_mapent *entry;
	struct autofs_point *ap;
	struct list_head *p;
	int state_pipe, cur_state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	master_mutex_lock();

	list_for_each(p, &master->mounts) {
		enum states next = ST_INVAL;

		entry = list_entry(p, struct master_mapent, list);

		ap = entry->ap;

		state_mutex_lock(ap);

		if (ap->state == ST_SHUTDOWN)
			goto next;

		state_pipe = ap->state_pipe[1];

		switch (sig) {
		case SIGTERM:
			if (ap->state != ST_SHUTDOWN_PENDING &&
			    ap->state != ST_SHUTDOWN_FORCE) {
				next = ST_SHUTDOWN_PENDING;
				nextstate(state_pipe, next);
			}
			break;
#ifdef ENABLE_FORCED_SHUTDOWN
		case SIGUSR2:
			if (ap->state != ST_SHUTDOWN_FORCE &&
			    ap->state != ST_SHUTDOWN_PENDING) {
				next = ST_SHUTDOWN_FORCE;
				nextstate(state_pipe, next);
			}
			break;
#endif
		case SIGUSR1:
			assert(ap->state == ST_READY);
			next = ST_PRUNE;
			nextstate(state_pipe, next);
			break;
		}
next:
		if (next != ST_INVAL)
			debug(ap->logopt,
			      "sig %d switching %s from %d to %d",
			      sig, ap->path, ap->state, next);

		state_mutex_unlock(ap);
	}

	master_mutex_unlock();
	pthread_setcancelstate(cur_state, NULL);

	return;
}

static int master_do_mount(struct master_mapent *entry)
{
	struct autofs_point *ap;
	pthread_t thid;
	int status;

	status = pthread_mutex_lock(&suc.mutex);
	if (status)
		fatal(status);

	suc.done = 0;
	suc.status = 0;

	ap = entry->ap;

	debug(ap->logopt, "mounting %s", entry->path);

	if (pthread_create(&thid, &thread_attr, handle_mounts, ap)) {
		crit(ap->logopt,
		     "failed to create mount handler thread for %s",
		     entry->path);
		status = pthread_mutex_unlock(&suc.mutex);
		if (status)
			fatal(status);
		return 0;
	}
	entry->thid = thid;

	while (!suc.done) {
		status = pthread_cond_wait(&suc.cond, &suc.mutex);
		if (status)
			fatal(status);
	}

	if (suc.status) {
		error(ap->logopt, "failed to startup mount");
		status = pthread_mutex_unlock(&suc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	status = pthread_mutex_unlock(&suc.mutex);
	if (status)
		fatal(status);

	return 1;
}

static void shutdown_entry(struct master_mapent *entry)
{
	int state_pipe;
	struct autofs_point *ap;
	struct stat st;
	int ret;

	ap = entry->ap;

	debug(ap->logopt, "%s", entry->path);

	state_mutex_lock(ap);

	state_pipe = ap->state_pipe[1];

	ret = fstat(state_pipe, &st);
	if (ret == -1)
		goto next;

	nextstate(state_pipe, ST_SHUTDOWN_PENDING);
next:
	state_mutex_unlock(ap);

	return;
}

static void check_update_map_sources(struct master_mapent *entry, int readall)
{
	struct map_source *source, *last;
	int state_pipe, map_stale = 0;
	struct autofs_point *ap;
	struct stat st;
	int ret;

	if (readall)
		map_stale = 1;

	ap = entry->ap;

	master_source_writelock(entry);

	last = NULL;
	source = entry->maps;
	while (source) {
		if (readall)
			source->stale = 1;

		/*
		 * If a map source is no longer valid and all it's
		 * entries have expired away we can get rid of it.
		 */
		if (entry->age > source->age) {
			struct mapent *me;
			cache_readlock(source->mc);
			me = cache_lookup_first(source->mc);
			cache_unlock(source->mc);
			if (!me) {
				struct map_source *next = source->next;

				if (!last)
					entry->maps = next;
				else
					last->next = next;

				if (entry->first == source)
					entry->first = next;

				master_free_map_source(source, 1);

				source = next;
				continue;
			}
		} else if (source->type) {
			if (!strcmp(source->type, "null")) {
/*				entry->ap->mc = cache_init(entry->ap); */
				entry->first = source->next;
				readall = 1;
				map_stale = 1;
			}
		}
		last = source;
		source = source->next;
	}

	master_source_unlock(entry);

	/* The map sources have changed */
	if (map_stale) {
		state_mutex_lock(ap);

		state_pipe = entry->ap->state_pipe[1];

		ret = fstat(state_pipe, &st);
		if (ret != -1)
			nextstate(state_pipe, ST_READMAP);

		state_mutex_unlock(ap);
	}

	return;
}

int master_mount_mounts(struct master *master, time_t age, int readall)
{
	struct list_head *p, *head;
	int cur_state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	master_mutex_lock();

	head = &master->mounts;
	p = head->next;
	while (p != head) {
		struct master_mapent *this;
		struct autofs_point *ap;
		struct stat st;
		int state_pipe, save_errno;
		int ret;

		this = list_entry(p, struct master_mapent, list);
		p = p->next;

		ap = this->ap;

		/* A master map entry has gone away */
		if (this->age < age) {
			shutdown_entry(this);
			continue;
		}

		check_update_map_sources(this, readall);

		state_mutex_lock(ap);

		state_pipe = this->ap->state_pipe[1];

		/* No pipe so mount is needed */
		ret = fstat(state_pipe, &st);
		save_errno = errno;

		state_mutex_unlock(ap);

		if (ret == -1 && save_errno == EBADF)
			if (!master_do_mount(this)) {
				list_del_init(&this->list);
				master_free_mapent_sources(ap->entry, 1);
				master_free_mapent(ap->entry);
		}
	}

	master_mutex_unlock();
	pthread_setcancelstate(cur_state, NULL);

	return 1;
}

int master_list_empty(struct master *master)
{
	int res = 0;

	master_mutex_lock();
	if (list_empty(&master->mounts))
		res = 1;
	master_mutex_unlock();

	return res;
}

int master_kill(struct master *master)
{
	if (!list_empty(&master->mounts))
		return 0;

	if (master->name)
		free(master->name);

	free(master);

	return 1;
}

void dump_master(struct master *master)
{
	struct list_head *p, *head;

	head = &master->mounts;
	list_for_each(p, head) {
		struct master_mapent *this = list_entry(p, struct master_mapent, list);
		debug(LOGOPT_ANY, "path %s", this->path);
	}
}
