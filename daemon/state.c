#ident "$Id: state.c,v 1.11 2006/04/03 08:15:36 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  state.c - state machine functions.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include "automount.h"

extern struct master *master;

extern pthread_attr_t thread_attr;

struct state_queue {
	pthread_t thid;
	struct list_head list;
	struct list_head pending;
	struct autofs_point *ap;
	enum states state;
	unsigned int busy;
	unsigned int cancel;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(state_queue);

static unsigned int signaled = 0;
static void st_set_thid(struct autofs_point *, pthread_t);

int do_mount_autofs_direct(struct autofs_point *, struct mnt_list *, struct mapent *, int);

void dump_state_queue(void)
{
	struct list_head *head = &state_queue;
	struct list_head *p, *q;

	debug(LOGOPT_ANY, "dumping queue");

	list_for_each(p, head) {
		struct state_queue *entry;

		entry = list_entry(p, struct state_queue, list);
		debug(LOGOPT_ANY,
		      "queue list head path %s state %d busy %d",
		      entry->ap->path, entry->state, entry->busy);

		list_for_each(q, &entry->pending) {
			struct state_queue *this;

			this = list_entry(q, struct state_queue, pending);
			debug(LOGOPT_ANY,
			      "queue list entry path %s state %d busy %d",
			      this->ap->path, this->state, this->busy);
		}
	}
}

void nextstate(int statefd, enum states next)
{
	char buf[MAX_ERR_BUF];

	if (write(statefd, &next, sizeof(next)) != sizeof(next)) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(LOGOPT_ANY, "write failed %s", estr);
	}
}

/*
 * Handle expire thread cleanup and return the next state the system
 * should enter as a result.
 */
void expire_cleanup(void *arg)
{
	pthread_t thid = pthread_self();
	struct expire_args *ea;
	struct autofs_point *ap;
	int statefd;
	enum states next = ST_INVAL;
	int success;
	int status;

	ea = (struct expire_args *) arg;
	ap = ea->ap;
	success = ea->status;

	status = pthread_mutex_lock(&ap->state_mutex);
	if (status) {
		error(ap->logopt, "state mutex lock failed");
		free(ea);
		return;
	}

	debug(ap->logopt,
	      "got thid %lu path %s stat %d",
	      (unsigned long) thid, ap->path, success);

	statefd = ap->state_pipe[1];

	/* Check to see if expire process finished */
	if (thid == ap->exp_thread) {
		ap->exp_thread = 0;

		switch (ap->state) {
		case ST_EXPIRE:
			/* FALLTHROUGH */
		case ST_PRUNE:
			/* If we're a submount and we've just
			   pruned or expired everything away,
			   try to shut down */
			if (ap->submount && !success && ap->state != ST_SHUTDOWN) {
				next = ST_SHUTDOWN_PENDING;
				break;
			}
			alarm_add(ap, ap->exp_runfreq);
			/* FALLTHROUGH */

		case ST_READY:
			next = ST_READY;
			break;

		case ST_SHUTDOWN_PENDING:
			next = ST_SHUTDOWN;
#ifndef ENABLE_IGNORE_BUSY_MOUNTS
			if (success == 0)
				break;

			/* Failed shutdown returns to ready */
			warn(ap->logopt, "filesystem %s still busy", ap->path);
			alarm_add(ap, ap->exp_runfreq);
			next = ST_READY;
#endif
			break;

		case ST_SHUTDOWN_FORCE:
			next = ST_SHUTDOWN;
			break;

		default:
			error(ap->logopt, "bad state %d", ap->state);
		}

		if (next != ST_INVAL) {
			debug(ap->logopt,
			  "sigchld: exp %lu finished, switching from %d to %d",
			  (unsigned long) thid, ap->state, next);
		}
	}

	if (next != ST_INVAL)
		nextstate(statefd, next);

	status = pthread_mutex_unlock(&ap->state_mutex);
	if (status)
		error(ap->logopt, "state mutex unlock failed");

	free(ea);

	return;
}

static unsigned int st_ready(struct autofs_point *ap)
{
	debug(ap->logopt,
	      "st_ready(): state = %d path %s", ap->state, ap->path);

	ap->state = ST_READY;

	if (ap->submount) {
		int status;

		status = pthread_mutex_lock(&ap->parent->mounts_mutex);
		if (status)
			fatal(status);

		status = pthread_cond_signal(&ap->parent->mounts_cond);
		if (status)
			error(ap->logopt,
			      "failed to signal submount notify condition");

		status = pthread_mutex_unlock(&ap->parent->mounts_mutex);
		if (status)
			fatal(status);
	}

	return 1;
}

enum expire {
	EXP_ERROR,
	EXP_STARTED,
	EXP_PARTIAL
};

/*
 * Generate expiry messages.  If "now" is true, timeouts are ignored.
 *
 * Returns: ERROR	- error
 *          STARTED	- expiry process started
 *          DONE	- nothing to expire
 *          PARTIAL	- partial expire
 */

void expire_proc_cleanup(void *arg)
{
	struct expire_args *ea;
	int status;

	ea = (struct expire_args *) arg;

	status = pthread_mutex_unlock(&ea->mutex);
	if (status)
		fatal(status);

	status = pthread_cond_destroy(&ea->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&ea->mutex);
	if (status)
		fatal(status);

	return;
}

static enum expire expire_proc(struct autofs_point *ap, int now)
{
	pthread_t thid;
	struct expire_args *ea;
	void *(*expire)(void *);
	int status;

	assert(ap->exp_thread == 0);

	ea = malloc(sizeof(struct expire_args));
	if (!ea) {
		error(ap->logopt, "failed to malloc expire cond struct");
		return EXP_ERROR;
	}

	status = pthread_mutex_init(&ea->mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_cond_init(&ea->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&ea->mutex);
	if (status)
		fatal(status);

	ea->ap = ap;
	ea->when = now;
	ea->status = 1;

	if (ap->type == LKP_INDIRECT)
		expire = expire_proc_indirect;
	else
		expire = expire_proc_direct;

	status = pthread_create(&thid, &thread_attr, expire, ea);
	if (status) {
		error(ap->logopt,
		      "expire thread create for %s failed", ap->path);
		expire_proc_cleanup((void *) ea);
		free(ea);
		return EXP_ERROR;
	}
	ap->exp_thread = thid;
	st_set_thid(ap, thid);

	pthread_cleanup_push(expire_proc_cleanup, ea);

	debug(ap->logopt, "exp_proc = %lu path %s",
		(unsigned long) ap->exp_thread, ap->path);

	ea->signaled = 0;
	while (!ea->signaled) {
		status = pthread_cond_wait(&ea->cond, &ea->mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return EXP_STARTED;
}

static void do_readmap_cleanup(void *arg)
{
	struct readmap_args *ra;
	struct autofs_point *ap;
	int status;

	ra = (struct readmap_args *) arg;

	ap = ra->ap;
	ap->readmap_thread = 0;

	status = pthread_mutex_lock(&ap->state_mutex);
	if (status)
		fatal(status);

	nextstate(ap->state_pipe[1], ST_READY);

	status = pthread_mutex_unlock(&ap->state_mutex);
	if (status)
		fatal(status);

	free(ra);

	return;
}

static void *do_readmap(void *arg)
{
	struct autofs_point *ap;
	struct map_source *map;
	struct mapent_cache *mc;
	struct readmap_args *ra;
	struct  mnt_list *mnts;
	int status;
	time_t now;

	ra = (struct readmap_args *) arg;

	status = pthread_mutex_lock(&ra->mutex);
	if (status)
		fatal(status);

	ap = ra->ap;
	now = ra->now;

	ra->signaled = 1;
	status = pthread_cond_signal(&ra->cond);
	if (status) {
		error(ap->logopt, "failed to signal expire condition");
		status = pthread_mutex_unlock(&ra->mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	status = pthread_mutex_unlock(&ra->mutex);
	if (status)
		fatal(status);

	pthread_cleanup_push(do_readmap_cleanup, ra);

	status = lookup_nss_read_map(ap, now);
	if (!status)
		pthread_exit(NULL);

	if (ap->type == LKP_INDIRECT) {
		lookup_prune_cache(ap, now);
		status = lookup_ghost(ap);
	} else {
		struct mapent *me;
		mnts = tree_make_mnt_tree(_PROC_MOUNTS, "/");
		pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
		master_source_readlock(ap->entry);
		map = ap->entry->first;
		while (map) {
			/* Is map source up to date or no longer valid */
			if (!map->stale || ap->entry->age > map->age) {
				map = map->next;
				continue;
			}
			ap->entry->current = map;
			mc = map->mc;
			pthread_cleanup_push(cache_lock_cleanup, mc);
			cache_readlock(mc);
			me = cache_enumerate(mc, NULL);
			while (me) {
				/* TODO: check return of do_... */
				if (me->age < now) {
					if (!tree_is_mounted(mnts, me->key))
						do_umount_autofs_direct(ap, mnts, me);
					else
                                		debug(ap->logopt,
						      "%s id mounted", me->key);
				} else
					do_mount_autofs_direct(ap, mnts, me, now);
				me = cache_enumerate(mc, me);
			}
			pthread_cleanup_pop(1);
			map = map->next;
		}
		pthread_cleanup_pop(1);
		tree_free_mnt_tree(mnts);
		ap->entry->current = NULL;
		lookup_prune_cache(ap, now);
	}

	pthread_cleanup_pop(1);

	return NULL;
}

static void st_readmap_cleanup(void *arg)
{
	struct readmap_args *ra;
	int status;

	ra = (struct readmap_args *) arg;

	status = pthread_mutex_unlock(&ra->mutex);
	if (status)
		fatal(status);

	status = pthread_cond_destroy(&ra->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&ra->mutex);
	if (status)
		fatal(status);

	return;
}

static unsigned int st_readmap(struct autofs_point *ap)
{
	pthread_t thid;
	struct readmap_args *ra;
	int status;
	int now = time(NULL);

	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_READMAP;

	ra = malloc(sizeof(struct readmap_args));
	if (!ra) {
		error(ap->logopt, "failed to malloc reamap cond struct");
		return 0;
	}

	status = pthread_mutex_init(&ra->mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_cond_init(&ra->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&ra->mutex);
	if (status)
		fatal(status);

	ra->ap = ap;
	ra->now = now;

	status = pthread_create(&thid, &thread_attr, do_readmap, ra);
	if (status) {
		error(ap->logopt, "read map thread create failed");
		st_readmap_cleanup(ra);
		free(ra);
		return 0;
	}
	ap->readmap_thread = thid;
	st_set_thid(ap, thid);

	ra->signaled = 0;
	while (!ra->signaled) {
		status = pthread_cond_wait(&ra->cond, &ra->mutex);
		if (status)
			fatal(status);
	}

	return 1;
}

static unsigned int st_prepare_shutdown(struct autofs_point *ap)
{
	int exp;

	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	/* Turn off timeouts for this mountpoint */
	alarm_delete(ap);

	assert(ap->state == ST_READY || ap->state == ST_EXPIRE);
	ap->state = ST_SHUTDOWN_PENDING;

	/* Unmount everything */
	exp = expire_proc(ap, 1);
	switch (exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		alarm_add(ap, ap->exp_runfreq);
		nextstate(ap->state_pipe[1], ST_READY);
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_force_shutdown(struct autofs_point *ap)
{
	int exp;

	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	/* Turn off timeouts for this mountpoint */
	alarm_delete(ap);

	assert(ap->state == ST_READY || ap->state == ST_EXPIRE);
	ap->state = ST_SHUTDOWN_FORCE;

	/* Unmount everything */
	exp = expire_proc(ap, 1);
	switch (exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		alarm_add(ap, ap->exp_runfreq);
		nextstate(ap->state_pipe[1], ST_READY);
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_prune(struct autofs_point *ap)
{
	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_PRUNE;

	/* Turn off timeouts while we prune */
	alarm_delete(ap);

	switch (expire_proc(ap, 1)) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		alarm_add(ap, ap->exp_runfreq);
		nextstate(ap->state_pipe[1], ST_READY);
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_expire(struct autofs_point *ap)
{
	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_EXPIRE;

	/* Turn off timeouts while we expire */
	alarm_delete(ap);

	switch (expire_proc(ap, 0)) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		alarm_add(ap, ap->exp_runfreq);
		nextstate(ap->state_pipe[1], ST_READY);
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

/* Insert alarm entry on ordered list. */
int st_add_task(struct autofs_point *ap, enum states state)
{
	struct list_head *head = &state_queue;
	struct list_head *p;
	struct state_queue *new;
	unsigned int empty = 1;
	int status;

	/* Task termination marker, poke state machine */
	if (state == ST_READY) {
		status = pthread_mutex_lock(&mutex);
		if (status)
			fatal(status);

		st_ready(ap);

		signaled = 1;
		status = pthread_cond_signal(&cond);
		if (status)
			fatal(status);

		status = pthread_mutex_unlock(&mutex);
		if (status)
			fatal(status);

		return 1;
	}

	new = malloc(sizeof(struct state_queue));
	if (!new)
		return 0;
	memset(new, 0, sizeof(struct state_queue));

	new->ap = ap;
	new->state = state;

	INIT_LIST_HEAD(&new->list);
	INIT_LIST_HEAD(&new->pending);

	/* If we are shutting down get rid on all tasks */
/*	if (ap->state == ST_SHUTDOWN_PENDING ||
	    ap->state == ST_SHUTDOWN_FORCE)
		st_remove_tasks(ap);
*/
	status = pthread_mutex_lock(&mutex);
	if (status)
		fatal(status);

	/* Add to task queue for autofs_point ? */
	list_for_each(p, head) {
		struct state_queue *task;

		task = list_entry(p, struct state_queue, list);

		if (task->ap == ap) {
			empty = 0;
			list_add_tail(&new->pending, &task->pending);
			break;
		}
	}

	if (empty)
		list_add(&new->list, head);

	/* Added task, encourage state machine */
	signaled = 1;
	status = pthread_cond_signal(&cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&mutex);
	if (status)
		fatal(status);

	return 1;
}

void st_remove_tasks(struct autofs_point *ap)
{
	struct list_head *head = &state_queue;
	struct list_head *p, *q;
	struct state_queue *task, *waiting;
	int status;

	status = pthread_mutex_lock(&mutex);
	if (status)
		fatal(status);

	if (list_empty(head)) {
		status = pthread_mutex_unlock(&mutex);
		if (status)
			fatal(status);
		return;
	}

	p = head->next;
	while (p != head) {
		task = list_entry(p, struct state_queue, list);
		p = p->next;

		if (task->ap != ap)
			continue;

		if (task->busy)
			task->cancel = 1;

		q = (&task->pending)->next;
		while(q != &task->pending) {
			waiting = list_entry(q, struct state_queue, pending);
			q = q->next;

			list_del(&waiting->pending);
			free(waiting);
		}
	}

	signaled = 1;
	status = pthread_cond_signal(&cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&mutex);
	if (status)
		fatal(status);
}

static int run_state_task(struct state_queue *task)
{
	struct autofs_point *ap;
	enum states state;
	enum states next_state;
	int status, ret = 1;

	ap = task->ap;
	status = pthread_mutex_lock(&ap->state_mutex);
	if (status)
		fatal(status);

	state = ap->state;
	next_state = task->state;

/*	debug("task %p state %d next %d", task, state, task->state); */

	if (next_state != state) {
		switch (next_state) {
		case ST_PRUNE:
			ret = st_prune(ap);
			break;

		case ST_EXPIRE:
			ret = st_expire(ap);
			break;

		case ST_READMAP:
			ret = st_readmap(ap);
			break;

		case ST_SHUTDOWN_PENDING:
			ret = st_prepare_shutdown(ap);
			break;

		case ST_SHUTDOWN_FORCE:
			ret = st_force_shutdown(ap);
			break;

		default:
			ret = 0;
			error(ap->logopt, "bad next state %d", next_state);
		}
	}

	status = pthread_mutex_unlock(&ap->state_mutex);
	if (status)
		fatal(status);

	return ret;
}

static void st_set_thid(struct autofs_point *ap, pthread_t thid)
{
	struct list_head *p, *head = &state_queue;
	struct state_queue *task;

	list_for_each(p, head) {
		task = list_entry(p, struct state_queue, list);
		if (task->ap == ap) {
			task->thid = thid;
			break;
		}
	}
	return;
}

static void *st_queue_handler(void *arg)
{
	struct list_head *head = &state_queue;
	struct list_head *p;
	int status;

	status = pthread_mutex_lock(&mutex);
	if (status)
		fatal(status);

	while (1) {
		/*
		 * If the state queue list is empty, wait until an
		 * entry is added.
		 */
		while (list_empty(head)) {
			status = pthread_cond_wait(&cond, &mutex);
			if (status)
				fatal(status);
		}

		list_for_each(p, head) {
			struct state_queue *task;

			task = list_entry(p, struct state_queue, list);
/*
			debug(LOGOPT_NONE,
			      "task %p ap %p state %d next %d busy %d",
			      task, task->ap, task->ap->state,
			      task->state, task->busy);
*/

			task->busy = 1;
			/*
			 * TODO: field return code and delete immediately
			 * 	 on fail
			 */
			/* TODO: field return code and delete immediately on fail */
			run_state_task(task);
		}

		while (1) {
			struct timespec wait;

			wait.tv_sec = time(NULL) + 1;
			wait.tv_nsec = 0;

			while (!signaled) {
				status = pthread_cond_timedwait(&cond, &mutex, &wait);
				if (status) {
					if (status == ETIMEDOUT)
						break;
					fatal(status);
				}
			}
			signaled = 0;

			p = head->next;
			while (p != head) {
				struct state_queue *task, *next;

				task = list_entry(p, struct state_queue, list);
				p = p->next;
/*
				debug(LOGOPT_NONE,
				      "task %p ap %p state %d next %d busy %d",
				      task, task->ap, task->ap->state,
				      task->state, task->busy);
*/
				if (!task->busy) {
					/* Start a new task */
					task->busy = 1;
					/*
					 * TODO: field return code and delete
					 *	 immediately on fail
					 */
					run_state_task(task);
					continue;
				}

				if (task->cancel)
					pthread_cancel(task->thid);

				/* Still busy */
				if (task->thid) {
					status = pthread_kill(task->thid, 0);
					if (status != ESRCH)
						continue;
				}

				/* No more tasks for this queue */
				if (list_empty(&task->pending)) {
					list_del(&task->list);
					/* debug("task complete %p", task); */
					free(task);
					continue;
				}

				/* Next task */
				next = list_entry((&task->pending)->next,
							struct state_queue, pending);

				list_del_init(&next->pending);
				list_add_tail(&next->list, head);

				list_del(&task->list);
				/* debug("task complete %p", task); */
				free(task);
			}

			if (list_empty(head))
				break;
		}
	}
}

int st_start_handler(void)
{
	pthread_t thid;
	pthread_attr_t attrs;
	pthread_attr_t *pattrs = &attrs;
	int status;

	status = pthread_attr_init(pattrs);
	if (status)
		pattrs = NULL;
	else {
		pthread_attr_setdetachstate(pattrs, PTHREAD_CREATE_DETACHED);
#ifdef _POSIX_THREAD_ATTR_STACKSIZE
		pthread_attr_setstacksize(pattrs, PTHREAD_STACK_MIN*4);
#endif
	}

	status = pthread_create(&thid, pattrs, st_queue_handler, NULL);
	if (status)
		return 0;

	return 1;
}

