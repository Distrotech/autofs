#ident "$Id: state.c,v 1.2 2006/03/24 03:43:40 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  state.c - state machine queue runner.
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

extern pthread_attr_t detach_attr;

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

unsigned int signaled = 0;

int do_mount_autofs_direct(struct autofs_point *, struct mapent *, int);

void dump_state_queue(void)
{
	struct list_head *head = &state_queue;
	struct list_head *p, *q;

	debug("dumping queue");

	list_for_each(p, head) {
		struct state_queue *entry;

		entry = list_entry(p, struct state_queue, list);
		debug("queue list head path %s state %d busy %d",
			entry->ap->path, entry->state, entry->busy);

		list_for_each(q, &entry->pending) {
			struct state_queue *this;

			this = list_entry(q, struct state_queue, pending);
			debug("queue list entry path %s state %d busy %d",
				this->ap->path, this->state, this->busy);
		}
	}
}

void nextstate(int statefd, enum states next)
{
	char buf[MAX_ERR_BUF];

	if (write(statefd, &next, sizeof(next)) != sizeof(next)) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error("write failed %s", estr);
	}
}

/*
 * Handle expire thread cleanup and return the next state the system
 * should enter as a result.
 */
void expire_cleanup(void *arg)
{
	pthread_t thid = pthread_self();
	struct expire_args *ex;
	struct autofs_point *ap;
	int statefd;
	enum states next = ST_INVAL;
	int success;
	int status;

	ex = (struct expire_args *) arg;
	ap = ex->ap;
	success = ex->status;

	status = pthread_mutex_lock(&ap->state_mutex);
	if (status) {
		error("state mutex lock failed");
		return;
	}

	debug("got thid %lu path %s stat %d", (unsigned long) thid, ap->path, success);

	statefd = ap->state_pipe[1];

	/* Check to see if expire process finished */
	if (thid == ap->exp_thread) {
		ap->exp_thread = 0;

		switch (ap->state) {
		case ST_EXPIRE:
			alarm_add(ap, ap->exp_runfreq);
			/* FALLTHROUGH */
		case ST_PRUNE:
			/* If we're a submount and we've just
			   pruned or expired everything away,
			   try to shut down */
			if (ap->submount && !success && ap->state != ST_SHUTDOWN) {
				next = ST_SHUTDOWN_PENDING;
				break;
			}
			/* FALLTHROUGH */

		case ST_READY:
			next = ST_READY;
			break;

		case ST_SHUTDOWN_PENDING:
			next = ST_SHUTDOWN;
			if (success == 0)
				break;

			/* Failed shutdown returns to ready */
			warn("filesystem %s still busy", ap->path);
			if (ap->submount) {
				status = pthread_mutex_unlock(&ap->parent->state_mutex);
				if (status)
					fatal(status);
			}
			alarm_add(ap, ap->exp_runfreq);
			next = ST_READY;
			break;

		case ST_SHUTDOWN_FORCE:
			next = ST_SHUTDOWN;
			break;

		default:
			error("bad state %d", ap->state);
		}

		if (next != ST_INVAL) {
			debug("sigchld: exp "
				"%lu finished, switching from %d to %d",
				(unsigned long) thid, ap->state, next);
		}
	}

	if (next != ST_INVAL)
		nextstate(statefd, next);

	status = pthread_mutex_unlock(&ap->state_mutex);
	if (status)
		error("state mutex unlock failed");

	return;
}

static int st_ready(struct autofs_point *ap)
{
	debug("st_ready(): state = %d path %s", ap->state, ap->path);

	ap->state = ST_READY;

	return 0;
}

enum expire {
	EXP_ERROR,
	EXP_STARTED,
	EXP_DONE,
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

void expire_cleanup_unlock(void *arg)
{
	struct expire_cond *ec;
	int status;

	ec = (struct expire_cond *) arg;

	status = pthread_mutex_unlock(&ec->mutex);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&ec->mutex);
	if (status)
		fatal(status);

	free(ec);

	return;
}

static enum expire expire_proc(struct autofs_point *ap, int now)
{
	pthread_t thid;
	struct expire_cond *ec;
	void *(*expire)(void *);
	int status;

	assert(ap->exp_thread == 0);

	ec = malloc(sizeof(struct expire_cond));
	if (!ec) {
		error("failed to malloc expire cond struct");
		return EXP_ERROR;
	}
	memset(ec, 0, sizeof(struct expire_cond));

	status = pthread_mutex_init(&ec->mutex, NULL);
	if (status)
		fatal(status);

	if (ap->type == LKP_INDIRECT)
		expire = expire_proc_indirect;
	else
		expire = expire_proc_direct;

	status = pthread_mutex_lock(&ec->mutex);
	if (status) {
		error("failed to lock state condition mutex");
		expire_cleanup_unlock(ec);
		return EXP_ERROR;
	}

	status = pthread_create(&thid, &detach_attr, expire, ec);
	if (status) {
		error("expire thread create for %s failed", ap->path);
		expire_cleanup_unlock(ec);
		return EXP_ERROR;
	}
	state_queue_set_thid(ap, thid);
	ap->exp_thread = thid;

	debug("exp_proc = %lu path %s", (unsigned long) thid, ap->path);

	ec->ap = ap;
	ec->when = now;

	status = pthread_mutex_unlock(&ec->mutex);
	if (status)
		fatal(status);

	return EXP_STARTED;
}

static void do_readmap_cleanup(void *arg)
{
	struct autofs_point *ap;
	int status;

	ap = (struct autofs_point *) arg;

	status = pthread_mutex_lock(&ap->state_mutex);
	if (status)
		fatal(status);

	nextstate(ap->state_pipe[1], ST_READY);

	status = pthread_mutex_unlock(&ap->state_mutex);
	if (status)
		fatal(status);

	return;
}

static void do_readmap_unlock(void *arg)
{
	struct readmap_cond *rc;
	int status;

	rc = (struct readmap_cond *) arg;

	status = pthread_mutex_unlock(&rc->mutex);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&rc->mutex);
	if (status)
		fatal(status);

	free(rc);

	return;
}

static void *do_readmap(void *arg)
{
	struct autofs_point *ap;
	struct mapent_cache *mc;
	struct readmap_cond *rc;
	int status, old_state;
	time_t now;

	rc = (struct readmap_cond *) arg;

	status = pthread_mutex_lock(&rc->mutex);
	if (status)
		fatal(status);

	ap = rc->ap;
	mc = ap->mc;

	now = rc->now;

	pthread_cleanup_push(do_readmap_unlock, rc);
	pthread_cleanup_push(do_readmap_cleanup, ap);

	status = lookup_nss_read_map(ap, now);
	if (!status)
		pthread_exit(NULL);

	lookup_prune_cache(ap, now);

	pthread_cleanup_push(cache_lock_cleanup, mc);
	cache_readlock(mc);
	if (ap->type == LKP_INDIRECT)
		status = lookup_ghost(ap);
	else
		status = lookup_enumerate(ap, do_mount_autofs_direct, now);
	cache_unlock(mc);
	pthread_cleanup_pop(0);

	debug("path %s status %d", ap->path, status);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return NULL;
}

static int st_readmap(struct autofs_point *ap)
{
	pthread_t thid;
	struct readmap_cond *rc;
	int status;
	int now = time(NULL);

	debug("state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_READMAP;

	rc = malloc(sizeof(struct readmap_cond));
	if (!rc) {
		error("failed to malloc reamap cond struct");
		return 0;
	}
	memset(rc, 0, sizeof(struct readmap_cond));

	status = pthread_mutex_init(&rc->mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&rc->mutex);
	if (status)
		fatal(status);

	status = pthread_create(&thid, &detach_attr, do_readmap, rc);
	if (status) {
		error("read map thread create failed");
		return 0;
	}
	state_queue_set_thid(ap, thid);

	rc->ap = ap;
	rc->now = now;

	status = pthread_mutex_unlock(&rc->mutex);
	if (status)
		fatal(status);

	return 1;
}

static int st_prepare_shutdown(struct autofs_point *ap)
{
	int status;
	int exp;

	debug("state %d path %s", ap->state, ap->path);

	/* Turn off timeouts for this mountpoint */
	alarm_delete(ap);

	assert(ap->state == ST_READY || ap->state == ST_EXPIRE);
	ap->state = ST_SHUTDOWN_PENDING;

	if (ap->submount) {
		status = pthread_mutex_lock(&ap->parent->state_mutex);
		if (status)
			fatal(status);
	}

	/* Unmount everything */
	exp = expire_proc(ap, 1);
	switch (exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		alarm_add(ap, ap->exp_runfreq);
		ap->state = ST_READY;
		return 0;

	case EXP_DONE:
		/* All expired: go straight to exit */
		ap->state = ST_SHUTDOWN;
		return 1;

	case EXP_STARTED:
		return 0;
	}
	return 1;
}

static int st_force_shutdown(struct autofs_point *ap)
{
	int status;
	int exp;

	debug("state %d path %s", ap->state, ap->path);

	/* Turn off timeouts for this mountpoint */
	alarm_delete(ap);

	assert(ap->state == ST_READY || ap->state == ST_EXPIRE);
	ap->state = ST_SHUTDOWN_FORCE;

	if (ap->submount) {
		status = pthread_mutex_lock(&ap->parent->state_mutex);
		if (status)
			fatal(status);
	}

	/* Unmount everything */
	exp = expire_proc(ap, 1);
	switch (exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		alarm_add(ap, ap->exp_runfreq);
		ap->state = ST_READY;
		return 0;

	case EXP_DONE:
		/* All expired: go straight to exit */
		ap->state = ST_SHUTDOWN;
		return 1;

	case EXP_STARTED:
		return 0;
	}
	return 1;
}

static int st_prune(struct autofs_point *ap)
{
	debug("state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_PRUNE;

	switch (expire_proc(ap, 1)) {
	case EXP_DONE:
		if (ap->submount)
			return st_prepare_shutdown(ap);
		/* FALLTHROUGH */

	case EXP_ERROR:
	case EXP_PARTIAL:
		ap->state = ST_READY;
		return 1;

	case EXP_STARTED:
		return 0;
	}
	return 1;
}

static int st_expire(struct autofs_point *ap)
{
	debug("state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_EXPIRE;

	/* Turn off timeouts for this mountpoint */
	alarm_delete(ap);

	switch (expire_proc(ap, 0)) {
	case EXP_DONE:
		if (ap->submount)
			return st_prepare_shutdown(ap);
		/* FALLTHROUGH */

	case EXP_ERROR:
	case EXP_PARTIAL:
		alarm_add(ap, ap->exp_runfreq);
		ap->state = ST_READY;
		return 1;

	case EXP_STARTED:
		return 0;
	}
	return 1;
}

/* Insert alarm entry on ordered list. */
int state_queue_add(struct autofs_point *ap, enum states state)
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

	new->thid = 0;
	new->ap = ap;
	new->state = state;
	new->busy = 0;

	INIT_LIST_HEAD(&new->list);
	INIT_LIST_HEAD(&new->pending);

	status = pthread_mutex_lock(&mutex);
	if (status)
		fatal(status);

	/* Add to task queue for autofs_point ? */
	list_for_each(p, head) {
		struct state_queue *entry;

		entry = list_entry(p, struct state_queue, list);

		if (entry->ap == ap) {
			empty = 0;
			list_add_tail(&new->pending, &entry->pending);
			break;
		}
	}

	if (empty) {
		list_add(&new->list, head);
	}

	/* Added task, enouurage state machine */
	signaled = 1;
	status = pthread_cond_signal(&cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&mutex);
	if (status)
		fatal(status);

	return 1;
}

void state_queue_delete(struct autofs_point *ap)
{
	struct list_head *head = &state_queue;
	struct list_head *p, *q;
	struct state_queue *entry, *this;
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
		entry = list_entry(p, struct state_queue, list);
		p = p->next;

		if (entry->ap != ap)
			continue;

		q = (&entry->pending)->next;
		while(q != &entry->pending) {
			this = list_entry(q, struct state_queue, pending);
			q = q->next;

			list_del(&this->pending);
			free(this);
		}

		list_del(&entry->list);
		free(entry);
	}

	signaled = 1;
	status = pthread_cond_signal(&cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&mutex);
	if (status)
		fatal(status);
}

static int run_state_task(struct state_queue *entry)
{
	struct autofs_point *ap;
	enum states state;
	enum states next_state;
	int ret;

	ap = entry->ap;
	state = ap->state;
	next_state = entry->state;

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
			error("bad next state %d", next_state);
		}
	}

	return ret;
}

void state_queue_set_thid(struct autofs_point *ap, pthread_t thid)
{
	struct list_head *p, *head = &state_queue;
	struct state_queue *entry;

	list_for_each(p, head) {
		entry = list_entry(p, struct state_queue, list);
		if (entry->ap == ap) {
			entry->thid = thid;
			break;
		}
	}
	return;
}

static void *state_queue_handler(void *arg)
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
			struct state_queue *entry;

			entry = list_entry(p, struct state_queue, list);

			msg("entry %p path %s thid %lu busy %d",
				entry, entry->ap->path,
				(unsigned int) entry->thid, entry->busy);
/*
			debug("state %d next %d path %s",
				entry->ap->state, entry->state, entry->ap->path);
*/
			entry->busy = 1;
			run_state_task(entry);
		}

		while (1) {
			struct timespec wait;

			wait.tv_sec = time(NULL) + 4;
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
				struct state_queue *this, *next;

				this = list_entry(p, struct state_queue, list);
				p = p->next;

				msg("entry %p path %s thid %lu busy %d",
					this, this->ap->path,
					(unsigned int) this->thid, this->busy);

				if (this->busy) {
					/* Still busy */
					if (this->thid) {
						status = pthread_kill(this->thid, 0);
						if (status != ESRCH)
							continue;
					}

					/* No more tasks for this queue */
					if (list_empty(&this->pending)) {
						list_del(&this->list);
						free(this);
						continue;
					}

					/* Next task */
					next = list_entry((&this->pending)->next,
								 struct state_queue, pending);

					list_del_init(&next->pending);
					list_add_tail(&next->list, head);

					list_del(&this->list);
					free(this);
				}
/*
				debug("state %d next %d path %s",
					this->ap->state, this->state, this->ap->path);
*/
				/* Start a new task */
				this->busy = 1;
				run_state_task(this);
				continue;

				if (list_empty(head))
					break;
			}
		}
	}
}

int state_queue_start_handler(void)
{
	pthread_t thid;
	int status;

	status = pthread_create(&thid, &detach_attr, state_queue_handler, NULL);
	if (status)
		return 0;

	return 1;
}

