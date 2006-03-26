#ident "$Id: state.c,v 1.5 2006/03/26 04:56:22 raven Exp $"
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

extern pthread_attr_t thread_attr;

struct state {
	struct list_head queue;
	enum states state;
};

int do_mount_autofs_direct(struct autofs_point *, struct mapent *, int);

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
		error("state mutex lock failed");
		free(ea);
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

	free(ea);

	return;
}

static unsigned int st_ready(struct autofs_point *ap)
{
	debug("st_ready(): state = %d path %s", ap->state, ap->path);

	ap->state = ST_READY;

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

static enum expire expire_proc(struct autofs_point *ap, int now)
{
	pthread_t thid;
	struct expire_args *ea;
	void *(*expire)(void *);
	int status;

	assert(ap->exp_thread == 0);

	ea = malloc(sizeof(struct expire_args));
	if (!ea) {
		error("failed to malloc expire cond struct");
		return EXP_ERROR;
	}
	memset(ea, 0, sizeof(struct expire_args));

	status = pthread_barrier_init(&ea->barrier, NULL, 2);
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
		error("expire thread create for %s failed", ap->path);
		return EXP_ERROR;
	}
	ap->exp_thread = thid;

	debug("exp_proc = %lu path %s",
		(unsigned long) ap->exp_thread, ap->path);

	status = pthread_barrier_wait(&ea->barrier);
	if (status && status != PTHREAD_BARRIER_SERIAL_THREAD)
		fatal(status);

	status = pthread_barrier_destroy(&ea->barrier);
	if (status)
		fatal(status);

	return EXP_STARTED;
}

static void do_readmap_cleanup(void *arg)
{
	struct readmap_args *ra;
	struct autofs_point *ap;
	int status;

	ra = (struct readmap_args *) arg;

	ap = ra->ap;

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
	struct mapent_cache *mc;
	struct readmap_args *ra;
	int status;
	time_t now;

	ra = (struct readmap_args *) arg;

	ap = ra->ap;
	now = ra->now;
	mc = ap->mc;

	status = pthread_barrier_wait(&ra->barrier);
	if (status && status != PTHREAD_BARRIER_SERIAL_THREAD)
		fatal(status);

	pthread_cleanup_push(do_readmap_cleanup, ra);

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

	return NULL;
}

static unsigned int st_readmap(struct autofs_point *ap)
{
	pthread_t thid;
	struct readmap_args *ra;
	int status;
	int now = time(NULL);

	debug("state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_READMAP;

	ra = malloc(sizeof(struct readmap_args));
	if (!ra) {
		error("failed to malloc reamap cond struct");
		return 0;
	}
	memset(ra, 0, sizeof(struct readmap_args));

	status = pthread_barrier_init(&ra->barrier, NULL, 2);
	if (status)
		fatal(status);

	ra->ap = ap;
	ra->now = now;

	status = pthread_create(&thid, &thread_attr, do_readmap, ra);
	if (status) {
		error("read map thread create failed");
		return 0;
	}

	status = pthread_barrier_wait(&ra->barrier);
	if (status && status != PTHREAD_BARRIER_SERIAL_THREAD)
		fatal(status);

	status = pthread_barrier_destroy(&ra->barrier);
	if (status)
		fatal(status);

	return 1;
}

static unsigned int st_prepare_shutdown(struct autofs_point *ap)
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

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_force_shutdown(struct autofs_point *ap)
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

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_prune(struct autofs_point *ap)
{
	debug("state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_PRUNE;

	switch (expire_proc(ap, 1)) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		ap->state = ST_READY;
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_expire(struct autofs_point *ap)
{
	debug("state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_EXPIRE;

	/* Turn off timeouts for this mountpoint */
	alarm_delete(ap);

	switch (expire_proc(ap, 0)) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		alarm_add(ap, ap->exp_runfreq);
		ap->state = ST_READY;
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_queue_head(struct autofs_point *ap, enum states state)
{
	struct state *st;

	st = malloc(sizeof(struct state));
	if (!st)
		return 0;

	st->state = state;
	INIT_LIST_HEAD(&st->queue);

	list_add(&st->queue, &ap->state_queue);

	return 1;
}

static unsigned int st_queue_tail(struct autofs_point *ap, enum states state)
{
	struct state *st;

	st = malloc(sizeof(struct state));
	if (!st)
		return 0;

	st->state = state;
	INIT_LIST_HEAD(&st->queue);

	list_add_tail(&st->queue, &ap->state_queue);

	return 1;
}

static enum states st_dequeue(struct autofs_point *ap)
{
	struct list_head *queue;
	enum states next;
	struct state *st;

	if (list_empty(&ap->state_queue))
		return ST_READY;

	queue = (&ap->state_queue)->next;

	st = list_entry(queue, struct state, queue);

	list_del(&st->queue);
	next = st->state;
	free(st);

	return next;
}

static void st_dequeue_all(struct autofs_point *ap)
{
	struct list_head *queue, *head;
	struct state *st;

	if (list_empty(&ap->state_queue))
		return;

	head = &ap->state_queue;
	queue = head->next;
	while (queue != head) {
		st = list_entry(queue, struct state, queue);
		queue = queue->next;
		list_del(&st->queue);
		free(st);
	}

	return;
}

/*
 * autofs_point state_mutex must be held when calling
 * this function.
 */
enum states st_next(struct autofs_point *ap, enum states state)
{
	enum states next;
	unsigned int ret = 1;

	next = state;

	switch (state) {
	case ST_READY:
		if (!list_empty(&ap->state_queue)) {
			st_ready(ap);
			next = st_dequeue(ap);
		}
		break;

	case ST_EXPIRE:
	case ST_PRUNE:
	case ST_READMAP:
		if (ap->state != ST_READY) {
			st_queue_tail(ap, state);
			return ap->state;
		}
		break;

	case ST_SHUTDOWN_PENDING:
	case ST_SHUTDOWN_FORCE:
		if (state != ST_READY) {
			st_queue_head(ap, state);
			return ap->state;
		}
		break;

	case ST_SHUTDOWN:
		break;

	default:
		error("bad next state %d", next);
		return ST_INVAL;
	}

	debug("state %d, next %d path %s", ap->state, next, ap->path);

	switch (next) {
	case ST_READY:
		ret = st_ready(ap);
		break;

	case ST_EXPIRE:
		ret = st_expire(ap);
		break;

	case ST_PRUNE:
		ret = st_prune(ap);
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

	case ST_SHUTDOWN:
		assert(ap->state == ST_SHUTDOWN ||
			ap->state == ST_SHUTDOWN_FORCE ||
			ap->state == ST_SHUTDOWN_PENDING);
		ap->state = ST_SHUTDOWN;
		st_dequeue_all(ap);
		break;

	default:
		error("bad next state %d", next);
	}

	if (!ret)
		warn("error during state transition");

	return next;
}

