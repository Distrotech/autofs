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

extern pthread_attr_t thread_attr;

struct state {
	struct list_head queue;
	enum states state;
};

int do_mount_autofs_direct(struct autofs_point *, struct mnt_list *, struct mapent *, int);

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
			/* FALLTHROUGH */
		case ST_PRUNE:
			alarm_add(ap, ap->exp_runfreq);
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
		error("failed to malloc expire cond struct");
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
		error("expire thread create for %s failed", ap->path);
		expire_proc_cleanup((void *) ea);
		free(ea);
		return EXP_ERROR;
	}
	ap->exp_thread = thid;

	pthread_cleanup_push(expire_proc_cleanup, ea);

	debug("exp_proc = %lu path %s",
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
	mc = ap->mc;

	ra->signaled = 1;
	status = pthread_cond_signal(&ra->cond);
	if (status) {
		error("failed to signal expire condition");
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

	lookup_prune_cache(ap, now);

	pthread_cleanup_push(cache_lock_cleanup, mc);
	cache_readlock(mc);
	if (ap->type == LKP_INDIRECT)
		status = lookup_ghost(ap);
	else {
		struct mapent *me;
		mnts = tree_make_mnt_tree(_PROC_MOUNTS, "/");
		me = cache_enumerate(mc, NULL);
		while (me) {
			/* TODO: check return, locking me */
			do_mount_autofs_direct(ap, mnts, me, now);
			me = cache_enumerate(mc, me);
		}
		tree_free_mnt_tree(mnts);
	}
	cache_unlock(mc);
	pthread_cleanup_pop(0);

	debug("path %s status %d", ap->path, status);

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

	debug("state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_READMAP;

	ra = malloc(sizeof(struct readmap_args));
	if (!ra) {
		error("failed to malloc reamap cond struct");
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
		error("read map thread create failed");
		st_readmap_cleanup(ra);
		free(ra);
		return 0;
	}
	ap->readmap_thread = thid;

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
		nextstate(ap->state_pipe[1], ST_READY);
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
		nextstate(ap->state_pipe[1], ST_READY);
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
	debug("state %d path %s", ap->state, ap->path);

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

static unsigned int st_queue(struct autofs_point *ap, enum states state)
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

static void st_cancel_pending(struct autofs_point *ap)
{
	if (ap->exp_thread) {
		debug("cancel expire thid %lu",
			(unsigned long) ap->exp_thread);
		while (pthread_cancel(ap->exp_thread) != ESRCH)
			sleep(1);
		alarm_delete(ap);
		debug("done");
	}
			
	if (ap->readmap_thread) {
		debug("cancel readmap thid %lu",
			(unsigned long) ap->readmap_thread);
		while (pthread_cancel(ap->readmap_thread) != ESRCH)
			sleep(1);
		debug("done");
	}
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
			st_queue(ap, state);
			return ap->state;
		}
		break;

	case ST_SHUTDOWN_PENDING:
	case ST_SHUTDOWN_FORCE:
	/*	st_dequeue_all(ap);
		if (ap->state != ST_READY &&
		    ap->state != ST_SHUTDOWN_PENDING &&
		    ap->state != ST_SHUTDOWN_FORCE)
			st_cancel_pending(ap); */
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
		break;

	default:
		error("bad next state %d", next);
	}

	if (!ret)
		warn("error during state transition");

	return next;
}

