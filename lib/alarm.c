/* ----------------------------------------------------------------------- *
 *
 *  alarm.c - alarm queue handling module.
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

#include <stdlib.h>
#include "automount.h"

struct alarm {
	time_t time;
	unsigned int cancel;
	struct autofs_point *ap;
	struct list_head list;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(alarms);

#define alarm_lock() \
do { \
	int status = pthread_mutex_lock(&mutex); \
	if (status) \
		fatal(status); \
} while (0)

#define alarm_unlock() \
do { \
	int status = pthread_mutex_unlock(&mutex); \
	if (status) \
		fatal(status); \
} while (0)

void dump_alarms(void)
{
	struct list_head *head;
	struct list_head *p;

	pthread_mutex_lock(&mutex);
	head = &alarms;
	list_for_each(p, head) {
		struct alarm *this;

		this = list_entry(p, struct alarm, list);
		msg("alarm time = %d", this->time);
	}
	pthread_mutex_unlock(&mutex);
}

/* Insert alarm entry on ordered list. */
int alarm_add(struct autofs_point *ap, time_t seconds)
{
	struct list_head *head;
	struct list_head *p;
	struct alarm *new;
	time_t now = time(NULL);
	time_t next_alarm = 0;
	unsigned int empty = 1;
	int status;

	new = malloc(sizeof(struct alarm));
	if (!new)
		return 0;

	new->ap = ap;
	new->cancel = 0;
	new->time = now + seconds;

	alarm_lock();

	head = &alarms;

	/* Check if we have a pending alarm */
	if (!list_empty(head)) {
		struct alarm *current;
		current = list_entry(head->next, struct alarm, list);
		next_alarm = current->time;
		empty = 0;
	}

	list_for_each(p, head) {
		struct alarm *this;

		this = list_entry(p, struct alarm, list);
		if (this->time >= new->time) {
			list_add_tail(&new->list, p);
			break;
		}
	}
	if (p == head)
		list_add_tail(&new->list, p);

	/*
	 * Wake the alarm thread if it is not busy (ie. if the
	 * alarms list was empty) or if the new alarm comes before
	 * the alarm we are currently waiting on.
	 */
	if (empty || new->time < next_alarm) {
        	status = pthread_cond_signal(&cond);
		if (status)
			fatal(status);
	}

	alarm_unlock();

	return 1;
}

void alarm_delete(struct autofs_point *ap)
{
	struct list_head *head;
	struct list_head *p;
	struct alarm *current;
	unsigned int signal_cancel = 0;
	int status;

	alarm_lock();

	head = &alarms;

	if (list_empty(head)) {
		alarm_unlock();
		return;
	}

	current = list_entry(head->next, struct alarm, list);

	p = head->next;
	while (p != head) {
		struct alarm *this;

		this = list_entry(p, struct alarm, list);
		p = p->next;

		if (ap == this->ap) {
			if (current != this) {
				list_del_init(&this->list);
				free(this);
				continue;
			}
			/* Mark as canceled */
			this->cancel = 1;
			this->time = 0;
			signal_cancel = 1;
		}
	}

	if (signal_cancel) {
        	status = pthread_cond_signal(&cond);
		if (status)
			fatal(status);
	}

	alarm_unlock();

	return;
}

static void *alarm_handler(void *arg)
{
	struct list_head *head;
	struct autofs_point *ap;
	struct timespec expire;
	time_t now;
	int status;

	alarm_lock();

	head = &alarms;

	while (1) {
		struct alarm *current;

		/*
		 * If the alarm list is empty, wait until an alarm is
		 * added.
		 */
		while (list_empty(head)) {
			status = pthread_cond_wait(&cond, &mutex);
			if (status)
				fatal(status);
		}

		current = list_entry(head->next, struct alarm, list);

		ap = current->ap;
		now = time(NULL);

		if (current->time <= now) {
			list_del(&current->list);

			if (current->cancel) {
				free(current);
				continue;
			}

			state_mutex_lock(ap);

			nextstate(ap->state_pipe[1], ST_EXPIRE);

			state_mutex_unlock(ap);

			free(current);
			continue;
		}

		expire.tv_sec = current->time;
		expire.tv_nsec = 0;

		while (1) {
			struct alarm *next;

			status = pthread_cond_timedwait(&cond, &mutex, &expire);
			if (status && status != ETIMEDOUT)
				fatal(status);

			next = list_entry(head->next, struct alarm, list);
			if (next->cancel) {
				list_del(&next->list);
				free(next);
				break;
			}

			if (next != current)
				break;

			list_del(&current->list);
			free(current);

			state_mutex_lock(ap);
			nextstate(ap->state_pipe[1], ST_EXPIRE);
			state_mutex_unlock(ap);

			break;
		}
	}
}

int alarm_start_handler(void)
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

	status = pthread_create(&thid, pattrs, alarm_handler, NULL);
	if (status)
	 	return 0;

	return 1;
}

