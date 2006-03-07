#ident "$Id: alarm.c,v 1.2 2006/03/07 23:16:41 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  alarm.c - alarm queueing module.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 *   Adapted from the example program alarm_cond.c from 
 *   "Programming with POSIX Threads", Butenhof D. R.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include "automount.h"

extern pthread_mutex_t state_mutex;
extern pthread_attr_t detach_attr;

struct alarm {
	time_t time;
	unsigned int cancel;
	struct autofs_point *ap;
	struct list_head list;
};

static pthread_mutex_t alarm_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t alarm_cond = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(alarm_list);
static time_t next_alarm = 0;

void dump_alarms(void)
{
	struct list_head *head = &alarm_list;
	struct list_head *p;

	list_for_each(p, head) {
		struct alarm *alarm;

		alarm = list_entry(p, struct alarm, list);
		msg("alarm time = %d\n", alarm->time);
	}
}

/*
 * Insert alarm entry on list, in order.
 */
int alarm_insert(struct autofs_point *ap, time_t seconds)
{
	struct list_head *head = &alarm_list;
	struct list_head *p;
	struct alarm *alarm;
	time_t now = time(NULL);
	int status;

	alarm = malloc(sizeof(struct alarm));
	if (!alarm)
		return 0;

	alarm->ap = ap;
	alarm->cancel = 0;
	alarm->time = now + seconds;

	status = pthread_mutex_lock(&alarm_mutex);
	if (status)
		fatal(status);

	list_for_each(p, head) {
		struct alarm *this;

		this = list_entry(p, struct alarm, list);
		if (this->time >= alarm->time) {
			list_add_tail(&alarm->list, p);
			break;
		}
	}
	if (p == head)
		list_add_tail(&alarm->list, p);

	/*
	 * Wake the alarm thread if it is not busy (that is, if
	 * next_alarm is 0, signifying that it's waiting for
	 * work), or if the new alarm comes before the one on
	 * which the alarm thread is waiting.
	 */
	if (next_alarm == 0 || alarm->time < next_alarm) {
        	next_alarm = alarm->time;
        	status = pthread_cond_signal(&alarm_cond);
		if (status)
			fatal(status);
	}

	status = pthread_mutex_unlock(&alarm_mutex);
	if (status)
		fatal(status);

	return 1;
}

void alarm_remove(struct autofs_point *ap)
{
	struct list_head *head = &alarm_list;
	struct list_head *p;
	int status;

	status = pthread_mutex_lock(&alarm_mutex);
	if (status)
		fatal(status);

	p = head->next;
	while (p != head) {
		struct alarm *alarm;

		alarm = list_entry(p, struct alarm, list);
		p = p->next;

		if (ap == alarm->ap) {
			if (next_alarm != alarm->time) {
				list_del_init(&alarm->list);
				free(alarm);
				continue;
			}
			/* Mark as canceled */
			alarm->cancel = 1;
		}
	}

	status = pthread_mutex_unlock(&alarm_mutex);
	if (status)
		fatal(status);
}

/* alarm thread routine. */
static void *alarm_handler(void *arg)
{
	struct list_head *head = &alarm_list;
	struct autofs_point *ap;
	struct alarm *alarm;
	struct timespec cond_time;
	time_t now;
	int status;

	status = pthread_mutex_lock(&alarm_mutex);
	if (status)
		fatal(status);

	while (1) {
		/*
		 * If the alarm list is empty, wait until an alarm is
		 * added. Setting next_alarm to 0 informs the insert
		 * routine that the thread is not busy.
		 */
		next_alarm = 0;
		while (list_empty(head)) {
			status = pthread_cond_wait(&alarm_cond, &alarm_mutex);
			if (status)
				fatal(status);
		}

		alarm = list_entry(head->next, struct alarm, list);

		ap = alarm->ap;
		now = time(NULL);

		if (alarm->time <= now) {
			list_del_init(&alarm->list);

			if (alarm->cancel) {
				free(alarm);
				continue;
			}

			status = pthread_mutex_lock(&state_mutex);
			if (status)
				fatal(status);

			nextstate(alarm->ap->state_pipe[1], ST_EXPIRE);

			status = pthread_mutex_unlock(&state_mutex);
			if (status)
				fatal(status);

			free(alarm);
			continue;
		}

		cond_time.tv_sec = alarm->time;
		cond_time.tv_nsec = 0;
		next_alarm = alarm->time;

		while (next_alarm == alarm->time) {
			status = pthread_cond_timedwait (
					&alarm_cond, &alarm_mutex, &cond_time);

			if (status && status != ETIMEDOUT)
				fatal(status);

			list_del_init(&alarm->list);

			if (alarm->cancel) {
				free(alarm);
				break;
			}

			status = pthread_mutex_lock(&state_mutex);
			if (status)
				fatal(status);

			nextstate(ap->state_pipe[1], ST_EXPIRE);

			status = pthread_mutex_unlock(&state_mutex);
			if (status)
				fatal(status);

			free (alarm);
			break;
		}
	}
}

int alarm_start_handler(void)
{
	pthread_t thid;
	int status;

	status = pthread_create(&thid, &detach_attr, alarm_handler, NULL);
	if (status)
		return 0;

	return 1;
}

