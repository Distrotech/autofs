#ident "$Id: state.h,v 1.6 2006/04/01 06:48:05 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  state.h - state queue functions.
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

#ifndef STATE_H
#define STATE_H

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include "automount.h"

/*
 * State machine for daemon
 * 
 * READY - reads from pipe; performs mount/umount operations
 * PRUNE - generates prune events in subprocess; reads from pipe
 * READMAP - read read map for maps taht use cache
 * EXPIRE - generates expire events in subprocess; reads from pipe
 * SHUTDOWN_PENDING - as prune, but goes to SHUTDOWN when done
 * SHUTDOWN - unmount autofs, exit
 *
 */
enum states {
	ST_INVAL = -1,
	ST_INIT,
	ST_READY,
	ST_EXPIRE,
	ST_PRUNE,
	ST_READMAP,
	ST_SHUTDOWN_PENDING,
	ST_SHUTDOWN_FORCE,
	ST_SHUTDOWN,
};

struct expire_args {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	unsigned int signaled;
	struct autofs_point *ap; /* autofs mount we are working on */
	enum states state;	 /* State prune or expire */
	unsigned int when;	 /* Immediate expire ? */
	int status;		 /* Return status */
};

struct readmap_args {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	unsigned int signaled;
	struct autofs_point *ap; /* autofs mount we are working on */
	time_t now;              /* Time when map is read */
};

void expire_cleanup(void *);
void expire_proc_cleanup(void *);
void nextstate(int, enum states);

int st_add_task(struct autofs_point *, enum states);
void st_remove_tasks(struct autofs_point *);
int st_start_handler(void);

#endif
