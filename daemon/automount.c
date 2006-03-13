#ident "$Id: automount.c,v 1.62 2006/03/13 21:15:57 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  automount.c - Linux automounter daemon
 *   
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2001-2005 Ian Kent <raven@themaw.net>
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

#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/poll.h>

#include "automount.h"

const char *program;		/* Initialized with argv[0] */
const char *version = VERSION_STRING;	/* Program version */

static pid_t my_pgrp;		/* The "magic" process group */
static pid_t my_pid;		/* The pid of this process */
static char *pid_file = NULL;	/* File in which to keep pid */

/* Attribute to create detached thread */
pthread_attr_t detach_attr;

struct startup_cond sc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0};
/*
struct readmap_cond rc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, 0, 0};
*/
pthread_key_t key_thread_stdenv_vars;

/* re-entrant syslog default context data */
#define AUTOFS_SYSLOG_CONTEXT {-1, 0, 0, LOG_PID, (const char *)0, LOG_DAEMON, 0xff};

#define DEFAULT_GHOST_MODE	0
#define MAX_OPEN_FILES		10240

int do_mount_autofs_direct(struct autofs_point *ap, struct mapent *me, int now);
static int umount_all(struct autofs_point *ap, int force);

pthread_mutex_t master_mutex = PTHREAD_MUTEX_INITIALIZER;
LIST_HEAD(mounts);

int mkdir_path(const char *path, mode_t mode)
{
	char *buf = alloca(strlen(path) + 1);
	const char *cp = path, *lcp = path;
	char *bp = buf;

	do {
		if (cp != path && (*cp == '/' || *cp == '\0')) {
			memcpy(bp, lcp, cp - lcp);
			bp += cp - lcp;
			lcp = cp;
			*bp = '\0';
			if (mkdir(buf, mode) == -1) {
				/* If it already exists, make sure it's a directory */
				if (errno == EEXIST) {
					struct stat st;

					if (stat(buf, &st) == 0 && !S_ISDIR(st.st_mode))
						errno = ENOTDIR;
					else {
						/* last component, return -1 */
						if (*cp != '\0')
							continue;
					}
				}
				return -1;
			}
		}
	} while (*cp++ != '\0');

	return 0;
}

/* Remove as much as possible of a path */
int rmdir_path(const char *path)
{
	int len = strlen(path);
	char *buf = alloca(len + 1);
	char *cp;
	int first = 1;

	strcpy(buf, path);
	cp = buf + len;

	do {
		*cp = '\0';

		/* Last element of path may be non-dir;
		   all others are directories */
		if (rmdir(buf) == -1 && (!first || unlink(buf) == -1))
			return -1;

		first = 0;
	} while ((cp = strrchr(buf, '/')) != NULL && cp != buf);

	return 0;
}

static int umount_offsets(struct autofs_point *ap, const char *base)
{
	char path[PATH_MAX + 1];
	char *offset = path;
	struct list_head head, *pos;
	char key[PATH_MAX + 1];
	struct mapent_cache *mc = ap->mc;
	struct mapent *me;
	struct mnt_list *mnts, *next;
	int ret = 0, status;

	INIT_LIST_HEAD(&head);

	pthread_cleanup_push(cache_lock_cleanup, mc);
	cache_readlock(mc);
	mnts = get_mnt_list(_PROC_MOUNTS, base, 0);
	for (next = mnts; next; next = next->next) {
		if (strcmp(next->fs_type, "autofs"))
			continue;

		INIT_LIST_HEAD(&next->list);
		add_ordered_list(next, &head);
	}

	pos = NULL;
	while ((offset = get_offset(base, offset, &head, &pos))) {
		if (strlen(base) + strlen(offset) >= PATH_MAX) {
			warn("can't umount - mount path too long");
			ret++;
			continue;
		}

		debug("umount offset %s", offset);

		strcpy(key, base);
		strcat(key, offset);
		me = cache_lookup(mc, key);
		if (!me) {
			debug("offset key %s not found", key);
			continue;
		}

		/*
		 * We're in trouble if umounting the triggers fails.
		 * It should always succeed due to the expire design.
		 */
		if (umount_autofs_offset(ap, me)) {
			crit("failed to umount offset %s", me->key);
			ret++;
		}
	}
	free_mnt_list(mnts);
	cache_unlock(mc);
	pthread_cleanup_pop(0);

	cache_writelock(mc);
	/*
	 * If it's a direct mount it's base is the key otherwise
	 * the last path componemt is the indirect entry key.
	 */
	me = cache_lookup(mc, base);
	if (!me) {
		char *ind_key = strrchr(base, '/');

		if (ind_key) {
			ind_key++;
			me = cache_lookup(mc, ind_key);
		}
	}

	if (!ret && me && me->multi == me) {
		status = cache_delete_offset_list(mc, me->key);
		if (status != CHE_OK)
			warn("couldn't delete offset list");
	}
	cache_unlock(mc);

	return ret;
}

static int umount_ent(struct autofs_point *ap, const char *path, const char *type)
{
	struct stat st;
	int sav_errno;
	int is_smbfs = (strcmp(type, "smbfs") == 0);
	int status;
	int ret, rv = 1;

	status = lstat(path, &st);
	sav_errno = errno;

	/*
	 * lstat failed and we're an smbfs fs returning an error that is not
	 * EIO or EBADSLT or the lstat failed so it's a bad path. Return
	 * a fail.
	 *
	 * EIO appears to correspond to an smb mount that has gone away
	 * and EBADSLT relates to CD changer not responding.
	 */
	if (!status && (S_ISDIR(st.st_mode) && st.st_dev != ap->dev)) {
		rv = spawnll(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, path, NULL);
	} else if (is_smbfs && (sav_errno == EIO || sav_errno == EBADSLT)) {
		rv = spawnll(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, path, NULL);
	}

	/* We are doing a forced shutcwdown down so unlink busy mounts */
	if (rv && (ap->state == ST_SHUTDOWN_FORCE || ap->state == ST_SHUTDOWN)) {
		ret = stat(path, &st);
		if (ret == -1 && errno == ENOENT) {
			error("mount point does not exist");
			return 0;
		}

		if (ret == 0 && !S_ISDIR(st.st_mode)) {
			error("mount point is not a directory");
			return 0;
		}

		msg("forcing umount of %s", path);
		rv = spawnll(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-l", path, NULL);
	}

	return rv;
}

/* Like ftw, except fn gets called twice: before a directory is
   entered, and after.  If the before call returns 0, the directory
   isn't entered. */
static int walk_tree(const char *base, int (*fn) (const char *file,
						  const struct stat * st,
						  int, void *), int incl, void *arg)
{
	char buf[PATH_MAX + 1];
	struct stat st;

	if (lstat(base, &st) != -1 && (fn) (base, &st, 0, arg)) {
		if (S_ISDIR(st.st_mode)) {
			struct dirent **de;
			int n;

			n = scandir(base, &de, 0, alphasort);
			if (n < 0)
				return -1;

			while (n--) {
				int ret, size;

				if (strcmp(de[n]->d_name, ".") == 0 ||
				    strcmp(de[n]->d_name, "..") == 0)
					continue;

				size = sizeof(buf);
				ret = cat_path(buf, size, base, de[n]->d_name);
				if (!ret) {
					do {
						free(de[n]);
					} while (n--);
					free(de);
					return -1;
				}

				walk_tree(buf, fn, 1, arg);
				free(de[n]);
			}
			free(de);
		}
		if (incl)
			(fn) (base, &st, 1, arg);
	}
	return 0;
}

static int rm_unwanted_fn(const char *file, const struct stat *st, int when, void *arg)
{
	dev_t dev = *(int *) arg;
	struct stat newst;

	if (when == 0) {
		if (st->st_dev != dev)
			return 0;
		return 1;
	}

	if (lstat(file, &newst)) {
		crit("unable to stat file, possible race condition");
		return 0;
	}

	if (newst.st_dev != dev) {
		crit("file %s has the wrong device, possible race condition",
			file);
		return 0;
	}

	if (S_ISDIR(newst.st_mode)) {
		debug("removing directory %s", file);
		if (rmdir(file)) {
			info("unable to remove directory %s", file);
			return 0;
		}
	} else if (S_ISREG(newst.st_mode)) {
		crit("attempting to remove files from a mounted directory");
		return 0;
	} else if (S_ISLNK(newst.st_mode)) {
		debug("removing symlink %s", file);
		unlink(file);
	}
	return 1;
}

void rm_unwanted(const char *path, int incl, dev_t dev)
{
	walk_tree(path, rm_unwanted_fn, incl, &dev);
}

struct counter_args {
	unsigned int count;
	dev_t dev;
};

static int counter_fn(const char *file, const struct stat *st, int when, void *arg)
{
	struct counter_args *counter = (struct counter_args *) arg;

	if (S_ISLNK(st->st_mode) || (S_ISDIR(st->st_mode) 
		&& st->st_dev != counter->dev)) {
		counter->count++;
		return 0;
	}

	return 1;
}

/* Count mounted filesystems and symlinks */
int count_mounts(struct autofs_point *ap, const char *path)
{
	struct counter_args counter;

	counter.count = 0;
	counter.dev = ap->dev;
	
	if (walk_tree(path, counter_fn, 0, &counter) == -1)
		return -1;

	return counter.count;
}

static void check_rm_dirs(struct autofs_point *ap, const char *path, int incl)
{
	if ((!ap->ghost) ||
	    (ap->state == ST_SHUTDOWN_PENDING ||
	     ap->state == ST_SHUTDOWN_FORCE ||
	     ap->state == ST_SHUTDOWN))
		rm_unwanted(path, incl, ap->dev);
	else if (ap->ghost && (ap->type == LKP_INDIRECT))
		rm_unwanted(path, 0, ap->dev);
}

/* umount all filesystems mounted under path.  If incl is true, then
   it also tries to umount path itself */
int umount_multi(struct autofs_point *ap, const char *path, int incl)
{
	int left;
	struct mnt_list *mnts = NULL;
	struct mnt_list *mptr;

	debug("path = %s incl = %d\n", path, incl);

	if (umount_offsets(ap, path)) {
		error("could not umount some offsets under %s", path);
		return 0;
	}

	debug("umounted offsets");

	mnts = get_mnt_list(_PATH_MOUNTED, path, incl);
	if (!mnts) {
		debug("no mounts found under %s", path);
		check_rm_dirs(ap, path, incl);
		return 0;
	}

	left = 0;
	for (mptr = mnts; mptr != NULL; mptr = mptr->next) {
		debug("unmounting dir = %s\n", mptr->path);
		if (umount_ent(ap, mptr->path, mptr->fs_type)) {
			left++;
		}
	}
	free_mnt_list(mnts);

	/* Delete detritus like unwanted mountpoints and symlinks */
	if (left == 0)
		check_rm_dirs(ap, path, incl);

	return left;
}

static int umount_all(struct autofs_point *ap, int force)
{
	int left;

	left = umount_multi(ap, ap->path, 0);
	if (force && left)
		warn("could not unmount %d dirs under %s", left, ap->path);

	return left;
}

int umount_autofs(struct autofs_point *ap, int force)
{
	int status = 0;

	if (ap->state == ST_INIT)
		return -1;

	if (ap->type == LKP_INDIRECT) {
		if (umount_all(ap, force) && !force)
			return -1;

		status = umount_autofs_indirect(ap);
	} else {
		status = umount_autofs_direct(ap);
	}

	if (ap->submount) {
		pthread_mutex_lock(&ap->parent->mounts_mutex);
		list_del_init(&ap->mounts);
		pthread_mutex_unlock(&ap->parent->mounts_mutex);
	}

	return status;
}

void nextstate(int statefd, enum states next)
{
	char buf[MAX_ERR_BUF];

	if (write(statefd, &next, sizeof(next)) != sizeof(next)) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error("write failed %s", estr);
	}
}

int send_ready(int ioctlfd, unsigned int wait_queue_token)
{
	char buf[MAX_ERR_BUF];

	if (wait_queue_token == 0)
		return 0;

	debug("token = %d", wait_queue_token);

	if (ioctl(ioctlfd, AUTOFS_IOC_READY, wait_queue_token) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error("AUTOFS_IOC_READY: error %s", estr);
		return 1;
	}
	return 0;
}

int send_fail(int ioctlfd, unsigned int wait_queue_token)
{
	char buf[MAX_ERR_BUF];

	if (wait_queue_token == 0)
		return 0;

	debug("token = %d\n", wait_queue_token);

	if (ioctl(ioctlfd, AUTOFS_IOC_FAIL, wait_queue_token) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error("AUTOFS_IOC_FAIL: error %s", estr);
		return 1;
	}
	return 0;
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

	status = pthread_cond_destroy(&ec->cond);
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
		error("failed to malloc expire condition struct");
		return EXP_ERROR;
	}

	status = pthread_mutex_init(&ec->mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_cond_init(&ec->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&ec->mutex);
	if (status) {
		error("failed to lock expire condition mutex");
		free(ec);
		return EXP_ERROR;
	}

	if (ap->type == LKP_INDIRECT)
		expire = expire_proc_indirect;
	else
		expire = expire_proc_direct;

	status = pthread_create(&thid, &detach_attr, expire, ec);
	if (status) {
		status = pthread_mutex_unlock(&ec->mutex);
		if (status)
			fatal(status);
		free(ec);
		error("thread create failed");
		return EXP_ERROR;
	}

	debug("exp_proc = %lu path %s", (unsigned long) thid, ap->path);

	ap->exp_thread = thid;
	ec->ap = ap;
	ec->when = now;
	ec->signaled = 0;

	pthread_cleanup_push(expire_cleanup_unlock, ec);

	while (!ec->signaled) {
		status = pthread_cond_wait(&ec->cond, &ec->mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return EXP_STARTED;
}

void do_readmap_cleanup_unlock(void *arg)
{
	struct readmap_cond *rc;
	int status;

	rc = (struct readmap_cond *) arg;

	status = pthread_mutex_unlock(&rc->mutex);
	if (status)
		error("failed to unlock expire cond mutex");

	return;
}

static void *do_readmap(void *arg)
{
	struct autofs_point *ap;
	struct mapent_cache *mc;
	struct readmap_cond *rc;
	int status;
	time_t now;

	rc = (struct readmap_cond *) arg;

	pthread_cleanup_push(do_readmap_cleanup_unlock, rc);

	while (!rc->signaled) {
		status = pthread_cond_wait(&rc->cond, &rc->mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	rc->signaled = 0;

	ap = rc->ap;
	mc = ap->mc;
	now = rc->now;

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

	debug("status %d", status);

	status = pthread_mutex_unlock(&rc->mutex);
	if (status)
		fatal(status);

	pthread_cleanup_pop(0);

	return NULL;
}

static int st_readmap(struct autofs_point *ap)
{
	pthread_t thid;
	int status;
	int now = time(NULL);

	debug("state = %d path = %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_READMAP;

	status = pthread_mutex_trylock(&ap->rc.mutex);
	if (status) {
		if (status == EBUSY)
			warn("read map already in progress for map %s",
			      ap->path);
		else
			fatal(status);
		return 0;
	}

	status = pthread_create(&thid, &detach_attr, do_readmap, &ap->rc);
	if (status) {
		error("read map thread create failed");
		status = pthread_mutex_unlock(&ap->rc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	ap->rc.thid = thid;
	ap->rc.ap = ap;
	ap->rc.now = now;
	ap->rc.signaled = 1;

	status = pthread_cond_signal(&ap->rc.cond);
	if (status) {
		error("failed to signal read map condition");
		status = pthread_mutex_unlock(&ap->rc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	status = pthread_mutex_unlock(&ap->rc.mutex);
	if (status) {
		error("failed to unlock read map condition mutex");
		return 0;
	}

	/*
	 * The goal is that map refresh should procceed in parallel
	 * instead of synchronously as they are in 4.1.
	 */
	ap->state = ST_READY;

	return 1;
}

static int st_prepare_shutdown(struct autofs_point *ap)
{
	int status;
	int exp;

	debug("state = %d path = %s", ap->state, ap->path);

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

	debug("state = %d path = %s", ap->state, ap->path);

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
	debug("state = %d path = %s", ap->state, ap->path);

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
	debug("state = %d path = %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_EXPIRE;

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

static int fullread(int fd, void *ptr, size_t len)
{
	char *buf = (char *) ptr;

	while (len > 0) {
		ssize_t r = read(fd, buf, len);

		if (r == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		buf += r;
		len -= r;
	}

	return len;
}

static int get_pkt(struct autofs_point *ap, union autofs_packet_union *pkt)
{
	struct pollfd fds[2];
	char buf[MAX_ERR_BUF];

	fds[0].fd = ap->pipefd;
	fds[0].events = POLLIN;
	fds[1].fd = ap->state_pipe[0];
	fds[1].events = POLLIN;

	for (;;) {
		if (poll(fds, 2, -1) == -1) {
			char *estr;
			if (errno == EINTR)
				continue;
			estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error("poll failed: %s", estr);
			return -1;
		}

		if (fds[1].revents & POLLIN) {
			enum states next_state;
			int status;
			int ret = 1;

			status = pthread_mutex_lock(&ap->state_mutex);
			if (status) {
				error("state mutex lock failed");
				continue;
			}

			if (fullread(ap->state_pipe[0], &next_state, sizeof(next_state)))
				continue;

			if (next_state != ap->state) {
				debug("state %d, next %d path %s",
					ap->state, next_state, ap->path);

				switch (next_state) {
				case ST_READY:
					ret = st_ready(ap);
					break;

				case ST_PRUNE:
					ret = st_prune(ap);
					break;

				case ST_EXPIRE:
					ret = st_expire(ap);
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

				case ST_READMAP:
					/* Syncronous reread of map */
					ret = st_readmap(ap);
					if (!ret)
						ret = st_prepare_shutdown(ap);
					break;

				default:
					error("bad next state %d", next_state);
				}
			}

			status = pthread_mutex_unlock(&ap->state_mutex);
			if (status)
				error("state mutex unlock failed");

			if (ap->state == ST_SHUTDOWN)
				return -1;
		}

		if (fds[0].revents & POLLIN) {
			int len = sizeof(pkt->v5_packet);
			return fullread(ap->pipefd, pkt, len);
		}
	}
}

int do_expire(struct autofs_point *ap, const char *name, int namelen)
{
	char buf[PATH_MAX + 1];
	int len, ret;

	if (*name != '/') {
		len = ncat_path(buf, sizeof(buf), ap->path, name, namelen);
	} else {
		len = snprintf(buf, PATH_MAX, "%s", name);
		if (len > PATH_MAX)
			len = 0;
	}

	if (!len) {
		crit("path to long for buffer");
		return 1;
	}

	msg("expiring path %s", buf);

	ret = umount_multi(ap, buf, 1);
	if (ret == 0) {
		msg("expired %s", buf);
	} else {
		error("error while expiring %s", buf);
	}
	return ret;
}

static int mount_autofs(struct autofs_point *ap)
{
	int status = 0;

	if (ap->type == LKP_DIRECT)
		status = mount_autofs_direct(ap);
	else
		status = mount_autofs_indirect(ap);

	if (status < 0)
		return -1;

	ap->state = ST_READY;

	return 0;
}

static int handle_packet(struct autofs_point *ap)
{
	union autofs_packet_union pkt;

	if (get_pkt(ap, &pkt))
		return -1;

	debug("type = %d\n", pkt.hdr.type);

	switch (pkt.hdr.type) {
	case autofs_ptype_missing_indirect:
		return handle_packet_missing_indirect(ap, &pkt.v5_packet);

	case autofs_ptype_missing_direct:
		return handle_packet_missing_direct(ap, &pkt.v5_packet);

	case autofs_ptype_expire_indirect:
		return handle_packet_expire_indirect(ap, &pkt.v5_packet);

	case autofs_ptype_expire_direct:
		return handle_packet_expire_direct(ap, &pkt.v5_packet);
	}
	error("unknown packet type %d\n", pkt.hdr.type);
	return -1;
}

static void become_daemon(struct autofs_point *ap)
{
	FILE *pidfp;
	char buf[MAX_ERR_BUF];
	pid_t pid;
	int nullfd;

	/* Don't BUSY any directories unnecessarily */
	chdir("/");

	/* Detach from foreground process */
	pid = fork();
	if (pid > 0) {
		exit(0);
	} else if (pid < 0) {
		fprintf(stderr, "%s: Could not detach process\n",
			program);
		exit(1);
	}

	/* Setup logging */
	log_to_syslog();

	/* Initialize global data */
	my_pid = getpid();

	/*
	 * Make our own process group for "magic" reason: processes that share
	 * our pgrp see the raw filesystem behind the magic.
	 *
	 * IMK: we now use setsid instead of setpgrp so that we also disassociate
	 * ouselves from the controling tty. This ensures we don't get unexpected
	 * signals. This call also sets us as the process group leader.
	 */
	if ((setsid() == -1)) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit("setsid: %s", estr);
		exit(1);
	}
	my_pgrp = getpgrp();

	/* Redirect all our file descriptors to /dev/null */
	if ((nullfd = open("/dev/null", O_RDWR)) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit("cannot open /dev/null: %s", estr);
		exit(1);
	}

	if (dup2(nullfd, STDIN_FILENO) < 0 ||
	    dup2(nullfd, STDOUT_FILENO) < 0 ||
	    dup2(nullfd, STDERR_FILENO) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit("redirecting file descriptors failed: %s", estr);
		exit(1);
	}
	close(nullfd);

	/* Write pid file if requested */
	if (pid_file) {
		if ((pidfp = fopen(pid_file, "wt"))) {
			fprintf(pidfp, "%lu\n", (unsigned long) my_pid);
			fclose(pidfp);
		} else {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn("failed to write pid file %s: %s", pid_file, estr);
			pid_file = NULL;
		}
	}
}

static void cleanup(struct autofs_point *ap)
{
	char buf[MAX_ERR_BUF];

	if (pid_file) {
		unlink(pid_file);
		pid_file = NULL;
	}

	closelog();

	if ((!ap->ghost || !ap->submount) &&
			(ap->path[1] != '-') && ap->dir_created) {
		if (rmdir(ap->path) == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn("failed to remove dir %s: %s", ap->path, estr);
		}
	}
	free_autofs_point(ap);
}

static unsigned long getnumopt(char *str, char option)
{
	unsigned long val;
	char *end;

	val = strtoul(str, &end, 0);
	if (!*str || *end) {
		fprintf(stderr,
			"%s: option -%c requires a numeric argument, got %s\n",
			program, option, str);
		exit(1);
	}
	return val;
}

static void usage(void)
{
	fprintf(stderr, "Usage: %s [options] path map_type [args...]\n", program);
}

static void notify_submounts(struct autofs_point *ap, enum states state)
{
	struct list_head *head;
	struct list_head *p;
	struct autofs_point *this;
	int status;

	status = pthread_mutex_lock(&ap->mounts_mutex);
	if (status)
		fatal(status);

	head = &ap->submounts;
	p = head->next;
	while (p != head) {
		unsigned int empty;

		this = list_entry(p, struct autofs_point, mounts);
		p = p->next;

		empty = list_empty(&this->submounts);

		pthread_mutex_unlock(&ap->mounts_mutex);

		status = pthread_mutex_lock(&this->state_mutex);
		if (status)
			fatal(status);

		if (!empty)
			notify_submounts(this, state);

		debug("notify %s state %d", this->path, state);
		nextstate(this->state_pipe[1], state);

		status = pthread_mutex_unlock(&this->state_mutex);
		if (status)
			fatal(status);

		pthread_mutex_lock(&ap->mounts_mutex);
	}

	status = pthread_mutex_unlock(&ap->mounts_mutex);
	if (status)
		fatal(status);

	return;
}

/* Deal with all the signal-driven events in the state machine */
static void *statemachine(void *arg)
{
	struct autofs_point *ap = NULL;
	struct list_head *p = NULL;
	enum states next = ST_INVAL;
	sigset_t sigset;
	int sig, status;
	int state_pipe;

	sigfillset(&sigset);
	sigdelset(&sigset, SIGCHLD);
	sigdelset(&sigset, SIGCONT);

	while (1) {
		sigwait(&sigset, &sig);

		status = pthread_mutex_lock(&master_mutex);
		if (status)
			fatal(status);

		if (list_empty(&mounts)) {
			status = pthread_mutex_unlock(&master_mutex);
			if (status)
				fatal(status);
			return NULL;
		}

		list_for_each(p, &mounts) {
			ap = list_entry(p, struct autofs_point, mounts);

			status = pthread_mutex_lock(&ap->state_mutex);
			if (status)
				fatal(status);

			state_pipe = ap->state_pipe[1];

			switch (sig) {
			case SIGTERM:
				if (ap->state != ST_SHUTDOWN) {
					next = ST_SHUTDOWN_PENDING;
					notify_submounts(ap, next);
					nextstate(state_pipe, next);
				}
/*
				} else if (ap->state == ST_SHUTDOWN) {
					if (ap->submount)
						break;
					debug("case SIGTERM exit");
					status = pthread_mutex_unlock(&ap->state_mutex);
					if (status)
						error("state mutex unlock failed");
					return NULL;
				}
*/
				break;

			case SIGUSR2:
				if (ap->state != ST_SHUTDOWN) {
					next = ST_SHUTDOWN_FORCE;
					notify_submounts(ap, next);
					nextstate(state_pipe, next);
				}
/*
				} else if (ap->state == ST_SHUTDOWN) {
					if (ap->submount)
						break;
					debug("case SIGUSR2 exit");
					status = pthread_mutex_unlock(&ap->state_mutex);
					if (status)
						error("state mutex unlock failed");
					return NULL;
				}
*/
				break;

			case SIGUSR1:
				assert(ap->state == ST_READY);
				next = ST_PRUNE;
				notify_submounts(ap, next);
				nextstate(state_pipe, next);
				break;

			case SIGHUP:
				assert(ap->state == ST_READY);
				next = ST_READMAP;
				notify_submounts(ap, next);
				nextstate(state_pipe, next);
				break;

			default:
				error("got unexpected signal %d!", sig);
				continue;
			}

			debug("sig %d switching %s from %d to %d",
				sig, ap->path, ap->state, next);

			status = pthread_mutex_unlock(&ap->state_mutex);
			if (status)
				fatal(status);
		}

		status = pthread_mutex_unlock(&master_mutex);
		if (status)
			fatal(status);
	}
}

static void return_start_status(struct startup_cond *sc, unsigned int status)
{
	sc->done = 1;
	sc->status = status;

	/*
	 * Startup condition mutex must be locked during 
	 * the startup process.
	 */
	status = pthread_cond_signal(&sc->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&sc->mutex);
	if (status)
		fatal(status);
}

void *handle_mounts(void *arg)
{
	struct autofs_point *ap = (struct autofs_point *) arg;
	int status = 0;

	status = pthread_mutex_lock(&ap->state_mutex);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&sc.mutex);
	if (status) {
		crit("failed to lock startup condition mutex!");
		fatal(status);
	}

	if (mount_autofs(ap) < 0) {
		crit("%s: mount failed!", ap->path);
		umount_autofs(ap, 1);
		return_start_status(&sc, 1);
		status = pthread_mutex_unlock(&ap->state_mutex);
		if (status)
			fatal(status);
		cleanup(ap);
		pthread_exit(NULL);
	}

	/* If we're a submount we're owned by someone else */
	if (!ap->submount)
		list_add(&ap->mounts, &mounts);

	if (ap->ghost && ap->type != LKP_DIRECT)
		msg("ghosting enabled");

	return_start_status(&sc, 0);

	/* We often start several automounters at the same time.  Add some
	   randomness so we don't all expire at the same time. */
	if (ap->exp_timeout)
		alarm_add(ap, ap->exp_runfreq + ap->thid % ap->exp_runfreq);

	status = pthread_mutex_unlock(&ap->state_mutex);
	if (status)
		fatal(status);

	while (ap->state != ST_SHUTDOWN) {
		if (handle_packet(ap)) {
			int ret;

			status = pthread_mutex_lock(&ap->state_mutex);
			if (status)
				fatal(status);

			/*
			 * For a direct mount map all mounts have already gone
			 * by the time we get here.
			 */
			if (ap->type == LKP_DIRECT) {
				status = 1;
				status = pthread_mutex_unlock(&ap->state_mutex);
				if (status)
					fatal(status);
				break;
			}

			ret = ioctl(ap->ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
			/*
			 * If the ioctl fails assume the kernel doesn't have
			 * AUTOFS_IOC_ASKUMOUNT and just continue.
			 */

			if (ret == -1) {
				status = pthread_mutex_unlock(&ap->state_mutex);
				if (status)
					fatal(status);
				break;
			}

			/* OK to exit */
			if (status) {
				status = pthread_mutex_unlock(&ap->state_mutex);
				if (status)
					fatal(status);
				break;
			}

			if (ap->state == ST_SHUTDOWN) {
				status = pthread_mutex_unlock(&ap->state_mutex);
				if (status)
					fatal(status);
				break;
			}

			/* Failed shutdown returns to ready */
			warn("can't shutdown: filesystem %s still busy",
					ap->path);
			alarm_add(ap, ap->exp_runfreq);
/*			if (ap->submount) {
				status = pthread_mutex_unlock(&ap->parent->state_mutex);
				if (status)
					fatal(status);
			} */
			ap->state = ST_READY;

			status = pthread_mutex_unlock(&ap->state_mutex);
			if (status)
				fatal(status);
		}
	}

	/* Close down */
	umount_autofs(ap, 1);

	msg("shut down, path = %s", ap->path);

	if (ap->submount) {
		/*
		 * We're a submount, possibly holding the parent state
		 * mutex so if we own it we need to unlock it so the
		 * parent can continue.
		 */
		status = pthread_mutex_trylock(&ap->parent->state_mutex);
		if (status && status != EBUSY)
			fatal(status);

		status = pthread_mutex_unlock(&ap->parent->state_mutex);
		if (status && status != EPERM)
			fatal(status);
	} else {
		status = pthread_mutex_lock(&master_mutex);
		if (status)
			fatal(status);

		list_del(&ap->mounts);

		/* If we are the last tell the state machine to shutdown */
		if (list_empty(&mounts))
			kill(getpid(), SIGUSR2);

		status = pthread_mutex_unlock(&master_mutex);
		if (status)
			fatal(status);
	}

	cleanup(ap);

	return NULL;
}

struct autofs_point *
new_autofs_point(char *path, char *type, char *fmt, time_t timeout,
		 unsigned ghost, int argc, const char **argv,
		 int submount) 
{
	struct autofs_point *ap;
	int status;

	ap = malloc(sizeof(struct autofs_point));
	if (!ap)
		return NULL;

	memset(ap, 0, sizeof(struct autofs_point));

	ap->state = ST_INIT;

	ap->mc = cache_init(ap);
	if (!ap->mc) {
		free(ap);
		return NULL;
	}

	ap->path = strdup(path);
	if (!ap->path) {
		free(ap->mc);
		free(ap);
		return NULL;
	}

	if (type) {
		ap->maptype = strdup(type);
		if (!ap->maptype) {
			free(ap->path);
			free(ap->mc);
			free(ap);
			return NULL;
		}
	} else
		ap->maptype = type;

	if (fmt) {
		ap->mapfmt = strdup(fmt);
		if (!ap->mapfmt) {
			free(ap->maptype);
			free(ap->path);
			free(ap->mc);
			free(ap);
			return NULL;
		}
	} else
		ap->mapfmt = fmt;

	ap->mapargc = argc;
	ap->mapargv = copy_argv(argc, argv);
	if (!ap->mapargv) {
		free(ap->mapfmt);
		free(ap->maptype);
		free(ap->path);
		free(ap->mc);
		free(ap);
		return NULL;
	}

	ap->exp_timeout = timeout;
	ap->exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
	ap->ghost = ghost;

	if (path[1] == '-')
		ap->type = LKP_DIRECT;
	else
		ap->type = LKP_INDIRECT;

	ap->dir_created = 0;

	ap->parent = NULL;
	ap->submount = submount;
	INIT_LIST_HEAD(&ap->mounts);
	INIT_LIST_HEAD(&ap->submounts);

	status = pthread_mutex_init(&ap->state_mutex, NULL);
	if (status) {
		free(ap->mapfmt);
		free(ap->maptype);
		free(ap->path);
		free(ap->mc);
		free(ap);
		return NULL;
	}

	status = pthread_mutex_init(&ap->mounts_mutex, NULL);
	if (status) {
		status = pthread_mutex_destroy(&ap->state_mutex);
		if (status)
			fatal(status);
		free(ap->mapfmt);
		free(ap->maptype);
		free(ap->path);
		free(ap->mc);
		free(ap);
		return NULL;
	}

	ap->rc.signaled = 0;

	status = pthread_mutex_init(&ap->rc.mutex, NULL);
	if (status) {
		status = pthread_mutex_destroy(&ap->mounts_mutex);
		if (status)
			fatal(status);
		status = pthread_mutex_destroy(&ap->state_mutex);
		if (status)
			fatal(status);
		free(ap->mapfmt);
		free(ap->maptype);
		free(ap->path);
		free(ap->mc);
		free(ap);
		return NULL;
	}

	status = pthread_cond_init(&ap->rc.cond, NULL);
	if (status) {
		status = pthread_mutex_destroy(&ap->rc.mutex);
		if (status)
			fatal(status);
		status = pthread_mutex_destroy(&ap->mounts_mutex);
		if (status)
			fatal(status);
		status = pthread_mutex_destroy(&ap->state_mutex);
		if (status)
			fatal(status);
		free(ap->mapfmt);
		free(ap->maptype);
		free(ap->path);
		free(ap->mc);
		free(ap);
		return NULL;
	}

	return ap;
}

void free_autofs_point(struct autofs_point *ap)
{
	int status;

	if (ap->submount) {
		pthread_mutex_lock(&ap->parent->mounts_mutex);
		if (!list_empty(&ap->mounts))
			list_del(&ap->mounts);
		pthread_mutex_unlock(&ap->parent->mounts_mutex);
	}
	cache_release(ap);
	free(ap->path);
	if (ap->maptype)
		free(ap->maptype);
	if (ap->mapfmt)
		free(ap->mapfmt);
	free_argv(ap->mapargc, ap->mapargv);
	status = pthread_mutex_destroy(&ap->state_mutex);
	if (status)
		fatal(status);
	status = pthread_mutex_destroy(&ap->mounts_mutex);
	if (status)
		fatal(status);
	status = pthread_mutex_destroy(&ap->rc.mutex);
	if (status)
		fatal(status);
	status = pthread_cond_destroy(&ap->rc.mutex);
	if (status)
		fatal(status);
	free(ap);
}

static void key_thread_stdenv_vars_destroy(void *arg)
{
	struct thread_stdenv_vars *tsv;

	tsv = (struct thread_stdenv_vars *) arg;
	if (tsv->user)
		free(tsv->user);
	if (tsv->group)
		free(tsv->group);
	if (tsv->home)
		free(tsv->home);
	free(tsv);
	return;
}

int main(int argc, char *argv[])
{
	pthread_t thid;
	struct autofs_point *ap;
	char *path, *map, *mapfmt = NULL;
	const char **mapargv;
	int mapargc, opt, res, status;
	unsigned ghost;
	time_t timeout;
	sigset_t allsigs;
	struct rlimit rlim;
	static const struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"pid-file", 1, 0, 'p'},
		{"timeout", 1, 0, 't'},
		{"verbose", 0, 0, 'v'},
		{"debug", 0, 0, 'd'},
		{"version", 0, 0, 'V'},
		{"ghost", 0, 0, 'g'},
		{0, 0, 0, 0}
	};

	program = argv[0];
	timeout = DEFAULT_TIMEOUT;
	ghost = DEFAULT_GHOST_MODE;

	if (pthread_attr_init(&detach_attr)) {
		fprintf(stderr, "%s: failed to init thread attribute struct!",
			program);
		exit(1);
	}

	if (pthread_attr_setdetachstate(
			&detach_attr, PTHREAD_CREATE_DETACHED)) {
		fprintf(stderr, "%s: failed to set detached thread attribute!",
			program);
		exit(1);
	}

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "+hp:t:vdVg", long_options, NULL)) != EOF) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);

		case 'p':
			pid_file = optarg;
			break;

		case 't':
			timeout = getnumopt(optarg, opt);
			break;

		case 'v':
			set_log_verbose();
			break;

		case 'd':
			set_log_debug();
			break;

		case 'V':
			printf("Linux automount version %s\n", version);
			exit(0);

		case 'g':
			ghost = LKP_GHOST;
			break;

		case '?':
		case ':':
			printf("%s: Ambiguous or unknown options\n", program);
			exit(1);
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "%s: this program must be run by root.\n",
			program);
		exit(1);
	}

	/* Remove the options */
	argv += optind;
	argc -= optind;

	if (argc < 2) {
		usage();
		exit(1);
	}

	/* Must be an absolute pathname */
	if (argv[0][0] != '/') {
		fprintf(stderr, "%s: invalid autofs mount point %s",
			program, argv[0]);
		exit(1);
	}

	path = argv[0];

	if (argv[1][0] == '\0')
		map = NULL;
	else
		map = argv[1];

	mapargv = (const char **) &argv[2];
	mapargc = argc - 2;

	if (map && (mapfmt = strchr(map, ',')))
		*(mapfmt++) = '\0';

	ap = new_autofs_point(path, map, mapfmt,
			timeout, ghost, mapargc, mapargv, 0); 

	become_daemon(ap);

	rlim.rlim_cur = MAX_OPEN_FILES;
	rlim.rlim_max = MAX_OPEN_FILES;
	res = setrlimit(RLIMIT_NOFILE, &rlim);
	if (res)
		warn("can't increase open file limit - continuing");

	msg("Starting automounter version %s, path = %s, "
	       "maptype = %s, mapname = %s", version, path, map,
	       (mapargc < 1) ? "none" : mapargv[0]);

#ifdef DEBUG
	if (mapargc) {
		int i;
		debug("Map argc = %d", mapargc);
		for (i = 0; i < mapargc; i++)
			debug("Map argv[%d] = %s", i, mapargv[i]);
	}
#endif

	status = pthread_key_create(&key_thread_stdenv_vars,
				key_thread_stdenv_vars_destroy);
	if (status) {
		crit("failed to create thread data key for std env vars!");
		cleanup(ap);
		pthread_exit(NULL);
	}

	if (!alarm_start_handler()) {
		crit("failed to create alarm handler thread!");
		cleanup(ap);
		pthread_exit(NULL);
	}

	sigfillset(&allsigs);
	pthread_sigmask(SIG_BLOCK, &allsigs, NULL);

	if (!sigchld_start_handler()) {
		crit("failed to create SIGCHLD handler thread!");
		cleanup(ap);
		pthread_exit(NULL);
	}

	status = pthread_mutex_lock(&sc.mutex);
	if (status) {
		crit("failed to lock startup condition mutex!");
		cleanup(ap);
		pthread_exit(NULL);
	}

	sc.done = 0;
	sc.status = 0;

	path = strdup(ap->path);
	if (!path) {
		error("malloc failure");
		pthread_mutex_unlock(&sc.mutex);
		cleanup(ap);
		pthread_exit(NULL);
	}

	if (pthread_create(&thid, &detach_attr, handle_mounts, ap)) {
		crit("failed to create mount handler thread for %s", path);
		pthread_mutex_unlock(&sc.mutex);
		cleanup(ap);
		pthread_exit(NULL);
	}
	ap->thid = thid;

	while (!sc.done) {
		status = pthread_cond_wait(&sc.cond, &sc.mutex);
		if (status) {
			crit("failed waiting or startup of mount %s", path);
		}
	}

	if (sc.status) {
		error("failed to startup mount %s", path);
		free(path);
		pthread_mutex_unlock(&sc.mutex);
		cleanup(ap);
		pthread_exit(NULL);
	}

	free(path);

	status = pthread_mutex_unlock(&sc.mutex);
	if (status) {
		crit("failed to unlock startup condition mutex!");
		fatal(status);
	}

	statemachine(NULL);

	exit(0);
}
