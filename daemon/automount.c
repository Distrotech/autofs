#ident "$Id: automount.c,v 1.53 2006/03/03 17:19:29 raven Exp $"
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

/* Serialize state transitions */
pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;

struct expire_cond ec = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, NULL, 0, 0};

struct readmap_cond rc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, 0, 0};

struct autofs_point ap;

/* re-entrant syslog default context data */
#define AUTOFS_SYSLOG_CONTEXT {-1, 0, 0, LOG_PID, (const char *)0, LOG_DAEMON, 0xff};

#define DEFAULT_GHOST_MODE	0
#define MAX_OPEN_FILES		10240

int do_mount_autofs_direct(struct autofs_point *ap, struct mapent_cache *me, int now);
static int umount_all(struct autofs_point *ap, int force);

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

int umount_offsets(const char *base)
{
	char path[PATH_MAX + 1];
	char *offset = path;
	struct list_head head, *pos;
	char key[PATH_MAX + 1];
	struct mapent_cache *me;
	struct mnt_list *mnts, *next;
	int ret = 0, status;

	INIT_LIST_HEAD(&head);

	pthread_cleanup_push(cache_lock_cleanup, NULL);
	cache_readlock();
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
		me = cache_lookup(key);
		if (!me) {
			debug("offset key %s not found", key);
			continue;
		}

		/*
		 * We're in trouble if umounting the triggers fails.
		 * It should always succeed due to the expire design.
		 */
		if (umount_autofs_offset(me)) {
			crit("failed to umount offset %s", me->key);
			ret++;
		}
	}
	free_mnt_list(mnts);
	cache_unlock();
	pthread_cleanup_pop(0);

	cache_writelock();
	/*
	 * If it's a direct mount it's base is the key otherwise
	 * the last path componemt is the indirect entry key.
	 */
	me = cache_lookup(base);
	if (!me) {
		char *ind_key = strrchr(base, '/');

		if (ind_key) {
			ind_key++;
			me = cache_lookup(ind_key);
		}
	}

	if (!ret && me && me->multi == me) {
		status = cache_delete_offset_list(me->key);
		if (status != CHE_OK)
			warn("couldn't delete offset list");
	}
	cache_unlock();

	return ret;
}

static int umount_ent(struct autofs_point *ap, const char *path, const char *type)
{
	struct stat st;
	int sav_errno;
	int is_smbfs = (strcmp(type, "smbfs") == 0);
	int status;
	int rv = 1;

	status = lstat(path, &st);
	sav_errno = errno;

	/* EIO appears to correspond to an smb mount that has gone away */
	if (!status ||
	    (is_smbfs && (sav_errno == EIO || sav_errno == EBADSLT))) {
		int umount_ok = 0;

		if (!status && (S_ISDIR(st.st_mode) && (st.st_dev != ap->dev)))
			umount_ok = 1;

		if (umount_ok || is_smbfs) {
			rv = spawnll(LOG_DEBUG, 
				    PATH_UMOUNT, PATH_UMOUNT, path, NULL);
		}
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

static void check_rm_dirs(struct autofs_point *ap, const char *path, int incl)
{
	if ((!ap->ghost) ||
	    (ap->state == ST_SHUTDOWN_PENDING ||
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

	debug("path=%s incl=%d\n", path, incl);

	if (umount_offsets(path)) {
		error("could not umount some offsets under %s", path);
		return 0;
	}

	mnts = get_mnt_list(_PATH_MOUNTED, path, incl);
	if (!mnts) {
		debug("no mounts found under %s", path);
		check_rm_dirs(ap, path, incl);
		return 0;
	}

	left = 0;
	for (mptr = mnts; mptr != NULL; mptr = mptr->next) {
		debug("unmounting dir=%s\n", mptr->path);
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

	return status;
}

static void nextstate(int statefd, enum states next)
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

	debug("token=%d", wait_queue_token);

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

	debug("token=%d\n", wait_queue_token);

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

	statefd = ap->state_pipe[1];

	debug("got thid %lu, stat %d\n", (unsigned long) thid, success);

	status = pthread_mutex_lock(&state_mutex);
	if (status) {
		error("state mutex lock failed");
		return;
	}

	/* Check to see if expire process finished */
	if (thid == ap->exp_thread) {
		ap->exp_thread = 0;

		switch (ap->state) {
		case ST_EXPIRE:
			alarm(ap->exp_runfreq);
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
			warn("can't shutdown: filesystem %s still busy",
			     ap->path);
			alarm(ap->exp_runfreq);
			next = ST_READY;
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

	status = pthread_mutex_unlock(&state_mutex);
	if (status)
		error("state mutex unlock failed");
}

static int st_ready(struct autofs_point *ap)
{
	debug("st_ready(): state = %d", ap->state);

	ap->state = ST_READY;

	return 0;
}

static int counter_fn(const char *file, const struct stat *st, int when, void *arg)
{
	int *countp = (int *) arg;

	if (S_ISLNK(st->st_mode) || (S_ISDIR(st->st_mode) 
		&& st->st_dev != ap.dev)) {
		(*countp)++;
		return 0;
	}

	return 1;
}

/* Count mounted filesystems and symlinks */
int count_mounts(const char *path)
{
	int count = 0;

	if (walk_tree(path, counter_fn, 0, &count) == -1)
		return -1;

	return count;
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
		error("failed to lock expire condition mutex");

	return;
}

static enum expire expire_proc(struct autofs_point *ap, int now)
{
	pthread_t thid;
	void *(*expire)(void *);
	int status;

	assert(ap->exp_thread == 0);

	status = pthread_mutex_lock(&ec.mutex);
	if (status) {
		error("failed to lock expire condition mutex");
		return EXP_ERROR;
	}

	if (ap->type == LKP_INDIRECT)
		expire = expire_proc_indirect;
	else
		expire = expire_proc_direct;

	status = pthread_create(&thid, &detach_attr, expire, NULL);
	if (status) {
		status = pthread_mutex_unlock(&ec.mutex);
		if (status)
			fatal(status);
		error("thread create failed");
		return EXP_ERROR;
	}

	debug("exp_proc = %lu", (unsigned long) thid);

	ap->exp_thread = thid;
	ec.ap = ap;
	ec.when = now;
	ec.signaled = 1;

	status = pthread_cond_signal(&ec.cond);
	if (status) {
		status = pthread_mutex_unlock(&ec.mutex);
		if (status)
			fatal(status);
		error("failed to signal expire condition");
		return EXP_ERROR;
	}

	status = pthread_mutex_unlock(&ec.mutex);
	if (status) {
		error("failed to unlock expire condition mutex");
		return EXP_ERROR;
	}

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
	int status;
	time_t now;

	pthread_cleanup_push(do_readmap_cleanup_unlock, &rc);

	while (!rc.signaled) {
		status = pthread_cond_wait(&rc.cond, &rc.mutex);
		if (status)
			error("expire condition wait failed");
		pthread_exit(NULL);
	}

	rc.signaled = 0;

	ap = rc.ap;
	now = rc.now;

	status = lookup_nss_read_map(ap, now);
	if (!status)
		pthread_exit(NULL);

	lookup_prune_cache(ap, now);

	pthread_cleanup_push(cache_lock_cleanup, NULL);
	cache_readlock();
	if (ap->type == LKP_INDIRECT)
		status = lookup_ghost(ap);
	else
		status = lookup_enumerate(ap, do_mount_autofs_direct, now);
	cache_unlock();
	pthread_cleanup_pop(0);

	debug("status %d", status);

	status = pthread_mutex_unlock(&rc.mutex);
	if (status)
		error("failed to unlock expire cond mutex");

	pthread_cleanup_pop(0);

	return NULL;
}

static int st_readmap(struct autofs_point *ap)
{
	pthread_t thid;
	int status;
	int now = time(NULL);

	assert(ap->state == ST_READY);
	ap->state = ST_READMAP;

	status = pthread_mutex_trylock(&rc.mutex);
	if (status) {
		if (status == EBUSY)
			warn("read map already in progress");
		else
			error("failed to lock read map condition mutex");
		return 0;
	}

	status = pthread_create(&thid, &detach_attr, do_readmap, NULL);
	if (status) {
		error("read map thread create failed");
		status = pthread_mutex_unlock(&rc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	rc.thid = thid;
	rc.ap = ap;
	rc.now = now;
	rc.signaled = 1;

	status = pthread_cond_signal(&rc.cond);
	if (status) {
		status = pthread_mutex_unlock(&rc.mutex);
		if (status)
			fatal(status);
		error("failed to signal read map condition");
		return 0;
	}

	status = pthread_mutex_unlock(&rc.mutex);
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
	int exp;

	debug("state = %d\n", ap->state);

	assert(ap->state == ST_READY || ap->state == ST_EXPIRE);
	ap->state = ST_SHUTDOWN_PENDING;

	/* Turn off timeouts */
	alarm(0);

	/* Where're the boss, tell everyone to finish up */
	if (getpid() == getpgrp()) 
		signal_children(SIGUSR2);

	/* Unmount everything */
	exp = expire_proc(ap, 1);

	debug("expire returns %d\n", exp);

	switch (exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		ap->state = ST_READY;
		alarm(ap->exp_runfreq);
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
	debug("state = %d\n", ap->state);

	assert(ap->state == ST_READY);
	ap->state = ST_PRUNE;

	/* We're the boss, pass on the prune event */
	if (getpid() == getpgrp()) 
		signal_children(SIGUSR1);

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
	debug("state = %d\n", ap->state);

	assert(ap->state == ST_READY);
	ap->state = ST_EXPIRE;

	switch (expire_proc(ap, 0)) {
	case EXP_DONE:
		if (ap->submount)
			return st_prepare_shutdown(ap);
		/* FALLTHROUGH */

	case EXP_ERROR:
	case EXP_PARTIAL:
		ap->state = ST_READY;
		alarm(ap->exp_runfreq);
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

			if (fullread(ap->state_pipe[0], &next_state, sizeof(next_state)))
				continue;

			status = pthread_mutex_lock(&state_mutex);
			if (status) {
				error("state mutex lock failed");
				continue;
			}

			if (next_state != ap->state) {
				debug("state %d, next %d",
					ap->state, next_state);

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

				case ST_SHUTDOWN:
					assert(ap->state == ST_SHUTDOWN ||
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

			status = pthread_mutex_unlock(&state_mutex);
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

static int mount_autofs(struct autofs_point *ap, char *path)
{
	int status = 0;

	if (!strcmp(path, "/-")) {
		ap->type = LKP_DIRECT;
		status = mount_autofs_direct(ap, path);
	} else {
		ap->type = LKP_INDIRECT;
		status = mount_autofs_indirect(ap, path);
	}

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
	if (!ap->submount) {
		pid = fork();
		if (pid > 0) {
			exit(0);
		} else if (pid < 0) {
			fprintf(stderr, "%s: Could not detach process\n",
				program);
			exit(1);
		}
	}

	/* Setup logging */
	log_to_syslog();

	/* Initialize global data */
	my_pid = getpid();

	/*
	 * Make our own process group for "magic" reason: processes that share
	 * our pgrp see the raw filesystem behind the magic.  So if we are a 
	 * submount, don't change -- otherwise we won't be able to actually
	 * perform the mount.  A pgrp is also useful for controlling all the
	 * child processes we generate. 
	 *
	 * IMK: we now use setsid instead of setpgrp so that we also disassociate
	 * ouselves from the controling tty. This ensures we don't get unexpected
	 * signals. This call also sets us as the process group leader.
	 */
	if (!ap->submount && (setsid() == -1)) {
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

/*
 * cleanup_exit() is valid to call once we have daemonized
 */

void cleanup_exit(struct autofs_point *ap, int exit_code)
{
	char buf[MAX_ERR_BUF];

	if (pid_file) {
		unlink(pid_file);
		pid_file = NULL;
	}

	closelog();

	if ((!ap->ghost || !ap->submount) &&
			(ap->path[1] != '-') && ap->dir_created)
		if (rmdir(ap->path) == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn("failed to remove dir %s: %s", ap->path, estr);
		}

	free(ap->path);
	cache_release();
	exit(exit_code);
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

/* Deal with all the signal-driven events in the state machine */
static void *statemachine(void *dummy)
{
	enum states next = ST_INVAL;
	sigset_t sigset;
	int sig, status;
	int state_pipe;

	sigfillset(&sigset);
	sigdelset(&sigset, SIGCHLD);
	sigdelset(&sigset, SIGCONT);

	while (1) {
		sigwait(&sigset, &sig);

		status = pthread_mutex_lock(&state_mutex);
		if (status) {
			error("state mutex lock failed");
			goto done;
		}

		next = ap.state;
		state_pipe = ap.state_pipe[1];

		switch (sig) {
		case SIGTERM:
		case SIGUSR2:
			if (ap.state != ST_SHUTDOWN)
				nextstate(state_pipe, next = ST_SHUTDOWN_PENDING);
			break;

		case SIGUSR1:
			assert(ap.state == ST_READY);
			nextstate(state_pipe, next = ST_PRUNE);
			break;

		case SIGALRM:
			assert(ap.state == ST_READY);
			nextstate(state_pipe, next = ST_EXPIRE);
			break;

		case SIGHUP:
			assert(ap.state == ST_READY);
			nextstate(state_pipe, next = ST_READMAP);
			break;

		default:
			error("got unexpected signal %d!", sig);
			continue;
		}
done:
		debug("sig %d switching from %d to %d",
			sig, ap.state, next);

		status = pthread_mutex_unlock(&state_mutex);
		if (status)
			error("state mutex unlock failed");
	}
}

int handle_mounts(struct autofs_point *ap, char *path)
{
	struct expire_args *ex;
	int status = 0;

	if (mount_autofs(ap, path) < 0) {
		crit("%s: mount failed!", path);
		umount_autofs(ap, 1);
		cleanup_exit(ap, 1);
	}

	if (ap->ghost && ap->type != LKP_DIRECT)
		msg("ghosting enabled");

	/* Initialization successful.  If we're a submount, send outselves
	   SIGSTOP to let our parent know that we have grown up and don't
	   need supervision anymore. */
	if (ap->submount)
		kill(my_pid, SIGSTOP);

	/* We often start several automounters at the same time.  Add some
	   randomness so we don't all expire at the same time. */
	if (ap->exp_timeout)
		alarm(ap->exp_runfreq + my_pid % ap->exp_runfreq);

	while (ap->state != ST_SHUTDOWN) {
		if (handle_packet(ap)) {
			int ret;

			status = pthread_mutex_lock(&state_mutex);
			if (status)
				fatal(status);

			/*
			 * For a direct mount map all mounts have already gone
			 * by the time we get here.
			 */
			if (ap->type == LKP_DIRECT) {
				status = 1;
				status = pthread_mutex_unlock(&state_mutex);
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
				status = pthread_mutex_unlock(&state_mutex);
				if (status)
					fatal(status);
				break;
			}

			/* OK to exit */
			if (status) {
				status = pthread_mutex_unlock(&state_mutex);
				if (status)
					fatal(status);
				break;
			}

			/* Failed shutdown returns to ready */
			warn("can't shutdown: filesystem %s still busy",
					ap->path);
			alarm(ap->exp_runfreq);
			ap->state = ST_READY;

			status = pthread_mutex_unlock(&state_mutex);
			if (status)
				fatal(status);
		}
	}


	/* Mop up remaining kids - expire_cleanup frees ex */
	ex = malloc(sizeof(struct expire_args));
	ex->ap = ap;
	ex->status = status;
	expire_cleanup(ex);

	/* Close down */
	umount_autofs(ap, 1);
	msg("shut down, path = %s", ap->path);
	cleanup_exit(ap, 0);

	return 0;
}

int main(int argc, char *argv[])
{
	char *path, *map, *mapfmt = NULL;
	const char **mapargv;
	int mapargc, opt, res;
	pthread_t thid;
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
		{"submount", 0, &ap.submount, 1},
		{0, 0, 0, 0}
	};

	program = argv[0];

	/* Initialize ap so we can test for null */
	memset(&ap, 0, sizeof ap);

	ap.exp_timeout = DEFAULT_TIMEOUT;
	ap.ghost = DEFAULT_GHOST_MODE;
	ap.type = LKP_INDIRECT;
	ap.dir_created = 0; /* We haven't created the main directory yet */
	ap.submount = 0;
	cache_init();

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
			ap.exp_timeout = getnumopt(optarg, opt);
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
			ap.ghost = LKP_GHOST;
			break;

		case '?':
		case ':':
			printf("%s: Ambiguous or unknown options\n", program);
			exit(1);
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "%s: This program must be run by root.\n",
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

	become_daemon(&ap);

	path = argv[0];
	if (argv[1][0] == '\0')
		map = NULL;
	else
		map = argv[1];
	mapargv = (const char **) &argv[2];
	mapargc = argc - 2;

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

	if (pthread_attr_init(&detach_attr)) {
		crit("failed to init thread attribute struct!");
		cleanup_exit(&ap, 1);
	}

	if (pthread_attr_setdetachstate(
			&detach_attr, PTHREAD_CREATE_DETACHED)) {
		crit("failed to set detached thread attribute!");
		cleanup_exit(&ap, 1);
	}

	sigfillset(&allsigs);
	pthread_sigmask(SIG_BLOCK, &allsigs, NULL);

	if (!sigchld_start_handler()) {
		crit("failed to create SIGCHLD handler thread!");
		cleanup_exit(&ap, 1);
	}

	if (pthread_create(&thid, &detach_attr, statemachine, NULL)) {
		crit("failed to create signal handler thread!");
		cleanup_exit(&ap, 1);
	}

	if (map && (mapfmt = strchr(map, ',')))
		*(mapfmt++) = '\0';

	ap.maptype = map;
	ap.mapfmt = mapfmt;
	ap.mapargc = mapargc;
	ap.mapargv = mapargv;

	rlim.rlim_cur = MAX_OPEN_FILES;
	rlim.rlim_max = MAX_OPEN_FILES;
	res = setrlimit(RLIMIT_NOFILE, &rlim);
	if (res)
		warn("can't increase open file limit - continuing");

	handle_mounts(&ap, path);

	exit(0);
}
