#ident "$Id: automount.c,v 1.78 2006/04/06 20:02:04 raven Exp $"
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
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/poll.h>
#include <dirent.h>

#include "automount.h"

const char *program;		/* Initialized with argv[0] */
const char *version = VERSION_STRING;	/* Program version */

static char *pid_file = NULL;	/* File in which to keep pid */
static char start_lockf[] = "/tmp/autofsXXXXXX";
static int start_lockfd = -1;

/* Attribute to create detached thread */
pthread_attr_t thread_attr;

struct master_readmap_cond mc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, 0, 0};

struct startup_cond sc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0};

pthread_key_t key_thread_stdenv_vars;

/* re-entrant syslog default context data */
#define AUTOFS_SYSLOG_CONTEXT {-1, 0, 0, LOG_PID, (const char *)0, LOG_DAEMON, 0xff};

#define MAX_OPEN_FILES		10240

static int umount_all(struct autofs_point *ap, int force);

extern pthread_mutex_t master_mutex;
extern struct master *master;

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

static int umount_offsets(struct autofs_point *ap, struct mnt_list *mnts, const char *base)
{
	char path[PATH_MAX + 1];
	char *offset = path;
	struct list_head list, head, *pos, *p;
	char key[PATH_MAX + 1];
	struct map_source *map;
	struct mapent_cache *mc = NULL;
	struct mapent *me = NULL;
	char *ind_key;
	int ret = 0, status;

	INIT_LIST_HEAD(&list);
	INIT_LIST_HEAD(&head);

	if (!tree_get_mnt_list(mnts, &list, base, 0))
		return 0;

	list_for_each(p, &list) {
		struct mnt_list *this;

		this = list_entry(p, struct mnt_list, list);

		if (strcmp(this->fs_type, "autofs"))
			continue;

		INIT_LIST_HEAD(&this->ordered);
		add_ordered_list(this, &head);
	}

	/*
	 * If it's a direct mount it's base is the key otherwise
	 * the last path component is the indirect entry key.
	 */
	ind_key = strrchr(base, '/');
	if (ind_key)
		ind_key++;

	master_source_readlock(ap->entry);
	map = ap->entry->first;
	while (map) {
		mc = map->mc;
		cache_writelock(mc);
		me = cache_lookup(mc, base);
		if (!me)
			me = cache_lookup(mc, ind_key);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}
	ap->entry->current = map;
	master_source_unlock(ap->entry);

	if (!me)
		return 0;

	pos = NULL;
	while ((offset = get_offset(base, offset, &head, &pos))) {
		struct mapent *oe;

		if (strlen(base) + strlen(offset) >= PATH_MAX) {
			warn("can't umount - mount path too long");
			ret++;
			continue;
		}

		debug("umount offset %s", offset);

		strcpy(key, base);
		strcat(key, offset);
		oe = cache_lookup(mc, key);

		if (!oe) {
			debug("offset key %s not found", key);
			continue;
		}

		/*
		 * We're in trouble if umounting the triggers fails.
		 * It should always succeed due to the expire design.
		 */
		pthread_cleanup_push(cache_lock_cleanup, mc);
		if (umount_autofs_offset(ap, oe)) {
			crit("failed to umount offset %s", key);
			ret++;
		}
		pthread_cleanup_pop(0);
	}

	if (!ret && me->multi == me) {
		status = cache_delete_offset_list(mc, me->key);
		if (status != CHE_OK)
			warn("couldn't delete offset list");
	}
	cache_unlock(mc);
	ap->entry->current = NULL;

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
		rv = spawnll(log_debug, PATH_UMOUNT, PATH_UMOUNT, path, NULL);
	} else if (is_smbfs && (sav_errno == EIO || sav_errno == EBADSLT)) {
		rv = spawnll(log_debug, PATH_UMOUNT, PATH_UMOUNT, path, NULL);
	}

	status = pthread_mutex_lock(&ap->state_mutex);
	if (status)
		fatal(status);

	/* We are doing a forced shutcwdown down so unlink busy mounts */
	if (rv && (ap->state == ST_SHUTDOWN_FORCE || ap->state == ST_SHUTDOWN)) {
		ret = stat(path, &st);
		if (ret == -1 && errno == ENOENT) {
			error("mount point does not exist");
			status = pthread_mutex_unlock(&ap->state_mutex);
			if (status)
				fatal(status);
			return 0;
		}

		if (ret == 0 && !S_ISDIR(st.st_mode)) {
			error("mount point is not a directory");
			status = pthread_mutex_unlock(&ap->state_mutex);
			if (status)
				fatal(status);
			return 0;
		}

		if (ap->state == ST_SHUTDOWN_FORCE) {
			msg("forcing umount of %s", path);
			rv = spawnll(log_debug, PATH_UMOUNT, PATH_UMOUNT, "-l", path, NULL);
			status = pthread_mutex_unlock(&ap->state_mutex);
			if (status)
				fatal(status);
		}
	}

	status = pthread_mutex_unlock(&ap->state_mutex);
	if (status)
		fatal(status);

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
int umount_multi(struct autofs_point *ap, struct mnt_list *mnts, const char *path, int incl)
{
	int left;
	struct mnt_list *mptr;
	struct list_head *p;
	LIST_HEAD(list);

	debug("path %s incl %d", path, incl);

	if (!tree_get_mnt_list(mnts, &list, path, incl)) {
		debug("no mounts found under %s", path);
/*		check_rm_dirs(ap, path, incl); */
		return 0;
	}

	left = 0;
	list_for_each(p, &list) {
		mptr = list_entry(p, struct mnt_list, list);

		/* We only want real mounts */
		if (!strcmp(mptr->fs_type, "autofs"))
			continue;

		if (umount_offsets(ap, mnts, mptr->path))
			error("could not umount some offsets under %s",
				mptr->path);

		debug("unmounting dir = %s", mptr->path);
		if (umount_ent(ap, mptr->path, mptr->fs_type)) {
			left++;
		}

		sched_yield();
	}

	/* Lastly check for offsets with no root mount */
	if (umount_offsets(ap, mnts, path)) {
		error("could not umount some offsets under %s", path);
		return 0;
	}

	/* Delete detritus like unwanted mountpoints and symlinks */
/*	if (left == 0)
		check_rm_dirs(ap, path, incl); */

	return left;
}

static int umount_all(struct autofs_point *ap, int force)
{
	struct mnt_list *mnts;
	int left;

	mnts = tree_make_mnt_tree(_PROC_MOUNTS, ap->path);

	left = umount_multi(ap, mnts, ap->path, 0);
	if (force && left)
		warn("could not unmount %d dirs under %s", left, ap->path);

	tree_free_mnt_tree(mnts);

	return left;
}

int umount_autofs(struct autofs_point *ap, int force)
{
	int status = 0;

	if (ap->state == ST_INIT)
		return -1;

	/*
	 * Since lookup.c is lazy about closing lookup modules
	 * to prevent unneeded opens, we need to clean them up
	 * before umount or the fs will be busy.
	 */
	lookup_close_lookup(ap);

	if (ap->type == LKP_INDIRECT) {
		if (umount_all(ap, force) && !force)
			return -1;

		status = umount_autofs_indirect(ap);
	} else {
		status = umount_autofs_direct(ap);
	}

	if (ap->submount) {
		int status;

		status = pthread_mutex_lock(&ap->parent->mounts_mutex);
		if (status)
			fatal(status);
		ap->parent->submnt_count--;
		list_del_init(&ap->mounts);
		status = pthread_cond_signal(&ap->parent->mounts_cond);
		if (status)
			error("failed to signal submount umount notify condition");
		status = pthread_mutex_unlock(&ap->parent->mounts_mutex);
		if (status)
			fatal(status);
	}

	return status;
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

	debug("token = %d", wait_queue_token);

	if (ioctl(ioctlfd, AUTOFS_IOC_FAIL, wait_queue_token) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error("AUTOFS_IOC_FAIL: error %s", estr);
		return 1;
	}
	return 0;
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

			status = pthread_mutex_lock(&ap->state_mutex);
			if (status)
				fatal(status);

			if (fullread(ap->state_pipe[0], &next_state, sizeof(next_state)))
				continue;

			if (next_state != ap->state) {
				if (next_state != ST_SHUTDOWN)
					st_add_task(ap, next_state);
				else
					ap->state = ST_SHUTDOWN;
			}

			status = pthread_mutex_unlock(&ap->state_mutex);
			if (status)
				fatal(status);

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
	struct mnt_list *mnts;
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

	mnts = tree_make_mnt_tree(_PROC_MOUNTS, buf);

	ret = umount_multi(ap, mnts, buf, 1);
	if (ret == 0) {
		msg("expired %s", buf);
	} else {
		error("error while expiring %s", buf);
	}

	tree_free_mnt_tree(mnts);

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

	debug("type = %d", pkt.hdr.type);

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
	error("unknown packet type %d", pkt.hdr.type);
	return -1;
}

static void become_daemon(unsigned foreground)
{
	FILE *pidfp;
	char buf[MAX_ERR_BUF];
	unsigned to_stderr = 0;
	pid_t pid;

	/* Don't BUSY any directories unnecessarily */
	chdir("/");

	/* Detach from foreground process */
	if (!foreground) {
		pid = fork();
		if (pid > 0) {
			struct stat st;
			close(start_lockfd);
			while (stat(start_lockf, &st) != -1)
				sleep(2);
			exit(0);
		} else if (pid < 0) {
			fprintf(stderr, "%s: Could not detach process\n",
				program);
			exit(1);
		}
		/*
		 * Make our own process group for "magic" reason: processes that share
		 * our pgrp see the raw filesystem behind the magic.
		 */
		if (setsid() == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			fprintf(stderr, "setsid: %s", estr);
			exit(1);
		}
	}

	/* Setup logging */
	if (to_stderr)
		log_to_stderr();
	else
		log_to_syslog();

	/* Write pid file if requested */
	if (pid_file) {
		if ((pidfp = fopen(pid_file, "wt"))) {
			fprintf(pidfp, "%lu\n", (unsigned long) getpid());
			fclose(pidfp);
		} else {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn("failed to write pid file %s: %s", pid_file, estr);
			pid_file = NULL;
		}
	}
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

static void do_master_cleanup_unlock(void *arg)
{
	int status;

	status = pthread_mutex_unlock(&mc.mutex);
	if (status)
		fatal(status);

	return;
}

static void *do_notify_state(void *arg)
{
	struct master *master;
	int sig;
	int status;

	sig = *(int *) arg;

	debug("signal %d", sig);

	status = pthread_mutex_lock(&mc.mutex);
	if (status)
		fatal(status);

	master = mc.master;

	mc.signaled = 1;
	status = pthread_cond_signal(&mc.cond);
	if (status) {
		error("failed to signal state notify condition");
		status = pthread_mutex_unlock(&mc.mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	status = pthread_mutex_unlock(&mc.mutex);
	if (status)
		fatal(status);

	master_notify_state_change(master, sig);

	return NULL;
}

static int do_signals(struct master *master, int signal)
{
	pthread_t thid;
	int sig = signal;
	int status;

	status = pthread_mutex_lock(&mc.mutex);
	if (status)
		fatal(status);

	status = pthread_create(&thid, &thread_attr, do_notify_state, &sig);
	if (status) {
		error("maount state notify thread create failed");
		status = pthread_mutex_unlock(&mc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	mc.thid = thid;
	mc.master = master;

	pthread_cleanup_push(do_master_cleanup_unlock, NULL);

	mc.signaled = 0;
	while (!mc.signaled) {
		status = pthread_cond_wait(&mc.cond, &mc.mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return 1;
}

static void *do_read_master(void *arg)
{
	struct master *master;
	time_t age;
	int readall = 1;
	int status;

	status = pthread_mutex_lock(&mc.mutex);
	if (status)
		fatal(status);

	master = mc.master;
	age = mc.age;

	mc.signaled = 1;
	status = pthread_cond_signal(&mc.cond);
	if (status) {
		error("failed to signal master read map condition");
		status = pthread_mutex_unlock(&mc.mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	status = pthread_mutex_unlock(&mc.mutex);
	if (status)
		fatal(status);

	status = master_read_master(master, age, readall);

	debug("status %d", status);

	return NULL;
}

static int do_hup_signal(struct master *master, time_t age)
{
	pthread_t thid;
	int status;

	status = pthread_mutex_lock(&mc.mutex);
	if (status)
		fatal(status);

	status = pthread_create(&thid, &thread_attr, do_read_master, NULL);
	if (status) {
		error("master read map thread create failed");
		status = pthread_mutex_unlock(&mc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	mc.thid = thid;
	mc.master = master;
	mc.age = age;

	pthread_cleanup_push(do_master_cleanup_unlock, NULL);

	mc.signaled = 0;
	while (!mc.signaled) {
		status = pthread_cond_wait(&mc.cond, &mc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	pthread_cleanup_pop(1);

	debug("started master map read"); 

	return 1;
}

/* Deal with all the signal-driven events in the state machine */
static void *statemachine(void *arg)
{
	sigset_t sigset;
	int sig, status;

	sigfillset(&sigset);
	sigdelset(&sigset, SIGCHLD);
	sigdelset(&sigset, SIGCONT);

	while (1) {
		sigwait(&sigset, &sig);

		status = pthread_mutex_lock(&master_mutex);
		if (status)
			fatal(status);

		if (list_empty(&master->mounts)) {
			status = pthread_mutex_unlock(&master_mutex);
			if (status)
				fatal(status);
			return NULL;
		}

		status = pthread_mutex_unlock(&master_mutex);
		if (status)
			fatal(status);

		switch (sig) {
		case SIGTERM:
		case SIGUSR2:
		case SIGUSR1:
			do_signals(master, sig);
			break;

		case SIGHUP:
			do_hup_signal(master, time(NULL));
			break;

		default:
			error("got unexpected signal %d!", sig);
			continue;
		}
	}
}

static void return_start_status(void *arg)
{
	struct startup_cond *sc;
	int status;

	sc = (struct startup_cond *) arg;

	sc->done = 1;

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

static void mutex_operation_wait(pthread_mutex_t *mutex)
{
	int status;

	/*
	 * Unlock a mutex, but wait for a pending operation
	 * if one is in progress
	 */
	status = pthread_mutex_trylock(mutex);
	if (status) {
		if (status == EBUSY) {
			/* Mutex locked - do we own it */
			status = pthread_mutex_unlock(mutex);
			if (status) {
				if (status != EPERM)
					fatal(status);
			} else
				return;

			status = pthread_mutex_lock(mutex);
			if (status)
				fatal(status);
		} else
			fatal(status);

		/* Operation complete, release it */
		status = pthread_mutex_unlock(mutex);
		if (status)
			fatal(status);
	} else {
		status = pthread_mutex_unlock(mutex);
		if (status)
			fatal(status);
	}

	return;
}

static void handle_mounts_cleanup(void *arg)
{
	struct autofs_point *ap;

	ap = (struct autofs_point *) arg;

	umount_autofs(ap, 1);

	/* If we have been canceled then we may hold the state mutex. */
	mutex_operation_wait(&ap->state_mutex);

	msg("shut down path %s", ap->path);

	master_free_mapent(ap->entry);

	/* If we are the last tell the state machine to shutdown */
	if (master_list_empty(master))
		kill(getpid(), SIGTERM);

	return;
}

void *handle_mounts(void *arg)
{
	struct autofs_point *ap;
	int cancel_state, status = 0;

	ap = (struct autofs_point *) arg;

	pthread_cleanup_push(return_start_status, &sc);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	status = pthread_mutex_lock(&ap->state_mutex);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&sc.mutex);
	if (status) {
		crit("failed to lock startup condition mutex!");
		fatal(status);
	}

	if (mount_autofs(ap) < 0) {
		crit("mount of %s failed!", ap->path);
		sc.status = 1;
		status = pthread_mutex_unlock(&ap->state_mutex);
		if (status)
			fatal(status);
		umount_autofs(ap, 1);
		master_free_mapent(ap->entry);
		pthread_exit(NULL);
	}

	if (ap->ghost && ap->type != LKP_DIRECT)
		msg("ghosting enabled");

	sc.status = 0;
	pthread_cleanup_pop(1);

	/* We often start several automounters at the same time.  Add some
	   randomness so we don't all expire at the same time. */
	if (ap->exp_timeout)
		alarm_add(ap, ap->exp_runfreq + rand() % ap->exp_runfreq);

	status = pthread_mutex_unlock(&ap->state_mutex);
	if (status)
		fatal(status);

	pthread_cleanup_push(handle_mounts_cleanup, ap);
	pthread_setcancelstate(cancel_state, &cancel_state);

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

			/*
			 * If the ioctl fails assume the kernel doesn't have
			 * AUTOFS_IOC_ASKUMOUNT and just continue.
			 */
			ret = ioctl(ap->ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
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
			nextstate(ap->state_pipe[1], ST_READY);

			status = pthread_mutex_unlock(&ap->state_mutex);
			if (status)
				fatal(status);
		}
	}

	status = pthread_mutex_lock(&ap->mounts_mutex);
	if (status)
		fatal(status);

	while (ap->submnt_count) {
		status = pthread_cond_wait(&ap->mounts_cond, &ap->mounts_mutex);
		if (status)
			fatal(status);
	}

	status = pthread_mutex_unlock(&ap->mounts_mutex);
	if (status)
		fatal(status);

	pthread_cleanup_pop(1);

	return NULL;
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

static int is_automount_running(void)
{
	FILE *fp;
	DIR *dir;
	struct dirent entry;
	struct dirent *result;
	char path[PATH_MAX], buf[PATH_MAX];
	int len;

	if ((dir = opendir("/proc")) == NULL) {
		printf("cannot opendir(/proc)\n");
		exit(1);
	}

	while (readdir_r(dir, &entry, &result) == 0) {
		if (!result)
			break;

		if (*entry.d_name == '.')
			continue;

		if (!strcmp(entry.d_name, "self"))
			continue;

		if (isdigit(*entry.d_name)) {
			int me = atoi(entry.d_name);

			if (me == getpid())
				continue;
		}

		len = sprintf(path, "/proc/%s/cmdline", entry.d_name);
		if (len >= PATH_MAX) {
			fprintf(stderr,
				"buffer to small for /proc path\n");
			exit(1);
		}
		path[len] = '\0';

		fp = fopen(path, "r");
		if (fp) {
			int c, len = 0;

			while (len < 127 && (c = fgetc(fp)) != EOF && c)
				buf[len++] = c;
			buf[len] = '\0';

			if (strstr(buf, "automount"))
				return 1;
			fclose(fp);
		}
	}
	closedir(dir);

	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: %s [options] [master_map_name]\n"
		"	-h --help	this text\n"
		"	-p --pid-file f write process id to file f\n"
		"	-t --timeout n	auto-unmount in n seconds (0-disable)\n"
		"	-v --verbose	be verbose\n"
		"	-d --debug	log debuging info\n"
		/*"	-f --foreground do not fork into background\n" */
		"	-V --version	print version and exit\n"
		, program);
}

int main(int argc, char *argv[])
{
	int res, opt, status;
	unsigned ghost;
	unsigned foreground;
	time_t timeout;
	time_t age = time(NULL);
	sigset_t allsigs;
	struct rlimit rlim;
	static const struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"pid-file", 1, 0, 'p'},
		{"timeout", 1, 0, 't'},
		{"verbose", 0, 0, 'v'},
		{"debug", 0, 0, 'd'},
		{"foreground", 0, 0, 'f'},
		{"version", 0, 0, 'V'},
		{0, 0, 0, 0}
	};

	sigfillset(&allsigs);
	sigprocmask(SIG_BLOCK, &allsigs, NULL);

	program = argv[0];

	defaults_read_config();

	timeout = defaults_get_timeout();
	ghost = defaults_get_browse_mode();
	foreground = 0;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "+hp:t:vdfV", long_options, NULL)) != EOF) {
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

		case 'f':
			foreground = 1;
			break;

		case 'V':
			printf("Linux automount version %s\n", version);
			exit(0);

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

	if (is_automount_running()) {
		fprintf(stderr, "%s: program is already running.\n",
			program);
		exit(1);
	}

	rlim.rlim_cur = MAX_OPEN_FILES;
	rlim.rlim_max = MAX_OPEN_FILES;
	res = setrlimit(RLIMIT_NOFILE, &rlim);
	if (res)
		warn("can't increase open file limit - continuing");

#if ENABLE_CORES
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	res = setrlimit(RLIMIT_CORE, &rlim);
	if (res)
		warn("can't increase core file limit - continuing");
#endif

	start_lockfd = mkstemp(start_lockf);

	become_daemon(foreground);

	if (argc == 0) {
		const char *name;

		name = defaults_get_master_map();
		if (!name)
			master = master_new(NULL, timeout, ghost);
		else
			master = master_new(name, timeout, ghost);
	} else
		master = master_new(argv[0], timeout, ghost);

	if (!master) {
		crit("%s: can't create master map %s",
			program, argv[0]);
		close(start_lockfd);
		unlink(start_lockf);
		exit(1);
	}

	if (pthread_attr_init(&thread_attr)) {
		crit("%s: failed to init thread attribute struct!",
			program);
		close(start_lockfd);
		unlink(start_lockf);
		exit(1);
	}

	if (pthread_attr_setdetachstate(
			&thread_attr, PTHREAD_CREATE_DETACHED)) {
		crit("%s: failed to set detached thread attribute!",
			program);
		close(start_lockfd);
		unlink(start_lockf);
		exit(1);
	}

#ifdef _POSIX_THREAD_ATTR_STACKSIZE
	if (pthread_attr_setstacksize(
			&thread_attr, PTHREAD_STACK_MIN*128)) {
		crit("%s: failed to set stack size thread attribute!",
			program);
		close(start_lockfd);
		unlink(start_lockf);
		exit(1);
	}
#endif

	msg("Starting automounter version %s, master map %s",
		version, master->name);

	status = pthread_key_create(&key_thread_stdenv_vars,
				key_thread_stdenv_vars_destroy);
	if (status) {
		crit("failed to create thread data key for std env vars!");
		master_kill(master, 1);
		close(start_lockfd);
		unlink(start_lockf);
		exit(1);
	}

	if (!alarm_start_handler()) {
		crit("failed to create alarm handler thread!");
		master_kill(master, 1);
		close(start_lockfd);
		unlink(start_lockf);
		exit(1);
	}

	if (!st_start_handler()) {
		crit("failed to create FSM handler thread!");
		master_kill(master, 1);
		close(start_lockfd);
		unlink(start_lockf);
		exit(1);
	}

	if (!sigchld_start_handler()) {
		crit("failed to create SIGCHLD handler thread!");
		master_kill(master, 1);
		close(start_lockfd);
		unlink(start_lockf);
		exit(1);
	}

	if (!load_autofs4_module()) {
		crit("%s: can't load %s filesystem module",
			program, FS_MODULE_NAME);
		master_kill(master, 1);
		close(start_lockfd);
		unlink(start_lockf);
		exit(2);
	}

	if (!master_read_master(master, age, 0)) {
		master_kill(master, 1);
		close(start_lockfd);
		unlink(start_lockf);
		exit(3);
	}

	close(start_lockfd);
	unlink(start_lockf);

	statemachine(NULL);

	master_kill(master, 1);

	if (pid_file) {
		unlink(pid_file);
		pid_file = NULL;
	}
	closelog();

	exit(0);
}
