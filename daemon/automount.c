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
#include <sys/vfs.h>

#include "automount.h"

const char *program;		/* Initialized with argv[0] */
const char *version = VERSION_STRING;	/* Program version */
const char *libdir = AUTOFS_LIB_DIR;	/* Location of library modules */
const char *mapdir = AUTOFS_MAP_DIR;	/* Location of mount maps */
const char *confdir = AUTOFS_CONF_DIR;	/* Location of autofs config file */

static char *pid_file = NULL;	/* File in which to keep pid */
static int start_pipefd[2];
static int st_stat = 0;
static int *pst_stat = &st_stat;

/* Attribute to create detached thread */
pthread_attr_t thread_attr;

struct master_readmap_cond mrc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, 0, 0, 0, 0};

struct startup_cond suc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0};

pthread_key_t key_thread_stdenv_vars;

/* re-entrant syslog default context data */
#define AUTOFS_SYSLOG_CONTEXT {-1, 0, 0, LOG_PID, (const char *)0, LOG_DAEMON, 0xff};

#define MAX_OPEN_FILES		10240

static int umount_all(struct autofs_point *ap, int force);

extern pthread_mutex_t master_mutex;
extern struct master *master_list;

static int do_mkdir(const char *parent, const char *path, mode_t mode)
{
	int status;
	struct stat st;
	struct statfs fs;

	/* If path exists we're done */
	status = stat(path, &st);
	if (status == 0) {
		if (!S_ISDIR(st.st_mode)) {
			errno = ENOTDIR;
			return 0;
		}
		return 1;
	}

	/*
	 * If we're trying to create a directory within an autofs fs
	 * of the path is contained in a localy mounted fs go ahead.
	 */
	status = -1;
	if (*parent)
		status = statfs(parent, &fs);
	if ((status != -1 && fs.f_type == AUTOFS_SUPER_MAGIC) ||
	    contained_in_local_fs(path)) {
		if (mkdir(path, mode) == -1) {
			if (errno == EEXIST)
				return 1;
			return 0;
		}
		return 1;
	}

	return 0;
}

int mkdir_path(const char *path, mode_t mode)
{
	char *buf = alloca(strlen(path) + 1);
	char *parent = alloca(strlen(path) + 1);
	const char *cp = path, *lcp = path;
	char *bp = buf, *pp = parent;

	*parent = '\0';

	do {
		if (cp != path && (*cp == '/' || *cp == '\0')) {
			memcpy(bp, lcp, cp - lcp);
			bp += cp - lcp;
			*bp = '\0';
			if (!do_mkdir(parent, buf, mode)) {
				if (*cp != '\0') {
					memcpy(pp, lcp, cp - lcp);
					pp += cp - lcp;
					*pp = '\0';
					lcp = cp;
					continue;
				}
				return -1;
			}
			memcpy(pp, lcp, cp - lcp);
			pp += cp - lcp;
			*pp = '\0';
			lcp = cp;
		}
	} while (*cp++ != '\0');

	return 0;
}

/* Remove as much as possible of a path */
int rmdir_path(struct autofs_point *ap, const char *path, dev_t dev)
{
	int len = strlen(path);
	char *buf = alloca(len + 1);
	char *cp;
	int first = 1;
	struct stat st;
	struct statfs fs;

	strcpy(buf, path);
	cp = buf + len;

	do {
		*cp = '\0';

		/*
		 *  Before removing anything, perform some sanity checks to
		 *  ensure that we are looking at files in the automount
		 *  file system.
		 */
		memset(&st, 0, sizeof(st));
		if (lstat(buf, &st) != 0) {
			crit(ap->logopt, "lstat of %s failed.", buf);
			return -1;
		}

		/* Termination condition removing full path within autofs fs */
		if (st.st_dev != dev)
			return 0;

		if (statfs(buf, &fs) != 0) {
			error(ap->logopt, "could not stat fs of %s", buf);
			return -1;
		}

		if (fs.f_type != AUTOFS_SUPER_MAGIC) {
			crit(ap->logopt, "attempt to remove directory from a "
			     "non-autofs filesystem!");
			crit(ap->logopt,
			     "requestor dev == %llu, \"%s\" owner dev == %llu",
			     dev, buf, st.st_dev);
			return -1;
		}
			     
		/*
		 * Last element of path may be a symbolic link; all others
		 * are directories (and the last directory element is
		 * processed first, hence the variable name)
		 */
		if (rmdir(buf) == -1) {
			if (first && errno == ENOTDIR) {
				/*
				 *  Ensure that we will only remove
				 *  symbolic links.
				 */
				if (S_ISLNK(st.st_mode)) {
					if (unlink(buf) == -1)
						return -1;
				} else {
					crit(ap->logopt,
					   "file \"%s\" is neither a directory"
					   " nor a symbolic link. mode %d",
					   buf, st.st_mode);
					return -1;
				}
			}

			/*
			 *  If we fail to remove a directory for any reason,
			 *  we need to return an error.
			 */
			return -1;
		}

		first = 0;
	} while ((cp = strrchr(buf, '/')) != NULL && cp != buf);

	return 0;
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
				    strcmp(de[n]->d_name, "..") == 0) {
					free(de[n]);
					continue;
				}

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
	char buf[MAX_ERR_BUF];
	struct stat newst;

	if (when == 0) {
		if (st->st_dev != dev)
			return 0;
		return 1;
	}

	if (lstat(file, &newst)) {
		crit(LOGOPT_ANY,
		     "unable to stat file, possible race condition");
		return 0;
	}

	if (newst.st_dev != dev) {
		crit(LOGOPT_ANY,
		     "file %s has the wrong device, possible race condition",
		     file);
		return 0;
	}

	if (S_ISDIR(newst.st_mode)) {
		debug(LOGOPT_ANY, "removing directory %s", file);
		if (rmdir(file)) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn(LOGOPT_ANY,
			      "unable to remove directory %s: %s", file, estr);
			return 0;
		}
	} else if (S_ISREG(newst.st_mode)) {
		crit(LOGOPT_ANY,
		     "attempting to remove files from a mounted "
		     "directory. file %s", file);
		return 0;
	} else if (S_ISLNK(newst.st_mode)) {
		debug(LOGOPT_ANY, "removing symlink %s", file);
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
int count_mounts(const char *path, dev_t dev)
{
	struct counter_args counter;

	counter.count = 0;
	counter.dev = dev;
	
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

/* Try to purge cache entries kept around due to existing mounts */
static void update_map_cache(struct autofs_point *ap, const char *path)
{
	struct map_source *map;
	struct mapent_cache *mc;
	const char *key;

	if (ap->type == LKP_INDIRECT)
		key = strrchr(path, '/') + 1;
	else
		key = path;

	pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
	master_source_readlock(ap->entry);
	map = ap->entry->first;
	while (map) {
		struct mapent *me = NULL;

		/* Skip current, in-use cache */
		if (ap->entry->age <= map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		cache_writelock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me && me->ioctlfd == -1)
			cache_delete(mc, key);
		cache_unlock(mc);

		map = map->next;
	}
	pthread_cleanup_pop(1);

	return;
}

static int umount_subtree_mounts(struct autofs_point *ap, const char *path, unsigned int is_autofs_fs)
{
	struct mapent_cache *mc;
	struct mapent *me;
	unsigned int is_mm_root;
	int left;

	me = lookup_source_mapent(ap, path, LKP_DISTINCT);
	if (!me) {
		char *ind_key;

		ind_key = strrchr(path, '/');
		if (ind_key)
			ind_key++;

		me = lookup_source_mapent(ap, ind_key, LKP_NORMAL);
		if (!me)
			return 0;
	}

	mc = me->mc;
	is_mm_root = (me->multi == me);

	left = 0;

	pthread_cleanup_push(cache_lock_cleanup, mc);

	if (me->multi) {
		char *root, *base;
		size_t ap_len;
		int cur_state;

		ap_len = strlen(ap->path);

		if (!strchr(me->multi->key, '/')) {
			/* Indirect multi-mount root */
			root = alloca(ap_len + strlen(me->multi->key) + 2);
			strcpy(root, ap->path);
			strcat(root, "/");
			strcat(root, me->multi->key);
		} else
			root = me->multi->key;

		if (is_mm_root)
			base = NULL;
		else
			base = me->key + strlen(root);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
		/* Lock the closest parent nesting point for umount */
		cache_multi_lock(me->parent);
		if (umount_multi_triggers(ap, root, me, base)) {
			warn(ap->logopt,
			     "could not umount some offsets under %s", path);
			left++;
		}
		cache_multi_unlock(me->parent);
		pthread_setcancelstate(cur_state, NULL);
	}

	pthread_cleanup_pop(1);

	if (left || is_autofs_fs)
		return left;

	/*
	 * If this is the root of a multi-mount we've had to umount
	 * it already to ensure it's ok to remove any offset triggers.
	 */
	if (!is_mm_root && is_mounted(_PATH_MOUNTED, path, MNTS_REAL)) {
		msg("unmounting dir = %s", path);
		if (umount_ent(ap, path)) {
			warn(ap->logopt, "could not umount dir %s", path);
			left++;
		}
	}

	return left;
}

/* umount all filesystems mounted under path.  If incl is true, then
   it also tries to umount path itself */
int umount_multi(struct autofs_point *ap, const char *path, int incl)
{
	struct statfs fs;
	int is_autofs_fs;
	int ret, left;

	debug(ap->logopt, "path %s incl %d", path, incl);

	ret = statfs(path, &fs);
	if (ret == -1) {
		error(ap->logopt, "could not stat fs of %s", path);
		return 1;
	}

	is_autofs_fs = fs.f_type == AUTOFS_SUPER_MAGIC ? 1 : 0;

	left = 0;

	/*
	 * If we are a submount we need to umount any offsets our
	 * parent may have mounted over top of us.
	 */
	/*if (ap->submount)
		left += umount_subtree_mounts(ap->parent, path, is_autofs_fs);*/

	left += umount_subtree_mounts(ap, path, is_autofs_fs);

	/* Delete detritus like unwanted mountpoints and symlinks */
	if (left == 0) {
		update_map_cache(ap, path);
		check_rm_dirs(ap, path, incl);
	}

	return left;
}

static int umount_all(struct autofs_point *ap, int force)
{
	int left;

	left = umount_multi(ap, ap->path, 0);
	if (force && left)
		warn(ap->logopt, "could not unmount %d dirs under %s",
		     left, ap->path);

	return left;
}

int umount_autofs(struct autofs_point *ap, int force)
{
	int ret = 0;

	if (ap->state == ST_INIT)
		return -1;

	/*
	 * Since lookup.c is lazy about closing lookup modules
	 * to prevent unneeded opens, we need to clean them up
	 * before umount.
	 */
	lookup_close_lookup(ap);

	if (ap->type == LKP_INDIRECT) {
		if (umount_all(ap, force) && !force)
			return -1;
		ret = umount_autofs_indirect(ap);
	} else
		ret = umount_autofs_direct(ap);

	return ret;
}

int send_ready(int ioctlfd, unsigned int wait_queue_token)
{
	char buf[MAX_ERR_BUF];

	if (wait_queue_token == 0)
		return 0;

	debug(LOGOPT_NONE, "token = %d", wait_queue_token);

	if (ioctl(ioctlfd, AUTOFS_IOC_READY, wait_queue_token) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(LOGOPT_ANY, "AUTOFS_IOC_READY: error %s", estr);
		return 1;
	}
	return 0;
}

int send_fail(int ioctlfd, unsigned int wait_queue_token)
{
	char buf[MAX_ERR_BUF];

	if (wait_queue_token == 0)
		return 0;

	debug(LOGOPT_NONE, "token = %d", wait_queue_token);

	if (ioctl(ioctlfd, AUTOFS_IOC_FAIL, wait_queue_token) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(LOGOPT_ANY, "AUTOFS_IOC_FAIL: error %s", estr);
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
			error(ap->logopt, "poll failed: %s", estr);
			return -1;
		}

		if (fds[1].revents & POLLIN) {
			enum states next_state, post_state;
			size_t read_size = sizeof(next_state);
			int state_pipe;

			next_state = post_state = ST_INVAL;

			state_mutex_lock(ap);

			state_pipe = ap->state_pipe[0];

			if (fullread(state_pipe, &next_state, read_size)) {
				state_mutex_unlock(ap);
				continue;
			}

			if (next_state != ST_INVAL && next_state != ap->state) {
				if (next_state != ST_SHUTDOWN)
					post_state = next_state;
				else
					ap->state = ST_SHUTDOWN;
			}

			state_mutex_unlock(ap);

			if (post_state != ST_INVAL) {
				if (post_state == ST_SHUTDOWN_PENDING ||
				    post_state == ST_SHUTDOWN_FORCE) {
					alarm_delete(ap);
					st_remove_tasks(ap);
				}
				st_add_task(ap, post_state);
			}

			if (next_state == ST_SHUTDOWN)
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
		crit(ap->logopt, "path to long for buffer");
		return 1;
	}

	msg("expiring path %s", buf);

	ret = umount_multi(ap, buf, 1);
	if (ret == 0)
		msg("expired %s", buf);
	else
		warn(ap->logopt, "couldn't complete expire of %s", buf);

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

	debug(ap->logopt, "type = %d", pkt.hdr.type);

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
	error(ap->logopt, "unknown packet type %d", pkt.hdr.type);
	return -1;
}

static void become_daemon(unsigned foreground)
{
	FILE *pidfp;
	char buf[MAX_ERR_BUF];
	unsigned to_stderr = 0;
	pid_t pid;

	/* Don't BUSY any directories unnecessarily */
	if (chdir("/")) {
		fprintf(stderr, "%s: failed change working directory.\n",
			program);
		exit(0);
	}

	if (pipe(start_pipefd) < 0) {
		fprintf(stderr, "%s: failed to create start_pipefd.\n",
			program);
		exit(0);
	}

	/* Detach from foreground process */
	if (!foreground) {
		pid = fork();
		if (pid > 0) {
			int r;
			close(start_pipefd[1]);
			r = read(start_pipefd[0], pst_stat, sizeof(pst_stat));
			if (r < 0)
				exit(1);
			exit(*pst_stat);
		} else if (pid < 0) {
			fprintf(stderr, "%s: Could not detach process\n",
				program);
			exit(1);
		}
		close(start_pipefd[0]);

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
			warn(LOGOPT_ANY,
			     "failed to write pid file %s: %s",
			     pid_file, estr);
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

	status = pthread_mutex_unlock(&mrc.mutex);
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

	status = pthread_mutex_lock(&mrc.mutex);
	if (status)
		fatal(status);

	master = mrc.master;

	debug(master->default_logging, "signal %d", sig);

	mrc.signaled = 1;
	status = pthread_cond_signal(&mrc.cond);
	if (status) {
		error(master->default_logging,
		      "failed to signal state notify condition");
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	status = pthread_mutex_unlock(&mrc.mutex);
	if (status)
		fatal(status);

	master_notify_state_change(master, sig);

	return NULL;
}

static int do_signals(struct master *master, int sig)
{
	pthread_t thid;
	int r_sig = sig;
	int status;

	status = pthread_mutex_lock(&mrc.mutex);
	if (status)
		fatal(status);

	status = pthread_create(&thid, &thread_attr, do_notify_state, &r_sig);
	if (status) {
		error(master->default_logging,
		      "mount state notify thread create failed");
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	mrc.thid = thid;
	mrc.master = master;

	pthread_cleanup_push(do_master_cleanup_unlock, NULL);

	mrc.signaled = 0;
	while (!mrc.signaled) {
		status = pthread_cond_wait(&mrc.cond, &mrc.mutex);
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

	status = pthread_mutex_lock(&mrc.mutex);
	if (status)
		fatal(status);

	master = mrc.master;
	age = mrc.age;

	mrc.signaled = 1;
	status = pthread_cond_signal(&mrc.cond);
	if (status) {
		error(master->default_logging,
		      "failed to signal master read map condition");
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	status = pthread_mutex_unlock(&mrc.mutex);
	if (status)
		fatal(status);

	status = master_read_master(master, age, readall);

	return NULL;
}

static int do_hup_signal(struct master *master, time_t age)
{
	pthread_t thid;
	int status;

	status = pthread_mutex_lock(&mrc.mutex);
	if (status)
		fatal(status);

	status = pthread_create(&thid, &thread_attr, do_read_master, NULL);
	if (status) {
		error(master->default_logging,
		      "master read map thread create failed");
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	mrc.thid = thid;
	mrc.master = master;
	mrc.age = age;

	pthread_cleanup_push(do_master_cleanup_unlock, NULL);

	mrc.signaled = 0;
	while (!mrc.signaled) {
		status = pthread_cond_wait(&mrc.cond, &mrc.mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return 1;
}

/* Deal with all the signal-driven events in the state machine */
static void *statemachine(void *arg)
{
	sigset_t signalset;
	int sig;

	sigfillset(&signalset);
	sigdelset(&signalset, SIGCHLD);
	sigdelset(&signalset, SIGCONT);

	while (1) {
		sigwait(&signalset, &sig);


		if (master_list_empty(master_list))
			return NULL;

		switch (sig) {
		case SIGTERM:
		case SIGUSR2:
		case SIGUSR1:
			do_signals(master_list, sig);
			break;

		case SIGHUP:
			do_hup_signal(master_list, time(NULL));
			break;

		default:
			error(master_list->default_logging,
			      "got unexpected signal %d!", sig);
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
	char path[PATH_MAX + 1];
	char buf[MAX_ERR_BUF];
	unsigned int clean = 0, submount;

	ap = (struct autofs_point *) arg;

	submount = ap->submount;

	strcpy(path, ap->path);
	if (!submount && strcmp(ap->path, "/-") && ap->dir_created)
		clean = 1;

	/* If we have been canceled then we may hold the state mutex. */
	mutex_operation_wait(&ap->state_mutex);

	alarm_delete(ap);
	st_remove_tasks(ap);

	umount_autofs(ap, 1);

	master_signal_submount(ap, MASTER_SUBMNT_JOIN);
	master_remove_mapent(ap->entry);
	master_free_mapent_sources(ap->entry, 1);
	master_free_mapent(ap->entry);

	sched_yield();

	if (clean) {
		if (rmdir(path) == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn(LOGOPT_NONE, "failed to remove dir %s: %s",
			     path, estr);
		}
	}

	msg("shut down path %s", path);

	/* If we are the last tell the state machine to shutdown */
	if (!submount && master_list_empty(master_list))
		kill(getpid(), SIGTERM);

	return;
}

void *handle_mounts(void *arg)
{
	struct autofs_point *ap;
	int cancel_state, status = 0;

	ap = (struct autofs_point *) arg;

	pthread_cleanup_push(return_start_status, &suc);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	state_mutex_lock(ap);

	status = pthread_mutex_lock(&suc.mutex);
	if (status) {
		crit(ap->logopt, "failed to lock startup condition mutex!");
		fatal(status);
	}

	if (mount_autofs(ap) < 0) {
		crit(ap->logopt, "mount of %s failed!", ap->path);
		suc.status = 1;
		state_mutex_unlock(ap);
		umount_autofs(ap, 1);
		pthread_setcancelstate(cancel_state, NULL);
		pthread_exit(NULL);
	}

	if (ap->ghost && ap->type != LKP_DIRECT)
		msg("ghosting enabled");

	suc.status = 0;
	pthread_cleanup_pop(1);

	/* We often start several automounters at the same time.  Add some
	   randomness so we don't all expire at the same time. */
	if (!ap->submount && ap->exp_timeout)
		alarm_add(ap, ap->exp_runfreq + rand() % ap->exp_runfreq);

	pthread_cleanup_push(handle_mounts_cleanup, ap);
	pthread_setcancelstate(cancel_state, NULL);

	state_mutex_unlock(ap);

	while (ap->state != ST_SHUTDOWN) {
		if (handle_packet(ap)) {
			int ret, result;

			state_mutex_lock(ap);
			/*
			 * For a direct mount map all mounts have already gone
			 * by the time we get here.
			 */
			if (ap->type == LKP_DIRECT) {
				status = 1;
				state_mutex_unlock(ap);
				break;
			}

			/*
			 * If the ioctl fails assume the kernel doesn't have
			 * AUTOFS_IOC_ASKUMOUNT and just continue.
			 */
			ret = ioctl(ap->ioctlfd, AUTOFS_IOC_ASKUMOUNT, &result);
			if (ret == -1) {
				state_mutex_unlock(ap);
				break;
			}

			/* OK to exit */
			if (ap->state == ST_SHUTDOWN || result) {
				state_mutex_unlock(ap);
				break;
			}

			/* Failed shutdown returns to ready */
			warn(ap->logopt,
			     "can't shutdown: filesystem %s still busy",
			     ap->path);
			if (!ap->submount)
				alarm_add(ap, ap->exp_runfreq);
			nextstate(ap->state_pipe[1], ST_READY);

			state_mutex_unlock(ap);
		}
	}

	pthread_cleanup_pop(1);

	/*
	 * A cowboy .. me!
	 * That noise yu ear aint spuurs sonny!!
	 *
	 * The libkrb5support destructor called indirectly through
	 * libgssapi_krb5 which is used bt libkrb5 (somehow) must run
	 * to completion before the last thread using it exits so
	 * that it's per thread data keys are deleted or we get a
	 * little segfault at exit. So much for dlclose being
	 * syncronous.
	 *
	 * So, the solution is a recipe for disaster.
	 * Hope we don't get a really busy system!
	 */
	/*sleep(1);*/
	sched_yield();

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
	char path[PATH_MAX + 1], buf[PATH_MAX];

	if ((dir = opendir("/proc")) == NULL) {
		fprintf(stderr, "cannot opendir(/proc)\n");
		exit(1);
	}

	while (readdir_r(dir, &entry, &result) == 0) {
		int path_len, pid = 0;

		if (!result)
			break;

		if (*entry.d_name == '.')
			continue;

		if (!strcmp(entry.d_name, "self"))
			continue;

		if (!isdigit(*entry.d_name))
			continue;

		pid = atoi(entry.d_name);
		if (pid == getpid())
			continue;

		path_len = sprintf(path, "/proc/%s/cmdline", entry.d_name);
		if (path_len >= PATH_MAX) {
			fprintf(stderr,
				"buffer to small for /proc path\n");
			return -1;
		}
		path[path_len] = '\0';

		fp = fopen(path, "r");
		if (fp) {
			int c, len = 0;

			while (len < 127 && (c = fgetc(fp)) != EOF && c)
				buf[len++] = c;
			buf[len] = '\0';

			if (strstr(buf, "automount"))
				return pid;
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
		"	-D --define	define global macro variable\n"
		/*"	-f --foreground do not fork into background\n" */
		"	-V --version	print version, build config and exit\n"
		, program);
}

static void show_build_info(void)
{
	char buf[2048];
	int count = 0;

	printf("\nLinux automount version %s\n", version);

	printf("\nDirectories:\n");
	printf("\tconfig dir:\t%s\n", confdir);
	printf("\tmaps dir:\t%s\n", mapdir);
	printf("\tmodules dir:\t%s\n", libdir);

	printf("\nCompile options:\n  ");

	memset(buf, 0, 2048);

#ifndef ENABLE_MOUNT_LOCKING
	printf("DISABLE_MOUNT_LOCKING ");
	count = 22;
#endif

#ifdef ENABLE_FORCED_SHUTDOWN
	printf("ENABLE_FORCED_SHUTDOWN ");
	count = count + 23;
#endif

#ifdef ENABLE_IGNORE_BUSY_MOUNTS
	printf("ENABLE_IGNORE_BUSY_MOUNTS ");
	count = count + 26;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif


#ifdef WITH_HESIOD
	printf("WITH_HESIOD ");
	count = count + 12;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_LDAP
	printf("WITH_LDAP ");
	count = count + 10;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_SASL
	printf("WITH_SASL ");
	count = count + 10;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_DMALLOC
	printf("WITH_DMALLOC ");
	count = count + 13;
#endif

	printf("\n\n");

	return;
}

int main(int argc, char *argv[])
{
	int res, opt, status;
	unsigned ghost, logging;
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
		{"define", 1, 0, 'D'},
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
	logging = defaults_get_logging();
	foreground = 0;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "+hp:t:vdD:fV", long_options, NULL)) != EOF) {
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
			logging |= LOGOPT_VERBOSE;
			break;

		case 'd':
			logging |= LOGOPT_DEBUG;
			break;

		case 'D':
			macro_parse_globalvar(optarg);
			break;

		case 'f':
			foreground = 1;
			break;

		case 'V':
			show_build_info();
			exit(0);

		case '?':
		case ':':
			printf("%s: Ambiguous or unknown options\n", program);
			exit(1);
		}
	}

	if (logging & LOGOPT_VERBOSE)
		set_log_verbose();

	if (logging & LOGOPT_DEBUG)
		set_log_debug();

	if (geteuid() != 0) {
		fprintf(stderr, "%s: this program must be run by root.\n",
			program);
		exit(1);
	}

	/* Remove the options */
	argv += optind;
	argc -= optind;

	if (is_automount_running() > 0) {
		fprintf(stderr, "%s: program is already running.\n",
			program);
		exit(1);
	}

	rlim.rlim_cur = MAX_OPEN_FILES;
	rlim.rlim_max = MAX_OPEN_FILES;
	res = setrlimit(RLIMIT_NOFILE, &rlim);
	if (res)
		warn(LOGOPT_NONE,
		     "can't increase open file limit - continuing");

#if ENABLE_CORES
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	res = setrlimit(RLIMIT_CORE, &rlim);
	if (res)
		warn(LOGOPT_NONE,
		     "can't increase core file limit - continuing");
#endif

	become_daemon(foreground);

	if (argc == 0)
		master_list = master_new(NULL, timeout, ghost);
	else
		master_list = master_new(argv[0], timeout, ghost);

	if (!master_list) {
		crit(LOGOPT_ANY, "%s: can't create master map %s",
			program, argv[0]);
		close(start_pipefd[1]);
		exit(1);
	}

	if (pthread_attr_init(&thread_attr)) {
		crit(LOGOPT_ANY,
		     "%s: failed to init thread attribute struct!",
		     program);
		close(start_pipefd[1]);
		exit(1);
	}

	if (pthread_attr_setdetachstate(
			&thread_attr, PTHREAD_CREATE_DETACHED)) {
		crit(LOGOPT_ANY,
		     "%s: failed to set detached thread attribute!",
		     program);
		close(start_pipefd[1]);
		exit(1);
	}

#ifdef _POSIX_THREAD_ATTR_STACKSIZE
	if (pthread_attr_setstacksize(
			&thread_attr, PTHREAD_STACK_MIN*128)) {
		crit(LOGOPT_ANY,
		     "%s: failed to set stack size thread attribute!",
		     program);
		close(start_pipefd[1]);
		exit(1);
	}
#endif

	msg("Starting automounter version %s, master map %s",
		version, master_list->name);

	status = pthread_key_create(&key_thread_stdenv_vars,
				key_thread_stdenv_vars_destroy);
	if (status) {
		crit(LOGOPT_ANY,
		     "failed to create thread data key for std env vars!");
		master_kill(master_list);
		close(start_pipefd[1]);
		exit(1);
	}

	if (!alarm_start_handler()) {
		crit(LOGOPT_ANY, "failed to create alarm handler thread!");
		master_kill(master_list);
		close(start_pipefd[1]);
		exit(1);
	}

	if (!st_start_handler()) {
		crit(LOGOPT_ANY, "failed to create FSM handler thread!");
		master_kill(master_list);
		close(start_pipefd[1]);
		exit(1);
	}
#if 0
	if (!load_autofs4_module()) {
		crit(LOGOPT_ANY, "%s: can't load %s filesystem module",
			program, FS_MODULE_NAME);
		master_kill(master_list);
		*pst_stat = 2;
		res = write(start_pipefd[1], pst_stat, sizeof(pst_stat));
		close(start_pipefd[1]);
		exit(2);
	}
#endif
	if (!master_read_master(master_list, age, 0)) {
		master_kill(master_list);
		*pst_stat = 3;
		res = write(start_pipefd[1], pst_stat, sizeof(pst_stat));
		close(start_pipefd[1]);
		exit(3);
	}

	res = write(start_pipefd[1], pst_stat, sizeof(pst_stat));
	close(start_pipefd[1]);

	statemachine(NULL);

	master_kill(master_list);

	if (pid_file) {
		unlink(pid_file);
		pid_file = NULL;
	}
	closelog();

	exit(0);
}
