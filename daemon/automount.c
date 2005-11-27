#ident "$Id: automount.c,v 1.42 2005/11/27 04:08:54 raven Exp $"
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
#include <errno.h>
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

int submount = 0;

int do_verbose = 0;		/* Verbose feedback option */
int do_debug = 0;		/* Enable full debug output */

sigset_t ready_sigs;		/* signals only accepted in ST_READY */
sigset_t lock_sigs;		/* signals blocked for locking */
sigset_t sigchld_mask;

struct autofs_point ap;
 
/* re-entrant syslog default context data */
#define AUTOFS_SYSLOG_CONTEXT {-1, 0, 0, LOG_PID, (const char *)0, LOG_DAEMON, 0xff};

volatile struct pending_mount *junk_mounts = NULL;

#define DEFAULT_GHOST_MODE	0

#define EXIT_CHECK_TIME		2000	/* Total time to wait before retry */
#define EXIT_CHECK_DELAY	200	/* Time interval to check if exited */

#define MAX_OPEN_FILES  10240

int do_mount_autofs_direct(struct mapent_cache *me, int now);

static int umount_all(int force);
static int handle_packet_expire(const struct autofs_packet_expire *pkt);

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

static int umount_offsets(const char *base)
{
	char path[PATH_MAX + 1];
	char *offset = path;
	struct list_head head, *pos = NULL;
	char key[PATH_MAX + 1];
	struct mapent_cache *me;
	struct mnt_list *mnts, *next;
	int ret = 0;

	INIT_LIST_HEAD(&head);

	mnts = get_mnt_list(_PROC_MOUNTS, base, 0);
	for (next = mnts; next; next = next->next) {
		if (strcmp(next->fs_type, "autofs"))
			continue;

		INIT_LIST_HEAD(&next->list);
		add_ordered_list(next, &head);
	}

	pos = NULL;
	offset = get_offset(base, offset, &head, &pos);
	while (offset) {
		if (strlen(base) + strlen(offset) >= PATH_MAX) {
			warn("can't umount - mount path too long");
			ret++;
			goto cont;
		}

		debug("trying to umount offset %s", offset);

		strcpy(key, base);
		strcat(key, offset);
		me = cache_lookup(key);
		if (!me) {
			debug("offset key %s not found", key);
			goto cont;
		}

		/*
		 * We're in trouble if umounting the triggers fails.
		 * It should always succeed due to the expire design.
		 */
		if (umount_autofs_offset(me)) {
			crit("failed to umount offset %s", me->key);
			ret++;
		}
cont:
		offset = get_offset(base, offset, &head, &pos);
	}
	free_mnt_list(mnts);

	return ret;
}

static int umount_ent(const char *path, const char *type)
{
	struct stat st;
	int sav_errno;
	int is_smbfs = (strcmp(type, "smbfs") == 0);
	int status;
	int rv = 0;

	if (umount_offsets(path)) {
		error("could not umount some offsets under %s", path);
		return 1;
	}

	status =  lstat(path, &st);
	sav_errno = errno;

	/* EIO appears to correspond to an smb mount that has gone away */
	if (!status ||
	    (is_smbfs && (sav_errno == EIO || sav_errno == EBADSLT))) {
		int umount_ok = 0;

		if (!status && (S_ISDIR(st.st_mode) && (st.st_dev != ap.dev)))
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
	int rmsymlink = *(int *) arg;
	struct stat newst;

	if (when == 0) {
		if (st->st_dev != ap.dev)
			return 0;
		return 1;
	}

	if (lstat(file, &newst)) {
		crit("unable to stat file, possible race condition");
		return 0;
	}

	if (newst.st_dev != ap.dev) {
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
	} else if (S_ISLNK(newst.st_mode) && rmsymlink) {
		debug("removing symlink %s", file);
		unlink(file);
	}
	return 1;
}

void rm_unwanted(const char *path, int incl, int rmsymlink)
{
	walk_tree(path, rm_unwanted_fn, incl, &rmsymlink);
}

static void check_rm_dirs(const char *path, int incl)
{
	if ((!ap.ghost) ||
	    (ap.state == ST_SHUTDOWN_PENDING ||
	     ap.state == ST_SHUTDOWN))
		rm_unwanted(path, incl, 1);
	else if (ap.ghost && (ap.type == LKP_INDIRECT))
		rm_unwanted(path, 0, 1);
}

/* umount all filesystems mounted under path.  If incl is true, then
   it also tries to umount path itself */
int umount_multi(const char *path, int incl)
{
	int left;
	struct mnt_list *mntlist = NULL;
	struct mnt_list *mptr;

	debug("path=%s incl=%d\n", path, incl);

	mntlist = get_mnt_list(_PATH_MOUNTED, path, incl);

	if (!mntlist) {
		debug("no mounts found under %s", path);
		check_rm_dirs(path, incl);
		return 0;
	}

	left = 0;
	for (mptr = mntlist; mptr != NULL; mptr = mptr->next) {
		debug("unmounting dir=%s\n", mptr->path);
		if (umount_ent(mptr->path, mptr->fs_type)) {
			left++;
		}
	}

	free_mnt_list(mntlist);

	/* Delete detritus like unwanted mountpoints and symlinks */
	if (left == 0)
		check_rm_dirs(path, incl);

	return left;
}

static int umount_all(int force)
{
	int left;

	left = umount_multi(ap.path, 0);
	if (force && left)
		warn("could not unmount %d dirs under %s", left, ap.path);

	return left;
}

int umount_autofs(int force)
{
	int status = 0;

	if (ap.state == ST_INIT)
		return -1;

	if (ap.type == LKP_INDIRECT) {
		if (umount_all(force) && !force)
			return -1;

		status = umount_autofs_indirect();
	} else {
		status = umount_autofs_direct();
	}

	return status;
}

static void nextstate(enum states next)
{
	static struct syslog_data syslog_context = AUTOFS_SYSLOG_CONTEXT;
	static struct syslog_data *slc = &syslog_context;

	if (write(ap.state_pipe[1], &next, sizeof(next)) != sizeof(next))
		error_r(slc, "write failed %m");
}

/* Deal with all the signal-driven events in the state machine */
static void sig_statemachine(int sig)
{
	static struct syslog_data syslog_context = AUTOFS_SYSLOG_CONTEXT;
	static struct syslog_data *slc = &syslog_context;
	int save_errno = errno;
	enum states next = ap.state;

	switch (sig) {
	default:		/* all the "can't happen" signals */
		error_r(slc, "process %d got unexpected signal %d!",
			getpid(), sig);
		break;
		/* don't FALLTHROUGH */

	case SIGTERM:
	case SIGUSR2:
		if (ap.state != ST_SHUTDOWN)
			nextstate(next = ST_SHUTDOWN_PENDING);
		break;

	case SIGUSR1:
		assert_r(slc, ap.state == ST_READY);
		nextstate(next = ST_PRUNE);
		break;

	case SIGALRM:
		assert_r(slc, ap.state == ST_READY);
		nextstate(next = ST_EXPIRE);
		break;

	case SIGHUP:
		assert_r(slc, ap.state == ST_READY);
		nextstate(next = ST_READMAP);
		break;
	}

	debug_r(slc, "sig %d switching from %d to %d", sig, ap.state, next);

	errno = save_errno;
}

int send_ready(int ioctlfd, unsigned int wait_queue_token)
{
	static struct syslog_data syslog_context = AUTOFS_SYSLOG_CONTEXT;
	static struct syslog_data *slc = &syslog_context;

	if (wait_queue_token == 0)
		return 0;
	debug_r(slc, "token=%d", wait_queue_token);
	if (ioctl(ioctlfd, AUTOFS_IOC_READY, wait_queue_token) < 0) {
		error_r(slc, "AUTOFS_IOC_READY: error %d", errno);
		return 1;
	}
	return 0;
}

int send_fail(int ioctlfd, unsigned int wait_queue_token)
{
	static struct syslog_data syslog_context = AUTOFS_SYSLOG_CONTEXT;
	static struct syslog_data *slc = &syslog_context;

	if (wait_queue_token == 0)
		return 0;
	debug_r(slc, "token=%d\n", wait_queue_token);
	if (ioctl(ioctlfd, AUTOFS_IOC_FAIL, wait_queue_token) < 0) {
		error_r(slc, "AUTOFS_IOC_FAIL: error %d", errno);
		return 1;
	}
	return 0;
}

/* Handle exiting children (either from SIGCHLD or synchronous wait at
   shutdown), and return the next state the system should enter as a
   result.  */
static enum states handle_child(int hang)
{
	static struct syslog_data syslog_context = AUTOFS_SYSLOG_CONTEXT;
	static struct syslog_data *slc = &syslog_context;
	pid_t pid;
	int status;
	enum states next = ST_INVAL;

	while ((pid = waitpid(-1, &status, hang ? 0 : WNOHANG)) > 0) {
		struct pending_mount volatile *mt, *volatile *mtp;

		debug_r(slc, "got pid %d, sig %d (%d), stat %d\n",
			pid, WIFSIGNALED(status),
			WTERMSIG(status), WEXITSTATUS(status));

		/* Check to see if expire process finished */
		if (pid == ap.exp_process) {
			int success;

			if (!WIFEXITED(status))
				continue;

			success = !WIFSIGNALED(status) && (WEXITSTATUS(status) == 0);

			ap.exp_process = 0;

			switch (ap.state) {
			case ST_EXPIRE:
				alarm(ap.exp_runfreq);
				/* FALLTHROUGH */
			case ST_PRUNE:
				/* If we're a submount and we've just
				   pruned or expired everything away,
				   try to shut down */
				if (submount && success && ap.state != ST_SHUTDOWN) {
					next = ST_SHUTDOWN_PENDING;
					break;
				}
				/* FALLTHROUGH */

			case ST_READY:
				next = ST_READY;
				break;

			case ST_SHUTDOWN_PENDING:
				next = ST_SHUTDOWN;
				if (success)
					break;

				/* Failed shutdown returns to ready */
				warn_r(slc, "can't shutdown: filesystem %s still busy",
				     ap.path);
				alarm(ap.exp_runfreq);
				next = ST_READY;
				break;

			default:
				error_r(slc, "bad state %d", ap.state);
			}

			if (next != ST_INVAL)
				debug_r(slc, "sigchld: exp "
				     "%d finished, switching from %d to %d",
				     pid, ap.state, next);

			continue;
		}

		/* Run through pending mount/unmounts and see what (if
		   any) has finished, and tell the kernel about it */
		for (mtp = &ap.mounts; (mt = *mtp); mtp = &mt->next) {
			if (mt->pid != pid)
				continue;

			if (!WIFEXITED(status) && !WIFSIGNALED(status))
				break;

			debug_r(slc, "found pending iop pid %d: "
				"signalled %d (sig %d), exit status %d",
				pid, WIFSIGNALED(status),
				WTERMSIG(status), WEXITSTATUS(status));

			if (WIFSIGNALED(status) || WEXITSTATUS(status) != 0)
				send_fail(mt->ioctlfd, mt->wait_queue_token);
			else {
				send_ready(mt->ioctlfd, mt->wait_queue_token);
				if (mt->me && mt->type == NFY_EXPIRE) {
					if (*mt->me->key == '/') {
						close(mt->me->ioctlfd);
						mt->me->ioctlfd = -1;
					}
					mt->me = NULL;
				}
			}

			/* Delete from list and add to freelist,
			   since we can't call free() here */
			*mtp = mt->next;
			mt->next = junk_mounts;
			junk_mounts = mt;
			break;
		}
	}

	return next;
}

/* Reap children */
static void sig_child(int sig)
{
	int save_errno = errno;
	enum states next;

	if (sig != SIGCHLD)
		return;

	next = handle_child(0);
	if (next != ST_INVAL)
		nextstate(next);

	errno = save_errno;
}

static int st_ready(void)
{
	debug("st_ready(): state = %d", ap.state);

	ap.state = ST_READY;

	return 0;
}

static int counter_fn(const char *file, const struct stat *st, int when, void *arg)
{
	int *countp = (int *) arg;

	if (S_ISLNK(st->st_mode) || (S_ISDIR(st->st_mode) && st->st_dev != ap.dev)) {
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
static enum expire expire_proc(int now)
{
	pid_t f;
	sigset_t old;

	if (ap.kver.major < 4) {
		if (now)
			umount_all(0);
		else {
			struct autofs_packet_expire pkt;

			while (ioctl(ap.ioctlfd, AUTOFS_IOC_EXPIRE, &pkt) == 0)
				handle_packet_expire(&pkt);
		}

		if (count_mounts(ap.path) != 0)
			return EXP_PARTIAL;

		return EXP_DONE;
	}

	assert(ap.exp_process == 0);

	/* Block SIGCHLD and SIGALRM between forking and setting up
	   exp_process */
	sigprocmask(SIG_BLOCK, &lock_sigs, &old);

	switch (f = fork()) {
	case 0:
		ignore_signals();
		close(ap.pipefd);
		close(ap.state_pipe[0]);
		close(ap.state_pipe[1]);

		if (ap.type == LKP_INDIRECT)
			expire_proc_indirect(now);
		else {
			int status;

			/* Generate an expire message for each direct mount. */
			status = cache_enumerate(expire_proc_direct, now);
			if (status)
				exit(1);
		}
		exit(0);
		
	case -1:
		error("fork failed: %m");
		sigprocmask(SIG_SETMASK, &old, NULL);
		return EXP_ERROR;

	default:
		debug("exp_proc=%d", f);
		ap.exp_process = f;
		sigprocmask(SIG_SETMASK, &old, NULL);
		return EXP_STARTED;
	}
}

static int st_readmap(void)
{
	int status;
	int now = time(NULL);

	assert(ap.state == ST_READY);
	ap.state = ST_READMAP;

	if (ap.type == LKP_INDIRECT)
		status = ap.lookup->lookup_ghost(ap.path,
				ap.ghost, 0, ap.lookup->context);
	else
		status = ap.lookup->lookup_enumerate(ap.path,
				do_mount_autofs_direct, now, ap.lookup->context);

	debug("status %d", status);

	ap.state = ST_READY;

	/* If I don't exist in the map any more then exit */
	if (status == LKP_FAIL)
		return 0;

	return 1;
}

static int st_prepare_shutdown(void)
{
	int exp;

	debug("state = %d\n", ap.state);

	assert(ap.state == ST_READY || ap.state == ST_EXPIRE);
	ap.state = ST_SHUTDOWN_PENDING;

	/* Turn off timeouts */
	alarm(0);

	/* Where're the boss, tell everyone to finish up */
	if (getpid() == getpgrp()) 
		signal_children(SIGUSR2);

	/* Unmount everything */
	exp = expire_proc(1);

	debug("expire returns %d\n", exp);

	switch (exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		ap.state = ST_READY;
		alarm(ap.exp_runfreq);
		return 0;

	case EXP_DONE:
		/* All expired: go straight to exit */
		ap.state = ST_SHUTDOWN;
		return 1;

	case EXP_STARTED:
		return 0;
	}
	return 1;
}

static int st_prune(void)
{
	debug("state = %d\n", ap.state);

	assert(ap.state == ST_READY);
	ap.state = ST_PRUNE;

	/* We're the boss, pass on the prune event */
	if (getpid() == getpgrp()) 
		signal_children(SIGUSR1);

	switch (expire_proc(1)) {
	case EXP_DONE:
		if (submount)
			return st_prepare_shutdown();
		/* FALLTHROUGH */

	case EXP_ERROR:
	case EXP_PARTIAL:
		ap.state = ST_READY;
		return 1;

	case EXP_STARTED:
		return 0;
	}
	return 1;
}

static int st_expire(void)
{
	debug("state = %d\n", ap.state);

	assert(ap.state == ST_READY);
	ap.state = ST_EXPIRE;

	switch (expire_proc(0)) {
	case EXP_DONE:
		if (submount)
			return st_prepare_shutdown();
		/* FALLTHROUGH */

	case EXP_ERROR:
	case EXP_PARTIAL:
		ap.state = ST_READY;
		alarm(ap.exp_runfreq);
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

static int get_pkt(int fd, union autofs_packet_union *pkt)
{
	sigset_t old;
	struct pollfd fds[2];

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	fds[1].fd = ap.state_pipe[0];
	fds[1].events = POLLIN;

	for (;;) {
		if (poll(fds, 2, -1) == -1) {
			if (errno == EINTR)
				continue;
			error("poll failed: %m");
			return -1;
		}

		if (fds[1].revents & POLLIN) {
			enum states next_state;
			int ret = 1;

			if (fullread(ap.state_pipe[0], &next_state, sizeof(next_state)))
				continue;

			sigprocmask(SIG_BLOCK, &ready_sigs, &old);
			if (next_state != ap.state) {
				debug("state %d, next %d",
					ap.state, next_state);

				switch (next_state) {
				case ST_READY:
					ret = st_ready();
					break;

				case ST_PRUNE:
					ret = st_prune();
					break;

				case ST_EXPIRE:
					ret = st_expire();
					break;

				case ST_SHUTDOWN_PENDING:
					ret = st_prepare_shutdown();
					break;

				case ST_SHUTDOWN:
					assert(ap.state == ST_SHUTDOWN ||
					       ap.state == ST_SHUTDOWN_PENDING);
					ap.state = ST_SHUTDOWN;
					break;

				case ST_READMAP:
					/* Syncronous reread of map */
					ret = st_readmap();
					if (!ret)
						ret = st_prepare_shutdown();
					break;

				default:
					error("bad next state %d", next_state);
				}
			}
			sigprocmask(SIG_SETMASK, &old, NULL);

			if (ap.state == ST_SHUTDOWN)
				return -1;
		}

		if (fds[0].revents & POLLIN) {
			int len;
			if (ap.type == LKP_INDIRECT)
				len = sizeof(pkt->missing_indirect);
			else
				len = sizeof(pkt->missing_direct);
			return fullread(fd, pkt, len);
		}
	}
}

static void do_expire(const char *name, int namelen)
{
	char buf[PATH_MAX + 1];
	int len;

	if (*name != '/') {
		len = ncat_path(buf, sizeof(buf), ap.path, name, namelen);
	} else {
		len = snprintf(buf, PATH_MAX, "%s", name);
		if (len > PATH_MAX)
			len = 0;
	}

	if (!len) {
		crit("path to long for buffer");
		return;
	}

	msg("expiring path %s", buf);

	if (umount_multi(buf, 1) == 0) {
		msg("expired %s", buf);
	} else {
		error("error while expiring %s", buf);
	}
}

int handle_expire(const char *name, int namelen, int ioctlfd, autofs_wqt_t token)
{
	sigset_t olds;
	pid_t f;
	struct pending_mount *mt = NULL;

	/* Temporarily block SIGCHLD and SIGALRM between forking and setting
	   pending (u)mount info */

	sigprocmask(SIG_BLOCK, &lock_sigs, &olds);

	/* Reclaim from doomed list if there is one */
	if ((mt = (struct pending_mount *) junk_mounts)) {
		junk_mounts = junk_mounts->next;
	} else {
		if (!(mt = malloc(sizeof(struct pending_mount)))) {
			sigprocmask(SIG_SETMASK, &olds, NULL);
			error("malloc: %m");
			return 1;
		}
	}

	f = fork();
	if (f == -1) {
		sigprocmask(SIG_SETMASK, &olds, NULL);
		error("fork: %m");
		free(mt);

		return 1;
	}
	if (f > 0) {
		mt->pid = f;
		mt->me = cache_lookup(name);
		mt->ioctlfd = ioctlfd;
		mt->type = NFY_EXPIRE;
		mt->wait_queue_token = token;
		mt->next = ap.mounts;
		ap.mounts = mt;

		sigprocmask(SIG_SETMASK, &olds, NULL);

		return 0;
	}

	/* This is the actual expire run, run as a subprocess */

	ignore_signals();
	close(ap.pipefd);
	close(ioctlfd);
	close(ap.state_pipe[0]);
	close(ap.state_pipe[1]);

	do_expire(name, namelen);

	exit(0);
}

static int handle_packet_expire(const struct autofs_packet_expire *pkt)
{
	return handle_expire(pkt->name, pkt->len, ap.ioctlfd, 0);
}

static int mount_autofs(char *path)
{
	int status = 0;

	if (path[0] == '/' && path[1] == '-')
		status = mount_autofs_direct(path);
	else
		status = mount_autofs_indirect(path);

	if (status < 0)
		return -1;

	ap.mounts = NULL;       /* No pending mounts */
	ap.state = ST_READY;

	return 0;
}

static int handle_packet(void)
{
	union autofs_packet_union pkt;

	if (get_pkt(ap.pipefd, &pkt))
		return -1;

	debug("type = %d\n", pkt.hdr.type);

	switch (pkt.hdr.type) {
	case autofs_ptype_missing_indirect:
		return handle_packet_missing_indirect(&pkt.missing_indirect);

	case autofs_ptype_missing_direct:
		return handle_packet_missing_direct(&pkt.missing_direct);

	case autofs_ptype_expire_indirect:
		return handle_packet_expire_indirect(&pkt.expire_indirect);

	case autofs_ptype_expire_direct:
		return handle_packet_expire_direct(&pkt.expire_direct);
	}
	error("unknown packet type %d\n", pkt.hdr.type);
	return -1;
}

static void become_daemon(void)
{
	FILE *pidfp;
	pid_t pid;
	int nullfd;

	/* Don't BUSY any directories unnecessarily */
	chdir("/");

	/* Detach from foreground process */
	if (!submount) {
		pid = fork();
		if (pid > 0) {
			kill(getpid(), SIGSTOP);
			exit(0);
		} else if (pid < 0) {
			fprintf(stderr, "%s: Could not detach process\n",
				program);
			exit(1);
		}
	}

	/* Open syslog */
	openlog("automount", LOG_PID, LOG_DAEMON);

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
	if (!submount && (setsid() == -1)) {
		crit("setsid: %m");
		kill(getppid(), SIGCONT);
		exit(1);
	}
	my_pgrp = getpgrp();

	/* Redirect all our file descriptors to /dev/null */
	if ((nullfd = open("/dev/null", O_RDWR)) < 0) {
		crit("cannot open /dev/null: %m");
		kill(getppid(), SIGCONT);
		exit(1);
	}

	if (dup2(nullfd, STDIN_FILENO) < 0 ||
	    dup2(nullfd, STDOUT_FILENO) < 0 || dup2(nullfd, STDERR_FILENO) < 0) {
		crit("redirecting file descriptors failed: %m");
		kill(getppid(), SIGCONT);
		exit(1);
	}
	close(nullfd);

	/* Write pid file if requested */
	if (pid_file) {
		if ((pidfp = fopen(pid_file, "wt"))) {
			fprintf(pidfp, "%lu\n", (unsigned long) my_pid);
			fclose(pidfp);
		} else {
			warn("failed to write pid file %s: %m", pid_file);
			pid_file = NULL;
		}
	}
}

/*
 * cleanup_exit() is valid to call once we have daemonized
 */

void cleanup_exit(const char *path, int exit_code)
{
	if (ap.lookup)
		close_lookup(ap.lookup);

	if (pid_file)
		unlink(pid_file);

	closelog();

	if ((!ap.ghost || !submount) && (*(path + 1) != '-') && ap.dir_created)
		if (rmdir(path) == -1)
			warn("failed to remove dir %s: %m", path);

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

static void setup_signals(__sighandler_t event_handler, __sighandler_t cld_handler)
{
	struct sigaction sa;

	if (event_handler == NULL)
		return;

	/* Signals which are only used in ST_READY state */
	sigemptyset(&ready_sigs);
	sigaddset(&ready_sigs, SIGUSR1);
	sigaddset(&ready_sigs, SIGUSR2);
	sigaddset(&ready_sigs, SIGTERM);
	sigaddset(&ready_sigs, SIGALRM);
	sigaddset(&ready_sigs, SIGHUP);

	/* Signals which are blocked to do locking */
	memcpy(&lock_sigs, &ready_sigs, sizeof(lock_sigs));
	sigaddset(&lock_sigs, SIGCHLD);

	sigemptyset(&sigchld_mask);
	sigaddset(&sigchld_mask, SIGCHLD);


	/* The following signals cause state transitions */
	sa.sa_handler = event_handler;
	memcpy(&sa.sa_mask, &ready_sigs, sizeof(sa.sa_mask));
	sa.sa_flags = SA_RESTART;

	/* SIGTERM and SIGUSR2 are synonymous */
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	/* The SIGALRM handler controls expiration of entries. */
	sigaction(SIGALRM, &sa, NULL);

	/* SIGUSR1 causes a prune event */
	sigaction(SIGUSR1, &sa, NULL);

	/* SIGHUP causes a reread of map */
	sigaction(SIGHUP, &sa, NULL);

	/* The following signals cause a shutdown event to occur, but if we
	   get more than one, permit the signal to proceed so we don't loop.
	   This is basically the complete list of "this shouldn't happen"
	   signals. */
	sa.sa_flags = SA_ONESHOT | SA_RESTART;
	sigaction(SIGIO, &sa, NULL);
	sigaction(SIGXCPU, &sa, NULL);
	sigaction(SIGXFSZ, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
#ifndef DEBUG
	/* When debugging, these signals should be in the default state; when
	   in production, we want to at least attempt to catch them and shut down. */
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGTRAP, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGPROF, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
#ifdef SIGSYS
	sigaction(SIGSYS, &sa, NULL);
#endif
#ifdef SIGSTKFLT
	sigaction(SIGSTKFLT, &sa, NULL);
#endif
#ifdef SIGLOST
	sigaction(SIGLOST, &sa, NULL);
#endif
#ifdef SIGEMT
	sigaction(SIGEMT, &sa, NULL);
#endif
#endif				/* DEBUG */

	if (cld_handler != NULL) {
		/* The SIGCHLD handler causes state transitions as
		 * processes exit (expire and mount) */
		sa.sa_handler = cld_handler;
		memcpy(&sa.sa_mask, &lock_sigs, sizeof(sa.sa_mask));
		/* Don't need info about stopped children */
		sa.sa_flags = SA_NOCLDSTOP;
		sigaction(SIGCHLD, &sa, NULL);
	}

	/* The following signals shouldn't occur, and are ignored */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGVTALRM, &sa, NULL);
	sigaction(SIGURG, &sa, NULL);
	sigaction(SIGWINCH, &sa, NULL);
#ifdef SIGPWR
	sigaction(SIGPWR, &sa, NULL);
#endif
#ifdef SIGUNUSED
	sigaction(SIGUNUSED, &sa, NULL);
#endif
}

int handle_mounts(char *path)
{
	if (mount_autofs(path) < 0) {
		crit("%s: mount failed!", path);
		umount_autofs(1);
		kill(getppid(), SIGCONT);
		cleanup_exit(path, 1);
	}

	setup_signals(sig_statemachine, sig_child);

	/* We often start several automounters at the same time.  Add some
	   randomness so we don't all expire at the same time. */
	if (ap.exp_timeout)
		alarm(ap.exp_runfreq + my_pid % ap.exp_runfreq);

	if (ap.ghost && ap.type != LKP_DIRECT)
		msg("ghosting enabled");

	/* Initialization successful.  If we're a submount, send outselves
	   SIGSTOP to let our parent know that we have grown up and don't
	   need supervision anymore. */
	if (submount)
		kill(my_pid, SIGSTOP);

	kill(getppid(), SIGCONT);

	while (ap.state != ST_SHUTDOWN) {
		if (handle_packet()) {
			sigset_t olds;
			int ret, status = 0;

			sigprocmask(SIG_BLOCK, &lock_sigs, &olds);
			ret = ioctl(ap.ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
			/*
			 * If the ioctl fails assume the kernel doesn't have
			 * AUTOFS_IOC_ASKUMOUNT and just continue.
			 */
			if (ret) {
				sigprocmask(SIG_SETMASK, &olds, NULL);
				break;
			}
			if (status) {
				sigprocmask(SIG_SETMASK, &olds, NULL);
				break;
			}

			/* Failed shutdown returns to ready */
			warn("can't shutdown: filesystem %s still busy",
					ap.path);
			alarm(ap.exp_runfreq);
			ap.state = ST_READY;
			sigprocmask(SIG_SETMASK, &olds, NULL);
		}
	}

	/* Mop up remaining kids */
	handle_child(1);

	/* Close down */
	umount_autofs(1);

	return 0;
}

int main(int argc, char *argv[])
{
	char *path, *map, *mapfmt;
	const char **mapargv;
	int mapargc, opt, res;
	struct rlimit rlim;
	static const struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"pid-file", 1, 0, 'p'},
		{"timeout", 1, 0, 't'},
		{"verbose", 0, 0, 'v'},
		{"debug", 0, 0, 'd'},
		{"version", 0, 0, 'V'},
		{"ghost", 0, 0, 'g'},
		{"submount", 0, &submount, 1},
		{0, 0, 0, 0}
	};

	program = argv[0];

	memset(&ap, 0, sizeof ap);	/* Initialize ap so we can test for null */
	ap.exp_timeout = DEFAULT_TIMEOUT;
	ap.ghost = DEFAULT_GHOST_MODE;
	ap.type = LKP_INDIRECT;
	ap.dir_created = 0; /* We haven't created the main directory yet */

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
			do_verbose = 1;
			break;

		case 'd':
			do_debug = 1;
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
		fprintf(stderr, "%s: This program must be run by root.\n", program);
		exit(1);
	}

	/* Remove the options */
	argv += optind;
	argc -= optind;

	if (argc < 2) {
		usage();
		exit(1);
	}

	become_daemon();

	path = argv[0];
	map = argv[1];
	mapargv = (const char **) &argv[2];
	mapargc = argc - 2;

	msg("starting automounter version %s, path = %s, "
	       "maptype = %s, mapname = %s", version, path, map,
	       (mapargc < 1) ? "none" : mapargv[0]);

#ifdef DEBUG
	if (mapargc) {
		int i;
		syslog(LOG_DEBUG, "Map argc = %d", mapargc);
		for (i = 0; i < mapargc; i++)
			syslog(LOG_DEBUG, "Map argv[%d] = %s", i, mapargv[i]);
	}
#endif

	if ((mapfmt = strchr(map, ',')))
		*(mapfmt++) = '\0';

	ap.maptype = map;

	rlim.rlim_cur = MAX_OPEN_FILES;
	rlim.rlim_max = MAX_OPEN_FILES;
	res = setrlimit(RLIMIT_NOFILE, &rlim);
	if (res)
		warn("can't increase open file limit - continuing");

	if (!(ap.lookup = open_lookup(map, "", mapfmt, mapargc, mapargv))) {
		kill(getppid(), SIGCONT);
		cleanup_exit(path, 1);
	}

	handle_mounts(path);

	msg("shut down, path = %s", path);

	cleanup_exit(path, 0);
	exit(0);
}
