#ident "$Id: direct.c,v 1.1 2005/11/27 04:08:54 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  direct.c - Linux automounter direct mount handling
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <pwd.h>
#include <grp.h>

#include "automount.h"

#define MAX_OPTIONS_LEN			128
#define MAX_MNT_NAME_LEN		128
#define REMOUNT_OPTIONS_LEN		30

static char options[MAX_OPTIONS_LEN];	/* common mount options string */
/*
static int kernel_pipefd = -1;		kernel pipe fd for use in direct mounts
*/

extern int submount;

extern sigset_t ready_sigs;		/* signals only accepted in ST_READY */
extern sigset_t lock_sigs;		/* signals blocked for locking */
extern sigset_t sigchld_mask;

extern volatile struct pending_mount *junk_mounts;

static int autofs_init_direct(char *path)
{
	int pipefd[2];

	if ((ap.state != ST_INIT)) {
		/* This can happen if an autofs process is already running*/
		error("bad state %d", ap.state);
		return -1;
	}

	/* Must be an absolute pathname */
	if (path[0] != '/' && path[1] != '-') {
		crit("invalid direct mount key %s", ap.path);
		errno = EINVAL;
		return -1;
	}

	ap.path = strdup(path);
	if (!ap.path) {
		crit("memory alloc failed");
		errno = ENOMEM;
		return -1;
	}
	ap.pipefd = ap.kpipefd = ap.ioctlfd = -1;

	/* Pipe for kernel communications */
	if (pipe(pipefd) < 0) {
		crit("failed to create commumication pipe for autofs path %s",
		     ap.path);
		free(ap.path);
		return -1;
	}

	ap.pipefd = pipefd[0];
	ap.kpipefd = pipefd[1];

	/* Pipe state changes from signal handler to main loop */
	if (pipe(ap.state_pipe) < 0) {
		crit("failed create state pipe for autofs path %s", ap.path);
		close(ap.pipefd);
		close(ap.kpipefd);
		free(ap.path);
		return -1;
	}
	return 0;
}

static int do_umount_autofs_direct(struct mapent_cache *me, int dummy)
{
	int rv, left, ret;
	int status = 1;
	struct stat st;

	left = umount_multi(me->key, 1);
	if (left) {
		warn("could not unmount %d dirs under %s", left, me->key);
		return -1;
	}

	if (me->ioctlfd < 0) {
		warn("ioctlfd not set at umount for %s", me->key);
		me->ioctlfd = open(me->key, O_RDONLY);
	}

	if (me->ioctlfd >= 0) {
		ioctl(me->ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
		ioctl(me->ioctlfd, AUTOFS_IOC_CATATONIC, 0);
		close(me->ioctlfd);
	}

	if (!status) {
		rv = 1;
		goto force_umount;
	}

	rv = spawnl(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", me->key, NULL);
	ret = stat(me->key, &st);
	if (rv != 0) {
		if (ret == -1 && errno == ENOENT) {
			error("mount point does not exist");
			return 0;
		}
		goto force_umount;
	}

	if (ret == 0 && !S_ISDIR(st.st_mode)) {
		error("mount point is not a directory");
		return 0;
	}

force_umount:
	if (rv != 0) {
		rv = spawnl(LOG_DEBUG,
			    PATH_UMOUNT, PATH_UMOUNT, "-n", "-l", me->key, NULL);
		msg("forcing unmount of %s\n", me->key);
	} else
		msg("umounted %s", me->key);

	if (!rv && me->dir_created) {
		if  (rmdir(me->key) == -1)
			warn("failed to remove dir %s: %m", me->key);
	}
	return rv;
}

int umount_autofs_direct(void)
{
	close(ap.state_pipe[0]);
	close(ap.state_pipe[1]);
	if (ap.pipefd >= 0)
		close(ap.pipefd);
	if (ap.kpipefd >= 0) {
		close(ap.kpipefd);
		ap.kpipefd = -1;
	}

	cache_enumerate(do_umount_autofs_direct, 0);

	free(ap.path);

	return 0;
}

int do_mount_autofs_direct(struct mapent_cache *me, int now)
{
	time_t timeout = ap.exp_timeout;
	char our_name[MAX_MNT_NAME_LEN];
	int name_len = MAX_MNT_NAME_LEN;
	int len;

	/* Handle cleanup for HUP signal */
	if (me->age < now) {
		/* Silently fail */
		if (do_umount_autofs_direct(me, 0))
			return 0;

		if (cache_delete(_PROC_MOUNTS, NULL, me->key, 1))
			return -1;

		return 0;
	}

	if (is_mounted(_PROC_MOUNTS, me->key)) {
		debug("trigger %s already mounted", me->key);
		return 0;
	}

	len = snprintf(our_name, name_len,
			"automount(pid%u)", (unsigned) getpid());

	if (len >= name_len) {
		crit("buffer to small for our_name - truncated");
		len = name_len - 1;
	}
        if (len < 0) {
                crit("failed setting up our_name for autofs path %s", me->key);
                return 0;
        }
	our_name[len] = '\0';

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(me->key, 0555) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit("failed to create mount directory %s", me->key);
			return -1;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		me->dir_created = 0;
	} else {
		/* No errors so the directory was successfully created */
		me->dir_created = 1;
	}

	if (spawnl(LOG_DEBUG, PATH_MOUNT, PATH_MOUNT,
		   "-t", "autofs", "-n", "-o", options, our_name, me->key, NULL) != 0) {
		crit("failed to mount autofs path %s", me->key);
		goto out_err;
	}

	/* Root directory for ioctl()'s */
	me->ioctlfd = open(me->key, O_RDONLY);
	if (me->ioctlfd < 0) {
		crit("failed to create ioctl fd for %s", me->key);
		goto out_umount;
	}

	/* Only calculate this first time round */
	if (ap.kver.major)
		goto got_version;

	ap.kver.major = 0;
	ap.kver.minor = 0;

	/* If this ioctl() doesn't work, it is kernel version 2 */
	if (!ioctl(me->ioctlfd, AUTOFS_IOC_PROTOVER, &ap.kver.major)) {
		 /* If this ioctl() fails the kernel doesn't support direct mounts */
		 if (ioctl(me->ioctlfd, AUTOFS_IOC_PROTOSUBVER, &ap.kver.minor)) {
			ap.kver.minor = 0;
			ap.ghost = 0;
		 }
	}

	msg("using kernel protocol version %d.%02d", ap.kver.major, ap.kver.minor);

	if (ap.kver.major < 5) {
		crit("kernel does not support direct mounts");
		goto out_close;
	}

	/* Calculate the timeouts */
	ap.exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;

	if (timeout) {
		msg("using timeout %d seconds; freq %d secs",
			(int) ap.exp_timeout, (int) ap.exp_runfreq);
	} else {
		msg("timeouts disabled");
	}

got_version:
	ioctl(me->ioctlfd, AUTOFS_IOC_SETTIMEOUT, &timeout);

	close(me->ioctlfd);
	me->ioctlfd = -1;

	debug("mounted trigger %s", me->key);

	return 0;

out_close:
	close(me->ioctlfd);
	me->ioctlfd = -1;
out_umount:
	/* TODO: maybe force umount (-l) */
	spawnl(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", me->key, NULL);
out_err:
	if (me->dir_created)
		rmdir(me->key);

	return -1;
}

int mount_autofs_direct(char *path)
{
	int map;
	time_t now = time(NULL);

	if (autofs_init_direct(path))
		return -1;

	if (!make_options_string(options, MAX_OPTIONS_LEN, ap.kpipefd, "direct")) {
		close(ap.state_pipe[0]);
		close(ap.state_pipe[1]);
		close(ap.pipefd);
		close(ap.kpipefd);
		free(ap.path);
		return -1;
	}

	ap.type = LKP_DIRECT;

	map = ap.lookup->lookup_enumerate(path,
			do_mount_autofs_direct, now, ap.lookup->context);
	if (map & LKP_FAIL) {
		if (map & LKP_INDIRECT) {
			error("bad map format, found indirect, expected direct exiting");
		} else {
			error("failed to load map, exiting");
		}
		return -1;
	}
	return 0;
}

int umount_autofs_offset(struct mapent_cache *me)
{
	int rv, ret;
	struct stat st;

	if (me->ioctlfd < 0)
		me->ioctlfd = open(me->key, O_RDONLY);

	if (me->ioctlfd >= 0) {
		int status = 1;

		ioctl(me->ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
		if (!status) {
			debug("ask umount returned busy");
			return 1;
		}

		ioctl(me->ioctlfd, AUTOFS_IOC_CATATONIC, 0);
		close(me->ioctlfd);
	} else {
		error("couldn't get ioctl fd for offset %s", me->key);
		rv = 1;
		goto force_umount;
	}

	rv = spawnl(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", me->key, NULL);
	ret = stat(me->key, &st);
	if (rv != 0) {
		if (ret == -1 && errno == ENOENT) {
			error("mount point does not exist");
			return 0;
		}
		goto force_umount;
	}

	if (ret == 0 && !S_ISDIR(st.st_mode)) {
		error("mount point is not a directory");
		return 0;
	}

force_umount:
	if (rv != 0) {
		rv = spawnl(LOG_DEBUG,
			    PATH_UMOUNT, PATH_UMOUNT, "-n", "-l", me->key, NULL);
		msg("forcing unmount of %s\n", me->key);
	} else
		msg("umounted %s", me->key);

	if (!rv && me->dir_created) {
		if  (rmdir(me->key) == -1)
			warn("failed to remove dir %s: %m", me->key);
	}
	return rv;
}

int mount_autofs_offset(struct mapent_cache *me, int is_autofs_fs)
{
	time_t timeout = ap.exp_timeout;
	char our_name[MAX_MNT_NAME_LEN];
	int name_len = MAX_MNT_NAME_LEN;
	struct stat st;
	int len, ret;

	if (!make_options_string(options, MAX_OPTIONS_LEN, ap.kpipefd, "offset"))
		return -1;

	if (is_mounted(_PROC_MOUNTS, me->key)) {
		debug("trigger %s already mounted", me->key);
		return 0;
	}

	len = snprintf(our_name, name_len,
			"automount(pid%u)", (unsigned) getpid());

	if (len >= name_len) {
		crit("buffer to small for our_name - truncated");
		len = name_len - 1;
	}
        if (len < 0) {
                crit("failed setting up our_name for autofs path %s", me->key);
                return 0;
        }
	our_name[len] = '\0';

	if (is_autofs_fs) {
		/* In case the directory doesn't exist, try to mkdir it */
		if (mkdir_path(me->key, 0555) < 0) {
			if (errno != EEXIST) {
				crit("failed to create mount directory %s",
				     me->key);
				return -1;
			}
			/* 
			 * If we recieve an error, and it's EEXIST
			 * we know the directory was not created.
			 */
			me->dir_created = 0;
		} else {
			/* No errors so the directory was successfully created */
			me->dir_created = 1;
		}
	} else {
		me->dir_created = 0;

		/*
		 * We require the mount point directory to exist when
		 * installing multi-mount triggers into a host filesystem.
		 *
		 * If it doesn't exist it is not a valid part of the
		 * mount heirachy so we silently succeed here.
		 */
		if (stat(me->key, &st) == -1 && errno == ENOENT)
			return 0;
	}

	debug("calling mount -t autofs " SLOPPY "-o %s %s %s",
		options, our_name, me->key);

	ret = spawnl(LOG_DEBUG, PATH_MOUNT, PATH_MOUNT, "-t", "autofs",
			 "-n", SLOPPYOPT "-o", options, our_name, me->key, NULL);
	if (ret != 0) {
		crit("failed to mount autofs offset trigger %s", me->key);
		goto out_err;
	}

	/* Root directory for ioctl()'s */
	me->ioctlfd = open(me->key, O_RDONLY);
	if (me->ioctlfd < 0) {
		crit("failed to create ioctl fd for %s", me->key);
		goto out_umount;
	}

	ioctl(me->ioctlfd, AUTOFS_IOC_SETTIMEOUT, &timeout);

	close(me->ioctlfd);
	me->ioctlfd = -1;

	debug("mounted trigger %s", me->key);

	return 0;

out_umount:
	spawnl(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", me->key, NULL);
out_err:
	if (me->dir_created)
		rmdir_path(me->key);

	return -1;
}

int expire_offsets_direct(struct mapent_cache *me, int now)
{
	struct list_head *p;
	struct mapent_cache *ee;
	int status, ret = 0;

	/* If it's not a top level multi-mount return success */
	if (!me->multi || me->multi != me)
		return 0;

	list_for_each_prev(p, &me->multi_list) {
		ee = list_entry(p, struct mapent_cache, multi_list);

		/* Leave the root entry for the normal expire */ 
		if (ee == me || ee->key[strlen(ee->key) - 1] == '/')
			continue;

		/* No mount => no expire needed */
		if (ee->ioctlfd < 0)
			continue;

		debug("check expiry of %s", ee->key);

		/*
		 * expire the direct offset
		 * the expire umounts offsets prior to umounting the entry
		 */
		status = ioctl(ee->ioctlfd, AUTOFS_IOC_EXPIRE_DIRECT, &now);
		if (status < 0 && errno != EAGAIN) {
			debug("failed sending expire to mount %s", ee->key);
			ret++;
		}
	}

	return ret;
}

int expire_proc_direct(struct mapent_cache *me, int now)
{
	int status;

	/* If there's not mount we don't need to send an expire */
	if (me->ioctlfd < 0)
		return 0;

	debug("attempting to expire offset mounts %s", me->key);

	/* attempt to expire away multi-mount entries below */
	status = expire_offsets_direct(me, now);
	if (status) {
		debug("multi-mount %s is busy", me->key);
		return 1;
	}

	/* Generate an expire message for the direct mount. */

	debug("sending expire to trigger %s", me->key);

	status = ioctl(me->ioctlfd, AUTOFS_IOC_EXPIRE_DIRECT, &now);
	if (status < 0 && errno != EAGAIN) {
		debug("failed sending expire to mount %s", me->key);
		return 1;
	}
	return 0;
}

int handle_packet_expire_direct(const struct autofs_packet_expire_direct *pkt)
{
	int ret;
	struct mapent_cache *me;
	char *path;

	/*
	 * This is a bit of a big deal.
	 * If we can't find the path and the map entry then
	 * we can't send a notification back to the kernel.
	 * Hang results.
	 *
	 * OTOH there is a mount so there should be a path
	 * and since it got mounted we have to trust that
	 * there is an entry in the cache.
	 */
	path = find_mnt_ino(_PROC_MOUNTS, pkt->dev, pkt->ino);
	if (!path) {
		/*
		 * Shouldn't happen as the kernel is telling there
		 * is something to expire.
		 */
		crit("can't find path for mount to expire");
		return 1;
	}

	me = cache_lookup(path);
	if (!me) {
		crit("entry cache corrupt - can't find map entry for %s", path);
		free(path);
		/* TODO:  umount to as it's not in map ?? */
		return 1;
	}
	free(path);

	debug("token %ld, name %s\n",
		  (unsigned long) pkt->wait_queue_token, me->key);

	ret = handle_expire(me->key, strlen(me->key),
			    me->ioctlfd, pkt->wait_queue_token);

	if (ret != 0)
		send_fail(me->ioctlfd, pkt->wait_queue_token);

	return ret;
}

int handle_packet_missing_direct(const struct autofs_packet_missing_direct *pkt)
{
	struct stat st;
	sigset_t oldsig;
	pid_t f;
	struct pending_mount *mt = NULL;
	struct mapent_cache *me;
	int status = 0;
	int ioctlfd;
	char *path;

	path = find_mnt_ino(_PROC_MOUNTS, pkt->dev, pkt->ino);
	if (!path) {
		/*
		 * Shouldn't happen as the kernel is telling us
		 * someone has walked on our mount point.
		 */
		crit("can't find path for mount to expire");
		return 1;
	}

	ioctlfd = open(path, O_RDONLY);
	if (ioctlfd < 0) {
		crit("failed to create ioctl fd for %s", path);
		/* TODO:  umount to clear wait q in kernel ?? */
		free(path);
		return 1;
	}

	me = cache_lookup(path);
	if (!me) {
		crit("can't find map entry for %s", path);
		send_fail(ioctlfd, pkt->wait_queue_token);
		free(path);
		close(ioctlfd);
		/* TODO:  umount to as it's not in map ?? */
		return 1;
	}
	free(path);
	me->ioctlfd = ioctlfd;

	debug("token %ld, name %s\n",
		  (unsigned long) pkt->wait_queue_token, me->key);

	/* Ignore packet if we're trying to shut down */
	if (ap.state == ST_SHUTDOWN_PENDING || ap.state == ST_SHUTDOWN) {
		send_fail(me->ioctlfd, pkt->wait_queue_token);
		goto out_close;
	}

	/* TODO: check out "dev" */
	if (fstat(me->ioctlfd, &st) == -1 ||
	   (S_ISDIR(st.st_mode) && st.st_dev == pkt->dev)) {
		/* Block SIGCHLD while mucking with linked lists */
		sigprocmask(SIG_BLOCK, &sigchld_mask, NULL);
		if ((mt = (struct pending_mount *) junk_mounts)) {
			junk_mounts = junk_mounts->next;
		} else {
			if (!(mt = malloc(sizeof(struct pending_mount)))) {
				error("malloc: %m");
				send_fail(me->ioctlfd, pkt->wait_queue_token);
				status = 1;
				goto out_close;
			}
		}
		sigprocmask(SIG_UNBLOCK, &sigchld_mask, NULL);

		msg("attempting to mount entry %s", me->key);

		sigprocmask(SIG_BLOCK, &lock_sigs, &oldsig);

		f = fork();
		if (f == -1) {
			sigprocmask(SIG_SETMASK, &oldsig, NULL);
			error("fork: %m");
			send_fail(me->ioctlfd, pkt->wait_queue_token);
			free(mt);
			status = 1;
			goto out_close;
		} else if (!f) {
			int err;
			struct passwd *u_pwd;
			struct group *u_grp;
			char env_buf[12];

			/* Set up a sensible signal environment */
			ignore_signals();
			/* close(ap.pipefd); */
			/* close(ap.kpipefd); */
			close(ap.state_pipe[0]);
			close(ap.state_pipe[1]);
			close(me->ioctlfd);

			/*
			 * Setup ENV for mount.
			 * Best effort only as it must go ahead.
			 */
			sprintf(env_buf, "%lu", (unsigned long) pkt->uid);
			setenv("UID", env_buf, 1);
			u_pwd = getpwuid(pkt->uid);
			if (u_pwd) {
				setenv("USER", u_pwd->pw_name, 1);
				setenv("HOME", u_pwd->pw_dir, 1);
			}

			sprintf(env_buf, "%lu", (unsigned long) pkt->gid);
			setenv("GID", env_buf, 1);
			u_grp = getgrgid(pkt->gid);
			if (u_grp)
				setenv("GROUP", u_grp->gr_name, 1);

			err = ap.lookup->lookup_mount(NULL,
					      me->key, strlen(me->key),
					      ap.lookup->context);
			/*
			 * Direct mounts are always a single mount.
			 * If it fails there's nothing to undo so
			 * just complain
			 */
			if (err)
				error("failed to mount %s", me->key);
			else
				msg("mounted %s", me->key);

			_exit(err ? 1 : 0);
		} else {
			/*
			 * Important: set up data structures while signals
			 * still blocked
			 */
			mt->pid = f;
			mt->me = me;
			mt->ioctlfd = me->ioctlfd;
			mt->type = NFY_MOUNT;
			mt->wait_queue_token = pkt->wait_queue_token;
			mt->next = ap.mounts;
			ap.mounts = mt;

			sigprocmask(SIG_SETMASK, &oldsig, NULL);
		}
	}
	return 0;

out_close:
	close(me->ioctlfd);
	me->ioctlfd = -1;
	spawnl(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", me->key, NULL);

	return status;
}

