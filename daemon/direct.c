#ident "$Id: direct.c,v 1.3 2006/02/10 00:50:42 raven Exp $"
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
#include <sys/mount.h>
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

extern pthread_mutex_t pending_mutex;
extern struct pending_mount *pending;

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

static int do_umount_autofs_direct(struct mapent_cache *me)
{
	char buf[MAX_ERR_BUF];
	int rv, left, ret;
	int status = 1;
	struct stat st;

	left = umount_multi(me->key, 1);
	if (left) {
		warn("could not unmount %d dirs under %s", left, me->key);
		return -1;
	}

	if (me->ioctlfd < 0)
		me->ioctlfd = open(me->key, O_RDONLY);

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
		msg("forcing unmount of %s", me->key);
	} else
		msg("umounted %s", me->key);

	if (!rv && me->dir_created) {
		if  (rmdir(me->key) == -1) {
			if (strerror_r(errno, buf, MAX_ERR_BUF))
				strcpy(buf, "strerror_r failed");
			warn("failed to remove dir %s: %s", me->key, buf);
		}
	}
	return rv;
}

int umount_autofs_direct(void)
{
	struct mapent_cache *me;

	close(ap.state_pipe[0]);
	close(ap.state_pipe[1]);
	if (ap.pipefd >= 0)
		close(ap.pipefd);
	if (ap.kpipefd >= 0) {
		close(ap.kpipefd);
		ap.kpipefd = -1;
	}

	me = cache_enumerate(NULL);
	while (me) {
		do_umount_autofs_direct(me);
		me = cache_enumerate(me);
	}
	free(ap.path);

	return 0;
}

int do_mount_autofs_direct(struct mapent_cache *me, int now)
{
	time_t timeout = ap.exp_timeout;
	char our_name[MAX_MNT_NAME_LEN];
	int name_len = MAX_MNT_NAME_LEN;
	struct stat st;
	int len, ret;

	/* Handle cleanup for HUP signal */
	if (me->age < now) {
		/* Silently fail */
/*		if (do_umount_autofs_direct(me, 0)) 
			return 0;
*/
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
/*
	ret = mount(our_name, me->key, "autofs", MS_MGC_VAL, options);
	if (ret) {
		crit("failed to mount autofs path %s", me->key);
		goto out_err;
	}
*/

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

	ret = fstat(me->ioctlfd, &st);
	if (ret == -1) {
		error("failed to stat direct mount trigger %s", me->key);
		goto out_umount;
	}
	cache_set_ino(me, st.st_dev, st.st_ino);
	cache_set_ino_index(me->key, st.st_dev, st.st_ino);

	close(me->ioctlfd);
	me->ioctlfd = -1;

	debug("mounted trigger %s", me->key);

	return 0;

out_close:
	close(me->ioctlfd);
	me->ioctlfd = -1;
out_umount:
	/* TODO: maybe force umount (-l) */
/*	spawnl(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", me->key, NULL); */
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
	char buf[MAX_ERR_BUF];
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
		msg("forcing unmount of %s", me->key);
	} else
		msg("umounted %s", me->key);

	if (!rv && me->dir_created) {
		if  (rmdir(me->key) == -1) {
			if (strerror_r(errno, buf, MAX_ERR_BUF))
				strcpy(buf, "strerror_r failed");
			warn("failed to remove dir %s: %s", me->key, buf);
		}
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

	ret = fstat(me->ioctlfd, &st);
	if (ret == -1) {
		error("failed to stat direct mount trigger %s", me->key);
		goto out_umount;
	}
	cache_set_ino(me, st.st_dev, st.st_ino);
	cache_set_ino_index(me->key, st.st_dev, st.st_ino);

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

void *expire_proc_direct(void *arg)
{
	struct mnt_list *mnts, *next;
	struct mapent_cache *me;
	unsigned int now;
	int ret, status = 0;

	pthread_cleanup_push(handle_cleanup, &status);

	status = pthread_cond_wait(&ec.cond, &ec.mutex);
	if (status) {
		error("expire condition wait failed");
		pthread_exit(NULL);
	}

	now = ec.when;

	status = pthread_mutex_unlock(&ec.mutex);
	if (status) {
		error("failed to unlock expire cond mutex");
		pthread_exit(NULL);
	}

	/* Get a list of real mounts and expire them if possible */
	mnts = get_mnt_list(_PROC_MOUNTS, "/", 0);
	for (next = mnts; next; next = next->next) {
		if (!strcmp(next->fs_type, "autofs"))
			continue;

		/*
		 * All direct mounts must be present in the map
		 * entry cache.
		 */
		me = cache_lookup(next->path);
		if (!me)
			continue;

		debug("send expire to trigger %s", me->key);

		/* Finally generate an expire message for the direct mount. */
		ret = ioctl(me->ioctlfd, AUTOFS_IOC_EXPIRE_DIRECT, &now);
		if (ret < 0 && errno != EAGAIN) {
			debug("failed to expire mount %s", me->key);
			status = 1;
			goto done;
		}
	}
done:
	free_mnt_list(mnts);

	pthread_cleanup_pop(1);
	return NULL;
}

static void *do_expire_direct(void *arg)
{
	struct mapent_cache *me = (struct mapent_cache *) arg;
	int len;
	int status = 0;

	pthread_cleanup_push(handle_cleanup, &status);

	len = _strlen(me->key, PATH_MAX);
	if (!len) {
		warn("direct key path too long %s", me->key);
		pthread_exit(NULL);
	}

	status = do_expire(me->key, len);

	pthread_cleanup_pop(1);
	return NULL;
}

int handle_packet_expire_direct(autofs_packet_expire_direct_t *pkt)
{
	struct mapent_cache *me;
	struct pending_mount *mt;
	char buf[MAX_ERR_BUF];
	pthread_t thid;
	int status;

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
	me = cache_lookup_ino(pkt->dev, pkt->ino);
	if (!me) {
		/*
		 * Shouldn't happen as we have been sent this following
		 * successful thread creation and lookup.
		 */
		crit("can't find map entry for (%lu,%lu)",
		    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		pthread_exit(NULL);
	}

	debug("token %ld, name %s\n",
		  (unsigned long) pkt->wait_queue_token, me->key);

	status = pthread_mutex_lock(&pending_mutex);
	if (status) {
		error("pending mutex lock failed");
		goto out_error;
	}

	if ((mt = (struct pending_mount *) pending)) {
		pending = pending->next;
	} else if (!(mt = malloc(sizeof(struct pending_mount)))) {
		if (strerror_r(errno, buf, MAX_ERR_BUF))
			strcpy(buf, "strerror_r failed");
		error("malloc: %s", buf);
		goto out_error;
	}

	status = pthread_create(&thid, NULL, do_expire_direct, me);
	if (status) {
		error("expire thread create failed");
		status = pthread_mutex_unlock(&pending_mutex);
		if (status)
			error("pending mutex unlock failed");
		free(mt);
		goto out_error;
	}

	mt->thid = thid;
	mt->me = me;
	mt->ioctlfd = me->ioctlfd;
	mt->type = NFY_EXPIRE;
	mt->wait_queue_token = pkt->wait_queue_token;
	mt->next = ap.mounts;
	ap.mounts = mt;

	status = pthread_mutex_unlock(&pending_mutex);
	if (status) {
		error("pending mutex unlock failed");
	/*	send_fail(me->ioctlfd, pkt->wait_queue_token); */
		return 1;
	}
	return 0;

out_error:
	send_fail(me->ioctlfd, pkt->wait_queue_token);
	return 1;
}

static void *do_mount_direct(void *arg)
{
	int err, status = 1;
	struct passwd *u_pwd;
	struct group *u_grp;
	char env_buf[30];
	autofs_packet_missing_direct_t *pkt;
	struct mapent_cache *me;
	struct stat st;

	pthread_cleanup_push(handle_cleanup, &status);

	pkt = (autofs_packet_missing_direct_t *) arg;
	me = cache_lookup_ino(pkt->dev, pkt->ino);
	if (!me) {
		/*
		 * Shouldn't happen as the kernel is telling us
		 * someone has walked on our mount point.
		 */
		crit("can't find map entry for (%lu,%lu)",
		    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		pthread_exit(NULL);
	}

	err = fstat(me->ioctlfd, &st);
	if (err == -1) {
		error("can't stat direct mount trigger %s", me->key);
		pthread_exit(NULL);
	}
	if (!S_ISDIR(st.st_mode) || st.st_dev != pkt->dev) {
		error("direct mount trigger is not valid mount point %s", me->key);
		pthread_exit(NULL);
	}

	msg("attempting to mount entry %s", me->key);

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

	status = ap.lookup->lookup_mount(NULL, me->key, strlen(me->key),
				      ap.lookup->context);
	/*
	 * Direct mounts are always a single mount. If it fails there's
	 * nothing to undo so just complain
	 */
	if (status)
		error("failed to mount %s", me->key);
	else
		msg("mounted %s", me->key);

	pthread_cleanup_pop(1);
	return NULL;
}

int handle_packet_missing_direct(autofs_packet_missing_direct_t *pkt)
{
	pthread_t thid;
	struct pending_mount *mt = NULL;
	struct mapent_cache *me;
	char buf[MAX_ERR_BUF];
	int status = 0;
	int ioctlfd;

	me = cache_lookup_ino(pkt->dev, pkt->ino);
	if (!me) {
		/*
		 * Shouldn't happen as the kernel is telling us
		 * someone has walked on our mount point.
		 */
		crit("can't find map entry for (%lu,%lu)",
		    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		return 1;
	}

	ioctlfd = open(me->key, O_RDONLY);
	if (ioctlfd < 0) {
		crit("failed to create ioctl fd for %s", me->key);
		/* TODO:  how do we clear wait q in kernel ?? */
		return 1;
	}
	me->ioctlfd = ioctlfd;

	debug("token %ld, name %s\n",
		  (unsigned long) pkt->wait_queue_token, me->key);

	/* Ignore packet if we're trying to shut down */
	if (ap.state == ST_SHUTDOWN_PENDING || ap.state == ST_SHUTDOWN)
		goto out_close;

	status = pthread_mutex_lock(&pending_mutex);
	if (status) {
		error("pending mutex lock failed");
		status = 1;
		goto out_close;
	}


	if ((mt = (struct pending_mount *) pending)) {
		pending = pending->next;
	} else {
		if (!(mt = malloc(sizeof(struct pending_mount)))) {
			if (strerror_r(errno, buf, MAX_ERR_BUF))
				strcpy(buf, "strerror_r failed");
			error("malloc: %s", buf);
			status = 1;
			goto out_unlock;
		}
	}

	status = pthread_create(&thid, NULL, do_mount_direct, pkt);
	if (status) {
		error("missing mount thread create failed");
		free(mt);
		status = 1;
		goto out_unlock;
	}

	mt->thid = thid;
	mt->me = me;
	mt->ioctlfd = me->ioctlfd;
	mt->type = NFY_MOUNT;
	mt->wait_queue_token = pkt->wait_queue_token;
	mt->next = ap.mounts;
	ap.mounts = mt;

	status = pthread_mutex_unlock(&pending_mutex);
	if (status) {
		error("pending mutex unlock failed");
/*		send_fail(me->ioctlfd, pkt->wait_queue_token); */
		status = 1;
	}
	return 0;

out_unlock:
	status = pthread_mutex_unlock(&pending_mutex);
	if (status)
		error("pending mutex unlock failed");
out_close:
	send_fail(me->ioctlfd, pkt->wait_queue_token);
	close(me->ioctlfd);
	me->ioctlfd = -1;
/*	spawnl(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", me->key, NULL); */
	return status;
}

