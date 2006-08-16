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
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>

#include "automount.h"

extern pthread_attr_t thread_attr;

struct mnt_params {
	char *options;
};

pthread_key_t key_mnt_direct_params;
pthread_key_t key_mnt_offset_params;
pthread_once_t key_mnt_params_once = PTHREAD_ONCE_INIT;

static void key_mnt_params_destroy(void *arg)
{
	struct mnt_params *mp;

	mp = (struct mnt_params *) arg;
	if (mp->options)
		free(mp->options);
	free(mp);
	return;
}

static void key_mnt_params_init(void)
{
	int status;

	status = pthread_key_create(&key_mnt_direct_params, key_mnt_params_destroy);
	if (status)
		fatal(status);

	status = pthread_key_create(&key_mnt_offset_params, key_mnt_params_destroy);
	if (status)
		fatal(status);

	return;
}

static int autofs_init_direct(struct autofs_point *ap)
{
	int pipefd[2];

	if ((ap->state != ST_INIT)) {
		/* This can happen if an autofs process is already running*/
		error(ap->logopt, "bad state %d", ap->state);
		return -1;
	}

	ap->pipefd = ap->kpipefd = ap->ioctlfd = -1;

	/* Pipe for kernel communications */
	if (pipe(pipefd) < 0) {
		crit(ap->logopt,
		     "failed to create commumication pipe for autofs path %s",
		     ap->path);
		return -1;
	}

	ap->pipefd = pipefd[0];
	ap->kpipefd = pipefd[1];

	/* Pipe state changes from signal handler to main loop */
	if (pipe(ap->state_pipe) < 0) {
		crit(ap->logopt, "failed create state pipe for autofs path %s",
		     ap->path);
		close(ap->pipefd);
		close(ap->kpipefd);
		return -1;
	}
	return 0;
}

int do_umount_autofs_direct(struct autofs_point *ap, struct mnt_list *mnts, struct mapent *me)
{
	char buf[MAX_ERR_BUF];
	int ioctlfd, rv, left, retries;

	left = umount_multi(ap, me->key, 0);
	if (left) {
		warn(ap->logopt, "could not unmount %d dirs under %s",
		     left, me->key);
		return 1;
	}

	if (me->ioctlfd != -1) {
		if (tree_is_mounted(mnts, me->key, MNTS_REAL)) {
			error(ap->logopt,
			      "attempt to umount busy direct mount %s",
			      me->key);
			return 1;
		}
		ioctlfd = me->ioctlfd;
	} else
		ioctlfd = open(me->key, O_RDONLY);

	if (ioctlfd >= 0) {
		int status = 1;

		rv = ioctl(ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
		if (rv) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, "ioctl failed: %s", estr);
			return 1;
		} else if (!status) {
			if (ap->state != ST_SHUTDOWN_FORCE) {
				error(ap->logopt,
				      "ask umount returned busy for %s",
				      me->key);
				return 1;
			} else {
				me->ioctlfd = -1;
				ioctl(ioctlfd, AUTOFS_IOC_CATATONIC, 0);
				close(ioctlfd);
				goto force_umount;
			}
		}
		me->ioctlfd = -1;
		ioctl(ioctlfd, AUTOFS_IOC_CATATONIC, 0);
		close(ioctlfd);
	} else {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      "couldn't get ioctl fd for offset %s", me->key);
		debug(ap->logopt, "open: %s", estr);
		return 1;
	}

	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(me->key)) == -1 && retries--) {
		struct timespec tm = {0, 100000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
		case EINVAL:
			warn(ap->logopt, "mount point %s does not exist",
			      me->key);
			return 0;
			break;
		case EBUSY:
			warn(ap->logopt, "mount point %s is in use", me->key);
			if (ap->state == ST_SHUTDOWN_FORCE)
				goto force_umount;
			else
				return 0;
			break;
		case ENOTDIR:
			error(ap->logopt, "mount point is not a directory");
			return 0;
			break;
		}
		return 1;
	}

force_umount:
	if (rv != 0) {
		msg("forcing umount of direct mount %s", me->key);
		rv = umount2(me->key, MNT_DETACH);
	} else
		msg("umounted direct mount %s", me->key);

	if (!rv && me->dir_created) {
		if  (rmdir(me->key) == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn(ap->logopt, "failed to remove dir %s: %s",
			     me->key, estr);
		}
	}
	return rv;
}

int umount_autofs_direct(struct autofs_point *ap)
{
	struct map_source *map;
	struct mapent_cache *mc;
	struct mnt_list *mnts;
	struct mapent *me;

	close(ap->state_pipe[0]);
	close(ap->state_pipe[1]);
	if (ap->pipefd >= 0)
		close(ap->pipefd);
	if (ap->kpipefd >= 0) {
		close(ap->kpipefd);
		ap->kpipefd = -1;
	}

	mnts = tree_make_mnt_tree(_PROC_MOUNTS, "/");
	pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
	master_source_readlock(ap->entry);
	map = ap->entry->first;
	while (map) {
		mc = map->mc;
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_readlock(mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			/* TODO: check return, locking me */
			do_umount_autofs_direct(ap, mnts, me);
			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);
	tree_free_mnt_tree(mnts);

	return 0;
}

static int unlink_mount_tree(struct autofs_point *ap, struct list_head *list)
{
	struct list_head *p;
	int rv, ret;
	pid_t pgrp = getpgrp();
	char spgrp[20];

	sprintf(spgrp, "pgrp=%d", pgrp);

	ret = 1;
	list_for_each(p, list) {
		struct mnt_list *mnt;

		mnt = list_entry(p, struct mnt_list, list);

		if (strstr(mnt->opts, spgrp))
			continue;

		if (strcmp(mnt->fs_type, "autofs"))
			rv = spawnll(log_debug,
			     PATH_UMOUNT, PATH_UMOUNT, "-l", mnt->path, NULL);
		else
			rv = umount2(mnt->path, MNT_DETACH);
		if (rv == -1) {
			ret = 0;
			debug(ap->logopt,
			      "can't unlink %s from mount tree", mnt->path);

			switch (errno) {
			case EINVAL:
				warn(ap->logopt,
				      "bad superblock or not mounted");
				break;

			case ENOENT:
			case EFAULT:
				warn(ap->logopt, "bad path for mount");
				break;
			}
		}
	}
	return ret;
}

int do_mount_autofs_direct(struct autofs_point *ap, struct mnt_list *mnts, struct mapent *me)
{
	struct mnt_params *mp;
	time_t timeout = ap->exp_timeout;
	struct stat st;
	int status, ret, ioctlfd;
	struct list_head list;

	INIT_LIST_HEAD(&list);

	if (tree_get_mnt_list(mnts, &list, me->key, 1)) {
		if (ap->state == ST_READMAP)
			return 0;
		if (!unlink_mount_tree(ap, &list)) {
			debug(ap->logopt,
			      "already mounted as other than autofs "
			      "or failed to unlink entry in tree");
			return -1;
		}
	}

	if (me->ioctlfd != -1) {
		error(ap->logopt, "active direct mount %s", me->key);
		return -1;
	}

	status = pthread_once(&key_mnt_params_once, key_mnt_params_init);
	if (status)
		fatal(status);

	mp = pthread_getspecific(key_mnt_direct_params);
	if (!mp) {
		mp = (struct mnt_params *) malloc(sizeof(struct mnt_params));
		if (!mp) {
			crit(ap->logopt,
			  "mnt_params value create failed for direct mount %s",
			  ap->path);
			return 0;
		}
		mp->options = NULL;

		status = pthread_setspecific(key_mnt_direct_params, mp);
		if (status) {
			free(mp);
			fatal(status);
		}
	}

	if (!mp->options) {
		mp->options = make_options_string(ap->path, ap->kpipefd, "direct");
		if (!mp->options)
			return 0;
	}

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(me->key, 0555) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit(ap->logopt,
			     "failed to create mount directory %s", me->key);
			return -1;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		me->dir_created = 0;
	} else {
		/* No errors so the directory was successfully created */
		me->dir_created = 1;
	}

	ret = mount("automount", me->key, "autofs", MS_MGC_VAL, mp->options);
	if (ret) {
		crit(ap->logopt, "failed to mount autofs path %s", me->key);
		goto out_err;
	}

	msg("mounted autofs direct mount on %s", me->key);

	/* Root directory for ioctl()'s */
	ioctlfd = open(me->key, O_RDONLY);
	if (ioctlfd < 0) {
		crit(ap->logopt, "failed to create ioctl fd for %s", me->key);
		goto out_umount;
	}

	/* Only calculate this first time round */
	if (ap->kver.major)
		goto got_version;

	ap->kver.major = 0;
	ap->kver.minor = 0;

	/* If this ioctl() doesn't work, it is kernel version 2 */
	if (!ioctl(ioctlfd, AUTOFS_IOC_PROTOVER, &ap->kver.major)) {
		 /* If this ioctl() fails the kernel doesn't support direct mounts */
		 if (ioctl(me->ioctlfd, AUTOFS_IOC_PROTOSUBVER, &ap->kver.minor)) {
			ap->kver.minor = 0;
			ap->ghost = 0;
		 }
	}

	msg("using kernel protocol version %d.%02d", ap->kver.major, ap->kver.minor);

	if (ap->kver.major < 5) {
		crit(ap->logopt, "kernel does not support direct mounts");
		goto out_close;
	}

	/* Calculate the timeouts */
	ap->exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;

	if (timeout) {
		msg("using timeout %d seconds; freq %d secs",
			(int) ap->exp_timeout, (int) ap->exp_runfreq);
	} else {
		msg("timeouts disabled");
	}

got_version:
	ioctl(ioctlfd, AUTOFS_IOC_SETTIMEOUT, &timeout);

	ret = fstat(ioctlfd, &st);
	if (ret == -1) {
		error(ap->logopt,
		      "failed to stat direct mount trigger %s", me->key);
		goto out_close;
	}
	cache_set_ino_index(me->source->mc, me->key, st.st_dev, st.st_ino);

	close(ioctlfd);

	debug(ap->logopt, "mounted trigger %s", me->key);

	return 0;

out_close:
	close(ioctlfd);
out_umount:
	/* TODO: maybe force umount (-l) */
	umount(me->key);
out_err:
	if (me->dir_created)
		rmdir(me->key);

	return -1;
}

int mount_autofs_direct(struct autofs_point *ap)
{
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me;
	struct mnt_list *mnts;
	time_t now = time(NULL);

	if (strcmp(ap->path, "/-")) {
		error(ap->logopt, "expected direct map, exiting");
		return -1;
	}

	if (autofs_init_direct(ap))
		return -1;

	/* TODO: check map type */
	if (lookup_nss_read_map(ap, now))
		lookup_prune_cache(ap, now);
	else {
		error(ap->logopt, "failed to read direct map");
		return -1;
	}

	mnts = tree_make_mnt_tree(_PROC_MOUNTS, "/");
	pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
	master_source_readlock(ap->entry);
	map = ap->entry->first;
	while (map) {
		/*
		 * Only consider map sources that have been read since
		 * the map entry was last updated.
		 */
		if (ap->entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_readlock(mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			/* TODO: check return, locking me */
			do_mount_autofs_direct(ap, mnts, me);
			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);
	tree_free_mnt_tree(mnts);

	return 0;
}

int umount_autofs_offset(struct autofs_point *ap, struct mapent *me)
{
	char buf[MAX_ERR_BUF];
	int ioctlfd, rv = 1, retries;

	if (me->ioctlfd != -1) {
		if (is_mounted(_PATH_MOUNTED, me->key, MNTS_REAL)) {
			error(ap->logopt,
			      "attempt to umount busy offset %s", me->key);
			return 1;
		}
		ioctlfd = me->ioctlfd;
	} else
		ioctlfd = open(me->key, O_RDONLY);

	if (ioctlfd >= 0) {
		int status = 1;

		rv = ioctl(ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
		if (rv) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, "ioctl failed: %s", estr);
			return 1;
		} else if (!status) {
			if (ap->state != ST_SHUTDOWN_FORCE) {
				error(ap->logopt,
				      "ask umount returned busy for %s",
				      me->key);
				return 1;
			} else {
				me->ioctlfd = -1;
				ioctl(ioctlfd, AUTOFS_IOC_CATATONIC, 0);
				close(ioctlfd);
				goto force_umount;
			}
		}
		me->ioctlfd = -1;
		ioctl(ioctlfd, AUTOFS_IOC_CATATONIC, 0);
		close(ioctlfd);
	} else {
		struct stat st;
		char *estr;
		int save_errno = errno;

		/* Non existent directory on remote fs - no mount */
		if (stat(me->key, &st) == -1 && errno == ENOENT)
			return 0;

		estr = strerror_r(save_errno, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      "couldn't get ioctl fd for offset %s: %s",
		      me->key, estr);
		goto force_umount;
	}

	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(me->key)) == -1 && retries--) {
		struct timespec tm = {0, 100000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
			warn(ap->logopt, "mount point does not exist");
			return 0;
			break;
		case EBUSY:
			error(ap->logopt, "mount point %s is in use", me->key);
			if (ap->state != ST_SHUTDOWN_FORCE)
				return 1;
			break;
		case ENOTDIR:
			error(ap->logopt, "mount point is not a directory");
			return 0;
			break;
		}
		goto force_umount;
	}

force_umount:
	if (rv != 0) {
		msg("forcing umount of offset mount %s", me->key);
		rv = umount2(me->key, MNT_DETACH);
	} else
		msg("umounted offset mount %s", me->key);

	return rv;
}

int mount_autofs_offset(struct autofs_point *ap, struct mapent *me, int is_autofs_fs)
{
	struct mnt_params *mp;
	time_t timeout = ap->exp_timeout;
	struct stat st;
	int ioctlfd, status, ret;

	if (is_mounted(_PROC_MOUNTS, me->key, MNTS_AUTOFS)) {
		if (ap->state != ST_READMAP)
			warn(ap->logopt,
			      "trigger %s already mounted", me->key);
		return 0;
	}

	if (me->ioctlfd != -1) {
		error(ap->logopt, "active offset mount %s", me->key);
		return -1;
	}

	status = pthread_once(&key_mnt_params_once, key_mnt_params_init);
	if (status)
		fatal(status);

	mp = pthread_getspecific(key_mnt_offset_params);
	if (!mp) {
		mp = (struct mnt_params *) malloc(sizeof(struct mnt_params));
		if (!mp) {
			crit(ap->logopt,
			  "mnt_params value create failed for offset mount %s",
			  me->key);
			return 0;
		}
		mp->options = NULL;

		status = pthread_setspecific(key_mnt_offset_params, mp);
		if (status) {
			free(mp);
			fatal(status);
		}
	}

	if (!mp->options) {
		mp->options = make_options_string(ap->path, ap->kpipefd, "offset");
		if (!mp->options)
			return 0;
	}

	if (is_autofs_fs) {
		/* In case the directory doesn't exist, try to mkdir it */
		if (mkdir_path(me->key, 0555) < 0) {
			if (errno != EEXIST) {
				crit(ap->logopt,
				     "failed to create mount directory %s %d",
				     me->key, errno);
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

	debug(ap->logopt,
	      "calling mount -t autofs " SLOPPY " -o %s automount %s",
	      mp->options, me->key);

	ret = mount("automount", me->key, "autofs", MS_MGC_VAL, mp->options);
	if (ret) {
		crit(ap->logopt, "failed to mount autofs path %s", me->key);
		goto out_err;
	}

	if (ret != 0) {
		crit(ap->logopt,
		     "failed to mount autofs offset trigger %s", me->key);
		goto out_err;
	}

	/* Root directory for ioctl()'s */
	ioctlfd = open(me->key, O_RDONLY);
	if (ioctlfd < 0) {
		crit(ap->logopt, "failed to create ioctl fd for %s", me->key);
		goto out_umount;
	}

	ioctl(ioctlfd, AUTOFS_IOC_SETTIMEOUT, &timeout);

	ret = fstat(ioctlfd, &st);
	if (ret == -1) {
		error(ap->logopt,
		     "failed to stat direct mount trigger %s", me->key);
		goto out_close;
	}

	cache_set_ino_index(me->source->mc, me->key, st.st_dev, st.st_ino);

	close(ioctlfd);

	debug(ap->logopt, "mounted trigger %s", me->key);

	return 0;

out_close:
	close(ioctlfd);
out_umount:
	umount(me->key);
out_err:
	if (is_autofs_fs) {
		if (stat(me->key, &st) == 0 && me->dir_created)
			 rmdir_path(ap, me->key, st.st_dev);
	}

	return -1;
}

static int expire_direct(int ioctlfd, const char *path, unsigned int when, unsigned int logopt)
{
	char buf[MAX_ERR_BUF];
	int ret, retries;
	struct stat st;

	if (fstat(ioctlfd, &st) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, "fstat failed: %s", estr);
		return 0;
	}

	retries = (count_mounts(path, st.st_dev) + 1) * EXPIRE_RETRIES;

	while (retries--) {
		struct timespec tm = {0, 100000000};

		/* Ggenerate expire message for the mount. */
		ret = ioctl(ioctlfd, AUTOFS_IOC_EXPIRE_DIRECT, &when);
		if (ret == -1) {
			/* Mount has gone away */
			if (errno == EBADF || errno == EINVAL)
				return 1;

			/* Other than need to wait for the kernel ? */
			if (errno != EAGAIN)
				return 0;
		}

		nanosleep(&tm, NULL);
	}

	return (retries >= 0);
}

void *expire_proc_direct(void *arg)
{
	struct mnt_list *mnts, *next;
	struct expire_args *ea;
	struct autofs_point *ap;
	struct mapent *me = NULL;
	unsigned int now;
	int ioctlfd = -1;
	int status, ret;

	ea = (struct expire_args *) arg;

	status = pthread_mutex_lock(&ea->mutex);
	if (status)
		fatal(status);

	ap = ea->ap;
	now = ea->when;
	ea->status = 0;

	ea->signaled = 1;
	status = pthread_cond_signal(&ea->cond);
	if (status) {
		error(ap->logopt, "failed to signal expire condition");
		status = pthread_mutex_unlock(&ea->mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	pthread_cleanup_push(expire_cleanup, ea);

	status = pthread_mutex_unlock(&ea->mutex);
	if (status)
		fatal(status);

	/* Get a list of real mounts and expire them if possible */
	mnts = get_mnt_list(_PROC_MOUNTS, "/", 0);
	for (next = mnts; next; next = next->next) {
		if (!strcmp(next->fs_type, "autofs")) {
			/*
			 * If we have submounts check if this path lives below
			 * one of them and pass on state change.
			 */
			if (strstr(next->opts, "indirect")) {
				master_notify_submount(ap, next->path, ap->state);
				continue;
			}

			/* Skip offsets */
			if (strstr(next->opts, "offset"))
				continue;
		}

		/*
		 * All direct mounts must be present in the map
		 * entry cache.
		 */
		me = lookup_source_mapent(ap, next->path, LKP_DISTINCT);
		if (!me)
			continue;

		if (me->ioctlfd >= 0) {
			/* Real mounts have an open ioctl fd */
			ioctlfd = me->ioctlfd;
			cache_unlock(me->source->mc);
		} else {
			cache_unlock(me->source->mc);
			continue;
		}

		debug(ap->logopt, "send expire to trigger %s", next->path);

		ret = expire_direct(ioctlfd, next->path, now, ap->logopt);
		if (!ret)
			ea->status++;
	}
	free_mnt_list(mnts);

	pthread_cleanup_pop(1);

	return NULL;
}

void pending_cleanup(void *arg)
{
	struct pending_args *mt;
	int status;

	mt = (struct pending_args *) arg;

	status = pthread_mutex_unlock(&mt->mutex);
	if (status)
		fatal(status);

	status = pthread_cond_destroy(&mt->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&mt->mutex);
	if (status)
		fatal(status);
}

static void expire_send_fail(void *arg)
{
	struct pending_args *mt = arg;
	send_fail(mt->ioctlfd, mt->wait_queue_token);
}

static void *do_expire_direct(void *arg)
{
	struct pending_args *mt;
	struct autofs_point *ap;
	size_t len;
	int status, state;

	mt = (struct pending_args *) arg;

	pthread_cleanup_push(expire_send_fail, mt);

	status = pthread_mutex_lock(&mt->mutex);
	if (status)
		fatal(status);

	ap = mt->ap;

	mt->signaled = 1;
	status = pthread_cond_signal(&mt->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&mt->mutex);
	if (status)
		fatal(status);

	len = _strlen(mt->name, KEY_MAX_LEN);
	if (!len) {
		warn(ap->logopt, "direct key path too long %s", mt->name);
		/* TODO: force umount ?? */
		pthread_exit(NULL);
	}

	status = do_expire(ap, mt->name, len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status)
		send_fail(mt->ioctlfd, mt->wait_queue_token);
	else {
		struct mapent *me;
		cache_readlock(mt->mc);
		me = cache_lookup_distinct(mt->mc, mt->name);
		me->ioctlfd = -1;
		cache_unlock(mt->mc);
		send_ready(mt->ioctlfd, mt->wait_queue_token);
		close(mt->ioctlfd);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);
	return NULL;
}

int handle_packet_expire_direct(struct autofs_point *ap, autofs_packet_expire_direct_t *pkt)
{
	struct map_source *map;
	struct mapent_cache *mc = NULL;
	struct mapent *me = NULL;
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	pthread_t thid;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

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
	master_source_readlock(ap->entry);
	map = ap->entry->first;
	while (map) {
		mc = map->mc;
		cache_readlock(mc);
		me = cache_lookup_ino(mc, pkt->dev, pkt->ino);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}
	master_source_unlock(ap->entry);

	if (!me) {
		/*
		 * Shouldn't happen as we have been sent this following
		 * successful thread creation and lookup.
		 */
		crit(ap->logopt, "can't find map entry for (%lu,%lu)",
		    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		pthread_setcancelstate(state, NULL);
		return 1;
	}


	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "malloc: %s", estr);
		send_fail(me->ioctlfd, pkt->wait_queue_token);
		cache_unlock(mc);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	status = pthread_mutex_init(&mt->mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_cond_init(&mt->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&mt->mutex);
	if (status)
		fatal(status);

	mt->ap = ap;
	mt->ioctlfd = me->ioctlfd;
	mt->mc = mc;
	/* TODO: check length here */
	strcpy(mt->name, me->key);
	mt->dev = me->dev;
	mt->type = NFY_EXPIRE;
	mt->wait_queue_token = pkt->wait_queue_token;

	debug(ap->logopt, "token %ld, name %s",
		  (unsigned long) pkt->wait_queue_token, mt->name);

	status = pthread_create(&thid, &thread_attr, do_expire_direct, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		free(mt);
		send_fail(mt->ioctlfd, pkt->wait_queue_token);
		cache_unlock(mc);
		pending_cleanup(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	cache_unlock(mc);
	pthread_cleanup_push(pending_cleanup, mt);
	pthread_setcancelstate(state, NULL);

	mt->signaled = 0;
	while (!mt->signaled) {
		status = pthread_cond_wait(&mt->cond, &mt->mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);
	return 0;
}

static void mount_send_fail(void *arg)
{
	struct pending_args *mt = arg;
	send_fail(mt->ioctlfd, mt->wait_queue_token);
	close(mt->ioctlfd);
}

static void *do_mount_direct(void *arg)
{
	struct pending_args *mt;
	struct autofs_point *ap;
	struct passwd pw;
	struct passwd *ppw = &pw;
	struct passwd **pppw = &ppw;
	struct group gr;
	struct group *pgr = &gr;
	struct group **ppgr = &pgr;
	char *pw_tmp, *gr_tmp;
	struct thread_stdenv_vars *tsv;
	int tmplen;
	struct stat st;
	int status, state;

	mt = (struct pending_args *) arg;

	status = pthread_mutex_lock(&mt->mutex);
	if (status)
		fatal(status);

	ap = mt->ap;

	mt->signaled = 1;
	status = pthread_cond_signal(&mt->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&mt->mutex);
	if (status)
		fatal(status);

	pthread_cleanup_push(mount_send_fail, mt);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	status = fstat(mt->ioctlfd, &st);
	if (status == -1) {
		error(ap->logopt,
		      "can't stat direct mount trigger %s", mt->name);
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	status = stat(mt->name, &st);
	if (!S_ISDIR(st.st_mode) || st.st_dev != mt->dev) {
		error(ap->logopt,
		     "direct trigger not valid or already mounted %s",
		     mt->name);
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	pthread_setcancelstate(state, NULL);

	msg("attempting to mount entry %s", mt->name);

	/*
	 * Setup thread specific data values for macro
	 * substution in map entries during the mount.
	 * Best effort only as it must go ahead.
	 */

	tsv = malloc(sizeof(struct thread_stdenv_vars));
	if (!tsv) 
		goto cont;

	tsv->uid = mt->uid;
	tsv->gid = mt->gid;

	/* Try to get passwd info */

	tmplen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (tmplen < 0) {
		error(ap->logopt, "failed to get buffer size for getpwuid_r");
		free(tsv);
		goto cont;
	}

	pw_tmp = malloc(tmplen + 1);
	if (!pw_tmp) {
		error(ap->logopt, "failed to malloc buffer for getpwuid_r");
		free(tsv);
		goto cont;
	}

	status = getpwuid_r(mt->uid, ppw, pw_tmp, tmplen, pppw);
	if (status) {
		error(ap->logopt, "failed to get passwd info from getpwuid_r");
		free(tsv);
		free(pw_tmp);
		goto cont;
	}

	tsv->user = strdup(pw.pw_name);
	if (!tsv->user) {
		error(ap->logopt, "failed to malloc buffer for user");
		free(tsv);
		free(pw_tmp);
		goto cont;
	}

	tsv->home = strdup(pw.pw_dir);
	if (!tsv->user) {
		error(ap->logopt, "failed to malloc buffer for home");
		free(pw_tmp);
		free(tsv->user);
		free(tsv);
		goto cont;
	}

	free(pw_tmp);

	/* Try to get group info */

	tmplen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (tmplen < 0) {
		error(ap->logopt, "failed to get buffer size for getgrgid_r");
		free(tsv->user);
		free(tsv->home);
		free(tsv);
		goto cont;
	}

	gr_tmp = malloc(tmplen + 1);
	if (!gr_tmp) {
		error(ap->logopt, "failed to malloc buffer for getgrgid_r");
		free(tsv->user);
		free(tsv->home);
		free(tsv);
		goto cont;
	}

	status = getgrgid_r(mt->gid, pgr, gr_tmp, tmplen, ppgr);
	if (status) {
		error(ap->logopt, "failed to get group info from getgrgid_r");
		free(tsv->user);
		free(tsv->home);
		free(tsv);
		free(gr_tmp);
		goto cont;
	}

	tsv->group = strdup(gr.gr_name);
	if (!tsv->group) {
		error(ap->logopt, "failed to malloc buffer for group");
		free(tsv->user);
		free(tsv->home);
		free(tsv);
		free(gr_tmp);
		goto cont;
	}

	free(gr_tmp);

	status = pthread_setspecific(key_thread_stdenv_vars, tsv);
	if (status) {
		error(ap->logopt, "failed to set stdenv thread var");
		free(tsv->group);
		free(tsv->user);
		free(tsv->home);
		free(tsv);
	}

cont:
	status = lookup_nss_mount(ap, mt->name, strlen(mt->name));
	/*
	 * Direct mounts are always a single mount. If it fails there's
	 * nothing to undo so just complain
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status) {
		struct mapent *me;
		cache_readlock(mt->mc);
		me = cache_lookup_distinct(mt->mc, mt->name);
		me->ioctlfd = mt->ioctlfd;
		cache_unlock(mt->mc);
		send_ready(mt->ioctlfd, mt->wait_queue_token);
		msg("mounted %s", mt->name);
	} else {
		send_fail(mt->ioctlfd, mt->wait_queue_token);
		close(mt->ioctlfd);
		msg("failed to mount %s", mt->name);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);
	return NULL;
}

int handle_packet_missing_direct(struct autofs_point *ap, autofs_packet_missing_direct_t *pkt)
{
	struct map_source *map;
	struct mapent_cache *mc = NULL;
	struct mapent *me = NULL;
	pthread_t thid;
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	int status = 0;
	int ioctlfd, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	master_source_readlock(ap->entry);
	map = ap->entry->first;
	while (map) {
		/*
		 * Only consider map sources that have been read since
		 * the map entry was last updated.
		 */
		if (ap->entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		cache_readlock(mc);
		me = cache_lookup_ino(mc, pkt->dev, pkt->ino);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}
	master_source_unlock(ap->entry);

	if (!me) {
		/*
		 * Shouldn't happen as the kernel is telling us
		 * someone has walked on our mount point.
		 */
		crit(ap->logopt, "can't find map entry for (%lu,%lu)",
		    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	ioctlfd = open(me->key, O_RDONLY);
	if (ioctlfd < 0) {
		cache_unlock(mc);
		pthread_setcancelstate(state, NULL);
		crit(ap->logopt, "failed to create ioctl fd for %s", me->key);
		/* TODO:  how do we clear wait q in kernel ?? */
		return 1;
	}

	debug(ap->logopt, "token %ld, name %s, request pid %u",
		  (unsigned long) pkt->wait_queue_token, me->key, pkt->pid);

	/* Ignore packet if we're trying to shut down */
	if (ap->state == ST_SHUTDOWN_PENDING ||
	    ap->state == ST_SHUTDOWN_FORCE ||
	    ap->state == ST_SHUTDOWN) {
		send_fail(ioctlfd, pkt->wait_queue_token);
		close(ioctlfd);
		cache_unlock(mc);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "malloc: %s", estr);
		send_fail(ioctlfd, pkt->wait_queue_token);
		close(ioctlfd);
		cache_unlock(mc);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	status = pthread_mutex_init(&mt->mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_cond_init(&mt->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&mt->mutex);
	if (status)
		fatal(status);

	mt->ap = ap;
	mt->ioctlfd = ioctlfd;
	mt->mc = mc;
	/* TODO: check length here */
	strcpy(mt->name, me->key);
	mt->dev = me->dev;
	mt->type = NFY_MOUNT;
	mt->uid = pkt->uid;
	mt->gid = pkt->gid;
	mt->wait_queue_token = pkt->wait_queue_token;

	status = pthread_create(&thid, &thread_attr, do_mount_direct, mt);
	if (status) {
		error(ap->logopt, "missing mount thread create failed");
		free(mt);
		send_fail(ioctlfd, pkt->wait_queue_token);
		close(ioctlfd);
		cache_unlock(mc);
		pending_cleanup(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	cache_unlock(mc);
	pthread_cleanup_push(pending_cleanup, mt);

	mt->signaled = 0;
	while (!mt->signaled) {
		status = pthread_cond_wait(&mt->cond, &mt->mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return 0;
}

