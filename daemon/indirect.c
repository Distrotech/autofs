/* ----------------------------------------------------------------------- *
 *
 *  indirect.c - Linux automounter indirect mount handling
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
#include <libgen.h>
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
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sched.h>

#include "automount.h"

extern pthread_attr_t thread_attr;

static pthread_mutex_t ma_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ea_mutex = PTHREAD_MUTEX_INITIALIZER;

static int unlink_mount_tree(struct autofs_point *ap, struct mnt_list *mnts)
{
	struct mnt_list *this;
	int rv, ret;
	pid_t pgrp = getpgrp();
	char spgrp[20];

	sprintf(spgrp, "pgrp=%d", pgrp);

	ret = 1;
	this = mnts;
	while (this) {
		if (strstr(this->opts, spgrp)) {
			this = this->next;
			continue;
		}

		if (strcmp(this->fs_type, "autofs"))
			rv = spawn_umount(ap->logopt, "-l", this->path, NULL);
		else
			rv = umount2(this->path, MNT_DETACH);
		if (rv == -1) {
			debug(ap->logopt,
			      "can't unlink %s from mount tree", this->path);

			switch (errno) {
			case EINVAL:
				warn(ap->logopt,
				      "bad superblock or not mounted");
				break;

			case ENOENT:
			case EFAULT:
				ret = 0;
				warn(ap->logopt, "bad path for mount");
				break;
			}
		}
		this = this->next;
	}
	return ret;
}

static int do_mount_autofs_indirect(struct autofs_point *ap)
{
	const char *str_indirect = mount_type_str(indirect);
	struct ioctl_ops *ops = get_ioctl_ops();
	time_t timeout = ap->exp_timeout;
	char *options = NULL;
	const char *type, *map_name = NULL;
	struct stat st;
	struct mnt_list *mnts;
	int ret;

	ap->exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;

	if (ops->version) {
		char device[AUTOFS_DEVID_LEN];
		struct statfs fst;
		int ioctlfd;
		dev_t devid;
		char *tmp;

		if (!find_mnt_devid(_PROC_MOUNTS, ap->path, device, indirect))
			goto cont;

		devid = strtoul(device, NULL, 0);

		ret = remount_active_mount(ap, NULL, ap->path, devid, indirect, &ioctlfd);

		/*
		 * The directory must exist since we found a device
		 * number for the mount above but we can't know if we
		 * created it or not. However, if we're mounted on an
		 * autofs fs then we need to cleanup the path anyway.
		 */
		ap->dir_created = 0;
		tmp = strdup(ap->path);
		if (tmp) {
			if (statfs(dirname(tmp), &fst) != -1)
				if (fst.f_type == AUTOFS_SUPER_MAGIC)
					ap->dir_created = 1;
			free(tmp);
		}

		/*
		 * Either we opened the mount or we're re-reading the map.
		 * If we opened the mount and ioctlfd is not -1 we have
		 * a descriptor for the indirect mount so we need to
		 * record that in the mount point struct. Otherwise we're
		 * re-reading the map.
		*/
		if (ret == REMOUNT_SUCCESS || ret == REMOUNT_READ_MAP) {
			if (ioctlfd != -1)
				ap->ioctlfd = ioctlfd;
			return 0;
		}
		/*
		 * Since we got the device number above a mount exists so
		 * any other failure warrants a failure return here.
		 */
		return -1;
	} else {
		mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 1);
		if (!mnts)
			goto cont;
		ret = unlink_mount_tree(ap, mnts);
		free_mnt_list(mnts);
		if (!ret) {
			error(ap->logopt,
			      "already mounted as other than autofs "
			      "or failed to unlink entry in tree");
			goto out_err;
		}
	}
cont:
	options = make_options_string(ap->path, ap->kpipefd, NULL);
	if (!options) {
		error(ap->logopt, "options string error");
		goto out_err;
	}

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(ap->path, 0555) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit(ap->logopt,
			     "failed to create autofs directory %s",
			     ap->path);
			goto out_err;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		ap->dir_created = 0;
	} else {
		/* No errors so the directory was successfully created */
		ap->dir_created = 1;
	}

	type = ap->entry->maps->type;
	if (type && !strcmp(ap->entry->maps->type, "hosts")) {
		char *tmp = alloca(7);
		if (tmp) {
			strcpy(tmp, "-hosts");
			map_name = (const char *) tmp;
		}
	} else
		map_name = ap->entry->maps->argv[0];

	ret = mount(map_name, ap->path, "autofs", MS_MGC_VAL, options);
	if (ret) {
		crit(ap->logopt, "failed to mount autofs path %s", ap->path);
		goto out_rmdir;
	}

	free(options);

	options = NULL;

	if (stat(ap->path, &st) == -1) {
		error(ap->logopt,
		      "failed to stat mount %s", ap->path);
		goto out_umount;
	}
	ap->dev = st.st_dev;

	if (ops->open(ap->logopt, &ap->ioctlfd, ap->dev, ap->path, indirect)) {
		crit(ap->logopt,
		     "failed to create ioctl fd for autofs path %s", ap->path);
		goto out_umount;
	}

	ops->timeout(ap->logopt, ap->ioctlfd, &timeout);
	notify_mount_result(ap, ap->path, str_indirect);

	return 0;

out_umount:
	umount(ap->path);
out_rmdir:
	if (ap->dir_created)
		rmdir_path(ap, ap->path, ap->dev);
out_err:
	if (options)
		free(options);
	close(ap->state_pipe[0]);
	close(ap->state_pipe[1]);
	close(ap->pipefd);
	close(ap->kpipefd);

	return -1;
}

int mount_autofs_indirect(struct autofs_point *ap)
{
	time_t now = time(NULL);
	int status;
	int map;

	/* TODO: read map, determine map type is OK */
	if (lookup_nss_read_map(ap, NULL, now))
		lookup_prune_cache(ap, now);
	else {
		error(ap->logopt, "failed to read map for %s", ap->path);
		return -1;
	}

	status = do_mount_autofs_indirect(ap);
	if (status < 0)
		return -1;

	map = lookup_ghost(ap);
	if (map & LKP_FAIL) {
		if (map & LKP_DIRECT) {
			error(ap->logopt,
			      "bad map format,found direct, "
			      "expected indirect exiting");
		} else {
			error(ap->logopt, "failed to load map, exiting");
		}
		/* TODO: Process cleanup ?? */
		return -1;
	}

	if (map & LKP_NOTSUP)
		ap->ghost = 0;

	return 0;
}

int umount_autofs_indirect(struct autofs_point *ap)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[MAX_ERR_BUF];
	int rv, retries;
	unsigned int ret;

	/*
	 * Since submounts look after themselves the parent never knows
	 * it needs to close the ioctlfd for offset mounts so we have
	 * to do it here. If the cache entry isn't found then there aren't
	 * any offset mounts.
	 */
	if (ap->submount)
		lookup_source_close_ioctlfd(ap->parent, ap->path);

	/* If we are trying to shutdown make sure we can umount */
	rv = ops->askumount(ap->logopt, ap->ioctlfd, &ret);
	if (rv == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("ioctl failed: %s", estr);
		return 1;
	} else if (!ret) {
		error(ap->logopt, "ask umount returned busy %s", ap->path);
		return 1;
	}

	ops->catatonic(ap->logopt, ap->ioctlfd);
	ops->close(ap->logopt, ap->ioctlfd);
	ap->ioctlfd = -1;
	close(ap->state_pipe[0]);
	close(ap->state_pipe[1]);
	ap->state_pipe[0] = -1;
	ap->state_pipe[1] = -1;

	if (ap->pipefd >= 0)
		close(ap->pipefd);

	if (ap->kpipefd >= 0)
		close(ap->kpipefd);

	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(ap->path)) == -1 && retries--) {
		struct timespec tm = {0, 100000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
		case EINVAL:
			error(ap->logopt,
			      "mount point %s does not exist", ap->path);
			return 0;
			break;
		case EBUSY:
			error(ap->logopt,
			      "mount point %s is in use", ap->path);
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
		warn(ap->logopt,
		     "forcing umount of indirect mount %s", ap->path);
		rv = umount2(ap->path, MNT_DETACH);
	} else {
		info(ap->logopt, "umounted indirect mount %s", ap->path);
		if (ap->submount)
			rm_unwanted(ap->logopt, ap->path, 1, ap->dev);
	}

	return rv;
}

static void mnts_cleanup(void *arg)
{
	struct mnt_list *mnts = (struct mnt_list *) arg;
	free_mnt_list(mnts);
	return;
}

void *expire_proc_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct autofs_point *ap;
	struct mapent *me = NULL;
	struct mnt_list *mnts = NULL, *next;
	struct expire_args *ea;
	struct expire_args ec;
	unsigned int now;
	int offsets, submnts, count;
	int ioctlfd, cur_state;
	int status, ret, left;

	ea = (struct expire_args *) arg;

	status = pthread_mutex_lock(&ea->mutex);
	if (status)
		fatal(status);

	ap = ec.ap = ea->ap;
	now = ea->when;
	ec.status = -1;

	ea->signaled = 1;
	status = pthread_cond_signal(&ea->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&ea->mutex);
	if (status)
		fatal(status);

	pthread_cleanup_push(expire_cleanup, &ec);

	left = 0;

	/* Get a list of real mounts and expire them if possible */
	mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 0);
	pthread_cleanup_push(mnts_cleanup, mnts);
	for (next = mnts; next; next = next->next) {
		char *ind_key;
		int ret;

		if (!strcmp(next->fs_type, "autofs")) {
			/*
			 * If we have submounts check if this path lives below
			 * one of them and pass on the state change.
			 */
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
			if (strstr(next->opts, "indirect"))
				master_notify_submount(ap, next->path, ap->state);
			pthread_setcancelstate(cur_state, NULL);
		}

		if (ap->state == ST_EXPIRE || ap->state == ST_PRUNE)
			pthread_testcancel();

		/*
		 * If the mount corresponds to an offset trigger then
		 * the key is the path, otherwise it's the last component.
		 */
		ind_key = strrchr(next->path, '/');
		if (ind_key)
			ind_key++;

		/*
		 * If me->key starts with a '/' and it's not an autofs
		 * filesystem it's a nested mount and we need to use
		 * the ioctlfd of the mount to send the expire.
		 * Otherwise it's a top level indirect mount (possibly
		 * with offsets in it) and we use the usual ioctlfd.
		 */
		me = lookup_source_mapent(ap, next->path, LKP_DISTINCT);
		if (!me && ind_key)
			me = lookup_source_mapent(ap, ind_key, LKP_NORMAL);
		if (!me)
			continue;

		if (*me->key == '/') {
			ioctlfd = me->ioctlfd;
		} else {
			ioctlfd = ap->ioctlfd;
		}
		cache_unlock(me->mc);

		debug(ap->logopt, "expire %s", next->path);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
		ret = ops->expire(ap->logopt, ioctlfd, next->path, now);
		if (ret)
			left++;
		pthread_setcancelstate(cur_state, NULL);
	}
	pthread_cleanup_pop(1);

	/*
	 * If there are no more real mounts left we could still
	 * have some offset mounts with no '/' offset so we need to
	 * umount them here.
	 */
	if (mnts) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
		ret = ops->expire(ap->logopt, ap->ioctlfd, ap->path, now);
		if (ret)
			left++;
		pthread_setcancelstate(cur_state, NULL);
	}

	count = offsets = submnts = 0;
	mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 0);
	pthread_cleanup_push(mnts_cleanup, mnts);
	/* Are there any real mounts left */
	for (next = mnts; next; next = next->next) {
		if (strcmp(next->fs_type, "autofs"))
			count++;
		else {
			if (strstr(next->opts, "indirect"))
				submnts++;
			else
				offsets++;
		}
	}
	pthread_cleanup_pop(1);

	if (submnts)
		info(ap->logopt,
		     "%d submounts remaining in %s", submnts, ap->path);

	/* 
	 * EXPIRE_MULTI is synchronous, so we can be sure (famous last
	 * words) the umounts are done by the time we reach here
	 */
	if (count)
		info(ap->logopt, "%d remaining in %s", count, ap->path);

	ec.status = left;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	pthread_cleanup_pop(1);
	pthread_setcancelstate(cur_state, NULL);

	return NULL;
}

static void pending_cond_destroy(void *arg)
{
	struct pending_args *mt;
	int status;

	mt = (struct pending_args *) arg;
	status = pthread_cond_destroy(&mt->cond);
	if (status)
		fatal(status);
}

static void expire_send_fail(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt = arg;
	struct autofs_point *ap = mt->ap;
	ops->send_fail(ap->logopt,
		       ap->ioctlfd, mt->wait_queue_token, -ENOENT);
}

static void free_pending_args(void *arg)
{
	struct pending_args *mt = arg;
	free(mt);
}

static void expire_mutex_unlock(void *arg)
{
	int status = pthread_mutex_unlock(&ea_mutex);
	if (status)
		fatal(status);
}

static void *do_expire_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt;
	struct autofs_point *ap;
	int status, state;

	mt = (struct pending_args *) arg;

	status = pthread_mutex_lock(&ea_mutex);
	if (status)
		fatal(status);

	ap = mt->ap;

	mt->signaled = 1;
	status = pthread_cond_signal(&mt->cond);
	if (status)
		fatal(status);

	expire_mutex_unlock(NULL);

	pthread_cleanup_push(free_pending_args, mt);
	pthread_cleanup_push(pending_cond_destroy, mt);
	pthread_cleanup_push(expire_send_fail, mt);

	status = do_expire(mt->ap, mt->name, mt->len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status)
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, mt->wait_queue_token, -status);
	else
		ops->send_ready(ap->logopt,
				ap->ioctlfd, mt->wait_queue_token);
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return NULL;
}

int handle_packet_expire_indirect(struct autofs_point *ap, autofs_packet_expire_indirect_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	pthread_t thid;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	debug(ap->logopt, "token %ld, name %s",
		  (unsigned long) pkt->wait_queue_token, pkt->name);

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOMEM);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	status = pthread_cond_init(&mt->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&ea_mutex);
	if (status)
		fatal(status);

	mt->ap = ap;
	strncpy(mt->name, pkt->name, pkt->len);
	mt->name[pkt->len] = '\0';
	mt->len = pkt->len;
	mt->wait_queue_token = pkt->wait_queue_token;

	status = pthread_create(&thid, &thread_attr, do_expire_indirect, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -status);
		expire_mutex_unlock(NULL);
		pending_cond_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	pthread_cleanup_push(expire_mutex_unlock, NULL);
	pthread_setcancelstate(state, NULL);

	mt->signaled = 0;
	while (!mt->signaled) {
		status = pthread_cond_wait(&mt->cond, &ea_mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return 0;
}

static void mount_send_fail(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt = arg;
	struct autofs_point *ap = mt->ap;
	ops->send_fail(ap->logopt,
		       ap->ioctlfd, mt->wait_queue_token, -ENOENT);
}

static void mount_mutex_unlock(void *arg)
{
	int status = pthread_mutex_unlock(&ma_mutex);
	if (status)
		fatal(status);
}

static void *do_mount_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt;
	struct autofs_point *ap;
	char buf[PATH_MAX + 1];
	struct stat st;
	int len, status, state;

	mt = (struct pending_args *) arg;

	status = pthread_mutex_lock(&ma_mutex);
	if (status)
		fatal(status);

	ap = mt->ap;
	mt->status = 0;

	mt->signaled = 1;
	status = pthread_cond_signal(&mt->cond);
	if (status)
		fatal(status);

	mount_mutex_unlock(NULL);

	pthread_cleanup_push(free_pending_args, mt);
	pthread_cleanup_push(pending_cond_destroy, mt);
	pthread_cleanup_push(mount_send_fail, mt);

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	len = ncat_path(buf, sizeof(buf), ap->path, mt->name, mt->len);
	if (!len) {
		crit(ap->logopt, "path to be mounted is to long");
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	status = lstat(buf, &st);
	if (status != -1 && !(S_ISDIR(st.st_mode) && st.st_dev == mt->dev)) {
		error(ap->logopt,
		      "indirect trigger not valid or already mounted %s", buf);
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	pthread_setcancelstate(state, NULL);

	info(ap->logopt, "attempting to mount entry %s", buf);

	set_tsd_user_vars(ap->logopt, mt->uid, mt->gid);

	status = lookup_nss_mount(ap, NULL, mt->name, mt->len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status) {
		ops->send_ready(ap->logopt,
				ap->ioctlfd, mt->wait_queue_token);
		info(ap->logopt, "mounted %s", buf);
	} else {
		/* TODO: get mount return status from lookup_nss_mount */
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, mt->wait_queue_token, -ENOENT);
		info(ap->logopt, "failed to mount %s", buf);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return NULL;
}

int handle_packet_missing_indirect(struct autofs_point *ap, autofs_packet_missing_indirect_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	pthread_t thid;
	char buf[MAX_ERR_BUF];
	struct pending_args *mt;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	debug(ap->logopt, "token %ld, name %s, request pid %u",
		(unsigned long) pkt->wait_queue_token, pkt->name, pkt->pid);

	/* Ignore packet if we're trying to shut down */
	if (ap->shutdown ||
	    ap->state == ST_SHUTDOWN_FORCE ||
	    ap->state == ST_SHUTDOWN) {
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOENT);
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOMEM);
		pthread_setcancelstate(state, NULL);
		return 1;
	}
	memset(mt, 0, sizeof(struct pending_args));

	status = pthread_cond_init(&mt->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&ma_mutex);
	if (status)
		fatal(status);

	mt->ap = ap;
	strncpy(mt->name, pkt->name, pkt->len);
	mt->name[pkt->len] = '\0';
	mt->len = pkt->len;
	mt->dev = pkt->dev;
	mt->uid = pkt->uid;
	mt->gid = pkt->gid;
	mt->wait_queue_token = pkt->wait_queue_token;

	status = pthread_create(&thid, &thread_attr, do_mount_indirect, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -status);
		mount_mutex_unlock(NULL);
		pending_cond_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	pthread_cleanup_push(mount_mutex_unlock, NULL);
	pthread_setcancelstate(state, NULL);

	mt->signaled = 0;
	while (!mt->signaled) {
		status = pthread_cond_wait(&mt->cond, &ma_mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return 0;
}

