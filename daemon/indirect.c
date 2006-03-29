#ident "$Id: indirect.c,v 1.23 2006/03/29 10:32:36 raven Exp $"
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
#include <sched.h>
#include <pwd.h>
#include <grp.h>

#include "automount.h"

extern pthread_attr_t thread_attr;

static int autofs_init_indirect(struct autofs_point *ap)
{
	int pipefd[2];

	if ((ap->state != ST_INIT)) {
		/* This can happen if an autofs process is already running*/
		error("bad state %d", ap->state);
		return -1;
	}

	ap->pipefd = ap->kpipefd = ap->ioctlfd = -1;

	/* Pipe for kernel communications */
	if (pipe(pipefd) < 0) {
		crit("failed to create commumication pipe for autofs path %s",
		     ap->path);
		free(ap->path);
		return -1;
	}

	ap->pipefd = pipefd[0];
	ap->kpipefd = pipefd[1];

	/* Pipe state changes from signal handler to main loop */
	if (pipe(ap->state_pipe) < 0) {
		crit("failed create state pipe for autofs path %s", ap->path);
		close(ap->pipefd);
		close(ap->kpipefd);	/* Close kernel pipe end */
		free(ap->path);
		return -1;
	}

	return 0;
}

static int do_mount_autofs_indirect(struct autofs_point *ap)
{
	time_t timeout = ap->exp_timeout;
	char *options = NULL;
	char *name = NULL;
	struct stat st;
	struct mnt_list *mnts;
	int ret;

	mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 1);
	if (mnts) {
		struct mnt_list *ent;

		for (ent = mnts; ent; ent = ent->next) {
			if (strcmp(ent->path, ap->path))
				continue;

			if (strstr(ent->opts, "direct"))
				continue;

			if (strstr(ent->opts, "offset"))
				continue;

			error("%s already mounted", ap->path);

			free_mnt_list(mnts);
			goto out_err;
		}
		free_mnt_list(mnts);
	}

	options = make_options_string(ap->path, ap->kpipefd, NULL);
	if (!options)
		goto out_err;

	name = make_mnt_name_string(ap->path);
	if (!name)
		goto out_err;

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(ap->path, 0555) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit("failed to create iautofs directory %s", ap->path);
			goto out_err;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		ap->dir_created = 0;
	} else {
		/* No errors so the directory was successfully created */
		ap->dir_created = 1;
	}

	ret = mount(name, ap->path, "autofs", MS_MGC_VAL, options);
	if (ret) {
		crit("failed to mount autofs path %s", ap->path);
		goto out_rmdir;
	}

	free(name);
	free(options);

	name = NULL;
	options = NULL;

	/* Root directory for ioctl()'s */
	ap->ioctlfd = open(ap->path, O_RDONLY);
	if (ap->ioctlfd < 0) {
		crit("failed to create ioctl fd for autofs path %s", ap->path);
		goto out_umount;
	}

	ap->kver.major = 0;
	ap->kver.minor = 0;

	/* If this ioctl() doesn't work, it is kernel version 2 */
	if (!ioctl(ap->ioctlfd, AUTOFS_IOC_PROTOVER, &ap->kver.major)) {
		 /* If this ioctl() doesn't work, kernel does not support ghosting */
		 if (ioctl(ap->ioctlfd, AUTOFS_IOC_PROTOSUBVER, &ap->kver.minor)) {
			ap->kver.minor = 0;
			if (ap->ghost) {
				msg("kernel does not support ghosting, disabled");
				ap->ghost = 0;
			}
		 }
	} else {
		ap->kver.major = 2;
		ap->kver.minor = 0;
	}

	msg("using kernel protocol version %d.%02d", ap->kver.major, ap->kver.minor);

	/* Calculate the timeouts */
	if (ap->kver.major < 3 || !timeout) {
		ap->exp_timeout = ap->exp_runfreq = 0;
		ap->ghost = 0;
		if (ap->kver.major >= 3) {
			msg("timeouts disabled");
		} else {
			msg("kernel does not support timeouts");
		}
	} else {
		ap->exp_runfreq = (ap->exp_timeout + CHECK_RATIO - 1) / CHECK_RATIO;

		msg("using timeout %d seconds; freq %d secs",
		       (int) ap->exp_timeout, (int) ap->exp_runfreq);
	}

	ioctl(ap->ioctlfd, AUTOFS_IOC_SETTIMEOUT, &timeout);

	fstat(ap->ioctlfd, &st);
	ap->dev = st.st_dev;	/* Device number for mount point checks */

	return 0;

out_umount:
	umount(ap->path);
out_rmdir:
	if (ap->dir_created)
		rmdir_path(ap->path);
out_err:
	if (options)
	free(options);
	if (name)
		free(name);
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

        if (autofs_init_indirect(ap))
		return -1;

	status = do_mount_autofs_indirect(ap);
	if (status < 0)
		return -1;

	/* TODO: read map, determine map type is OK */
	if (!lookup_nss_read_map(ap, now)) {
		error("failed to read map for %s", ap->path);
		return -1;
	}

	lookup_prune_cache(ap, now);

	map = lookup_ghost(ap);
	if (map & LKP_FAIL) {
		if (map & LKP_DIRECT) {
			error("bad map format, "
				"found direct, expected indirect exiting");
		} else {
			error("failed to load map, exiting");
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
	int rv;
	int status = 1;
	int left;

	left = umount_multi(ap, ap->path, 0);
	if (left) {
		warn("could not unmount %d dirs under %s", left, ap->path);
		return -1;
	}

	if (ap->ioctlfd >= 0) {
		ioctl(ap->ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
		ioctl(ap->ioctlfd, AUTOFS_IOC_CATATONIC, 0);
		close(ap->ioctlfd);
		close(ap->state_pipe[0]);
		close(ap->state_pipe[1]);
		ap->state_pipe[0] = -1;
		ap->state_pipe[1] = -1;
	}

	if (ap->pipefd >= 0)
		close(ap->pipefd);

	if (ap->kpipefd >= 0)
		close(ap->kpipefd);

	if (!status) {
		rv = 1;
		goto force_umount;
	}

	rv = umount(ap->path);
	if (rv == -1) {
		if (errno == ENOENT) {
			error("mount point does not exist");
			return 0;
		} else if (errno == EBUSY) {
			debug("mount point %s is in use", ap->path);
			if (ap->state != ST_SHUTDOWN_FORCE)
				return 0;
		} else if (errno == ENOTDIR) {
			error("mount point is not a directory");
			return 0;
		}
		return 1;
	}

force_umount:
	if (rv != 0) {
		warn("forcing umount of %s", ap->path);
		rv = umount2(ap->path, MNT_FORCE);
	} else {
		msg("umounted %s", ap->path);
		if (ap->submount)
			rm_unwanted(ap->path, 1, ap->dev);
	}

	return rv;
}

void *expire_proc_indirect(void *arg)
{
	struct mnt_list *mnts, *next;
	struct expire_args *ea;
	struct autofs_point *ap;
	struct mapent_cache *mc;
	struct mapent *me;
	unsigned int now;
	int offsets, count, ret;
	int ioctlfd;
	int status;

	ea = (struct expire_args *) arg;

	ap = ea->ap;
	mc = ap->mc;
	now = ea->when;
	ea->status = 0;

	status = pthread_barrier_wait(&ea->barrier);
	if (status && status != PTHREAD_BARRIER_SERIAL_THREAD)
		fatal(status);

	pthread_cleanup_push(expire_cleanup, ea);

	/* Get a list of real mounts and expire them if possible */
	mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 0);
	for (next = mnts; next; next = next->next) {
		if (!strcmp(next->fs_type, "autofs"))
			continue;

		debug("expire %s", next->path);

		/*
		 * If me->key starts with a '/' and it's not an autofs
		 * filesystem it's a nested mount and we need to use
		 * the ioctlfd of the mount to send the expire.
		 * Otherwise it's a top level indirect mount (possibly
		 * with offsets in it) and we use the usual ioctlfd.
		 * The next->path is the full path so an indirect mount
		 * won't be found by a cache_lookup, never the less it's
		 * a mount under ap->path.
		 */
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_readlock(mc);
		me = cache_lookup(mc, next->path);
		if (me && *me->key == '/')
			ioctlfd = me->ioctlfd;
		else
			ioctlfd = ap->ioctlfd;
		pthread_cleanup_pop(1);

		ret = ioctl(ioctlfd, AUTOFS_IOC_EXPIRE_MULTI, &now);
		if (ret < 0 && errno != EAGAIN) {
			debug("failed to expire mount %s", next->path);
			ea->status = 1;
			goto done;
		} else
			sched_yield();
	}
done:
	free_mnt_list(mnts);

	count = offsets = 0;
	mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 0);
	/* Are there any real mounts left */
	for (next = mnts; next; next = next->next) {
		if (strcmp(next->fs_type, "autofs"))
			count++;
		else
			offsets++;
	}

	/*
	 * If there are no more real mounts left the we could still
	 * have some offset mounts with no '/' offset so we need to
	 * umount them here.
	 */
	if (mnts && !ea->status && !count) {
		int ret;

		while (offsets--) {
			ret = ioctl(ap->ioctlfd, AUTOFS_IOC_EXPIRE_MULTI, &now);
			if (ret < 0 && errno != EAGAIN) {
				debug("failed to expire ofsets under %s", ap->path);
				ea->status = 1;
				break;
			}
		}
	}
	free_mnt_list(mnts);

	/* 
	 * EXPIRE_MULTI is synchronous, so we can be sure (famous last
	 * words) the umounts are done by the time we reach here
	 */
	if (count) {
		debug("%d remaining in %s", count, ap->path);
		ea->status = 1;
		pthread_exit(NULL);
	}

	/* If we are trying to shutdown make sure we can umount */

	if (ap->state == ST_SHUTDOWN_PENDING) {
		if (!ioctl(ap->ioctlfd, AUTOFS_IOC_ASKUMOUNT, &ret)) {
			if (!ret) {
				debug("mount still busy %s", ap->path);
				ea->status = 1;
				pthread_exit(NULL);
			}
		}
	}

	pthread_cleanup_pop(1);

	return NULL;
}

static void kernel_callback_cleanup(void *arg)
{
	struct autofs_point *ap;
	struct pending_args *mt;

	mt = (struct pending_args *) arg;
	ap = mt->ap;

	if (mt->status)
		send_ready(ap->ioctlfd, mt->wait_queue_token);
	else
		send_fail(ap->ioctlfd, mt->wait_queue_token);

	free(mt);
	return;
}

static void *do_expire_indirect(void *arg)
{
	struct pending_args *mt;
	int status;

	mt = (struct pending_args *) arg;

	mt->status = 1;
	pthread_cleanup_push(kernel_callback_cleanup, mt);

	status = do_expire(mt->ap, mt->name, mt->len);
	if (status)
		mt->status = 0;

	pthread_cleanup_pop(1);
	return NULL;
}

int handle_packet_expire_indirect(struct autofs_point *ap, autofs_packet_expire_indirect_t *pkt)
{
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	pthread_t thid;
	int status;

	debug("token %ld, name %s",
		  (unsigned long) pkt->wait_queue_token, pkt->name);

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error("malloc: %s", estr);
		send_fail(ap->ioctlfd, pkt->wait_queue_token);
		return 1;
	}

	mt->ap = ap;
	strncpy(mt->name, pkt->name, pkt->len);
	mt->name[pkt->len] = '\0';
	mt->len = pkt->len;
	mt->wait_queue_token = pkt->wait_queue_token;

	status = pthread_create(&thid, &thread_attr, do_expire_indirect, mt);
	if (status) {
		error("expire thread create failed");
		send_fail(ap->ioctlfd, pkt->wait_queue_token);
		free(mt);
	}
	return 0;
}

static void *do_mount_indirect(void *arg)
{
	struct pending_args *mt;
	struct autofs_point *ap;
	char buf[PATH_MAX + 1];
	struct stat st;
	struct passwd pw;
	struct passwd *ppw = &pw;
	struct passwd **pppw = &ppw;
	struct group gr;
	struct group *pgr = &gr;
	struct group **ppgr = &pgr;
	char *pw_tmp, *gr_tmp;
	struct thread_stdenv_vars *tsv;
	int len, tmplen, status;

	mt = (struct pending_args *) arg;
	ap = mt->ap;

	mt->status = 0;
	pthread_cleanup_push(kernel_callback_cleanup, mt);

	len = ncat_path(buf, sizeof(buf), ap->path, mt->name, mt->len);
	if (!len) {
		crit("path to be mounted is to long");
		pthread_exit(NULL);
	}

	status = lstat(buf, &st);
	debug("status %d S_ISDIR(st.st_mode) %d st.st_dev %ld mt->dev %ld",
		status, S_ISDIR(st.st_mode), (long) st.st_dev, (long)  mt->dev);
	if (status != -1 && !(S_ISDIR(st.st_mode) && st.st_dev == mt->dev)) {
		error("indirect trigger not valid or already mounted %s", buf);
		pthread_exit(NULL);
	}

	msg("attempting to mount entry %s", buf);

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
		error("failed to get buffer size for getpwuid_r");
		free(tsv);
		goto cont;
	}

	pw_tmp = malloc(tmplen + 1);
	if (!pw_tmp) {
		error("failed to malloc buffer for getpwuid_r");
		free(tsv);
		goto cont;
	}

	status = getpwuid_r(mt->uid, ppw, pw_tmp, tmplen, pppw);
	if (status) {
		error("failed to get passwd info from getpwuid_r");
		free(tsv);
		free(pw_tmp);
		goto cont;
	}

	tsv->user = strdup(pw.pw_name);
	if (!tsv->user) {
		error("failed to malloc buffer for user");
		free(tsv);
		free(pw_tmp);
		goto cont;
	}

	tsv->home = strdup(pw.pw_dir);
	if (!tsv->user) {
		error("failed to malloc buffer for home");
		free(pw_tmp);
		free(tsv->user);
		free(tsv);
		goto cont;
	}

	free(pw_tmp);

	/* Try to get group info */

	tmplen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (tmplen < 0) {
		error("failed to get buffer size for getgrgid_r");
		free(tsv->user);
		free(tsv->home);
		free(tsv);
		goto cont;
	}

	gr_tmp = malloc(tmplen + 1);
	if (!gr_tmp) {
		error("failed to malloc buffer for getgrgid_r");
		free(tsv->user);
		free(tsv->home);
		free(tsv);
		goto cont;
	}

	status = getgrgid_r(mt->gid, pgr, gr_tmp, tmplen, ppgr);
	if (status) {
		error("failed to get group info from getgrgid_r");
		free(tsv->user);
		free(tsv->home);
		free(tsv);
		free(gr_tmp);
		goto cont;
	}

	tsv->group = strdup(gr.gr_name);
	if (!tsv->group) {
		error("failed to malloc buffer for group");
		free(tsv->user);
		free(tsv->home);
		free(tsv);
		free(gr_tmp);
		goto cont;
	}

	free(gr_tmp);

	status = pthread_setspecific(key_thread_stdenv_vars, tsv);
	if (status) {
		error("failed to set stdenv thread var");
		free(tsv->group);
		free(tsv->user);
		free(tsv->home);
		free(tsv);
	}
cont:
	status = lookup_nss_mount(ap, mt->name, mt->len);
	if (status) {
		mt->status = 1;
		msg("mounted %s", buf);
	} else
		msg("failed to mount %s", buf);

	pthread_cleanup_pop(1);
	return NULL;
}

int handle_packet_missing_indirect(struct autofs_point *ap, autofs_packet_missing_indirect_t *pkt)
{
	pthread_t thid;
	char buf[MAX_ERR_BUF];
	struct pending_args *mt;
	int status;

	debug("token %ld, name %s, request pid %u",
		(unsigned long) pkt->wait_queue_token, pkt->name, pkt->pid);

	/* Ignore packet if we're trying to shut down */
	if (ap->state == ST_SHUTDOWN_PENDING ||
	    ap->state == ST_SHUTDOWN_FORCE ||
	    ap->state == ST_SHUTDOWN) {
		send_fail(ap->ioctlfd, pkt->wait_queue_token);
		return 0;
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error("malloc: %s", estr);
		send_fail(ap->ioctlfd, pkt->wait_queue_token);
		return 1;
	}

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
		error("expire thread create failed");
		send_fail(ap->ioctlfd, pkt->wait_queue_token);
		free(mt);
		return 1;
	}
	return 0;
}

