#ident "$Id"
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
#include <pwd.h>
#include <grp.h>

#include "automount.h"

#define MAX_OPTIONS_LEN         128
#define MAX_MNT_NAME_LEN        128

static char options[MAX_OPTIONS_LEN];   /* common mount options string */
/*
static int kernel_pipefd = -1;           kernel pipe fd for use in direct mounts
*/
extern int submount;

extern sigset_t ready_sigs;		/* signals only accepted in ST_READY */
extern sigset_t lock_sigs;		/* signals blocked for locking */
extern sigset_t sigchld_mask;

extern volatile struct pending_mount *junk_mounts;

static int autofs_init_indirect(char *path)
{
	int pipefd[2];

	if ((ap.state != ST_INIT)) {
		/* This can happen if an autofs process is already running*/
		error("bad state %d", ap.state);
		return -1;
	}

	/* Must be an absolute pathname */
	if (path[0] != '/') {
		crit("invalid indirect mount key %s", ap.path);
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
		close(ap.kpipefd);	/* Close kernel pipe end */
		free(ap.path);
		return -1;
	}

	return 0;
}

static int do_mount_autofs_indirect(char *path)
{
	time_t timeout = ap.exp_timeout;
	char our_name[MAX_MNT_NAME_LEN];
	int name_len = MAX_MNT_NAME_LEN;
	struct stat st;
	int len;

	if (is_mounted(_PROC_MOUNTS, path)) {
		error("already mounted");
		goto out_err;
	}

	len = snprintf(our_name, name_len,
			"automount(pid%u)", (unsigned) getpid());
	if (len >= name_len) {
		crit("buffer to small for our_name - truncated");
		len = name_len - 1;
	}
        if (len < 0) {
                crit("failed setting up our_name for autofs path %s", path);
                return 0;
        }
	our_name[len] = '\0';
	
	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(path, 0555) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit("failed to create iautofs directory %s", path);
			goto out_err;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		ap.dir_created = 0;
	} else {
		/* No errors so the directory was successfully created */
		ap.dir_created = 1;
	}

	if (spawnl(LOG_DEBUG, PATH_MOUNT, PATH_MOUNT,
		   "-t", "autofs", "-n", "-o", options, our_name, path, NULL) != 0) {
		crit("failed to mount autofs path %s", path);
		goto out_rmdir;
	}
/*
	close(kernel_pipefd);
	kernel_pipefd = -1;
*/

	/* Root directory for ioctl()'s */
	ap.ioctlfd = open(path, O_RDONLY);
	if (ap.ioctlfd < 0) {
		crit("failed to create ioctl fd for autofs path %s", path);
		goto out_umount;
	}

	ap.kver.major = 0;
	ap.kver.minor = 0;

	/* If this ioctl() doesn't work, it is kernel version 2 */
	if (!ioctl(ap.ioctlfd, AUTOFS_IOC_PROTOVER, &ap.kver.major)) {
		 /* If this ioctl() doesn't work, kernel does not support ghosting */
		 if (ioctl(ap.ioctlfd, AUTOFS_IOC_PROTOSUBVER, &ap.kver.minor)) {
			ap.kver.minor = 0;
			if (ap.ghost) {
				msg("kernel does not support ghosting, disabled");
				ap.ghost = 0;
			}
		 }
	} else {
		ap.kver.major = 2;
		ap.kver.minor = 0;
	}

	msg("using kernel protocol version %d.%02d", ap.kver.major, ap.kver.minor);

	/* Calculate the timeouts */
	if (ap.kver.major < 3 || !timeout) {
		ap.exp_timeout = ap.exp_runfreq = 0;
		ap.ghost = 0;
		if (ap.kver.major >= 3) {
			msg("timeouts disabled");
		} else {
			msg("kernel does not support timeouts");
		}
	} else {
		ap.exp_runfreq = (ap.exp_timeout + CHECK_RATIO - 1) / CHECK_RATIO;

		msg("using timeout %d seconds; freq %d secs",
		       (int) ap.exp_timeout, (int) ap.exp_runfreq);
	}

	ioctl(ap.ioctlfd, AUTOFS_IOC_SETTIMEOUT, &timeout);

	fstat(ap.ioctlfd, &st);
	ap.dev = st.st_dev;	/* Device number for mount point checks */

	return 0;

out_umount:
	spawnll(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", path, NULL);
out_rmdir:
	if (ap.dir_created)
		rmdir_path(ap.path);
out_err:
	close(ap.state_pipe[0]);
	close(ap.state_pipe[1]);
	close(ap.pipefd);
	close(ap.kpipefd);
	free(ap.path);

	return -1;
}

int mount_autofs_indirect(char *path)
{
	int status;
	int map;

        if (autofs_init_indirect(path))
		return -1;

	if (!make_options_string(options, MAX_OPTIONS_LEN, ap.kpipefd, NULL)) {
		close(ap.state_pipe[0]);
		close(ap.state_pipe[1]);
		close(ap.pipefd);
		close(ap.kpipefd);
		free(ap.path);
		return -1;
	}

	ap.type = LKP_INDIRECT;
	status = do_mount_autofs_indirect(path);
	if (status < 0)
		return -1;

	map = ap.lookup->lookup_ghost(ap.path, ap.ghost, 0, ap.lookup->context);
	if (map & LKP_FAIL) {
		if (map & LKP_DIRECT) {
			error("bad map format, "
				"found direct, expected indirect exiting");
		} else {
			error("failed to load map, exiting");
		}
		rm_unwanted(path, 1, 1);
		return -1;
	}

	if (map & LKP_NOTSUP)
		ap.ghost = 0;

	ap.mounts = NULL;	/* No pending mounts */
	ap.state = ST_READY;

	return 0;
}

int umount_autofs_indirect(void)
{
	int rv, ret;
	int status = 1;
	int left;
	struct stat st;

	left = umount_multi(ap.path, 0);
	if (left) {
		warn("could not unmount %d dirs under %s", left, ap.path);
		return -1;
	}

	if (ap.ioctlfd >= 0) {
		ioctl(ap.ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status);
		ioctl(ap.ioctlfd, AUTOFS_IOC_CATATONIC, 0);
		close(ap.ioctlfd);
		close(ap.state_pipe[0]);
		close(ap.state_pipe[1]);
	}

	if (ap.pipefd >= 0)
		close(ap.pipefd);

	if (ap.kpipefd >= 0)
		close(ap.kpipefd);

	if (!status) {
		rv = 1;
		goto force_umount;
	}

	rv = spawnl(LOG_DEBUG, PATH_UMOUNT, PATH_UMOUNT, "-n", ap.path, NULL);
	ret = stat(ap.path, &st);
	if (rv != 0 && ((ret == -1 && errno == ENOENT) ||
	    (ret == 0 && (!S_ISDIR(st.st_mode) || st.st_dev != ap.dev)))) {
		rv = 0;
	}

force_umount:
	if (rv != 0) {
		rv = spawnl(LOG_DEBUG,
			    PATH_UMOUNT, PATH_UMOUNT, "-n", "-l", ap.path, NULL);
		warn("forcing umount of %s\n", ap.path);
	} else {
		msg("umounted %s\n", ap.path);
		if (submount)
			rm_unwanted(ap.path, 1, 1);
	}
	free(ap.path);

	return rv;
}

int expire_proc_indirect(int now)
{
	int count;
	int status = 1;

	/* make a pass over the map to try to expire any offsets */
	cache_enumerate(expire_offsets_direct, now);

	/* 
	 * Generate expire messages until there's nothing more to
	 * expire.  If a bug prevents unmounting, limit attempts to
	 * 20/second and a few more than the known number of mounts.
	 */

	count = count_mounts(ap.path) + 3;
	while (ioctl(ap.ioctlfd, AUTOFS_IOC_EXPIRE_MULTI, &now) == 0
				&& count--) {
		struct timespec nap = { 0, 50000000 }; /*5e-2 seconds*/;
		nanosleep(&nap, NULL);
	}

	/* 
	 * EXPIRE_MULTI is synchronous, so we can be sure (famous last
	 * words) the umounts are done by the time we reach here
	 */
	if ((count = count_mounts(ap.path))) {
		debug("%d remaining in %s\n", count, ap.path);
		exit(1);
	}

	/* If we are trying to shutdown make sure we can umount */
	if (ap.state == ST_SHUTDOWN_PENDING) {
		if (!ioctl(ap.ioctlfd, AUTOFS_IOC_ASKUMOUNT, &status))
			if (!status)
				exit(1);
	}

	exit(0);
}

int handle_packet_expire_indirect(const struct autofs_packet_expire_indirect *pkt)
{
	int ret;

	debug("token %ld, name %s\n",
		  (unsigned long) pkt->wait_queue_token, pkt->name);

	ret = handle_expire(pkt->name, pkt->len, ap.ioctlfd, pkt->wait_queue_token);

	if (ret != 0)
		send_fail(ap.ioctlfd, pkt->wait_queue_token);

	return ret;
}

static int do_mount_indirect(const struct autofs_packet_missing_indirect *pkt)
{
	sigset_t oldsig;
	pid_t f;
	struct pending_mount *mt = NULL;
	char buf[PATH_MAX + 1];
	int size;

	/* Block SIGCHLD while mucking with linked lists */
	sigprocmask(SIG_BLOCK, &sigchld_mask, NULL);
	if ((mt = (struct pending_mount *) junk_mounts)) {
		junk_mounts = junk_mounts->next;
	} else {
		if (!(mt = malloc(sizeof(struct pending_mount)))) {
			error("malloc: %m");
			send_fail(ap.ioctlfd, pkt->wait_queue_token);
			return 1;
		}
	}
	sigprocmask(SIG_UNBLOCK, &sigchld_mask, NULL);

	size = ncat_path(buf, sizeof(buf), ap.path, pkt->name, pkt->len);
	if (!size) {
		crit("path to be mounted is to long");
		send_fail(ap.ioctlfd, pkt->wait_queue_token);
		free(mt);
		return 0;
	}

	msg("attempting to mount entry %s", buf);

	sigprocmask(SIG_BLOCK, &lock_sigs, &oldsig);

	f = fork();
	if (f == -1) {
		sigprocmask(SIG_SETMASK, &oldsig, NULL);
		error("fork: %m");
		send_fail(ap.ioctlfd, pkt->wait_queue_token);
		free(mt);
		return 1;
	} else if (!f) {
		int err;
		struct passwd *u_pwd;
		struct group *u_grp;
		char env_buf[12];

		/* Set up a sensible signal environment */
		ignore_signals();
		/* close(ap.pipefd); */
		/* close(ap.kpipefd); */
		close(ap.ioctlfd);
		close(ap.state_pipe[0]);
		close(ap.state_pipe[1]);

		if (ap.kver.major > 4) {
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
		}

		err = ap.lookup->lookup_mount(ap.path,
					      pkt->name, pkt->len,
					      ap.lookup->context);

		if (err) {
			error("failed to mount %s", buf);
		} else
			msg("mounted %s", buf);

		_exit(err ? 1 : 0);
	} else {
		/*
		 * Important: set up data structures while signals
		 * still blocked
		 */
		mt->pid = f;
		mt->me = NULL;
		mt->ioctlfd = ap.ioctlfd;
		mt->wait_queue_token = pkt->wait_queue_token;
		mt->next = ap.mounts;
		ap.mounts = mt;

		sigprocmask(SIG_SETMASK, &oldsig, NULL);
	}

	return 0;
}

int handle_packet_missing_indirect(const struct autofs_packet_missing_indirect *pkt)
{
	struct stat st;

	debug("token %ld, name %s\n",
		(unsigned long) pkt->wait_queue_token, pkt->name);

	/* Ignore packet if we're trying to shut down */
	if (ap.state == ST_SHUTDOWN_PENDING || ap.state == ST_SHUTDOWN) {
		send_fail(ap.ioctlfd, pkt->wait_queue_token);
		return 0;
	}

	chdir(ap.path);
	if (lstat(pkt->name, &st) == -1 ||
	   (S_ISDIR(st.st_mode) && st.st_dev == ap.dev)) {
		/* Need to mount or symlink */
		do_mount_indirect(pkt);
	} else {
		/*
		 * Already there (can happen if a process connects to a
		 * directory while we're still working on it)
		 */
		/*
		 * XXX For v4, this would be the wrong thing to do if it could
		 * happen. It should add the new wait_queue_token to the pending
		 * mount structure so that it gets sent a ready when its really
		 * done.  In practice, the kernel keeps any other processes
		 * blocked until the initial mount request is done. -JSGF
		 */
		send_ready(ap.ioctlfd, pkt->wait_queue_token);
	}
	chdir("/");

	return 0;
}

