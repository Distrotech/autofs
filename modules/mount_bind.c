/* ----------------------------------------------------------------------- *
 *   
 *  mount_bind.c      - module to mount a local filesystem if possible;
 *			otherwise create a symlink.
 *
 *   Copyright 2000 Transmeta Corporation - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_MOUNT
#include "automount.h"

#define MODPREFIX "mount(bind): "

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

static int bind_works = 0;

int mount_init(void **context)
{
	char tmp1[] = "autoXXXXXX", *t1_dir;
	char tmp2[] = "autoXXXXXX", *t2_dir;
	int err;
	struct stat st1, st2;

	t1_dir = mkdtemp(tmp1);
	t2_dir = mkdtemp(tmp2);
	if (t1_dir == NULL || t2_dir == NULL) {
		if (t1_dir)
			rmdir(t1_dir);
		if (t2_dir)
			rmdir(t2_dir);
		return 0;
	}

	if (lstat(t1_dir, &st1) == -1)
		goto out;

	err = spawn_mount(log_debug, "-n", "--bind", t1_dir, t2_dir, NULL);
	if (err == 0 &&
	    lstat(t2_dir, &st2) == 0 &&
	    st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
		bind_works = 1;
	}

	debug(LOGOPT_NONE, MODPREFIX "bind_works = %d", bind_works);

	spawn_umount(log_debug, "-n", t2_dir, NULL);

out:
	rmdir(t2_dir);
	rmdir(t2_dir);

	return 0;
}

int mount_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context)
{
	char *fullpath;
	char buf[MAX_ERR_BUF];
	int err;
	int i, rlen;

	/* Root offset of multi-mount */
	if (*name == '/' && name_len == 1) {
		rlen = strlen(root);
		name_len = 0;
	/* Direct mount name is absolute path so don't use root */
	} else if (*name == '/')
		rlen = 0;
	else
		rlen = strlen(root);

	fullpath = alloca(rlen + name_len + 2);
	if (!fullpath) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "alloca: %s", estr);
		return 1;
	}

	if (name_len) {
		if (rlen)
			sprintf(fullpath, "%s/%s", root, name);
		else
			sprintf(fullpath, "%s", name);
	} else
		sprintf(fullpath, "%s", root);

	i = strlen(fullpath);
	while (--i > 0 && fullpath[i] == '/')
		fullpath[i] = '\0';

	if (options == NULL || *options == '\0')
		options = "defaults";

	if (bind_works) {
		int status, existed = 1;

		debug(ap->logopt, MODPREFIX "calling mkdir_path %s", fullpath);

		status = mkdir_path(fullpath, 0555);
		if (status && errno != EEXIST) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt,
			      MODPREFIX "mkdir_path %s failed: %s",
			      fullpath, estr);
			return 1;
		}

		if (!status)
			existed = 0;

		if (is_mounted(_PATH_MOUNTED, fullpath, MNTS_REAL)) {
			error(ap->logopt,
			      MODPREFIX "warning: %s is already mounted",
			      fullpath);
			return 0;
		}

		debug(ap->logopt,
		      MODPREFIX
		      "calling mount --bind " SLOPPY " -o %s %s %s",
		      options, what, fullpath);

		err = spawn_bind_mount(log_debug,
			     SLOPPYOPT "-o", options, what, fullpath, NULL);

		if (err) {
			if (ap->type != LKP_INDIRECT)
				return 1;

			if ((!ap->ghost && name_len) || !existed)
				rmdir_path(ap, fullpath, ap->dev);

			return 1;
		} else {
			debug(ap->logopt,
			      MODPREFIX "mounted %s type %s on %s",
			      what, fstype, fullpath);
			return 0;
		}
	} else {
		char *cp;
		char *basepath = alloca(strlen(fullpath) + 1);
		int status;
		struct stat st;

		strcpy(basepath, fullpath);
		cp = strrchr(basepath, '/');

		if (cp != NULL && cp != basepath)
			*cp = '\0';

		if ((status = stat(fullpath, &st)) == 0) {
			if (S_ISDIR(st.st_mode))
				rmdir(fullpath);
		} else {
			debug(ap->logopt,
			      MODPREFIX "calling mkdir_path %s", basepath);
			if (mkdir_path(basepath, 0555) && errno != EEXIST) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(ap->logopt,
				      MODPREFIX "mkdir_path %s failed: %s",
				      basepath, estr);
				return 1;
			}
		}

		if (symlink(what, fullpath) && errno != EEXIST) {
			error(ap->logopt,
			      MODPREFIX
			      "failed to create local mount %s -> %s",
			      fullpath, what);
			if (ap->ghost && !status)
				mkdir_path(fullpath, 0555);
			else {
				if (ap->type == LKP_INDIRECT)
					rmdir_path(ap, fullpath, ap->dev);
			}
			return 1;
		} else {
			debug(ap->logopt,
			      MODPREFIX "symlinked %s -> %s", fullpath, what);
			return 0;
		}
	}
}

int mount_done(void *context)
{
	return 0;
}
