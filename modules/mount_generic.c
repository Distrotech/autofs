#ident "$Id: mount_generic.c,v 1.8 2004/05/10 12:44:30 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  mount_generic.c - module for Linux automountd to mount filesystems
 *                    for which no special magic is required
 *
 *   Copyright 1997-1999 Transmeta Corporation - All Rights Reserved
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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_MOUNT
#include "automount.h"

#define MODPREFIX "mount(generic): "

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

extern struct autofs_point ap;

int mount_init(void **context)
{
	return 0;
}

int mount_mount(const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options,
		void *context)
{
	char *fullpath;
	int err;
	int status;

	fullpath = alloca(strlen(root) + name_len + 2);
	if (!fullpath) {
		error(MODPREFIX "alloca: %m");
		return 1;
	}

	if (name_len)
		sprintf(fullpath, "%s/%s", root, name);
	else
		sprintf(fullpath, "%s", root);

	debug(MODPREFIX "calling mkdir_path %s", fullpath);

	if ((status = mkdir_path(fullpath, 0555)) && errno != EEXIST) {
		error(MODPREFIX "mkdir_path %s failed: %m", fullpath);
		return 1;
	}

	if (is_mounted(fullpath)) {
		error("BUG: %s already mounted", fullpath);
		return 0;
	}

	wait_for_lock();
	if (options) {
		debug(MODPREFIX "calling mount -t %s " SLOPPY "-o %s %s %s",
		      fstype, options, what, fullpath);

		err = spawnl(LOG_NOTICE, MOUNTED_LOCK,
			     PATH_MOUNT, PATH_MOUNT, "-t", fstype,
			     SLOPPYOPT "-o", options, what, fullpath, NULL);
	} else {
		debug(MODPREFIX "calling mount -t %s %s %s",
		      fstype, what, fullpath);
		err = spawnl(LOG_NOTICE, MOUNTED_LOCK,
			     PATH_MOUNT, PATH_MOUNT, "-t", fstype,
			     what, fullpath, NULL);
	}
	unlink(AUTOFS_LOCK);

	if (err) {
		if (!ap.ghost && name_len)
			rmdir_path(name);

		error(MODPREFIX "failed to mount %s (type %s) on %s",
		      what, fstype, fullpath);

		return 1;
	} else {
		debug(MODPREFIX "mounted %s type %s on %s",
		      what, fstype, fullpath);
		return 0;
	}
}

int mount_done(void *context)
{
	return 0;
}
