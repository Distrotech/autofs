#ident "$Id: mount_ext2.c,v 1.7 2004/01/01 11:49:09 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  mount_ext2.c - module for Linux automountd to mount ext2 filesystems
 *                 after running fsck on them.
 *
 *   Copyright 1998 Transmeta Corporation - All Rights Reserved
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

#ifdef DEBUG
#define DB(x)           do { x; } while(0)
#else
#define DB(x)           do { } while(0)
#endif

#define MODPREFIX "mount(ext2): "

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

extern struct autofs_point ap;

int mount_init(void **context)
{
	return 0;
}


int mount_mount(const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context)
{
	char *fullpath;
	const char *p, *p1;
	int err, ro = 0;
	const char *fsck_prog;

	fullpath = alloca(strlen(root) + name_len + 2);
	if (!fullpath) {
		syslog(LOG_ERR, MODPREFIX "alloca: %m");
		return 1;
	}
	sprintf(fullpath, "%s/%s", root, name);

	DB(syslog(LOG_DEBUG, MODPREFIX "calling mkdir_path %s", fullpath));
	if (mkdir_path(fullpath, 0555) && errno != EEXIST) {
		syslog(LOG_ERR, MODPREFIX "mkdir_path %s failed: %m", name);
		return 1;
	}

	if (is_mounted(fullpath)) {
		syslog(LOG_WARNING, "BUG: %s already mounted", fullpath);
		return 0;
	}

	if (options) {
		for (p = options; (p1 = strchr(p, ',')); p = p1)
			if (!strncmp(p, "ro", p1 - p) && ++p1 - p == sizeof("ro"))
				ro = 1;
		if (!strcmp(p, "ro"))
			ro = 1;
	}

#ifdef HAVE_E3FSCK
	if (!strcmp(fstype,"ext3") || !strcmp(fstype,"auto"))
		fsck_prog = PATH_E3FSCK;
	else
		fsck_prog = PATH_E2FSCK;
#else
	fsck_prog = PATH_E2FSCK;
#endif
	if (ro) {
		DB(syslog(LOG_DEBUG, MODPREFIX "calling %s -n %s", fsck_prog, what));
		err = spawnl(LOG_DEBUG, fsck_prog, fsck_prog, "-n", what, NULL);
	} else {
		DB(syslog(LOG_DEBUG, MODPREFIX "calling %s -p %s", fsck_prog, what));
		err = spawnl(LOG_DEBUG, fsck_prog, fsck_prog, "-p", what, NULL);
	}

	if (err & ~6) {
		syslog(LOG_ERR, MODPREFIX "%s: filesystem needs repair, won't mount",
		       what);
		return 1;
	}
	wait_for_lock();

	if (options) {
		DB(syslog
		   (LOG_DEBUG, MODPREFIX "calling mount -t %s " SLOPPY "-o %s %s %s",
		    fstype, options, what, fullpath));
		err =
		    spawnl(LOG_NOTICE, MOUNTED_LOCK, PATH_MOUNT, PATH_MOUNT, "-t", fstype,
			   SLOPPYOPT "-o", options, what, fullpath, NULL);
	} else {
		DB(syslog(LOG_DEBUG, MODPREFIX "calling mount -t %s %s %s",
			  fstype, what, fullpath));
		err =
		    spawnl(LOG_NOTICE, MOUNTED_LOCK, PATH_MOUNT, PATH_MOUNT, "-t", fstype,
			   what, fullpath, NULL);
	}
	unlink(AUTOFS_LOCK);
	if (err) {
		if (!ap.ghost)
			rmdir_path(fullpath);
		syslog(LOG_ERR, MODPREFIX "failed to mount %s (type %s) on %s",
		       what, fstype, fullpath);
		return 1;
	} else {
		DB(syslog(LOG_DEBUG, MODPREFIX "mounted %s type %s on %s",
			  what, fstype, fullpath));
		return 0;
	}
}

int mount_done(void *context)
{
	return 0;
}
