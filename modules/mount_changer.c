/* ----------------------------------------------------------------------- *
 *   
 *  mount_changer.c - module for Linux automountd to mount filesystems
 *                    from cd changers
 *
 *   Copyright 1999 Toby Jaffey - All Rights Reserved
 *   CD swapping code from linux kernel in Documentation/cdrom/ide-cd
 * Based on code originally from Gerhard Zuber <zuber@berlin.snafu.de>.
 * Changer status information, and rewrite for the new Uniform CDROM driver
 * interface by Erik Andersen <andersee@debian.org>.
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/cdrom.h>

#define MODULE_MOUNT
#include "automount.h"

#ifdef DEBUG
#define DB(x)           do { x; } while(0)
#else
#define DB(x)           do { } while(0)
#endif

#define MODPREFIX "mount(changer): "
int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

extern struct autofs_point ap;

int swapCD(const char *device, const char *slotName);

int mount_init(void **context)
{
	return 0;
}

int mount_mount(const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context)
{
	char *fullpath;
	int err;

	fstype = "iso9660";

	fullpath = alloca(strlen(root) + name_len + 2);
	if (!fullpath) {
		syslog(LOG_ERR, MODPREFIX "alloca: %m");
		return 1;
	}
	sprintf(fullpath, "%s/%s", root, name);

	DB(syslog(LOG_DEBUG, MODPREFIX "calling umount %s", what));

	wait_for_lock();
	err = spawnl(LOG_DEBUG, MOUNTED_LOCK, PATH_UMOUNT, PATH_UMOUNT, what, NULL);
	unlink(AUTOFS_LOCK);
	if (err) {
		syslog(LOG_ERR, MODPREFIX "umount of %s failed (all may be unmounted)",
		       what);
	}

	DB(syslog(LOG_DEBUG, MODPREFIX "calling mkdir_path %s", fullpath));

	if (mkdir_path(fullpath, 0555) && errno != EEXIST) {
		syslog(LOG_ERR, MODPREFIX "mkdir_path %s failed: %m", name);
		return 1;
	}

	DB(syslog(LOG_NOTICE, MODPREFIX "Swapping CD to slot %s", name));

	err = swapCD(what, name);
	if (err) {
		syslog(LOG_NOTICE, MODPREFIX "failed to swap CD to slot %s", name);
		return 1;
	}
	wait_for_lock();

	if (options) {
		DB(syslog
		   (LOG_DEBUG, MODPREFIX "calling mount -t %s " SLOPPY "-o %s %s %s",
		    fstype, options, what, fullpath));
		err =
		    spawnl(LOG_DEBUG, MOUNTED_LOCK, PATH_MOUNT, PATH_MOUNT, "-t", fstype,
			   what, SLOPPYOPT "-o", options, what, fullpath, NULL);
	} else {
		DB(syslog(LOG_DEBUG, MODPREFIX "calling mount -t %s %s %s",
			  fstype, what, fullpath));
		err = spawnl(LOG_DEBUG, MOUNTED_LOCK, PATH_MOUNT, PATH_MOUNT,
			     "-t", fstype, what, fullpath, NULL);
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

int swapCD(const char *device, const char *slotName)
{
	int fd;			/* file descriptor for CD-ROM device */
	int status;		/* return status for system calls */
	int slot = -1;
	int total_slots_available;

	slot = atoi(slotName) - 1;

	/* open device */
	fd = open(device, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		syslog(LOG_NOTICE, MODPREFIX "Opening device %s failed : %s", device,
		       strerror(errno));
		return 1;
	}

	/* Check CD player status */
	total_slots_available = ioctl(fd, CDROM_CHANGER_NSLOTS);
	if (total_slots_available <= 1) {
		syslog(LOG_NOTICE, MODPREFIX
		       "Device %s is not an ATAPI compliant CD changer.\n", device);
		return 1;
	}

	/* load */
	slot = ioctl(fd, CDROM_SELECT_DISC, slot);
	if (slot < 0) {
		syslog(LOG_NOTICE, MODPREFIX "CDROM_SELECT_DISC failed");
		return 1;
	}

	/* close device */
	status = close(fd);
	if (status != 0) {
		syslog(LOG_NOTICE, MODPREFIX "close failed for `%s': %s\n", device,
		       strerror(errno));
		return 1;
	}
	return 0;
}
