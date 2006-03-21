#ident "$Id: lookup_userhome.c,v 1.10 2006/03/21 04:28:53 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  lookup_userhome.c - module for Linux automount to generate symlinks
 *                      to user home directories
 *
 *   Copyright 1999 Transmeta Corporation - All Rights Reserved
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
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MODPREFIX "lookup(userhome): "

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	return 0;		/* Nothing to do */
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
        return NSS_STATUS_UNKNOWN;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	return NSS_STATUS_UNKNOWN;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct passwd *pw;
	char buf[MAX_ERR_BUF];

	debug(MODPREFIX "looking up %s", name);

	/* Get the equivalent username */
	pw = getpwnam(name);
	if (!pw) {
		info(MODPREFIX "not found: %s", name);
		return NSS_STATUS_NOTFOUND;	/* Unknown user or error */
	}

	/* Create the appropriate symlink */
	if (chdir(ap->path)) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(MODPREFIX "chdir failed: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	if (symlink(pw->pw_dir, name) && errno != EEXIST) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(MODPREFIX "symlink failed: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	return 0;
}
