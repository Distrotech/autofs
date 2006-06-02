#ident "$Id: mount.c,v 1.12 2006/03/08 02:40:22 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  mount.c - Abstract mount code used by modules for an unexpected
 *            filesystem type
 *
 *   Copyright 1997-2000 Transmeta Corporation - All Rights Reserved
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

#include <stdlib.h>
#include <string.h>
#include "automount.h"

/* These filesystems are known not to work with the "generic" module */
/* Note: starting with Samba 2.0.6, smbfs is handled generically.    */
static char *not_generic[] = { "nfs", "userfs", "afs", "autofs",
			       "changer", "bind", NULL
};

int do_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
	     const char *what, const char *fstype, const char *options)
{
	struct mount_mod *mod;
	const char *modstr;
	char **ngp;
	int rv;

	mod = open_mount(modstr = fstype, NULL);
	if (!mod) {
		for (ngp = not_generic; *ngp; ngp++) {
			if (!strcmp(fstype, *ngp))
				break;
		}
		if (!*ngp)
			mod = open_mount(modstr = "generic", NULL);
		if (!mod) {
			error(ap->logopt,
			      "cannot find mount method for filesystem %s",
			      fstype);
			return -1;
		}
	}

	if (ap->type == LKP_DIRECT)
		debug(ap->logopt,
		      "%s %s type %s options %s using module %s",
		      what, name, fstype, options, modstr);
	else
		debug(ap->logopt,
		      "%s %s/%s type %s options %s using module %s",
		      what, root, name, fstype, options, modstr);

	rv = mod->mount_mount(ap, root, name, name_len, what, fstype, options, mod->context);
	close_mount(mod);

	return rv;
}
