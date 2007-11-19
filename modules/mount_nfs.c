/* ----------------------------------------------------------------------- *
 *   
 * mount_nfs.c - Module for Linux automountd to mount an NFS filesystem,
 *               with fallback to symlinking if the path is local
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
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
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#include <linux/nfs.h>
#include <linux/nfs2.h>
#include <ctype.h>

#define MODULE_MOUNT
#include "automount.h"
#include "replicated.h"

#define MODPREFIX "mount(nfs): "

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

static struct mount_mod *mount_bind = NULL;
static int init_ctr = 0;

int mount_init(void **context)
{
	/* Make sure we have the local mount method available */
	if (!mount_bind) {
		if ((mount_bind = open_mount("bind", MODPREFIX)))
			init_ctr++;
	} else
		init_ctr++;

	seed_random();

	return !mount_bind;
}

int mount_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options,
		void *context)
{
	char *fullpath, buf[MAX_ERR_BUF];
	struct host *this, *hosts = NULL;
	unsigned int save_ghost = ap->ghost;
	unsigned int vers;
	char *nfsoptions = NULL;
	int len, rlen, status, err, existed = 1;
	int nosymlink = 0;
	int ro = 0;            /* Set if mount bind should be read-only */

	debug(ap->logopt,
	      MODPREFIX "root=%s name=%s what=%s, fstype=%s, options=%s",
	      root, name, what, fstype, options);

	/* Extract "nosymlink" pseudo-option which stops local filesystems
	 * from being symlinked.
	 *
	 * "nosymlink" is not used anymore. It is left for compatibility
	 * only (so we don't choke on it).
	 */
	if (options) {
		const char *comma;
		char *nfsp;
		int o_len = strlen(options) + 1;

		nfsp = nfsoptions = alloca(o_len + 1);
		if (!nfsoptions)
			return 1;

		memset(nfsoptions, '\0', o_len + 1);

		for (comma = options; *comma != '\0';) {
			const char *cp;
			const char *end;

			while (*comma == ',')
				comma++;

			/* Skip leading white space */
			while (*comma == ' ' || *comma == '\t')
				comma++;

			cp = comma;
			while (*comma != '\0' && *comma != ',')
				comma++;

			/* Skip trailing white space */
			end = comma - 1;
			while (*comma == ' ' || *comma == '\t')
				end--;

			if (strncmp("nosymlink", cp, end - cp + 1) == 0)
				nosymlink = 1;
			else {
				/* Check for options that also make sense
				   with bind mounts */
				if (strncmp("ro", cp, end - cp + 1) == 0)
					ro = 1;
				/* and jump over trailing white space */
				memcpy(nfsp, cp, comma - cp + 1);
				nfsp += comma - cp + 1;
			}
		}

		debug(ap->logopt, 
		      MODPREFIX "nfs options=\"%s\", nosymlink=%d, ro=%d",
		      nfsoptions, nosymlink, ro);
	}

	if (strcmp(fstype, "nfs4") == 0)
		vers = NFS4_VERS_MASK | NFS_PROTO_MASK;
	else
		vers = NFS_VERS_MASK | NFS_PROTO_MASK;

	if (!parse_location(ap->logopt, &hosts, what)) {
		info(ap->logopt, MODPREFIX "no hosts available");
		return 1;
	}
	prune_host_list(ap->logopt, &hosts, vers, nfsoptions, ap->random_selection);

	if (!hosts) {
		info(ap->logopt, MODPREFIX "no hosts available");
		return 1;
	}

	/* Construct and perhaps create mount point directory */

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
		logerr(MODPREFIX "alloca: %s", estr);
		free_host_list(&hosts);
		return 1;
	}

	if (name_len) {
		if (rlen)
			len = sprintf(fullpath, "%s/%s", root, name);
		else
			len = sprintf(fullpath, "%s", name);
	} else
		len = sprintf(fullpath, "%s", root);
	fullpath[len] = '\0';

	debug(ap->logopt, MODPREFIX "calling mkdir_path %s", fullpath);

	status = mkdir_path(fullpath, 0555);
	if (status && errno != EEXIST) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      MODPREFIX "mkdir_path %s failed: %s", fullpath, estr);
		return 1;
	}

	if (!status)
		existed = 0;

	/*
	 * We need to stop the bind mount module from removing the
	 * mount point directory if a bind attempt fails so abuse
	 * the ap->ghost field for this.
	 */
	ap->ghost = 1;

	this = hosts;
	while (this) {
		char *loc, *port_opt = NULL;

		if (is_mounted(_PATH_MOUNTED, fullpath, MNTS_REAL)) {
			error(ap->logopt,
			      MODPREFIX
			      "warning: %s is already mounted", fullpath);
			break;
		}

		/*
		 * If the "port" option is specified, then we don't want
		 * a bind mount. Use the "port" option if you want to
		 * avoid attempting a local bind mount, such as when
		 * tunneling NFS via localhost.
		 */
		if (nfsoptions && *nfsoptions)
			port_opt = strstr(nfsoptions, "port=");

		/* Port option specified, don't try to bind */
		if (!nosymlink && !port_opt && this->proximity == PROXIMITY_LOCAL) {
			/* Local host -- do a "bind" */
			const char *bind_options = ro ? "ro" : "";

			debug(ap->logopt,
			      MODPREFIX "%s is local, attempt bind mount",
			      name);

			err = mount_bind->mount_mount(ap, root, name, name_len,
					       this->path, "bind", bind_options,
					       mount_bind->context);

			/* Success - we're done */
			if (!err) {
				free_host_list(&hosts);
				ap->ghost = save_ghost;
				return 0;
			}

			/* Failed to update mtab, don't try any more */
			if (err == MNT_FORCE_FAIL)
				goto forced_fail;

			/* No hostname, can't be NFS */
			if (!this->name) {
				this = this->next;
				continue;
			}
		}

		/* Not a local host - do an NFS mount */

		loc = malloc(strlen(this->name) + 1 + strlen(this->path) + 1);
		strcpy(loc, this->name);
		strcat(loc, ":");
		strcat(loc, this->path);

		if (nfsoptions && *nfsoptions) {
			debug(ap->logopt,
			      MODPREFIX "calling mount -t %s " SLOPPY 
			      "-o %s %s %s", fstype, nfsoptions, loc, fullpath);

			err = spawn_mount(ap->logopt,
					  "-t", fstype, SLOPPYOPT "-o",
					  nfsoptions, loc, fullpath, NULL);
		} else {
			debug(ap->logopt,
			      MODPREFIX "calling mount -t %s %s %s",
			      fstype, loc, fullpath);
			err = spawn_mount(ap->logopt,
					  "-t", fstype, loc, fullpath, NULL);
		}

		if (!err) {
			info(ap->logopt, MODPREFIX "mounted %s on %s", loc, fullpath);
			free(loc);
			free_host_list(&hosts);
			ap->ghost = save_ghost;
			return 0;
		}

		free(loc);
		this = this->next;
	}

forced_fail:
	free_host_list(&hosts);
	ap->ghost = save_ghost;

	/* If we get here we've failed to complete the mount */

	info(ap->logopt, MODPREFIX "nfs: mount failure %s on %s", what, fullpath);

	if (ap->type != LKP_INDIRECT)
		return 1;

	if ((!ap->ghost && name_len) || !existed)
		rmdir_path(ap, fullpath, ap->dev);

	return 1;
}

int mount_done(void *context)
{
	int rv = 0;

	if (--init_ctr == 0) {
		rv = close_mount(mount_bind);
		mount_bind = NULL;
	}
	return rv;
}
