#ident "$Id: mount_nfs.c,v 1.5 2003/10/04 13:20:27 raven Exp $"
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
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>

#define MODULE_MOUNT
#include "automount.h"

#ifdef DEBUG
#define DB(x)           do { x; } while(0)
#else
#define DB(x)           do { } while(0)
#endif

#define MODPREFIX "mount(nfs): "
int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

extern struct autofs_point ap;

static int udpproto;
static short port_discard;

static struct mount_mod *mount_bind = NULL;

int mount_init(void **context)
{
	struct protoent *udp;
	struct servent *port_dis;

	/* These are context independent */
	udp = getprotobyname("udp");
	udpproto = udp ? udp->p_proto : 0;
	port_dis = getservbyname("discard", "udp");

	if (port_dis)
		port_discard = port_dis->s_port;
	else
		port_discard = htons(9);	/* 9 is the standard discard port */

	/* Make sure we have the local mount method available */
	if (!mount_bind)
		mount_bind = open_mount("bind", MODPREFIX);

	return !mount_bind;
}

int mount_mount(const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context)
{
	char *colon, *localname, **haddr, *fullpath;
	char *whatstr, *hostname, *comma, *paren;
	char *nfsoptions = NULL;
	struct hostent *he;
	struct sockaddr_in saddr, laddr;
	int sock, local, err;
	int nosymlink = 0;
	size_t len;

	DB(syslog(LOG_DEBUG, MODPREFIX " root=%s name=%s what=%s, fstype=%s, options=%s",
		  root, name, what, fstype, options));

	whatstr = alloca(strlen(what) + 1);
	if (!whatstr) {
		syslog(LOG_NOTICE, MODPREFIX "alloca: %m");
		return 1;
	}
	strcpy(whatstr, what);

	/* Extract "nosymlink" pseudo-option which stops local filesystems
	   from being symlinked */
	if (options) {
		const char *comma;
		char *nfsp;
		int len = strlen(options) + 1;

		nfsp = nfsoptions = alloca(len);
		if (!nfsoptions)
			return 1;

		for (comma = options; *comma != '\0';) {
			const char *cp;

			while (*comma == ',')
				comma++;

			cp = comma;
			while (*comma != '\0' && *comma != ',')
				comma++;
#if 0
			syslog(LOG_DEBUG, MODPREFIX "*comma=%x %c  comma=%p %s cp=%p %s "
			       "nfsoptions=%p nfsp=%p end=%p used=%d len=%d\n",
			       *comma, *comma, comma, comma, cp, cp,
			       nfsoptions, nfsp, nfsoptions + len, nfsp - nfsoptions,
			       len);
#endif
			if (strncmp("nosymlink", cp, comma - cp - 1) == 0)
				nosymlink = 1;
			else {
				memcpy(nfsp, cp, comma - cp + 1);
				nfsp += comma - cp + 1;
			}
		}
		nfsp[-1] = '\0';
		DB(syslog(LOG_DEBUG, MODPREFIX "nfs options=\"%s\", nosymlink=%d",
			  nfsoptions, nosymlink));
	}

	local = 0;
	localname = NULL;

	colon = strchr(whatstr, ':');
	if (!colon) {
		/* No colon, take this as a bind (local) entry */
		local = 1;
		localname = whatstr;
	} else if (!nosymlink) {
		*colon = '\0';

		/* The host part may actually be a comma-separated list of hosts with 
		   parenthesized weights.  We want to check each host, ignoring any 
		   weights, until we either find the localhost or reach the end of the 
		   list. */
		local = 0;
		localname = colon + 1;
		hostname = whatstr;
		do {
			comma = strchr(hostname, ',');
			if (comma)
				*comma = '\0';

			paren = strchr(hostname, '(');
			if (paren)
				*paren = '\0';

			if (!(he = gethostbyname(hostname))) {
				syslog(LOG_ERR,
				       MODPREFIX "entry %s: host %s: lookup failure",
				       name, hostname);
				return 1;	/* No such host */
			}

			/* Probe to see if we are the local host.  Open a UDP socket and see
			   if the local address is the same as the remote one */
			for (haddr = he->h_addr_list; *haddr; haddr++) {
				sock = socket(AF_INET, SOCK_DGRAM, udpproto);
				if (sock < 0) {
					syslog(LOG_ERR, MODPREFIX "socket: %m");
					return 1;
				}
				saddr.sin_family = AF_INET;
				memcpy(&saddr.sin_addr, *haddr, he->h_length);
				saddr.sin_port = port_discard;

				len = sizeof(laddr);

				if (connect
				    (sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
					continue;	/* Assume it wasn't local */

				if (getsockname(sock, (struct sockaddr *) &laddr, &len) <
				    0) {
					syslog(LOG_ERR,
					       MODPREFIX "getsockname failed for %s: %m",
					       name);
					close(sock);
					return 1;
				}
				close(sock);

				if (!memcmp
				    (&saddr.sin_addr, &laddr.sin_addr, he->h_length)) {
					local = 1;
					break;
				}
			}

			if (paren)
				*paren = '(';

			if (comma) {
				*comma = ',';
				hostname = comma + 1;
			} else {
				hostname += strlen(hostname);
			}
		} while (*hostname && !local);
	}

	fullpath = alloca(strlen(root) + name_len + 2);
	if (!fullpath) {
		syslog(LOG_ERR, MODPREFIX "alloca: %m");
		return 1;
	}
	sprintf(fullpath, "%s/%s", root, name);

	if (local) {
		/* Local host -- do a "bind" */

		DB(syslog(LOG_DEBUG, MODPREFIX "%s is local, doing bind", name));

		return mount_bind->mount_mount(root, name, name_len,
					       localname, "bind", NULL,
					       mount_bind->context);
	} else {
		/* Not a local host - do an NFS mount */
		int save_errno;

		*colon = ':';
		DB(syslog(LOG_DEBUG, MODPREFIX "calling mkdir_path %s", fullpath));
		if (mkdir_path(fullpath, 0555) && errno != EEXIST) {
			syslog(LOG_ERR, MODPREFIX "mkdir_path %s failed: %m", name);
			return 1;
		}
		save_errno = errno;

		if (is_mounted(fullpath)) {
			syslog(LOG_WARNING, "BUG: %s already mounted", fullpath);
			return 0;
		}

		wait_for_lock();
		if (nfsoptions && *nfsoptions) {
			DB(syslog
			   (LOG_DEBUG,
			    MODPREFIX "calling mount -t nfs " SLOPPY "-o %s %s %s",
			    nfsoptions, whatstr, fullpath));
			err =
			    spawnl(LOG_NOTICE, MOUNTED_LOCK, PATH_MOUNT, PATH_MOUNT, "-t",
				   "nfs", SLOPPYOPT "-o", nfsoptions, whatstr, fullpath,
				   NULL);
		} else {
			DB(syslog
			   (LOG_DEBUG, MODPREFIX "calling mount -t nfs %s %s", whatstr,
			    fullpath));
			err =
			    spawnl(LOG_NOTICE, MOUNTED_LOCK, PATH_MOUNT, PATH_MOUNT, "-t",
				   "nfs", whatstr, fullpath, NULL);
		}
		unlink(AUTOFS_LOCK);
		if (err) {
			if (save_errno != EEXIST)
				if (!ap.ghost)
					rmdir_path(fullpath);
			syslog(LOG_ERR, MODPREFIX "nfs: mount failure %s on %s",
			       whatstr, fullpath);
			return 1;
		} else {
			DB(syslog
			   (LOG_DEBUG, MODPREFIX "mounted %s on %s", whatstr, fullpath));
			return 0;
		}
	}
}

int mount_done(void *context)
{
	return mount_bind->mount_done(mount_bind->context);
}
