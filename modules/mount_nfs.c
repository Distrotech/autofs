#ident "$Id: mount_nfs.c,v 1.12 2004/05/18 12:20:08 raven Exp $"
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
#include <linux/nfs.h>
#include <linux/nfs2.h>

#define MODULE_MOUNT
#include "automount.h"

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

int is_local_addr(const char *host, const char *host_addr, int addr_len)
{
	struct sockaddr_in src_addr, local_addr;
	int src_len = sizeof(src_addr);
	int local_len = sizeof(local_addr);
	int sock, ret;

	sock = socket(AF_INET, SOCK_DGRAM, udpproto);
	if (sock < 0) {
		error(MODPREFIX "socket creation failed: %m");
		return -1;
	}

	src_addr.sin_family = AF_INET;
	memcpy(&src_addr.sin_addr, host_addr, addr_len);
	src_addr.sin_port = port_discard;

	ret = connect(sock, (struct sockaddr *) &src_addr, src_len);
	if (ret < 0 ) {
		error(MODPREFIX "connect failed for %s: %m", host);
		close(sock);
		return 0;
	}

	ret = getsockname(sock, (struct sockaddr *) &local_addr, &local_len);
	if (ret < 0) {
		error(MODPREFIX "getsockname failed: %m");
		close(sock);
		return 0;
	}

	close(sock);

	ret = memcmp(&src_addr.sin_addr, &local_addr.sin_addr, addr_len);
	if (ret)
		return 0;
	
	return 1;
}
/*
 * Given a mount string, return (in the same string) the
 * best mount to use based on weight/locality/rpctime
 * - return -1 and what = '\0' on error,
 *           1 and what = local mount path if local bind,
 *     else  0 and what = remote mount path
 */
int get_best_mount(char *what, const char *original, int longtimeout, int skiplocal)
{
	char *p = what;
	char *winner = NULL;
	char *is_replicated = NULL;
	int winner_weight = INT_MAX, local = 0;
	double winner_time = 0;
	char *delim;
	int sec = (longtimeout) ? 10 : 0;
	int micros = (longtimeout) ? 0 : 100000;

	if (!p) {
		*what = '\0';
		return -1;
	}

	/*
	 * If it's not a replicated server map entry we need
	 * to only check for a local mount and return the mount
	 * string
	 */
	is_replicated = strpbrk(p, "(,");
	if (skiplocal)
		return local;

	while (p && *p) {
		char *next;
		unsigned int ping_stat = 0;

		p += strspn(p, " \t,");
		delim = strpbrk(p, "(, \t:");
		if (!delim)
			break;

		/* Find lowest weight whose server is alive */
		if (*delim == '(') {
			char *weight = delim + 1;
			unsigned int alive;

			*delim = '\0';

			delim = strchr(weight, ')');
			if (delim) {
				int w;

				*delim = '\0';
				w = atoi(weight);

				alive = rpc_ping(p, sec, micros);
				if (w < winner_weight && alive) {
					winner_weight = w;
					winner = p;
				}
			}
			delim++;
		}

		if (*delim == ':') {
			*delim = '\0';
			next = strpbrk(delim + 1, " \t");
		} else if (*delim != '\0') {
			*delim = '\0';
			next = delim + 1;
		} else
			break;

		/* p points to a server, next is our next parse point */
		if (!skiplocal) {
			/* First, check if it's up and if it's localhost */
			struct hostent *he;
			char **haddr;

			he = gethostbyname(p);
			if (!he) {
				error(MODPREFIX "host %s: lookup failure", p);
				p = next;
				continue;
			}

			/* Check each host in round robin list */
			for (haddr = he->h_addr_list; *haddr; haddr++) {
				local = is_local_addr(p, *haddr, he->h_length);

				if (local < 0)
					continue;

				if (local) {
					winner = p;
					break;
				}
			}
			
			if (local < 0) {
				local = 0;
				p = next;
				continue;
			}

			if (local)
				break;
		}

		/*
		 * If it's not local and it's a replicated server map entry
		 * is it alive
		 */
		if (!local && is_replicated && !(ping_stat = rpc_ping(p, sec, micros))) {
			p = next;
			continue;
		}

		/* see if we have a previous 'winner' */
		if (!winner) {
			winner = p;
		}
		/* compare RPC times if there are no weighted hosts */
		else if (winner_weight == INT_MAX) {
			int status;
			double resp_time;
			unsigned int vers = NFS2_VERSION;
			unsigned int proto = RPC_PING_UDP;

			if (ping_stat) {
				vers = ping_stat & 0x00ff;
				proto = ping_stat & 0xff00;
			}

			status = rpc_time(winner, vers, proto, sec, micros, &resp_time);
			/* did we time the first winner? */
			if (winner_time == 0) {
				if (status)
					winner_time = resp_time;
				else
					winner_time = 6;
			} else {
				if ((status) && (resp_time < winner_time)) {
					winner = p;
					winner_time = resp_time;
				}
			}
		}
		p = next;
	}

	debug(MODPREFIX "winner = %s local = %d", winner, local);

	/*
	 * We didn't find a weighted winner or local and it's a replicated
	 * server map entry
	 */
	if (!local && is_replicated && winner_weight == INT_MAX) {
		/* We had more than one contender and none responded in time */
		if (winner_time != 0 && winner_time > 5) {
			/* We've already tried a longer timeout */
			if (longtimeout) {
				/* SOL: Just pick the first one */
				winner = what;
			}
			/* Reset string and try again */
			else {
				strcpy(what, original);

				debug(MODPREFIX 
				      "all hosts rpc timed out for '%s', "
				      "retrying with longer timeout",
				      original);

				return get_best_mount(what, original, 1, 1);
			}
		}
	}

	/* No winner found so bail */
	if (!winner) {
		*what = '\0';
		return 0;
	}

	/*
	 * We now have our winner, copy it to the front of the string,
	 * followed by the next :string<delim>
	 */
	
	/* if it's local */
	if (!local)
		strcpy(what, winner);
	else
		what[0] = '\0';

	/* We know we're only reading from p, so discard const */
	p = (char *) original + (winner - what);
	delim = what + strlen(what);

	/* Find the colon (in the original string) */
	while (*p && *p != ':')
		p++;

	/* skip : for local paths */
	if (local)
		p++;

	/* copy to next space or end of string */
	while (*p && *p != ' ' && *p != '\t')
		*delim++ = *p++;

	*delim = '\0';

	return local;
}

int mount_mount(const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options,
		void *context)
{
	char *colon, *fullpath;
	char *whatstr;
	char *nfsoptions = NULL;
	int local, err;
	int nosymlink = 0;

	debug(MODPREFIX " root=%s name=%s what=%s, fstype=%s, options=%s",
	      root, name, what, fstype, options);

	whatstr = alloca(strlen(what) + 1);
	if (!whatstr) {
		error(MODPREFIX "alloca: %m");
		return 1;
	}
	strcpy(whatstr, what);

	/* Extract "nosymlink" pseudo-option which stops local filesystems
	   from being symlinked */
	if (options) {
		const char *comma;
		char *nfsp;
		int len = strlen(options) + 1;

		nfsp = nfsoptions = alloca(len + 1);
		if (!nfsoptions)
			return 1;

		memset(nfsoptions, '\0', len + 1);

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

#if 0
			debug(MODPREFIX "*comma=%x %c  comma=%p %s cp=%p %s "
			      "nfsoptions=%p nfsp=%p end=%p used=%d len=%d\n",
			      *comma, *comma, comma, comma, cp, cp,
			      nfsoptions, nfsp, nfsoptions + len,
			      nfsp - nfsoptions, len);
#endif
			if (strncmp("nosymlink", cp, end - cp + 1) == 0)
				nosymlink = 1;
			else {
				/* and jump over trailing white space */
				memcpy(nfsp, cp, comma - cp + 1);
				nfsp += comma - cp + 1;
			}
		}

		debug(MODPREFIX "nfs options=\"%s\", nosymlink=%d",
		      nfsoptions, nosymlink);
	}

	local = 0;

	colon = strchr(whatstr, ':');
	if (!colon) {
		/* No colon, take this as a bind (local) entry */
		local = 1;
	} else if (!nosymlink) {
		local = get_best_mount(whatstr, what, 0, 0);
		if (!*whatstr) {
			warn(MODPREFIX "no host elected");
			return 1;
		}
		debug(MODPREFIX "from %s elected %s", what, whatstr);
	}

	fullpath = alloca(strlen(root) + name_len + 2);
	if (!fullpath) {
		error(MODPREFIX "alloca: %m");
		return 1;
	}

	if (name_len)
		sprintf(fullpath, "%s/%s", root, name);
	else
		sprintf(fullpath, "%s", root);

	if (local) {
		/* Local host -- do a "bind" */

		debug(MODPREFIX "%s is local, doing bind", name);

		return mount_bind->mount_mount(root, name, name_len,
			       whatstr, "bind", NULL, mount_bind->context);
	} else {
		/* Not a local host - do an NFS mount */
		int status;

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
		if (nfsoptions && *nfsoptions) {
			debug(MODPREFIX "calling mount -t nfs " SLOPPY 
			      " -o %s %s %s", nfsoptions, whatstr, fullpath);

			err = spawnl(LOG_NOTICE, MOUNTED_LOCK,
				     PATH_MOUNT, PATH_MOUNT, "-t",
				     "nfs", SLOPPYOPT "-o", nfsoptions,
				     whatstr, fullpath, NULL);
		} else {
			debug(MODPREFIX "calling mount -t nfs %s %s",
			      whatstr, fullpath);
			err = spawnl(LOG_NOTICE, MOUNTED_LOCK,
				     PATH_MOUNT, PATH_MOUNT, "-t",
				     "nfs", whatstr, fullpath, NULL);
		}
		unlink(AUTOFS_LOCK);

		if (err) {
			if (!ap.ghost && name_len)
				rmdir_path(name);
			error(MODPREFIX "nfs: mount failure %s on %s",
			      whatstr, fullpath);
			return 1;
		} else {
			debug(MODPREFIX "mounted %s on %s", whatstr, fullpath);
			return 0;
		}
	}
}

int mount_done(void *context)
{
	return mount_bind->mount_done(mount_bind->context);
}
