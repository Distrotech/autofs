#ident "$Id: mount_nfs.c,v 1.26 2005/04/24 11:57:41 raven Exp $"
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
#include <ctype.h>

#define MODULE_MOUNT
#include "automount.h"

#define MODPREFIX "mount(nfs): "

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

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
 * If the map doesn't contain a ',' or doesn't contain more than
 * one ':' then @what is not a multimount entry.
 */
static int is_multimount_entry(char *what)
{
	int ret;

	ret = (*what == '/') ||
		strchr(what, ',') ||
		(strchr(what, ':') != strrchr(what, ':'));

	return ret;
}

/*
 *  Check to see if the 'host:path' or 'host' is on the local machine
 *  Returns < 0 if there is a host lookup problem, otherwise returns 0
 *  if it's not a local mount, and returns > 0 if it is a local mount.
 */
int is_local_mount(const char *hostpath)
{
	struct hostent *he;
	char **haddr;
	char *delim;
	char *hostname;
	int hostnamelen;
	int local = 0;

	debug(MODPREFIX "is_local_mount: %s", hostpath);
	delim = strpbrk(hostpath,":");

	if (delim) 
		hostnamelen = delim - hostpath; 
	else 
		hostnamelen = strlen(hostpath);

	hostname = malloc(hostnamelen+1);
	strncpy(hostname,hostpath,hostnamelen);
	hostname[hostnamelen] = '\0';
	he = gethostbyname(hostname);
	if (!he) {
		error(MODPREFIX "host %s: lookup failure", hostname);
		return -1;
	}

	for (haddr = he->h_addr_list; *haddr; haddr++) {
		local = is_local_addr(hostname, *haddr, he->h_length);
		if (local < 0) 
			return local;
 		if (local) {
			debug(MODPREFIX "host %s: is localhost",
					hostname);
			return local;
		}
	}
	return 0;
}

/*
 * Given a mount string, return (in the same string) the
 * best mount to use based on locality/weight/rpctime.
 *
 * If longtimeout is set to 0 then we only do 100 ms pings to hosts.  In
 * the event that this fails, we call ourself recursively with the
 * longtimeout option set to 1.  In this case we ping for up to 10s and
 * skip logic for detecting if a localhost has been passed. (if a local
 * host had been passed, we would have returned that mount as the best
 * mount.  The skipping of local maps in this case is an optimization).
 *
 * - return -1 and what = '\0' on error,
 *           1 and what = local mount path if local bind,
 *     else  0 and what = remote mount path
 */
int get_best_mount(char *what, const char *original, int longtimeout)
{
	char *p = what;
	char *winner = NULL;
	int winner_weight = INT_MAX, local = 0;
	double winner_time = 0;
	char *delim, *pstrip;
	int sec = (longtimeout) ? 10 : 0;
	int micros = (longtimeout) ? 0 : 100000;
	int skiplocal = longtimeout; /* clearly local is not available */

	if (!p) {
		*what = '\0';
		return -1;
	}

	/*
	 *  If only one mountpoint has been passed in, we don't need to
	 *  do anything except strip whitespace from the end of the string.
	 */
	if (!is_multimount_entry(p)) {
		for (pstrip = p+strlen(p) - 1; pstrip >= p; pstrip--) 
			if (isspace(*pstrip))
				*pstrip = '\0';

		/* Check if the host is the localhost */
		if (is_local_mount(p)) {
			debug(MODPREFIX "host %s: is localhost", p);

			/* Strip off hostname and ':' */
			delim = strchr(p,':');
			while (delim && *delim != '\0') {
				delim++;
				*what = *delim;
				what++;
			}
			return 1;
		}
		return 0;
	}

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

		/* p points to a server, "next is our next parse point */
		if (!skiplocal) {
			/* Check if it's localhost */
			local = is_local_mount(p);
			if (local < 0) {
				local = 0;
				p = next;
				continue;
			}

			if (local) {
				winner = p;
				break;
			}
		}

		/* ping each (or the) entry to see if it's alive. */
		ping_stat = rpc_ping(p, sec, micros);
		if (!ping_stat) {
			p = next;
			continue;
		}

		/* First unweighted or only host is alive so set winner */
		if (!winner) {
			winner = p;
			/* No more to check, return it */
			if (!next || !*next)
				break;
		}

		/* Multiple entries and no weighted hosts so compare times */
		if (winner_weight == INT_MAX) {
			int status;
			double resp_time;
			unsigned int vers = NFS2_VERSION;
			unsigned int proto = RPC_PING_UDP;

			if (ping_stat) {
				vers = ping_stat & 0x00ff;
				proto = ping_stat & 0xff00;
			}

			status = rpc_time(p, vers, proto, sec, micros, &resp_time);
			/* did we time the first winner? */
			if (winner_time == 0) {
				if (status) {
					winner = p;
					winner_time = resp_time;
				} else
					winner_time = 501;
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
	 * We didn't find a weighted winner or local
	 */
	if (!local && winner_weight == INT_MAX) {
		/* We had more than one contender and none responded in time */
		if (winner_time == 0 || winner_time > 500) {
			/* We've already tried a longer timeout */
			if (!longtimeout) {
				/* Reset string and try again */
				strcpy(what, original);

				debug(MODPREFIX 
				      "all hosts timed out for '%s', "
				      "retrying with longer timeout",
				      original);

				return get_best_mount(what, original, 1);
			}
		}
	}

	/* No winner found so return first */
	if (!winner)
		winner = what;

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
	int ro = 0;            /* Set if mount bind should be read-only */

	debug(MODPREFIX "root=%s name=%s what=%s, fstype=%s, options=%s",
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
				/* Check for options that also make sense
				   with bind mounts */
				if (strncmp("ro", cp, end - cp + 1) == 0)
					ro = 1;
				/* and jump over trailing white space */
				memcpy(nfsp, cp, comma - cp + 1);
				nfsp += comma - cp + 1;
			}
		}

		debug(MODPREFIX "nfs options=\"%s\", nosymlink=%d, ro=%d",
		      nfsoptions, nosymlink, ro);
	}

	local = 0;

	colon = strchr(whatstr, ':');
	if (!colon) {
		/* No colon, take this as a bind (local) entry */
		local = 1;
	} else if (!nosymlink) {
		local = get_best_mount(whatstr, what, 0);
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

		const char *bind_options = ro ? "ro" : "";

		debug(MODPREFIX "%s is local, doing bind", name);

		return mount_bind->mount_mount(root, name, name_len,
					       whatstr, "bind", bind_options,
					       mount_bind->context);
	} else {
		/* Not a local host - do an NFS mount */
		int status, existed = 1;

		debug(MODPREFIX "calling mkdir_path %s", fullpath);

		status = mkdir_path(fullpath, 0555);
		if (status && errno != EEXIST) {
			error(MODPREFIX "mkdir_path %s failed: %m", fullpath);
			return 1;
		}

		if (!status)
			existed = 0;

		if (is_mounted(_PATH_MOUNTED, fullpath)) {
			error(MODPREFIX 
			  "warning: %s is already mounted", fullpath);
			return 0;
		}

		if (nfsoptions && *nfsoptions) {
			debug(MODPREFIX "calling mount -t nfs " SLOPPY 
			      " -o %s %s %s", nfsoptions, whatstr, fullpath);

			err = spawnll(LOG_NOTICE,
				     PATH_MOUNT, PATH_MOUNT, "-t",
				     "nfs", SLOPPYOPT "-o", nfsoptions,
				     whatstr, fullpath, NULL);
		} else {
			debug(MODPREFIX "calling mount -t nfs %s %s",
			      whatstr, fullpath);
			err = spawnll(LOG_NOTICE,
				     PATH_MOUNT, PATH_MOUNT, "-t",
				     "nfs", whatstr, fullpath, NULL);
		}

		if (err) {
			if ((!ap.ghost && name_len) || !existed)
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
