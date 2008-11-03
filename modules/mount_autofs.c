/* ----------------------------------------------------------------------- *
 *
 *  mount_autofs.c - Module for recursive autofs mounts.
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <alloca.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define MODULE_MOUNT
#include "automount.h"

#define MODPREFIX "mount(autofs): "

/* Attribute to create detached thread */
extern pthread_attr_t thread_attr;
extern struct startup_cond suc;

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

int mount_init(void **context)
{
	return 0;
}

int mount_mount(struct autofs_point *ap, const char *root, const char *name,
		int name_len, const char *what, const char *fstype,
		const char *c_options, void *context)
{
	struct startup_cond suc;
	pthread_t thid;
	char *realpath, *mountpoint;
	const char **argv;
	int argc, status, ghost = ap->flags & MOUNT_FLAG_GHOST;
	time_t timeout = ap->exp_timeout;
	unsigned logopt = ap->logopt;
	char *type, *format, *tmp, *tmp2;
	struct master *master;
	struct master_mapent *entry;
	struct map_source *source;
	struct autofs_point *nap;
	char buf[MAX_ERR_BUF];
	char *options, *p;
	int len, ret;

	/* Root offset of multi-mount */
	len = strlen(root);
	if (root[len - 1] == '/') {
		realpath = alloca(strlen(ap->path) + name_len + 2);
		mountpoint = alloca(len + 1);
		strcpy(realpath, ap->path);
		strcat(realpath, "/");
		strcat(realpath, name);
		len--;
		strncpy(mountpoint, root, len);
		mountpoint[len] = '\0';
	} else if (*name == '/') {
		realpath = alloca(name_len + 1);
		mountpoint = alloca(len + 1);
		if (ap->flags & MOUNT_FLAG_REMOUNT) {
			strcpy(mountpoint, name);
			strcpy(realpath, name);
		} else {
			strcpy(mountpoint, root);
			strcpy(realpath, name);
		}
	} else {
		realpath = alloca(len + name_len + 2);
		mountpoint = alloca(len + name_len + 2);
		strcpy(mountpoint, root);
		strcat(mountpoint, "/");
		strcpy(realpath, mountpoint);
		strcat(mountpoint, name);
		strcat(realpath, name);
	}

	options = NULL;
	if (c_options) {
		char *noptions;
		const char *comma;
		char *np;
		int len = strlen(c_options) + 1;

		noptions = np = alloca(len);
		if (!np) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "alloca: %s", estr);
			return 1;
		}
		memset(np, 0, len);

		/* Grab the autofs specific options */
		for (comma = c_options; *comma != '\0';) {
			const char *cp;

			while (*comma == ',')
				comma++; 

			cp = comma;

			while (*comma != '\0' && *comma != ',')
				comma++;

			if (strncmp(cp, "nobrowse", 8) == 0)
				ghost = 0;
			else if (strncmp(cp, "browse", 6) == 0)
				ghost = 1;
			else if (strncmp(cp, "timeout=", 8) == 0) {
				char *val = strchr(cp, '=');
				unsigned tout;
				if (val++) {
					int ret = sscanf(cp, "timeout=%u", &tout);
					if (ret)
						timeout = tout;
				}
			} else {
				memcpy(np, cp, comma - cp + 1);
				np += comma - cp + 1;
			}
		}
		options = noptions;
	}

	debug(ap->logopt,
	      MODPREFIX "mountpoint=%s what=%s options=%s",
	      mountpoint, what, options);

	master = ap->entry->master;

	entry = master_new_mapent(master, realpath, ap->entry->age);
	if (!entry) {
		error(ap->logopt,
		      MODPREFIX "failed to malloc master_mapent struct");
		return 1;
	}

	ret = master_add_autofs_point(entry, timeout, logopt, ghost, 1);
	if (!ret) {
		error(ap->logopt,
		      MODPREFIX "failed to add autofs_point to entry");
		master_free_mapent(entry);
		return 1;
	}
	nap = entry->ap;
	nap->parent = ap;

	argc = 1;

	if (options) {
		char *t = options;
		do {
			argc++;
			if (*t == ',')
				t++;
		} while ((t = strchr(t, ',')) != NULL);
	}
	argv = (const char **) alloca((argc + 1) * sizeof(char *));

	argc = 1;

	type = NULL;
	format = NULL;

	tmp = strchr(what, ':');
	if (tmp) {
		*tmp++ = '\0';
		tmp2 = strchr(what, ',');
		if (tmp2) {
			*tmp2++ = '\0';
			format = tmp2;
		}
		type = (char *) what;
		argv[0] = tmp;
	} else
		argv[0] = (char *) what;

	if (options) {
		p = options;
		do {
			if (*p == ',') {
				*p = '\0';
				p++;
			}
			argv[argc++] = p;
		} while ((p = strchr(p, ',')) != NULL);
	}
	argv[argc] = NULL;

	source = master_add_map_source(entry, type, format, time(NULL), argc, argv);
	if (!source) {
		error(ap->logopt,
		      MODPREFIX "failed to add map source to entry");
		master_free_mapent(entry);
		return 1;
	}

	source->mc = cache_init(entry->ap, source);
	if (!source->mc) {
		error(ap->logopt, MODPREFIX "failed to init source cache");
		master_free_map_source(source, 0);
		master_free_mapent(entry);
		return 1;
	}

	mounts_mutex_lock(ap);

	if (handle_mounts_startup_cond_init(&suc)) {
		crit(ap->logopt, MODPREFIX
		     "failed to init startup cond for mount %s", entry->path);
		mounts_mutex_unlock(ap);
		master_free_map_source(source, 1);
		master_free_mapent(entry);
		return 1;
	}

	suc.ap = nap;
	suc.root = mountpoint;
	suc.done = 0;
	suc.status = 0;

	if (pthread_create(&thid, &thread_attr, handle_mounts, &suc)) {
		crit(ap->logopt,
		     MODPREFIX
		     "failed to create mount handler thread for %s",
		     realpath);
		handle_mounts_startup_cond_destroy(&suc);
		mounts_mutex_unlock(ap);
		master_free_map_source(source, 1);
		master_free_mapent(entry);
		return 1;
	}

	while (!suc.done) {
		status = pthread_cond_wait(&suc.cond, &suc.mutex);
		if (status) {
			handle_mounts_startup_cond_destroy(&suc);
			mounts_mutex_unlock(ap);
			master_free_map_source(source, 1);
			master_free_mapent(entry);
			fatal(status);
		}
	}

	if (suc.status) {
		crit(ap->logopt,
		     MODPREFIX "failed to create submount for %s", realpath);
		handle_mounts_startup_cond_destroy(&suc);
		mounts_mutex_unlock(ap);
		master_free_map_source(source, 1);
		master_free_mapent(entry);
		return 1;
	}
	nap->thid = thid;

	ap->submnt_count++;
	list_add(&nap->mounts, &ap->submounts);

	handle_mounts_startup_cond_destroy(&suc);
	mounts_mutex_unlock(ap);

	return 0;
}

int mount_done(void *context)
{
	return 0;
}
