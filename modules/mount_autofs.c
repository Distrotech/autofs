#ident "$Id: mount_autofs.c,v 1.25 2006/03/25 05:22:52 raven Exp $"
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
extern struct startup_cond sc;

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

int mount_init(void **context)
{
	return 0;
}

int mount_mount(struct autofs_point *ap, const char *root, const char *name,
		int name_len, const char *what, const char *fstype,
		const char *c_options, void *context)
{
	pthread_t thid;
	char *fullpath;
	const char **argv;
	int argc, status, ghost = ap->ghost;
	time_t timeout = ap->exp_timeout;
	unsigned logopt = ap->logopt;
	char *type, *format, *tmp, *tmp2;
	struct master_mapent *entry;
	struct map_source *source;
	struct autofs_point *nap;
	char buf[MAX_ERR_BUF];
	char *options, *p;
	int ret, rlen;

	/* Root offset of multi-mount */
	if (*name == '/' && name_len == 1) {
		rlen = strlen(root);
		name_len = 0;
	} else if (*name == '/')
		rlen = 0;
	else
		rlen = strlen(root);

	fullpath = alloca(rlen + name_len + 2);
	if (!fullpath) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(MODPREFIX "alloca: %s", estr);
		return 1;
	}

	if (rlen)
		sprintf(fullpath, "%s/%s", root, name);
	else
		sprintf(fullpath, "%s", name);

	if (is_mounted(_PATH_MOUNTED, fullpath)) {
		error(MODPREFIX 
		 "warning: about to mount over %s, continuing", fullpath);
		return 0;
	}

	if (c_options) {
		options = alloca(strlen(c_options) + 1);
		if (!options) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(MODPREFIX "alloca: %s", estr);
			return 1;
		}
		strcpy(options, c_options);
	} else {
		options = NULL;
	}

	debug(MODPREFIX "fullpath=%s what=%s options=%s",
		  fullpath, what, options);

	/* TODO: options processing needs more work */

	if (strstr(options, "browse")) {
		if (strstr(options, "nobrowse"))
			ghost = 0;
		else
			ghost = 1;
	}

	entry = master_new_mapent(fullpath, ap->entry->age);
	if (!entry) {
		error(MODPREFIX "failed to malloc master_mapent struct");
		return 1;
	}

	ret = master_add_autofs_point(entry, timeout, logopt, ghost, 1);
	if (!ret) {
		error(MODPREFIX "failed to add autofs_point to entry");
		master_free_mapent(entry);
		return 1;
	}
	nap = entry->ap;
	nap->parent = ap;

	argc = 1;

	if (options) {
		char *p = options;
		do {
			argc++;
			if (*p == ',')
				p++;
		} while ((p = strchr(p, ',')) != NULL);
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
		error(MODPREFIX "failed to add map source to entry");
		master_free_mapent(entry);
		return 1;
	}

	source->mc = cache_init(source);
	if (!source->mc) {
		error(MODPREFIX "failed to init source cache");
		master_free_mapent(entry);
		return 1;
	}

	status = pthread_mutex_lock(&sc.mutex);
	if (status) {
		crit("failed to lock startup condition mutex!");
		cache_release(source);
		master_free_mapent(entry);
		return 1;
	}

	sc.done = 0;
	sc.status = 0;

	pthread_mutex_lock(&ap->mounts_mutex);

	if (pthread_create(&thid, &thread_attr, handle_mounts, nap)) {
		crit("failed to create mount handler thread for %s", fullpath);
		pthread_mutex_unlock(&ap->mounts_mutex);
		status = pthread_mutex_unlock(&sc.mutex);
		if (status)
			fatal(status);
		cache_release(source);
		master_free_mapent(entry);
		return 1;
	}
	nap->thid = thid;

	while (!sc.done) {
		status = pthread_cond_wait(&sc.cond, &sc.mutex);
		if (status) {
			pthread_mutex_unlock(&ap->mounts_mutex);
			pthread_mutex_unlock(&sc.mutex);
			fatal(status);
		}
	}

	if (sc.status) {
		crit("failed to create submount for %s", fullpath);
		pthread_mutex_unlock(&ap->mounts_mutex);
		status = pthread_mutex_unlock(&sc.mutex);
		if (status)
			fatal(status);
		return 1;
	}

	ap->submnt_count++;
	list_add(&nap->mounts, &ap->submounts);

	pthread_mutex_unlock(&ap->mounts_mutex);

	status = pthread_mutex_unlock(&sc.mutex);
	if (status)
		fatal(status);

	return 0;
}

int mount_done(void *context)
{
	return 0;
}
