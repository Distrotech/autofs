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
	pthread_t thid;
	char *fullpath;
	const char **argv;
	int argc, status, ghost = ap->ghost;
	time_t timeout = ap->exp_timeout;
	unsigned logopt = ap->logopt;
	char *type, *format, *tmp, *tmp2;
	struct master *master;
	struct master_mapent *entry;
	struct map_source *source;
	struct autofs_point *nap;
	char buf[MAX_ERR_BUF];
	char *options, *p;
	int ret;

	fullpath = alloca(strlen(root) + name_len + 2);
	if (!fullpath) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "alloca: %s", estr);
		return 1;
	}

	/* Root offset of multi-mount */
	if (*name == '/' && name_len == 1)
		strcpy(fullpath, root);
	else if (*name == '/')
		strcpy(fullpath, name);
	else {
		strcpy(fullpath, root);
		strcat(fullpath, "/");
		strcat(fullpath, name);
	}

	if (is_mounted(_PATH_MOUNTED, fullpath, MNTS_REAL)) {
		error(ap->logopt,
		      MODPREFIX 
		      "warning: about to mount over %s, continuing",
		      fullpath);
		return 0;
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
	      MODPREFIX "fullpath=%s what=%s options=%s",
	      fullpath, what, options);

	master = ap->entry->master;

	entry = master_new_mapent(master, fullpath, ap->entry->age);
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
	set_mnt_logging(nap);

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

	source->mc = cache_init(source);
	if (!source->mc) {
		error(ap->logopt, MODPREFIX "failed to init source cache");
		master_free_mapent(entry);
		return 1;
	}

	status = pthread_mutex_lock(&suc.mutex);
	if (status) {
		crit(ap->logopt,
		     MODPREFIX "failed to lock startup condition mutex!");
		cache_release(source);
		master_free_mapent(entry);
		return 1;
	}

	suc.done = 0;
	suc.status = 0;

	mounts_mutex_lock(ap);

	if (pthread_create(&thid, NULL, handle_mounts, nap)) {
		crit(ap->logopt,
		     MODPREFIX
		     "failed to create mount handler thread for %s",
		     fullpath);
		mounts_mutex_unlock(ap);
		status = pthread_mutex_unlock(&suc.mutex);
		if (status)
			fatal(status);
		cache_release(source);
		master_free_mapent(entry);
		return 1;
	}
	nap->thid = thid;

	while (!suc.done) {
		status = pthread_cond_wait(&suc.cond, &suc.mutex);
		if (status) {
			mounts_mutex_unlock(ap);
			pthread_mutex_unlock(&suc.mutex);
			fatal(status);
		}
	}

	if (suc.status) {
		crit(ap->logopt,
		     MODPREFIX "failed to create submount for %s", fullpath);
		mounts_mutex_unlock(ap);
		status = pthread_mutex_unlock(&suc.mutex);
		if (status)
			fatal(status);
		master_free_mapent(entry);
		return 1;
	}

	ap->submnt_count++;
	list_add(&nap->mounts, &ap->submounts);

	mounts_mutex_unlock(ap);

	status = pthread_mutex_unlock(&suc.mutex);
	if (status)
		fatal(status);

	return 0;
}

int mount_done(void *context)
{
	return 0;
}
