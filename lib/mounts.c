#ident "$Id: mounts.c,v 1.10 2005/04/24 15:04:51 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  mounts.c - module for Linux automount mount table lookup functions
 *
 *   Copyright 2002-2004 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <mntent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "automount.h"

/*
 * Get list of mounts under path in longest->shortest order
 */
struct mnt_list *get_mnt_list(const char *table, const char *path, int include)
{
	FILE *tab;
	int pathlen = strlen(path);
	struct mntent *mnt;
	struct mnt_list *ent, *mptr, *last;
	struct mnt_list *list = NULL;
	struct stat st;
	int len;

	if (!path || !pathlen || pathlen > PATH_MAX)
		return NULL;

	tab = setmntent(table, "r");
	if (!tab) {
		error("get_mntlist: setmntent: %m");
		return NULL;
	}

	while ((mnt = getmntent(tab)) != NULL) {
		len = strlen(mnt->mnt_dir);

		if ((!include && len <= pathlen) ||
	  	     strncmp(mnt->mnt_dir, path, pathlen) != 0)
			continue;

		/* Not a subdirectory of requested path ? */
		/* pathlen == 1 => everything is subdir    */
		if (pathlen > 1 && len > pathlen &&
				mnt->mnt_dir[pathlen] != '/')
			continue;

		ent = malloc(sizeof(*ent));
		if (!ent) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}

		mptr = list;
		last = NULL;
		while (mptr) {
			if (len > strlen(mptr->path))
				break;
			last = mptr;
			mptr = mptr->next;
		}

		if (mptr == list)
			list = ent;

		ent->next = mptr;
		if (last)
			last->next = ent;

		ent->path = malloc(len + 1);
		if (!ent->path) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->path, mnt->mnt_dir);

		ent->fs_type = malloc(strlen(mnt->mnt_type) + 1);
		if (!ent->fs_type) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->fs_type, mnt->mnt_type);

		ent->pid = 0;
		if (strncmp(ent->fs_type, "autofs", 6) == 0)
			sscanf(mnt->mnt_fsname, "automount(pid%d)", &ent->pid);
	}
	endmntent(tab);

	mptr = list;
	while (mptr) {
		mptr->last_access = time(NULL);

		if (stat(mptr->path, &st) != -1)
			mptr->last_access = st.st_atime;

		mptr = mptr->next;
	}

	return list;
}

/*
 * Reverse a list of mounts
 */
struct mnt_list *reverse_mnt_list(struct mnt_list *list)
{
	struct mnt_list *next, *last;

	if (!list)
		return NULL;

	next = list;
	last = NULL;
	while (next) {
		struct mnt_list *this = next;

		next = this->next;
		this->next = last;
		last = this;
	}

	return last;
}

static struct mnt_list *copy_mnt_list_ent(struct mnt_list *ent)
{
	struct mnt_list *new;

	if (!ent)
		return NULL;
		
	new = malloc(sizeof(*new));
	if (!new) {
		return NULL;
	}

	if (!ent->path || !ent->fs_type) {
		free(new);
		return NULL;
	}

	new->path = malloc(strlen(ent->path) + 1);
	if (!new->path) {
		free(new);
		return NULL;
	}
	strcpy(new->path, ent->path);

	new->fs_type = malloc(strlen(ent->fs_type) + 1);
	if (!new->fs_type) {
		free(new->path);
		free(new);
		return NULL;
	}
	strcpy(new->fs_type, ent->fs_type);

	new->next = NULL;

	return new;
}

/*
 * Get list of mount points that are the base of a mount
 * tree (ie. get highest point at which we cross file
 * system boundary). Assumes mount list with
 * shortest -> longest paths.
 */
struct mnt_list *get_base_mnt_list(struct mnt_list *list)
{
	struct mnt_list *next, *ret = NULL;
	char *base;

	if (!list)
		return NULL;

	next = list;
	base = next->path;
	ret = copy_mnt_list_ent(next);
	while (next) {
		struct mnt_list *this = next;
		struct mnt_list *new;
		int blen = strlen(base);
		int nlen, eq;

		next = this->next;
		if (!next)
			break;
		nlen = strlen(next->path);


		eq = strncmp(this->path, base, blen);
		if (!eq)
			continue;

		if (strncmp(this->path, base, blen)) {
			if (nlen > blen && next->path[blen + 1] == '/')
				continue;
		}

		base = this->path;

		new = copy_mnt_list_ent(this);
		new->next = ret;
		ret = new;
	}

	return ret;
}

void free_mnt_list(struct mnt_list *list)
{
	struct mnt_list *next;

	if (!list)
		return;

	next = list;
	while (next) {
		struct mnt_list *this = next;

		next = this->next;

		if (this->path)
			free(this->path);

		if (this->fs_type)
			free(this->fs_type);

		free(this);
	}
}

static int find_mntent(const char *table, const char *path, struct mntent *ent)
{
	struct mntent *mnt;
	FILE *tab;
	int pathlen = strlen(path);
	int ret = 0;

	if (!path || !pathlen || pathlen > PATH_MAX)
		return 0;

	tab = setmntent(table, "r");
	if (!tab) {
		error("find_mntent: setmntent: %m");
		return 0;
	}

	while ((mnt = getmntent(tab)) != NULL) {
		int len = strlen(mnt->mnt_dir);

		if (pathlen == len && !strncmp(path, mnt->mnt_dir, pathlen)) {
			int szent = sizeof(struct mntent);

			if (ent)
				memcpy(ent, mnt, szent);
			ret = 1;

			break;
		}
	}
	endmntent(tab);

	return ret;
}
	
int is_mounted(const char *table, const char *path)
{
	int ret = 0;

	if (find_mntent(table, path, NULL))
		ret = 1;

	return ret;
}

int has_fstab_option(const char *path, const char *opt)
{
	struct mntent ent;
	char *res = NULL;

	if (find_mntent(_PATH_MNTTAB, path, &ent)) {
		if ((res = hasmntopt(&ent, opt)))
			return 1;
	}

	return 0;
}

/*
 * Check id owner option is present in fstab of requested
 * mount. If it is return iowner uid of requested dev.
 */
int allow_owner_mount(const char *path)
{
	struct mntent ent;
	int ret = 0;

	if (getuid() || is_mounted(_PATH_MOUNTED, path))
		return 0;

	if (find_mntent(_PATH_MNTTAB, path, &ent)) {
		struct stat st;

		if (!hasmntopt(&ent, "owner"))
			return 0;

		if (stat(ent.mnt_fsname, &st) == -1)
			return 0;

		ret = st.st_uid;
	}

	return ret;
}

