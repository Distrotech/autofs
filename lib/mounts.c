/* ----------------------------------------------------------------------- *
 *   
 *  mounts.c - module for Linux automount mount table lookup functions
 *
 *   Copyright 2002-2005 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mntent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <stdio.h>

#include "automount.h"

#define MAX_OPTIONS_LEN		80
#define MAX_MNT_NAME_LEN	30

static const char options_template[]       = "fd=%d,pgrp=%u,minproto=5,maxproto=%d";
static const char options_template_extra[] = "fd=%d,pgrp=%u,minproto=5,maxproto=%d,%s";
static const char mnt_name_template[]      = "automount(pid%u)";

static struct kernel_mod_version kver = {0, 0};
static const char kver_options_template[]  = "fd=%d,pgrp=%u,minproto=3,maxproto=5";

unsigned int query_kproto_ver(void)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	char dir[] = "/tmp/autoXXXXXX", *t_dir;
	char options[MAX_OPTIONS_LEN + 1];
	pid_t pgrp = getpgrp();
	int pipefd[2], ioctlfd, len;

	t_dir = mkdtemp(dir);
	if (!t_dir)
		return 0;

	if (pipe(pipefd) == -1) {
		rmdir(t_dir);
		return 0;
	}

	len = snprintf(options, MAX_OPTIONS_LEN,
		       kver_options_template, pipefd[1], (unsigned) pgrp);
	if (len < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		rmdir(t_dir);
		return 0;
	}

	if (mount("automount", t_dir, "autofs", MS_MGC_VAL, options)) {
		close(pipefd[0]);
		close(pipefd[1]);
		rmdir(t_dir);
		return 0;
	}

	close(pipefd[1]);

	ops->open(LOGOPT_NONE, &ioctlfd, -1, t_dir, AUTOFS_TYPE_INDIRECT);
	if (ioctlfd == -1) {
		umount(t_dir);
		close(pipefd[0]);
		rmdir(t_dir);
		return 0;
	}

	ops->catatonic(LOGOPT_NONE, ioctlfd);

	/* If this ioctl() doesn't work, it is kernel version 2 */
	if (ops->protover(LOGOPT_NONE, ioctlfd, &kver.major)) {
		ops->close(LOGOPT_NONE, ioctlfd);
		umount(t_dir);
		close(pipefd[0]);
		rmdir(t_dir);
		return 0;
	}

	/* If this ioctl() doesn't work, version is 4 or less */
	if (ops->protosubver(LOGOPT_NONE, ioctlfd, &kver.minor)) {
		ops->close(LOGOPT_NONE, ioctlfd);
		umount(t_dir);
		close(pipefd[0]);
		rmdir(t_dir);
		return 0;
	}

	ops->close(LOGOPT_NONE, ioctlfd);
	umount(t_dir);
	close(pipefd[0]);
	rmdir(t_dir);

	return 1;
}

unsigned int get_kver_major(void)
{
	return kver.major;
}

unsigned int get_kver_minor(void)
{
	return kver.minor;
}

/*
 * Make common autofs mount options string
 */
char *make_options_string(char *path, int pipefd, char *extra)
{
	char *options;
	int len;

	options = malloc(MAX_OPTIONS_LEN + 1);
	if (!options) {
		logerr("can't malloc options string");
		return NULL;
	}

	if (extra) 
		len = snprintf(options, MAX_OPTIONS_LEN,
				options_template_extra,
				pipefd, (unsigned) getpgrp(),
				AUTOFS_MAX_PROTO_VERSION, extra);
	else
		len = snprintf(options, MAX_OPTIONS_LEN, options_template,
			pipefd, (unsigned) getpgrp(),
			AUTOFS_MAX_PROTO_VERSION);

	if (len >= MAX_OPTIONS_LEN) {
		logerr("buffer to small for options - truncated");
		len = MAX_OPTIONS_LEN - 1;
	}

	if (len < 0) {
		logerr("failed to malloc autofs mount options for %s", path);
		free(options);
		return NULL;
	}
	options[len] = '\0';

	return options;
}

char *make_mnt_name_string(char *path)
{
	char *mnt_name;
	int len;

	mnt_name = malloc(MAX_MNT_NAME_LEN + 1);
	if (!mnt_name) {
		logerr("can't malloc mnt_name string");
		return NULL;
	}

	len = snprintf(mnt_name, MAX_MNT_NAME_LEN,
			mnt_name_template, (unsigned) getpid());

	if (len >= MAX_MNT_NAME_LEN) {
		logerr("buffer to small for mnt_name - truncated");
		len = MAX_MNT_NAME_LEN - 1;
	}

	if (len < 0) {
		logerr("failed setting up mnt_name for autofs path %s", path);
		free(mnt_name);
		return NULL;
	}
	mnt_name[len] = '\0';

	return mnt_name;
}

/*
 * Get list of mounts under path in longest->shortest order
 */
struct mnt_list *get_mnt_list(const char *table, const char *path, int include)
{
	FILE *tab;
	size_t pathlen = strlen(path);
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	struct mntent *mnt;
	struct mnt_list *ent, *mptr, *last;
	struct mnt_list *list = NULL;
	char *pgrp;
	size_t len;

	if (!path || !pathlen || pathlen > PATH_MAX)
		return NULL;

	tab = setmntent(table, "r");
	if (!tab) {
		char *estr = strerror_r(errno, buf, PATH_MAX - 1);
		logerr("setmntent: %s", estr);
		return NULL;
	}

	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
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
		memset(ent, 0, sizeof(*ent));

		mptr = list;
		last = NULL;
		while (mptr) {
			if (len >= strlen(mptr->path))
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

		ent->fs_name = malloc(strlen(mnt->mnt_fsname) + 1);
		if (!ent->fs_name) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->fs_name, mnt->mnt_fsname);

		ent->fs_type = malloc(strlen(mnt->mnt_type) + 1);
		if (!ent->fs_type) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->fs_type, mnt->mnt_type);

		ent->opts = malloc(strlen(mnt->mnt_opts) + 1);
		if (!ent->opts) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->opts, mnt->mnt_opts);

		ent->owner = 0;
		pgrp = strstr(mnt->mnt_opts, "pgrp=");
		if (pgrp) {
			char *end = strchr(pgrp, ',');
			if (end)
				*end = '\0';
			sscanf(pgrp, "pgrp=%d", &ent->owner);
		}
	}
	endmntent(tab);

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

		if (this->fs_name)
			free(this->fs_name);

		if (this->fs_type)
			free(this->fs_type);

		if (this->opts)
			free(this->opts);

		free(this);
	}
}

int contained_in_local_fs(const char *path)
{
	struct mnt_list *mnts, *this;
	size_t pathlen = strlen(path);
	int ret;

	if (!path || !pathlen || pathlen > PATH_MAX)
		return 0;

	mnts = get_mnt_list(_PATH_MOUNTED, "/", 1);
	if (!mnts)
		return 0;

	ret = 0;

	for (this = mnts; this != NULL; this = this->next) {
		size_t len = strlen(this->path);

		if (!strncmp(path, this->path, len)) {
			if (len > 1 && pathlen > len && path[len] != '/')
				continue;
			else if (this->fs_name[0] == '/') {
				if (strlen(this->fs_name) > 1) {
					if (this->fs_name[1] != '/')
						ret = 1;
				} else
					ret = 1;
			} else if (!strncmp("LABEL=", this->fs_name, 6) ||
				   !strncmp("UUID=", this->fs_name, 5))
				ret = 1;
			break;
		}
	}

	free_mnt_list(mnts);

	return ret;
}

int is_mounted(const char *table, const char *path, unsigned int type)
{
	struct mntent *mnt;
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	size_t pathlen = strlen(path);
	FILE *tab;
	int ret = 0;

	if (!path || !pathlen || pathlen >= PATH_MAX)
		return 0;

	tab = setmntent(table, "r");
	if (!tab) {
		char *estr = strerror_r(errno, buf, PATH_MAX - 1);
		logerr("setmntent: %s", estr);
		return 0;
	}

	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		size_t len = strlen(mnt->mnt_dir);

		if (type) {
			unsigned int autofs_fs;

			autofs_fs = !strcmp(mnt->mnt_type, "autofs");

			if (type & MNTS_REAL)
				if (autofs_fs)
					continue;

			if (type & MNTS_AUTOFS)
				if (!autofs_fs)
					continue;
		}

		if (pathlen == len && !strncmp(path, mnt->mnt_dir, pathlen)) {
			ret = 1;
			break;
		}
	}
	endmntent(tab);

	return ret;
}

int has_fstab_option(const char *opt)
{
	struct mntent *mnt;
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	FILE *tab;
	int ret = 0;

	if (!opt)
		return 0;

	tab = setmntent(_PATH_MNTTAB, "r");
	if (!tab) {
		char *estr = strerror_r(errno, buf, PATH_MAX - 1);
		logerr("setmntent: %s", estr);
		return 0;
	}

	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		if (hasmntopt(mnt, opt)) {
			ret = 1;
			break;
		}
	}
	endmntent(tab);

	return ret;
}

/*
 * Find the device number of an autofs mount with given path and
 * type (eg..AUTOFS_TYPE_DIRECT). An autofs display mount option
 * "dev=<device number>" is provided by the kernel module for this.
 *
 * The device number is used by the kernel to identify the autofs
 * super block when searching for the mount.
 */
int find_mnt_devid(const char *table,
		   const char *path, char *devid, unsigned int type)
{
	struct mntent *mnt;
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	FILE *tab;
	char *dev;

	tab = setmntent(table, "r");
	if (!tab) {
		printf("failed to open mount table\n");
		return 0;
	}

	dev = NULL;
	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		if (strcmp(mnt->mnt_type, "autofs"))
			continue;

		if (strcmp(mnt->mnt_dir, path))
			continue;

		switch (type) {
		case AUTOFS_TYPE_INDIRECT:
			if (!hasmntopt(mnt, "indirect"))
				continue;
			break;

		case AUTOFS_TYPE_DIRECT:
			if (!hasmntopt(mnt, "direct"))
				continue;
			break;

		case AUTOFS_TYPE_OFFSET:
			if (!hasmntopt(mnt, "offset"))
				continue;
			break;
		}

		dev = hasmntopt(mnt, "dev");
		if (dev) {
			char *start = strchr(dev, '=') + 1;
			char *end = strchr(start, ',');
			if (end)
				*end = '\0';
			if (start) {
				int len = strlen(start);
				memcpy(devid, start, len);
				devid[len] = '\0';
			}
			break;
		}
	}

	endmntent(tab);

	if (!dev)
		return 0;

	return 1;
}

char *get_offset(const char *prefix, char *offset,
		 struct list_head *head, struct list_head **pos)
{
	struct list_head *next;
	struct mnt_list *this;
	size_t plen = strlen(prefix);
	size_t len = 0;

	*offset = '\0';
	next = *pos ? (*pos)->next : head->next;
	while (next != head) {
		char *pstart, *pend;

		this = list_entry(next, struct mnt_list, ordered);
		*pos = next;
		next = next->next;

		if (strlen(this->path) <= plen)
			continue;

		if (!strncmp(prefix, this->path, plen)) {
			pstart = &this->path[plen];

			/* not part of this sub-tree */
			if (*pstart != '/')
				continue;

			/* get next offset */
			pend = pstart;
			while (*pend++) ;
			len = pend - pstart - 1;
			strncpy(offset, pstart, len);
			offset[len] ='\0';
			break;
		}
	}

	while (next != head) {
		char *pstart;

		this = list_entry(next, struct mnt_list, ordered);

		if (strlen(this->path) <= plen + len)
			break;

		pstart = &this->path[plen];

		/* not part of this sub-tree */
		if (*pstart != '/')
			break;

		/* new offset */
		if (!*(pstart + len + 1))
			break;

		/* compare next offset */
		if (pstart[len] != '/' || strncmp(offset, pstart, len))
			break;

		*pos = next;
		next = next->next;
	}

	return *offset ? offset : NULL;
}

void add_ordered_list(struct mnt_list *ent, struct list_head *head)
{
	struct list_head *p;
	struct mnt_list *this;

	list_for_each(p, head) {
		size_t tlen;
		int eq;

		this = list_entry(p, struct mnt_list, ordered);
		tlen = strlen(this->path);

		eq = strncmp(this->path, ent->path, tlen);
		if (!eq && tlen == strlen(ent->path))
			return;

		if (eq > 0) {
			INIT_LIST_HEAD(&ent->ordered);
			list_add_tail(&ent->ordered, p);
			return;
		}
	}
	INIT_LIST_HEAD(&ent->ordered);
	list_add_tail(&ent->ordered, p);

	return;
}

/*
 * Since we have to look at the entire mount tree for direct
 * mounts (all mounts under "/") and we may have a large number
 * of entries to traverse again and again we need to
 * use a more efficient method than the routines above.
 *
 * Thre tree_... routines allow us to read the mount tree
 * once and pass it to subsequent functions for use. Since
 * it's a tree structure searching should be a low overhead
 * operation.
 */
void tree_free_mnt_tree(struct mnt_list *tree)
{
	struct list_head *head, *p;

	if (!tree)
		return;

	tree_free_mnt_tree(tree->left);
	tree_free_mnt_tree(tree->right);

	head = &tree->self;
	p = head->next;
	while (p != head) {
		struct mnt_list *this;

		this = list_entry(p, struct mnt_list, self);

		p = p->next;

		list_del(&this->self);

		free(this->path);
		free(this->fs_name);
		free(this->fs_type);

		if (this->opts)
			free(this->opts);

		free(this);
	}

	free(tree->path);
	free(tree->fs_name);
	free(tree->fs_type);

	if (tree->opts)
		free(tree->opts);

	free(tree);
}

/*
 * Make tree of system mounts in /proc/mounts.
 */
struct mnt_list *tree_make_mnt_tree(const char *table, const char *path)
{
	FILE *tab;
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	struct mntent *mnt;
	struct mnt_list *ent, *mptr;
	struct mnt_list *tree = NULL;
	char *pgrp;
	size_t plen;
	int eq;

	tab = setmntent(table, "r");
	if (!tab) {
		char *estr = strerror_r(errno, buf, PATH_MAX - 1);
		logerr("setmntent: %s", estr);
		return NULL;
	}

	plen = strlen(path);

	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		size_t len = strlen(mnt->mnt_dir);

		/* Not matching path */
		if (strncmp(mnt->mnt_dir, path, plen))
			continue;

		/* Not a subdirectory of requested path */
		if (plen > 1 && len > plen && mnt->mnt_dir[plen] != '/')
			continue;

		ent = malloc(sizeof(*ent));
		if (!ent) {
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		memset(ent, 0, sizeof(*ent));

		INIT_LIST_HEAD(&ent->self);
		INIT_LIST_HEAD(&ent->list);
		INIT_LIST_HEAD(&ent->entries);
		INIT_LIST_HEAD(&ent->sublist);
		INIT_LIST_HEAD(&ent->ordered);

		ent->path = malloc(len + 1);
		if (!ent->path) {
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		strcpy(ent->path, mnt->mnt_dir);

		ent->fs_name = malloc(strlen(mnt->mnt_fsname) + 1);
		if (!ent->fs_name) {
			free(ent->path);
			free(ent);
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		strcpy(ent->fs_name, mnt->mnt_fsname);

		ent->fs_type = malloc(strlen(mnt->mnt_type) + 1);
		if (!ent->fs_type) {
			free(ent->fs_name);
			free(ent->path);
			free(ent);
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		strcpy(ent->fs_type, mnt->mnt_type);

		ent->opts = malloc(strlen(mnt->mnt_opts) + 1);
		if (!ent->opts) {
			free(ent->fs_type);
			free(ent->fs_name);
			free(ent->path);
			free(ent);
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		strcpy(ent->opts, mnt->mnt_opts);

		ent->owner = 0;
		pgrp = strstr(mnt->mnt_opts, "pgrp=");
		if (pgrp) {
			char *end = strchr(pgrp, ',');
			if (end)
				*end = '\0';
			sscanf(pgrp, "pgrp=%d", &ent->owner);
		}

		mptr = tree;
		while (mptr) {
			int elen = strlen(ent->path);
			int mlen = strlen(mptr->path);

			if (elen < mlen) {
				if (mptr->left) {
					mptr = mptr->left;
					continue;
				} else {
					mptr->left = ent;
					break;
				}
			} else if (elen > mlen) {
				if (mptr->right) {
					mptr = mptr->right;
					continue;
				} else {
					mptr->right = ent;
					break;
				}
			}

			eq = strcmp(ent->path, mptr->path);
			if (eq < 0) {
				if (mptr->left)
					mptr = mptr->left;
				else {
					mptr->left = ent;
					break;
				}
			} else if (eq > 0) {
				if (mptr->right)
					mptr = mptr->right;
				else {
					mptr->right = ent;
					break;
				}
			} else {
				list_add_tail(&ent->self, &mptr->self);
				break;
			}
		}

		if (!tree)
			tree = ent;
	}
	endmntent(tab);

	return tree;
}

/*
 * Get list of mounts under "path" in longest->shortest order
 */
int tree_get_mnt_list(struct mnt_list *mnts, struct list_head *list, const char *path, int include)
{
	size_t mlen, plen;

	if (!mnts)
		return 0;

	plen = strlen(path);
	mlen = strlen(mnts->path);
	if (mlen < plen)
		return tree_get_mnt_list(mnts->right, list, path, include);
	else {
		struct list_head *self, *p;

		tree_get_mnt_list(mnts->left, list, path, include);

		if ((!include && mlen <= plen) ||
				strncmp(mnts->path, path, plen))
			goto skip;

		if (plen > 1 && mlen > plen && mnts->path[plen] != '/')
			goto skip;

		INIT_LIST_HEAD(&mnts->list);
		list_add(&mnts->list, list);

		self = &mnts->self;
		list_for_each(p, self) {
			struct mnt_list *this;

			this = list_entry(p, struct mnt_list, self);
			INIT_LIST_HEAD(&this->list);
			list_add(&this->list, list);
		}
skip:
		tree_get_mnt_list(mnts->right, list, path, include);
	}

	if (list_empty(list))
		return 0;

	return 1;
}

/*
 * Get list of mounts under "path" in longest->shortest order
 */
int tree_get_mnt_sublist(struct mnt_list *mnts, struct list_head *list, const char *path, int include)
{
	size_t mlen, plen;

	if (!mnts)
		return 0;

	plen = strlen(path);
	mlen = strlen(mnts->path);
	if (mlen < plen)
		return tree_get_mnt_sublist(mnts->right, list, path, include);
	else {
		struct list_head *self, *p;

		tree_get_mnt_sublist(mnts->left, list, path, include);

		if ((!include && mlen <= plen) ||
				strncmp(mnts->path, path, plen))
			goto skip;

		if (plen > 1 && mlen > plen && mnts->path[plen] != '/')
			goto skip;

		INIT_LIST_HEAD(&mnts->sublist);
		list_add(&mnts->sublist, list);

		self = &mnts->self;
		list_for_each(p, self) {
			struct mnt_list *this;

			this = list_entry(p, struct mnt_list, self);
			INIT_LIST_HEAD(&this->sublist);
			list_add(&this->sublist, list);
		}
skip:
		tree_get_mnt_sublist(mnts->right, list, path, include);
	}

	if (list_empty(list))
		return 0;

	return 1;
}

int tree_find_mnt_ents(struct mnt_list *mnts, struct list_head *list, const char *path)
{
	int mlen, plen;

	if (!mnts)
		return 0;

	plen = strlen(path);
	mlen = strlen(mnts->path);
	if (mlen < plen)
		return tree_find_mnt_ents(mnts->right, list, path);
	else if (mlen > plen)
		return tree_find_mnt_ents(mnts->left, list, path);
	else {
		struct list_head *self, *p;

		tree_find_mnt_ents(mnts->left, list, path);

		if (!strcmp(mnts->path, path)) {
			INIT_LIST_HEAD(&mnts->entries);
			list_add(&mnts->entries, list);
		}

		self = &mnts->self;
		list_for_each(p, self) {
			struct mnt_list *this;

			this = list_entry(p, struct mnt_list, self);

			if (!strcmp(this->path, path)) {
				INIT_LIST_HEAD(&this->entries);
				list_add(&this->entries, list);
			}
		}

		tree_find_mnt_ents(mnts->right, list, path);

		if (!list_empty(list))
			return 1;
	}

	return 0;
}

int tree_is_mounted(struct mnt_list *mnts, const char *path, unsigned int type)
{
	struct list_head *p;
	struct list_head list;
	int mounted = 0;

	INIT_LIST_HEAD(&list);

	if (!tree_find_mnt_ents(mnts, &list, path))
		return 0;

	list_for_each(p, &list) {
		struct mnt_list *mptr;

		mptr = list_entry(p, struct mnt_list, entries);

		if (type) {
			unsigned int autofs_fs;

			autofs_fs = !strcmp(mptr->fs_type, "autofs");

			if (type & MNTS_REAL) {
				if (!autofs_fs) {
					mounted = 1;
					break;
				}
			} else if (type & MNTS_AUTOFS) {
				if (autofs_fs) {
					mounted = 1;
					break;
				}
			} else {
				mounted = 1;
				break;
			}
		}
	}
	return mounted;
}

int tree_find_mnt_devid(struct mnt_list *mnts,
			const char *path, char *devid, unsigned int type)
{
	struct list_head *p;
	struct list_head list;
	size_t len = strlen(path);
	char *dev;

	INIT_LIST_HEAD(&list);

	if (!tree_find_mnt_ents(mnts, &list, path))
		return 0;

	dev = NULL;
	list_for_each(p, &list) {
		struct mnt_list *mptr;

		mptr = list_entry(p, struct mnt_list, entries);

		if (strcmp(mptr->fs_type, "autofs"))
			continue;

		if (strlen(mptr->path) < len)
			return 0;

		if (strcmp(mptr->path, path))
			continue;

		switch (type) {
		case AUTOFS_TYPE_INDIRECT:
			if (!strstr(mptr->opts, "indirect"))
				continue;
			break;

		case AUTOFS_TYPE_DIRECT:
			if (!strstr(mptr->opts, "direct"))
				continue;
			break;

		case AUTOFS_TYPE_OFFSET:
			if (!strstr(mptr->opts, "offset"))
				continue;
			break;
		}

		dev = strstr(mptr->opts, "dev");
		if (dev) {
			char *start = strchr(dev, '=') + 1;
			char *end = strchr(start, ',');
			if (end)
				*end = '\0';
			if (start) {
				int len = strlen(start);
				memcpy(devid, start, len);
				devid[len] = '\0';
			}
			*end = ',';
			break;
		}
	}

	if (!dev)
		return 0;

	return 1;
}

