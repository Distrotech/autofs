/* ----------------------------------------------------------------------- *
 *
 *  mounts.h - header file for mount utilities module.
 *
 *   Copyright 2008 Red Hat, Inc. All rights reserved.
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net> - All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef MOUNTS_H
#define MOUNTS_H

#include <linux/version.h>
#include <sys/utsname.h>

#ifndef AUTOFS_TYPE_ANY
#define AUTOFS_TYPE_ANY		0x0000
#endif
#ifndef AUTOFS_TYPE_INDIRECT
#define AUTOFS_TYPE_INDIRECT	0x0001
#endif
#ifndef AUTOFS_TYPE_DIRECT
#define AUTOFS_TYPE_DIRECT	0x0002
#endif
#ifndef AUTOFS_TYPE_OFFSET
#define AUTOFS_TYPE_OFFSET	0x0004
#endif

#define MNTS_ALL	0x0001
#define MNTS_REAL	0x0002
#define MNTS_AUTOFS	0x0004

#define REMOUNT_SUCCESS		0x0000
#define REMOUNT_FAIL		0x0001
#define REMOUNT_OPEN_FAIL	0x0002
#define REMOUNT_STAT_FAIL	0x0004
#define REMOUNT_READ_MAP	0x0008

extern const unsigned int t_indirect;
extern const unsigned int t_direct;
extern const unsigned int t_offset;

struct mapent;

struct mnt_list {
	char *path;
	char *fs_name;
	char *fs_type;
	char *opts;
	pid_t owner;
	/*
	 * List operations ie. get_mnt_list.
	 */
	struct mnt_list *next;
	/*
	 * Tree operations ie. tree_make_tree,
	 * tree_get_mnt_list etc.
	 */
	struct mnt_list *left;
	struct mnt_list *right;
	struct list_head self;
	struct list_head list;
	struct list_head entries;
	struct list_head sublist;
	/*
	 * Offset mount handling ie. add_ordered_list
	 * and get_offset.
	 */
	struct list_head ordered;
};

static inline unsigned int linux_version_code(void)
{
        struct utsname my_utsname;
        unsigned int p, q, r;

        if (uname(&my_utsname))
                return 0;

        p = (unsigned int)atoi(strtok(my_utsname.release, "."));
        q = (unsigned int)atoi(strtok(NULL, "."));
        r = (unsigned int)atoi(strtok(NULL, "."));
        return KERNEL_VERSION(p, q, r);
}

unsigned int query_kproto_ver(void);
unsigned int get_kver_major(void);
unsigned int get_kver_minor(void);
char *make_options_string(char *path, int kernel_pipefd, const char *extra);
char *make_mnt_name_string(char *path);
struct mnt_list *get_mnt_list(const char *table, const char *path, int include);
struct mnt_list *reverse_mnt_list(struct mnt_list *list);
void free_mnt_list(struct mnt_list *list);
int contained_in_local_fs(const char *path);
int is_mounted(const char *table, const char *path, unsigned int type);
int has_fstab_option(const char *opt);
char *get_offset(const char *prefix, char *offset,
                 struct list_head *head, struct list_head **pos);
void add_ordered_list(struct mnt_list *ent, struct list_head *head);
void tree_free_mnt_tree(struct mnt_list *tree);
struct mnt_list *tree_make_mnt_tree(const char *table, const char *path);
int tree_get_mnt_list(struct mnt_list *mnts, struct list_head *list, const char *path, int include);
int tree_get_mnt_sublist(struct mnt_list *mnts, struct list_head *list, const char *path, int include);
int tree_find_mnt_ents(struct mnt_list *mnts, struct list_head *list, const char *path);
int tree_is_mounted(struct mnt_list *mnts, const char *path, unsigned int type);
void set_tsd_user_vars(unsigned int, uid_t, gid_t);
const char *mount_type_str(unsigned int);
void notify_mount_result(struct autofs_point *, const char *, const char *);
int try_remount(struct autofs_point *, struct mapent *, unsigned int);
int umount_ent(struct autofs_point *, const char *);
int mount_multi_triggers(struct autofs_point *, struct mapent *, const char *, unsigned int, const char *);
int umount_multi_triggers(struct autofs_point *, struct mapent *, char *, const char *);

#endif
