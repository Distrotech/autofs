#ident "$Id: master.h,v 1.1 2006/03/21 04:28:52 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  master.h - header file for master map parser utility routines.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#ifndef MASTER_H
#define MASTER_H

#define DEFAULT_MASTER_MAP	"/etc/auto.master"

#define DEFAULT_TIMEOUT (10*60)
#define DEFAULT_GHOST_MODE	1
#define DEFAULT_LOGGING		0

struct map_source {
	char *type;
	char *format;
	time_t age;
	struct lookup_mod *lookup;
	int argc;
	const char **argv;
	struct map_source *instance;
	struct map_source *next;
};

struct master_mapent {
	char *path;
	pthread_t thid;
	time_t age;
	struct map_source *first;
	struct map_source *maps;
	struct autofs_point *ap;
	struct list_head list;
};

struct master {
	char *name;
	unsigned int default_ghost;
	unsigned int default_logging;
	unsigned int default_timeout;
	struct list_head mounts;
};

struct readmap_cond;

/* From the yacc master map parser */

void master_init_scan(void);
int master_parse_entry(const char *, unsigned int, unsigned int, time_t);

/* From master.c master parser utility routines */

void master_set_default_timeout(void);
void master_set_default_ghost_mode(void);
int master_readmap_cond_init(struct readmap_cond *);
void master_readmap_cond_destroy(struct readmap_cond *);
int master_add_autofs_point(struct master_mapent *, time_t, unsigned, unsigned, int);
void master_free_autofs_point(struct autofs_point *);
struct map_source *
master_add_map_source(struct master_mapent *, char *, char *, time_t, int, const char **);
struct map_source *
master_find_map_source(struct master_mapent *, const char *, const char *, int, const char **);
void master_free_map_source(struct map_source *);
struct map_source *
master_find_source_instance(struct map_source *, const char *, const char *, int, const char **);
struct map_source *
master_add_source_instance(struct map_source *, const char *, const char *, time_t);
struct master_mapent *master_find_mapent(struct master *, const char *);
struct master_mapent *master_new_mapent(const char *, time_t);
void master_add_mapent(struct master *, struct master_mapent *);
void master_free_mapent(struct master_mapent *);
struct master *master_new(const char *);
int master_read_master(struct master *, time_t, int);
void master_notify_state_change(struct master *, int);
int master_mount_mounts(struct master *, time_t, int);
int master_list_empty(struct master *);
int master_kill(struct master *, unsigned int);

#endif
