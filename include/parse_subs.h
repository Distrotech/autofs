/* ----------------------------------------------------------------------- *
 *   
 *  parse_subs.c - misc parser subroutines
 *                automounter map
 * 
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef PARSE_SUBS_H
#define PARSE_SUBS_H

#define PROXIMITY_ERROR		0x0000
#define PROXIMITY_LOCAL         0x0001
#define PROXIMITY_SUBNET        0x0002
#define PROXIMITY_NET           0x0004
#define PROXIMITY_OTHER         0x0008
#define PROXIMITY_UNSUPPORTED   0x0010

struct mapent;

struct map_type_info {
	char *type;
	char *format;
	char *map;
};

unsigned int get_proximity(struct sockaddr *);
const char *skipspace(const char *);
int check_colon(const char *);
int chunklen(const char *, int);
int strmcmp(const char *, const char *, int);
char *dequote(const char *, int, unsigned int);
int span_space(const char *, unsigned int);
char *sanitize_path(const char *, int, unsigned int, unsigned int);
char *merge_options(const char *, const char *);
int expandamdent(const char *, char *, const struct substvar *);
int expand_selectors(struct autofs_point *, const char *, char **, struct substvar *);
void free_map_type_info(struct map_type_info *);
struct map_type_info *parse_map_type_info(const char *);

#endif
