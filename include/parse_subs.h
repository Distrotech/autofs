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

struct mapent;

const char *skipspace(const char *);
int check_colon(const char *);
int chunklen(const char *, int);
int strmcmp(const char *, const char *, int);
char *dequote(const char *, int, unsigned int);
int span_space(const char *, unsigned int);
char *sanitize_path(const char *, int, unsigned int, unsigned int);

#endif
