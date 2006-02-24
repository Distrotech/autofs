#ident "$Id: args.c,v 1.1 2006/02/24 17:20:55 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  args.c - argument vector handling.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net> - All Rights Reserved
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

#include "automount.h"

const char **copy_argv(int argc, const char **argv)
{
	char **vector;
	int i;

	vector = (char **) malloc((argc + 1) * sizeof(char *));
	if (!vector)
		return NULL;

	for (i = 0; i < argc; i++) {
		if (argv[i]) {
			vector[i] = strdup(argv[i]);
			if (!vector[i]) {
				error("failed to strdup arg");
				break;
			}
		} else
			vector[i] = NULL;
	}

	if (i < argc) {
		for (i = 0; i < argc; i++) {
			if (vector[i])
				free(vector[i]);
		}
		free(vector);
		return NULL;
	}

	vector[argc] = NULL;

	return (const char **) vector;

}

int free_argv(int argc, const char **argv)
{
	char **vector = (char **) argv;
	int i;

	for (i = 0; i < argc; i++) {
		if (vector[i])
			free(vector[i]);
	}
	free(vector);

	return 1;
}

