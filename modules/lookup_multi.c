/* ----------------------------------------------------------------------- *
 *   
 *  lookup_multi.c - module for Linux automount to seek multiple lookup
 *                   methods in succession
 *
 *   Copyright 1999 Transmeta Corporation - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <ctype.h>
#include <limits.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MODPREFIX "lookup(multi): "

struct module_info {
	int argc;
	const char *const *argv;
	struct lookup_mod *mod;
};

struct lookup_context {
	int n;
	const char **argl;
	struct module_info *m;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *my_mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	char *map, *mapfmt;
	int i, j, an;
	char *estr;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt)
		goto nomem;

	memset(ctxt, 0, sizeof(struct lookup_context));

	if (argc < 1) {
		crit(LOGOPT_ANY, MODPREFIX "No map list");
		goto error_out;
	}

	ctxt->n = 1;				/* Always at least one map */
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--"))	/* -- separates maps */
			ctxt->n++;
	}

	if (!(ctxt->m = malloc(ctxt->n * sizeof(struct module_info))) ||
	    !(ctxt->argl = malloc((argc + 1) * sizeof(const char *))))
		goto nomem;

	memset(ctxt->m, 0, ctxt->n * sizeof(struct module_info));

	memcpy(ctxt->argl, argv, (argc + 1) * sizeof(const char *));

	for (i = j = an = 0; ctxt->argl[an]; an++) {
		if (ctxt->m[i].argc == 0) {
			ctxt->m[i].argv = &ctxt->argl[an];
		}
		if (!strcmp(ctxt->argl[an], "--")) {
			ctxt->argl[an] = NULL;
			i++;
		} else {
			ctxt->m[i].argc++;
		}
	}

	for (i = 0; i < ctxt->n; i++) {
		if (!ctxt->m[i].argv[0]) {
			crit(LOGOPT_ANY, MODPREFIX "missing module name");
			goto error_out;
		}
		map = strdup(ctxt->m[i].argv[0]);
		if (!map)
			goto nomem;

		if ((mapfmt = strchr(map, ',')))
			*(mapfmt++) = '\0';

		if (!(ctxt->m[i].mod = open_lookup(map, MODPREFIX,
						   mapfmt ? mapfmt : my_mapfmt,
						   ctxt->m[i].argc - 1,
						   ctxt->m[i].argv + 1)))
			error(LOGOPT_ANY, MODPREFIX "error opening module");
			goto error_out;
	}

	*context = ctxt;
	return 0;

nomem:
	estr = strerror_r(errno, buf, MAX_ERR_BUF);
	crit(LOGOPT_ANY, MODPREFIX "error: %s", estr);
error_out:
	if (ctxt) {
		for (i = 0; i < ctxt->n; i++)
			if (ctxt->m[i].mod)
				close_lookup(ctxt->m[i].mod);
		if (ctxt->m)
			free(ctxt->m);
		if (ctxt->argl)
			free(ctxt->argl);
		free(ctxt);
	}
	return 1;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
        return NSS_STATUS_UNKNOWN;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int i, ret, at_least_1 = 0;

	for (i = 0; i < ctxt->n; i++) {
		ret = ctxt->m[i].mod->lookup_read_map(ap, age,
						ctxt->m[i].mod->context);
		if (ret & LKP_FAIL || ret == LKP_NOTSUP)
			continue;

		at_least_1 = 1;	
	}

	if (!at_least_1)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int i;

	for (i = 0; i < ctxt->n; i++) {
		if (ctxt->m[i].mod->lookup_mount(ap, name, name_len,
						 ctxt->m[i].mod->context) == 0)
			return NSS_STATUS_SUCCESS;
	}
	return NSS_STATUS_NOTFOUND;		/* No module succeeded */
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int i, rv = 0;

	for (i = 0; i < ctxt->n; i++) {
		if (ctxt->m[i].mod)
			rv = rv || close_lookup(ctxt->m[i].mod);
	}
	free(ctxt->argl);
	free(ctxt->m);
	free(ctxt);
	return rv;
}
