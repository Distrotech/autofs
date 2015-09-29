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
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAX_MAP_TYPE_STRING	20

#define MODPREFIX "lookup(multi): "

struct module_info {
	int argc;
	const char **argv;
	struct lookup_mod *mod;
};

struct lookup_context {
	int n;
	const char **argl;
	struct module_info *m;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

static int free_multi_context(struct lookup_context *);

static struct lookup_context *alloc_context(const char *format,
					    int argc, const char *const *argv)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	char **args;
	int i, an;
	char *estr;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt)
		goto nomem;

	memset(ctxt, 0, sizeof(struct lookup_context));

	if (argc < 1) {
		logerr(MODPREFIX "No map list");
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

	args = NULL;
	for (i = an = 0; ctxt->argl[an]; an++) {
		if (ctxt->m[i].argc == 0)
			args = (char **) &ctxt->argl[an];

		if (strcmp(ctxt->argl[an], "--"))
			ctxt->m[i].argc++;
		else {
			ctxt->argl[an] = NULL;
			if (!args) {
				logerr(MODPREFIX "error assigning map args");
				goto error_out;
			}
			ctxt->m[i].argv = copy_argv(ctxt->m[i].argc,
						    (const char **) args);
			if (!ctxt->m[i].argv)
				goto nomem;
			args = NULL;
			i++;
		}
	}

	/* catch the last one */
	if (args) {
		ctxt->m[i].argv = copy_argv(ctxt->m[i].argc, (const char **) args);
		if (!ctxt->m[i].argv)
			goto nomem;
	}

	return ctxt;

nomem:
	estr = strerror_r(errno, buf, MAX_ERR_BUF);
	logerr(MODPREFIX "error: %s", estr);

error_out:
	free_multi_context(ctxt);
	free(ctxt);

	return NULL;
}

static int free_multi_context(struct lookup_context *ctxt)
{
	int rv;

	if (!ctxt)
		return 0;

	rv = 0;
	if (ctxt->m) {
		int i;

		for (i = 0; i < ctxt->n; i++) {
			if (ctxt->m[i].mod)
				rv = rv || close_lookup(ctxt->m[i].mod);
			if (ctxt->m[i].argv)
				free_argv(ctxt->m[i].argc, ctxt->m[i].argv);
		}
		free(ctxt->m);
	}

	if (ctxt->argl)
		free(ctxt->argl);

	return rv;
}

static struct lookup_context *update_multi_context(struct lookup_context *ctxt,
						   struct lookup_context *new)
{
	int i;

	for (i = 0; i < new->n && i < ctxt->n; i++) {
		if (new->m[i].mod)
			continue;

		if (!ctxt->m[i].mod)
			continue;

		/* reinit or open failed, use old one, questionable but
		 * we need to do something.
		 */
		new->m[i].mod = ctxt->m[i].mod;
		ctxt->m[i].mod = NULL;
		new->m[i].argc = ctxt->m[i].argc;
		new->m[i].argv = ctxt->m[i].argv;
		ctxt->m[i].argv = NULL;
	}

	return new;
}

static struct lookup_mod *nss_open_lookup(const char *format, int argc, const char **argv)
{
	struct list_head nsslist;
	struct list_head *head, *p;
	struct lookup_mod *mod;
	char buf[MAX_ERR_BUF], *estr;

	if (!argv || !argv[0])
		return NULL;

	if (*argv[0] == '/') {
		open_lookup("file", MODPREFIX, format, argc, argv, &mod);
		return mod;
	}

	if (!strncmp(argv[0], "file", 4) ||
	    !strncmp(argv[0], "yp", 2) ||
	    !strncmp(argv[0], "nisplus", 7) ||
	    !strncmp(argv[0], "nis", 3) ||
	    !strncmp(argv[0], "ldaps", 5) ||
	    !strncmp(argv[0], "ldap", 4) ||
	    !strncmp(argv[0], "sss", 3)) {
		char type[MAX_MAP_TYPE_STRING];
		char *fmt;

		strcpy(type, argv[0]);
		fmt = strchr(type, ',');
		if (!fmt)
			fmt = (char *) format;
		else {
			*fmt = '\0';
			fmt++;
		}
		open_lookup(argv[0], MODPREFIX, fmt, argc - 1, argv + 1, &mod);
		return mod;
	}

	INIT_LIST_HEAD(&nsslist);

	if (nsswitch_parse(&nsslist)) {
		if (!list_empty(&nsslist))
			free_sources(&nsslist);
		logerr("can't to read name service switch config.");
		return NULL;
	}

	head = &nsslist;
	list_for_each(p, head) {
		struct nss_source *this;
		int status;
		int ret;

		this = list_entry(p, struct nss_source, list);

		if (!strcmp(this->source, "files")) {
			char src_file[] = "file";
			char src_prog[] = "program";
			struct stat st;
			char *type, *path, *save_argv0;

			path = malloc(strlen(AUTOFS_MAP_DIR) + strlen(argv[0]) + 2);
			if (!path) {
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				logerr(MODPREFIX "error: %s", estr);
				free_sources(&nsslist);
				return NULL;
			}
			strcpy(path, AUTOFS_MAP_DIR);
			strcat(path, "/");
			strcat(path, argv[0]);

			if (stat(path, &st) == -1 || !S_ISREG(st.st_mode)) {
				free(path);
				continue;
			}

			if (st.st_mode & __S_IEXEC)
				type = src_prog;
			else
				type = src_file;

			save_argv0 = (char *) argv[0];
			argv[0] = path;

			status = open_lookup(type, MODPREFIX,
					     format, argc, argv, &mod);
			if (status == NSS_STATUS_SUCCESS) {
				free_sources(&nsslist);
				free(save_argv0);
				return mod;
			}

			argv[0] = save_argv0;
			free(path);

			ret = check_nss_result(this, status);
			if (ret >= 0)
				break;
		}

		status = open_lookup(this->source, MODPREFIX,
				     format, argc, argv, &mod);
		if (status == NSS_STATUS_SUCCESS) {
			free_sources(&nsslist);
			return mod;
		}

		ret = check_nss_result(this, status);
		if (ret >= 0)
			break;
	}
	free_sources(&nsslist);

	return NULL;
}

int lookup_init(const char *my_mapfmt,
		int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	int i;

	*context = NULL;

	ctxt = alloc_context(my_mapfmt, argc, argv);
	if (!ctxt)
		return 1;

	for (i = 0; i < ctxt->n; i++) {
		ctxt->m[i].mod = nss_open_lookup(my_mapfmt,
				 ctxt->m[i].argc, ctxt->m[i].argv);
		if (!ctxt->m[i].mod) {
			logerr(MODPREFIX "error opening module");
			free_multi_context(ctxt);
			free(ctxt);
			return 1;
		}
	}

	*context = ctxt;

	return 0;
}

int lookup_reinit(const char *my_mapfmt,
		  int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt = (struct lookup_context *) *context;
	struct list_head nsslist;
	struct list_head *head, *p;
	struct lookup_context *new;
	char buf[MAX_ERR_BUF], *estr;
	int i, ret = 0;
	int status;

	new = alloc_context(my_mapfmt, argc, argv);
	if (!new)
		return 1;

	for (i = 0; i < new->n; i++) {
		if (i >= ctxt->n) {
			new->m[i].mod = nss_open_lookup(my_mapfmt,
							new->m[i].argc,
							new->m[i].argv);
			if (!new->m[i].mod) {
				logerr(MODPREFIX "error opening module");
				/* TODO: check */
				ret = 1;
				goto out;
			}
			continue;
		}

		if (*new->m[i].argv[0] == '/') {
			if (strcmp(new->m[i].argv[0], ctxt->m[i].argv[0]))
				open_lookup("file", MODPREFIX,
					     my_mapfmt,
					     new->m[i].argc,
					     new->m[i].argv,
					     &new->m[i].mod);
			else {
				new->m[i].mod = ctxt->m[i].mod;
				if (reinit_lookup(new->m[i].mod, "file",
					      MODPREFIX, my_mapfmt,
					      new->m[i].argc, new->m[i].argv))
					new->m[i].mod = NULL;
				else
					ctxt->m[i].mod = NULL;
			}
			continue;
		}

		if (!strncmp(new->m[i].argv[0], "file", 4) ||
		    !strncmp(new->m[i].argv[0], "yp", 2) ||
		    !strncmp(new->m[i].argv[0], "nisplus", 7) ||
		    !strncmp(new->m[i].argv[0], "nis", 3) ||
		    !strncmp(new->m[i].argv[0], "ldaps", 5) ||
		    !strncmp(new->m[i].argv[0], "ldap", 4) ||
		    !strncmp(new->m[i].argv[0], "sss", 3)) {
			char type[MAX_MAP_TYPE_STRING];
			char *fmt;

			strcpy(type, new->m[i].argv[0]);
			fmt = strchr(type, ',');
			if (!fmt)
				fmt = (char *) my_mapfmt;
			else {
				*fmt = '\0';
				fmt++;
			}

			if (!strcmp(new->m[i].argv[0], ctxt->m[i].argv[0]) &&
			    !strcmp(new->m[i].argv[1], ctxt->m[i].argv[1])) {
				new->m[i].mod = ctxt->m[i].mod;
				if (reinit_lookup(new->m[i].mod, new->m[i].argv[0],
					      MODPREFIX, fmt,
					      new->m[i].argc - 1, new->m[i].argv + 1))
					new->m[i].mod = NULL;
				else
					ctxt->m[i].mod = NULL;
			} else {
				open_lookup(type, MODPREFIX, fmt,
					    new->m[i].argc - 1,
					    new->m[i].argv + 1,
					    &new->m[i].mod);
			}
			continue;
		}

		INIT_LIST_HEAD(&nsslist);

		if (nsswitch_parse(&nsslist)) {
			if (!list_empty(&nsslist))
				free_sources(&nsslist);
			logerr("can't to read name service switch config.");
			/* TODO: check */
			ret = 1;
			goto out;
		}

		head = &nsslist;
		list_for_each(p, head) {
			struct nss_source *this;

			this = list_entry(p, struct nss_source, list);

			if (!strcmp(this->source, ctxt->m[i].mod->type)) {
				new->m[i].mod = ctxt->m[i].mod;
				if (reinit_lookup(new->m[i].mod, this->source,
					      MODPREFIX, my_mapfmt,
					      new->m[i].argc, new->m[i].argv))
					new->m[i].mod = NULL;
				else
					ctxt->m[i].mod = NULL;
				continue;
			}

			if (!strcmp(this->source, "files")) {
				char src_file[] = "file";
				char src_prog[] = "program";
				struct stat st;
				char *type, *path, *save_argv0;

				path = malloc(strlen(AUTOFS_MAP_DIR) +
					      strlen(new->m[i].argv[0]) + 2);
				if (!path) {
					estr = strerror_r(errno, buf, MAX_ERR_BUF);
					logerr(MODPREFIX "error: %s", estr);
					free_sources(&nsslist);
					ret = 1;
					goto out;
				}
				strcpy(path, AUTOFS_MAP_DIR);
				strcat(path, "/");
				strcat(path, new->m[i].argv[0]);

				if (stat(path, &st) == -1 || !S_ISREG(st.st_mode)) {
					free(path);
					continue;
				}

				if (st.st_mode & __S_IEXEC)
					type = src_prog;
				else
					type = src_file;

				save_argv0 = (char *) new->m[i].argv[0];
				new->m[i].argv[0] = path;

				if (strcmp(type, ctxt->m[i].mod->type)) {
					status = open_lookup(type,
							     MODPREFIX,
							     my_mapfmt,
							     new->m[i].argc,
							     new->m[i].argv,
							     &new->m[i].mod);
					if (status == NSS_STATUS_SUCCESS) {
						free(save_argv0);
						break;
					}
				} else {
					new->m[i].mod = ctxt->m[i].mod;
					if (reinit_lookup(new->m[i].mod, type,
						      MODPREFIX, my_mapfmt,
						      new->m[i].argc, new->m[i].argv))
						new->m[i].mod = NULL;
					else {
						ctxt->m[i].mod = NULL;
						free(save_argv0);
						break;
					}
				}

				new->m[i].argv[0] = save_argv0;
				free(path);
				continue;
			}

			if (strcmp(this->source, ctxt->m[i].mod->type)) {
				status = open_lookup(this->source, MODPREFIX,
						     my_mapfmt,
						     new->m[i].argc,
						     new->m[i].argv,
						     &new->m[i].mod);
				if (status == NSS_STATUS_SUCCESS)
					break;
			} else {
				new->m[i].mod = ctxt->m[i].mod;
				if (reinit_lookup(new->m[i].mod, this->source,
					      MODPREFIX, my_mapfmt,
					      new->m[i].argc, new->m[i].argv))
					new->m[i].mod = NULL;
				else {
					ctxt->m[i].mod = NULL;
					break;
				}
			}
		}
		free_sources(&nsslist);
	}
out:
	/* Update new context with any needed old context */
	*context = update_multi_context(ctxt, new);
	free_multi_context(ctxt);
	free(ctxt);

	return ret;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
        return NSS_STATUS_UNKNOWN;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	int i, ret, at_least_1 = 0;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	for (i = 0; i < ctxt->n; i++) {
		master_source_current_wait(ap->entry);
		ap->entry->current = source;
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
	struct map_source *source;
	int i;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	for (i = 0; i < ctxt->n; i++) {
		master_source_current_wait(ap->entry);
		ap->entry->current = source;
		if (ctxt->m[i].mod->lookup_mount(ap, name, name_len,
						 ctxt->m[i].mod->context) == 0)
			return NSS_STATUS_SUCCESS;
	}
	return NSS_STATUS_NOTFOUND;		/* No module succeeded */
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv;

	rv = free_multi_context(ctxt);
	free(ctxt);

	return rv;
}
