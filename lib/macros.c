#ident "$Id: macros.c,v 1.1 2006/03/09 23:01:01 raven Exp $"
/* ----------------------------------------------------------------------- *
 *   
 *  macros.c - module to handle macro substitution variables for map
 *		entries.
 * 
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>

#include "automount.h"
#include "macros.h"

static struct utsname un;
static char processor[65];		/* Not defined on Linux, so we make our own */

/* Predefined variables: tail of link chain */
static struct substvar
	sv_arch   = {"ARCH",   un.machine,  1, NULL },
	sv_cpu    = {"CPU",    processor,   1, &sv_arch},
	sv_host   = {"HOST",   un.nodename, 1, &sv_cpu},
	sv_osname = {"OSNAME", un.sysname,  1, &sv_host},
	sv_osrel  = {"OSREL",  un.release,  1, &sv_osname},
	sv_osvers = {"OSVERS", un.version,  1, &sv_osrel
};

static struct substvar *system_table = &sv_osvers;

static pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;

void dump_table(struct substvar *table)
{
	struct substvar *lv = table;
	int status;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	while (lv) {
		debug("lv->def %s lv->val %s lv->next %p", lv->def, lv->val, lv->next);
		lv = lv->next;
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);
}

/* Get processor information for predefined macro definitions */
void macro_init(void)
{
	uname(&un);
	/*
	 * uname -p is not defined on Linux.  Make it the same as
	 * uname -m, except make it return i386 on all x86 (x >= 3)
	 */
	strcpy(processor, un.machine);
	if (processor[0] == 'i' && processor[1] >= '3' &&
		!strcmp(processor + 2, "86"))
		processor[1] = '3';
}

int macro_is_systemvar(const char *str, int len)
{
	struct substvar *sv = system_table;
	int found = 0;
	int status;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0') {
			found = 1;
			break;
		}
		sv = sv->next;
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return found;
}

int macro_global_addvar(const char *str, int len, const char *value)
{
	struct substvar *sv = system_table;
	int status, ret = 0;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0')
			break;
		sv = sv->next;
	}

	if (sv) {
		char *this = realloc(sv->val, strlen(value) + 1);
		if (!this)
			goto done;
		strcat(this, value);
		sv->val = this;
		ret = 1;
	} else {
		struct substvar *new;
		char *def, *val;

		def = strdup(str);
		if (!def)
			goto done;
		def[len] = '\0';

		val = strdup(value);
		if (!val) {
			free(def);
			goto done;
		}

		new = malloc(sizeof(struct substvar));
		if (!new) {
			free(def);
			free(val);
			goto done;
		}
		new->def = def;
		new->val = val;
		new->readonly = 0;
		new->next = system_table;
		system_table = new;
		ret =1;
	}
done:
	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return ret;
}

struct substvar *
macro_addvar(struct substvar *table, const char *str, int len, const char *value)
{
	struct substvar *lv = table;
	int status;

	if (macro_is_systemvar(str, len))
		return table;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	while (lv) {
		if (!strncmp(str, lv->def, len) && lv->def[len] == '\0')
			break;
		lv = lv->next;
	}

	if (lv) {
		char *this = realloc(lv->val, strlen(value) + 1);
		if (!this) {
			lv = table;
			goto done;
		}
		strcat(this, value);
		lv->val = this;
	} else {
		struct substvar *new;
		char *def, *val;

		def = strdup(str);
		if (!def) {
			lv = table;
			goto done;
		}
		def[len] = '\0';

		val = strdup(value);
		if (!val) {
			lv = table;
			free(def);
			goto done;
		}

		new = malloc(sizeof(struct substvar));
		if (!new) {
			lv = table;
			free(def);
			free(val);
			goto done;
		}
		new->def = def;
		new->val = val;
		new->next = table;
		lv = new;
	}
done:
	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return lv;
}

void macro_global_removevar(const char *str, int len)
{
	struct substvar *sv;
	struct substvar *last = NULL;
	int status;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	sv = system_table;

	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0')
			break;
		last = sv;
		sv = sv->next;
	}

	if (sv && !sv->readonly) {
		if (last)
			last->next = sv->next;
		else
			system_table = sv->next;
		if (sv->def)
			free(sv->def);
		if (sv->val)
			free(sv->val);
		free(sv);
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return;
}

struct substvar *
macro_removevar(struct substvar *table, const char *str, int len)
{
	struct substvar *list, *lv;
	struct substvar *last = NULL;
	int status;

	if (macro_is_systemvar(str, len))
		return table;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	lv = list = table;

	while (lv) {
		if (!strncmp(str, lv->def, len) && lv->def[len] == '\0')
			break;
		last = lv;
		lv = lv->next;
	}

	if (lv) {
		if (last)
			last->next = lv->next;
		else
			list = lv->next;
		if (lv->def)
			free(lv->def);
		if (lv->val)
			free(lv->val);
		free(lv);
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return list;
}

void macro_free_global_table(void)
{
	struct substvar *sv = system_table;
	struct substvar *next;
	int status;

	if (!sv)
		return;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	while (sv) {
		if (sv->readonly) {
			sv = sv->next;
			continue;
		}
		next = sv->next;
		if (sv->def)
			free(sv->def);
		if (sv->val)
			free(sv->val);
		free(sv);
		sv = next;
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return;
}

void macro_free_table(struct substvar *table)
{
	struct substvar *lv = table;
	struct substvar *next;
	int status;

	if (!lv)
		return;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	while (lv) {
		next = lv->next;
		if (lv->def)
			free(lv->def);
		if (lv->val)
			free(lv->val);
		free(lv);
		lv = next;
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return;
}

/* Find the $-variable matching a certain string fragment */
const struct substvar *
macro_findvar(const struct substvar *table, const char *str, int len)
{
	const struct substvar *sv = system_table;
	const struct substvar *lv = table;
#ifdef ENABLE_EXT_ENV
	/* holds one env var */
	static struct substvar *lv_var;
	static char *value;
	char etmp[512];
#endif

	/* First look in the system wide table */
	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0')
			return sv;
		sv = sv->next;
	}

	/* Then try the passed in local table */
	while (lv) {
		if (!strncmp(str, lv->def, len) && lv->def[len] == '\0')
			return lv;
		lv = lv->next;
	}

#ifdef ENABLE_EXT_ENV
	/* builtin and local map failed, try the $ENV */
	memcpy(etmp, str, len);
	etmp[len]='\0';

	if ((value=getenv(etmp)) != NULL) {
		lv_var = macro_addvar(table, str, len, value);
		return(lv_var);
	}
#endif

	return NULL;
}

