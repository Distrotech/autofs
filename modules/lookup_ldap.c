#ident "$Id: lookup_ldap.c,v 1.23 2005/04/25 03:42:08 raven Exp $"
/*
 * lookup_ldap.c - Module for Linux automountd to access automount
 *		   maps in LDAP directories.
 *
 *   Copyright 2001-2003 Ian Kent <raven@themaw.net>
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
 */

#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <lber.h>
#include <ldap.h>

#define MODULE_LOOKUP
#include "automount.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(ldap): "

struct lookup_context {
	char *server, *base;
	int port;
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

static LDAP *do_connect(struct lookup_context *ctxt, int *result_ldap)
{
	LDAP *ldap;
	int version = 3;
	int timeout = 8;
	int rv;

	/* Initialize the LDAP context. */
	ldap = ldap_init(ctxt->server, ctxt->port);
	if (!ldap) {
		crit(MODPREFIX "couldn't initialize LDAP connection"
		     " to %s", ctxt->server ? ctxt->server : "default server");
		return NULL;
	}

	/* Use LDAPv3 */
	rv = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (rv != LDAP_SUCCESS) {
		/* fall back to LDAPv2 */
		ldap_unbind(ldap);
		ldap = ldap_init(ctxt->server, ctxt->port);
		if (!ldap) {
			crit(MODPREFIX "couldn't initialize LDAP");
			return NULL;
		} else {
			version = 2;
		}
	}

	/* Sane network connection timeout */
	rv = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
	if (rv != LDAP_SUCCESS) {
		warn(MODPREFIX
		     "failed to set connection timeout to %d", timeout);
	}

	/* Connect to the server as an anonymous user. */
	if (version == 2)
		rv = ldap_simple_bind_s(ldap, ctxt->base, NULL);
	else
		rv = ldap_simple_bind_s(ldap, NULL, NULL);

	if (rv != LDAP_SUCCESS) {
		crit(MODPREFIX "couldn't bind to %s",
		     ctxt->server ? ctxt->server : "default server");
		*result_ldap = rv;
		return NULL;
	}

	return ldap;
}

/*
 * This initializes a context (persistent non-global data) for queries to
 * this module.  Return zero if we succeed.
 */
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt = NULL;
	int l, rv;
	LDAP *ldap;
	char *ptr = NULL;

	/* If we can't build a context, bail. */
	ctxt = (struct lookup_context *) malloc(sizeof(struct lookup_context));
	*context = ctxt;
	if (ctxt == NULL) {
		crit(MODPREFIX "malloc: %m");
		return 1;
	}
	memset(ctxt, 0, sizeof(struct lookup_context));

	/* If a map type isn't explicitly given, parse it like sun entries. */
	if (mapfmt == NULL) {
		mapfmt = MAPFMT_DEFAULT;
	}

	/* Now we sanity-check by binding to the server temporarily. We have
	 * to be a little strange in here, because we want to provide for
	 * use of the "default" server, which is set in an ldap.conf file
	 * somewhere. */

	ctxt->server = NULL;
	ctxt->port = LDAP_PORT;
	ctxt->base = NULL;

	ptr = (char *) argv[0];

	if (!strncmp(ptr, "//", 2)) {
		char *s = ptr + 2;
		char *p = NULL, *q = NULL;

		/* Isolate the server's name and possibly port. But the : breaks
		   the SUN parser for submounts so we can't actually use it.
		 */
		if ((q = strchr(s, '/'))) {
			if ((p = strchr(s, ':'))) {
				l = p - s;
				p++;
				ctxt->port = atoi(p);
			} else {
				l = q - s;
			}

			ctxt->server = malloc(l + 1);
			memset(ctxt->server, 0, l + 1);
			memcpy(ctxt->server, s, l);

			ptr = q + 1;
		}
	} else if (strchr(ptr, ':') != NULL) {
		l = strchr(ptr, ':') - ptr;
		/* Isolate the server's name. */
		ctxt->server = malloc(l + 1);
		memset(ctxt->server, 0, l + 1);
		memcpy(ctxt->server, argv[0], l);
		ptr += l+1;
	}

	/* Isolate the base DN. */
	l = strlen(ptr);
	ctxt->base = malloc(l + 1);
	memset(ctxt->base, 0, l + 1);
	memcpy(ctxt->base, ptr, l);

	debug(MODPREFIX "server = \"%s\", port = %d, base dn = \"%s\"",
		  ctxt->server ? ctxt->server : "(default)",
		  ctxt->port, ctxt->base);

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt, &rv);
	if (!ldap)
		return 1;

	/* Okay, we're done here. */
	ldap_unbind(ldap);

	/* Open the parser, if we can. */
	return !(ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1));
}

static int read_one_map(const char *root,
			const char *class, char *key,
			const char *keyval, int keyvallen, char *type,
			struct lookup_context *ctxt,
			time_t age, int *result_ldap)
{
	int rv, i, j, l, count, keycount;
	char *query;
	LDAPMessage *result, *e;
	char **keyValue = NULL;
	char **values = NULL;
	char *attrs[] = { key, type, NULL };
	LDAP *ldap;

	if (ctxt == NULL) {
		crit(MODPREFIX "context was NULL");
		return 0;
	}

	/* Build a query string. */
	l = strlen("(objectclass=)") + strlen(class) + 1;
	if (keyvallen > 0) {
		l += strlen(key) +keyvallen + strlen("(&(=))");
	}

	query = alloca(l);
	if (query == NULL) {
		crit(MODPREFIX "malloc: %m");
		return 0;
	}

	memset(query, '\0', l);
	if (keyvallen > 0) {
		if (sprintf(query, "(&(objectclass=%s)(%s=%.*s))", class,
			    key, keyvallen, keyval) >= l) {
			debug(MODPREFIX "error forming query string");
		}
	} else {
		if (sprintf(query, "(objectclass=%s)", class) >= l) {
			debug(MODPREFIX "error forming query string");
		}
	}
	query[l - 1] = '\0';

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt, result_ldap);
	if (!ldap)
		return 0;

	/* Look around. */
	debug(MODPREFIX "searching for \"%s\" under \"%s\"", query, ctxt->base);

	rv = ldap_search_s(ldap, ctxt->base, LDAP_SCOPE_SUBTREE,
			   query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		crit(MODPREFIX "query failed for %s: %s", query, ldap_err2string(rv));
		ldap_unbind(ldap);
		*result_ldap = rv;
		return 0;
	}

	e = ldap_first_entry(ldap, result);
	if (!e) {
		debug(MODPREFIX "query succeeded, no matches for %s", query);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return 0;
	} else
		debug(MODPREFIX "examining entries");

	while (e) {
		keyValue = ldap_get_values(ldap, e, key);

		if (!keyValue || !*keyValue) {
			e = ldap_next_entry(ldap, e);
			continue;
		}

		values = ldap_get_values(ldap, e, type);
		if (!values) {
			info(MODPREFIX "no %s defined for %s", type, query);
			ldap_value_free(keyValue);
			e = ldap_next_entry(ldap, e);
			continue;
		}

		count = ldap_count_values(values);
		keycount = ldap_count_values(keyValue);
		for (i = 0; i < count; i++) {
			for (j = 0; j < keycount; j++) {
				if (*(keyValue[j]) == '/' &&
				    strlen(keyValue[j]) == 1)
					*(keyValue[j]) = '*';
				cache_add(root, keyValue[j], values[i], age);
			}
		}
		ldap_value_free(values);

		ldap_value_free(keyValue);
		e = ldap_next_entry(ldap, e);
	}

	debug(MODPREFIX "done updating map");

	/* Clean up. */
	ldap_msgfree(result);
	ldap_unbind(ldap);

	return 1;
}

static int read_map(const char *root, struct lookup_context *ctxt,
		    const char *key, int keyvallen, time_t age, int *result_ldap)
{
	int rv1 = LDAP_SUCCESS, rv2 = LDAP_SUCCESS;
	int ret;

	/* all else fails read entire map */
	ret = read_one_map(root, "nisObject", "cn", 
			  key, keyvallen, "nisMapEntry", ctxt, age, &rv1);
	if (ret)
		goto ret_ok;

	ret = read_one_map(root, "automount", "cn", key, keyvallen, 
			  "automountInformation", ctxt, age, &rv2);
	if (ret)
		goto ret_ok;

	if (result_ldap)
		*result_ldap = (rv1 == LDAP_SUCCESS ? rv2 : rv1);

	return 0;

ret_ok:
	/* Clean stale entries from the cache */
	cache_clean(root, age);

	return 1;
}

int lookup_ghost(const char *root, int ghost, time_t now, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *me;
	int status = 1, rv = LDAP_SUCCESS;
	char *mapname;
	time_t age = now ? now : time(NULL);

	chdir("/");

	if (!read_map(root, ctxt, NULL, 0, age, &rv))
		switch (rv) {
		case LDAP_SIZELIMIT_EXCEEDED:
		case LDAP_UNWILLING_TO_PERFORM:
			return LKP_NOTSUP;
		default:
			return LKP_FAIL;
		}

	if (ctxt->server) {
		int len = strlen(ctxt->server) + strlen(ctxt->base) + 4;

		mapname = alloca(len);
		sprintf(mapname, "//%s/%s", ctxt->server, ctxt->base);
	} else {
		mapname = alloca(strlen(ctxt->base) + 1);
		sprintf(mapname, "%s", ctxt->base);
	}

	status = cache_ghost(root, ghost, mapname, "ldap", ctxt->parse);

	me = cache_lookup_first();
	/* me NULL => empty map */
	if (me == NULL)
		return LKP_FAIL;

	if (*me->key == '/' && *(root + 1) != '-') {
		me = cache_partial_match(root);
		/* 
		 * me NULL => no entries for this direct mount
		 * root or indirect map
		 */
		if (me == NULL)
			return LKP_FAIL | LKP_INDIRECT;
	}

	return status;
}

static int lookup_one(const char *root, const char *qKey,
		      const char *class, char *key, char *type,
		      struct lookup_context *ctxt)
{
	int rv, i, l, ql;
	time_t age = time(NULL);
	char *query;
	LDAPMessage *result, *e;
	char **values = NULL;
	char *attrs[] = { key, type, NULL };
	LDAP *ldap;
	struct mapent_cache *me = NULL;
	int ret = CHE_OK;

	if (ctxt == NULL) {
		crit(MODPREFIX "context was NULL");
		return 0;
	}

	/* Build a query string. */
	l = strlen("(&(objectclass=") + strlen(class) + strlen(")");
	l += strlen("(") + strlen(key) + strlen("=") 
				+ strlen(qKey) + strlen("))") + 1;

	query = alloca(l);
	if (query == NULL) {
		crit(MODPREFIX "malloc: %m");
		return 0;
	}

	/* Look around. */
	memset(query, '\0', l);
	ql = sprintf(query, "(&(objectclass=%s)(%s=%s))", class, key, qKey);
	if (ql >= l) {
		debug(MODPREFIX "error forming query string");
		return 0;
	}
	query[l - 1] = '\0';

	debug(MODPREFIX "searching for \"%s\" under \"%s\"", query, ctxt->base);

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt, &rv);
	if (!ldap)
		return 0;

	rv = ldap_search_s(ldap, ctxt->base, LDAP_SCOPE_SUBTREE,
			   query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		crit(MODPREFIX "query failed for %s", query);
		ldap_unbind(ldap);
		return 0;
	}

	debug(MODPREFIX "getting first entry for %s=\"%s\"", key, qKey);

	e = ldap_first_entry(ldap, result);
	if (!e) {
		crit(MODPREFIX "got answer, but no first entry for %s", query);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return CHE_MISSING;
	}

	debug(MODPREFIX "examining first entry");

	values = ldap_get_values(ldap, e, type);
	if (!values) {
		debug(MODPREFIX "no %s defined for %s", type, query);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return CHE_MISSING;
	}

	/* Compare cache entry against LDAP */
	for (i = 0; values[i]; i++) {
		me = cache_lookup(qKey);
		while (me && (strcmp(me->mapent, values[i]) != 0))
			me = cache_lookup_next(me);
		if (!me)
			break;
	}

	if (!me) {
		cache_delete(root, qKey, 0);

		for (i = 0; values[i]; i++) {	
			rv = cache_add(root, qKey, values[i], age);
			if (!rv)
				return 0;
		}

		ret = CHE_UPDATED;
	}

	/* Clean up. */
	ldap_value_free(values);
	ldap_msgfree(result);
	ldap_unbind(ldap);

	return ret;
}

static int lookup_wild(const char *root,
		      const char *class, char *key, char *type,
		      struct lookup_context *ctxt)
{
	int rv, i, l, ql;
	time_t age = time(NULL);
	char *query;
	LDAPMessage *result, *e;
	char **values = NULL;
	char *attrs[] = { key, type, NULL };
	LDAP *ldap;
	struct mapent_cache *me = NULL;
	int ret = CHE_OK;
	char qKey[KEY_MAX_LEN + 1];
	int qKey_len;

	if (ctxt == NULL) {
		crit(MODPREFIX "context was NULL");
		return 0;
	}

	strcpy(qKey, "/");
	qKey_len = 1;

	/* Build a query string. */
	l = strlen("(&(objectclass=") + strlen(class) + strlen(")");
	l += strlen("(") + strlen(key) + strlen("=") + qKey_len + strlen("))") + 1;

	query = alloca(l);
	if (query == NULL) {
		crit(MODPREFIX "malloc: %m");
		return 0;
	}

	/* Look around. */
	memset(query, '\0', l);
	ql = sprintf(query, "(&(objectclass=%s)(%s=%s))", class, key, qKey);
	if (ql >= l) {
		debug(MODPREFIX "error forming query string");
		return 0;
	}
	query[l - 1] = '\0';

	debug(MODPREFIX "searching for \"%s\" under \"%s\"", query, ctxt->base);

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt, &rv);
	if (!ldap)
		return 0;

	rv = ldap_search_s(ldap, ctxt->base, LDAP_SCOPE_SUBTREE,
			   query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		crit(MODPREFIX "query failed for %s", query);
		ldap_unbind(ldap);
		return 0;
	}

	debug(MODPREFIX "getting first entry for %s=\"%s\"", key, qKey);

	e = ldap_first_entry(ldap, result);
	if (!e) {
		crit(MODPREFIX "got answer, but no first entry for %s", query);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return CHE_MISSING;
	}

	debug(MODPREFIX "examining first entry");

	values = ldap_get_values(ldap, e, type);
	if (!values) {
		debug(MODPREFIX "no %s defined for %s", type, query);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return CHE_MISSING;
	}

	/* Compare cache entry against LDAP */
	for (i = 0; values[i]; i++) {
		me = cache_lookup("*");
		while (me && (strcmp(me->mapent, values[i]) != 0))
			me = cache_lookup_next(me);
		if (!me)
			break;
	}

	if (!me) {
		cache_delete(root, "*", 0);

		for (i = 0; values[i]; i++) {	
			rv = cache_add(root, "*", values[i], age);
			if (!rv)
				return 0;
		}

		ret = CHE_UPDATED;
	}

	/* Clean up. */
	ldap_value_free(values);
	ldap_msgfree(result);
	ldap_unbind(ldap);

	return ret;
}

int lookup_mount(const char *root, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int ret, ret2;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char mapent[MAPENT_MAX_LEN + 1];
	char *mapname;
	struct mapent_cache *me;
	time_t now = time(NULL);
	time_t t_last_read;
	int need_hup = 0;

	if (ap.type == LKP_DIRECT)
		key_len = snprintf(key, KEY_MAX_LEN, "%s/%s", root, name);
	else
		key_len = snprintf(key, KEY_MAX_LEN, "%s", name);

	if (key_len > KEY_MAX_LEN)
		return 1;

	ret = lookup_one(root, key, "nisObject", "cn", "nisMapEntry", ctxt);
	ret2 = lookup_one(root, key,
			    "automount", "cn", "automountInformation", ctxt);
	
   	debug("ret = %d, ret2 = %d", ret, ret2);

	if (!ret && !ret2)
		return 1;

	me = cache_lookup_first();
	t_last_read = me ? now - me->age : ap.exp_runfreq + 1;

	if (t_last_read > ap.exp_runfreq) 
		if ((ret & (CHE_MISSING | CHE_UPDATED)) && 
		    (ret2 & (CHE_MISSING | CHE_UPDATED)))
			need_hup = 1;

	if (ret == CHE_MISSING && ret2 == CHE_MISSING) {
		int wild = CHE_MISSING;

		/* Maybe update wild card map entry */
		if (ap.type == LKP_INDIRECT) {
			ret = lookup_wild(root, "nisObject",
					  "cn", "nisMapEntry", ctxt);
			ret2 = lookup_wild(root, "automount",
					   "cn", "automountInformation", ctxt);
			wild = (ret & (CHE_MISSING | CHE_FAIL)) &&
					(ret2 & (CHE_MISSING | CHE_FAIL));

			if (ret & CHE_MISSING && ret2 & CHE_MISSING)
				cache_delete(root, "*", 0);
		}

		if (cache_delete(root, key, 0) && wild)
			rmdir_path(key);
	}

	me = cache_lookup(key);
	if (me) {
		/* Try each of the LDAP entries in sucession. */
		while (me) {
			sprintf(mapent, me->mapent);

			debug(MODPREFIX "%s -> %s", key, mapent);
			ret = ctxt->parse->parse_mount(root, name, name_len,
						  mapent, ctxt->parse->context);
			me = cache_lookup_next(me);
		}
	} else {
		/* path component, do submount */
		me = cache_partial_match(key);
		if (me) {
			if (ctxt->server) {
				int len = strlen(ctxt->server) +
					    strlen(ctxt->base) + 2 + 1 + 1;
				mapname = alloca(len);
				sprintf(mapname, "//%s/%s", ctxt->server, ctxt->base);
			} else {
				mapname = alloca(strlen(ctxt->base) + 1);
				sprintf(mapname, "%s", ctxt->base);
			}
			sprintf(mapent, "-fstype=autofs ldap:%s", mapname);

			debug(MODPREFIX "%s -> %s", key, mapent);
			ret = ctxt->parse->parse_mount(root, name, name_len,
						  mapent, ctxt->parse->context);
		}
	}

	/* Have parent update its map */
	if (need_hup)
		kill(getppid(), SIGHUP);

	return ret;
}

/*
 * This destroys a context for queries to this module.  It releases the parser
 * structure (unloading the module) and frees the memory used by the context.
 */
int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt->server);
	free(ctxt->base);
	free(ctxt);
	return rv;
}
