#ident "$Id: lookup_ldap.c,v 1.6 2004/04/03 07:14:33 raven Exp $"
/*
 * lookup_ldap.c
 *
 *   Copyright 2001-2003 Ian Kent <raven@themaw.net>
 *
 * Module for Linux automountd to access automount maps in LDAP directories.
 *
 */

#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
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

/*
 * This initializes a context (persistent non-global data) for queries to
 * this module.  Return zero if we succeed.
 */
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt = NULL;
	int rv, l;
	LDAP *ldap;
	int version = 3;
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

	/* Now we sanity-check by binding to the server temporarily.  We have to be
	 * a little strange in here, because we want to provide for use of the
	 * "default" server, which is set in an ldap.conf file somewhere. */

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
	if ((ldap = ldap_init(ctxt->server, ctxt->port)) == NULL) {
		crit(MODPREFIX "couldn't initialize LDAP");
		return 1;
	}

	/* Use LDAPv3 */
	if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
		/* fall back to LDAPv2 */
		ldap_unbind(ldap);
		if ((ldap = ldap_init(ctxt->server, ctxt->port)) == NULL) {
			crit(MODPREFIX "couldn't initialize LDAP");
			return 1;
		} else {
			version = 2;
		}
	}

	/* Connect to the server as an anonymous user. */
	if (version == 2)
		rv = ldap_simple_bind_s(ldap, ctxt->base, NULL);
	else
		rv = ldap_simple_bind_s(ldap, NULL, NULL);

	if (rv != LDAP_SUCCESS) {
		crit(MODPREFIX "couldn't connect to %s", ctxt->server);
		return 1;
	}

	/* Okay, we're done here. */
	ldap_unbind(ldap);

	/* Open the parser, if we can. */
	return !(ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1));
}

static int read_one_map(const char *root,
			const char *class, char *key, char *type,
			struct lookup_context *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv, i, l, count;
	time_t age = time(NULL);
	char *query;
	LDAPMessage *result, *e;
	char **keyValue = NULL;
	char **values = NULL;
	char *attrs[] = { key, type, NULL };
	LDAP *ldap;
	int version = 3;

	if (ctxt == NULL) {
		crit(MODPREFIX "context was NULL");
		return 0;
	}

	/* Build a query string. */
	l = strlen("(&(objectclass=))") + strlen(class) + 1;

	query = alloca(l);
	if (query == NULL) {
		crit(MODPREFIX "malloc: %m");
		return 0;
	}

	memset(query, '\0', l);
	if (sprintf(query, "(&(objectclass=%s))", class) >= l) {
		debug(MODPREFIX "error forming query string");
	}
	query[l - 1] = '\0';

	/* Initialize the LDAP context. */
	if ((ldap = ldap_init(ctxt->server, ctxt->port)) == NULL) {
		crit(MODPREFIX "couldn't initialize LDAP connection"
		     " to %s", ctxt->server ? ctxt->server : "default server");
		return 0;
	}

	/* Use LDAPv3 */
	if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
		/* fall back to LDAPv2 */
		ldap_unbind(ldap);
		if ((ldap = ldap_init(ctxt->server, ctxt->port)) == NULL) {
			crit(MODPREFIX "couldn't initialize LDAP");
			return 1;
		} else {
			version = 2;
		}
	}

	/* Connect to the server as an anonymous user. */
	if (version == 2)
		rv = ldap_simple_bind_s(ldap, ctxt->base, NULL);
	else
		rv = ldap_simple_bind_s(ldap, NULL, NULL);

	if (rv != LDAP_SUCCESS) {
		crit(MODPREFIX "couldn't bind to %s",
		     ctxt->server ? ctxt->server : "default server");
		return 0;
	}

	/* Look around. */
	debug(MODPREFIX "searching for \"%s\" under \"%s\"", query, ctxt->base);

	rv = ldap_search_s(ldap, ctxt->base, LDAP_SCOPE_SUBTREE,
			   query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || (result == NULL)) {
		crit(MODPREFIX "query failed for %s", query);
		return 0;
	}

	e = ldap_first_entry(ldap, result);
	if (e == NULL) {
		debug(MODPREFIX "query succeeded, no matches for %s", query);
		return 0;
	} else
		debug(MODPREFIX "examining first entry");

	while (e != NULL) {
		keyValue = ldap_get_values(ldap, e, key);

		if (keyValue == NULL || !*keyValue) {
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
		for (i = 0; i < count; i++) {
			if (**keyValue == '/' && strlen(*keyValue) == 1)
				**keyValue = '*';
			cache_update(*keyValue, values[i], age);
		}
		ldap_value_free(values);

		ldap_value_free(keyValue);
		e = ldap_next_entry(ldap, e);
	}

	/* Clean up. */
	ldap_msgfree(result);
	ldap_unbind(ldap);

	return 1;
}

static int read_map(const char *root, struct lookup_context *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	time_t age = time(NULL);

	/* all else fails read entire map */
	if (!read_one_map(root, "nisObject", "cn", "nisMapEntry", ctxt)) {
		if (!read_one_map(root, "automount", "cn", "automountInformation", ctxt))
			return 0;
	}

	/* Clean stale entries from the cache */
	cache_clean(root, age);

	return 1;
}

int lookup_ghost(const char *root, int ghost, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *me;
	int status = 1;
	char *mapname;

	chdir("/");

	if (!read_map(root, ctxt))
		return LKP_FAIL;

	if (ctxt->server) {
		mapname = alloca(strlen(ctxt->server) + strlen(ctxt->base) + 2 + 1 + 1);
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

static int lookup(const char *root, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	char key[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	struct mapent_cache *me = NULL;
	char *mapname;
	int status = -1;

	me = cache_lookup(name);
	if (me == NULL) {
		if (sprintf(key, "%s/%s", root, name))
			me = cache_lookup(key);
	}

	if (me) {
		/* Try each of the LDAP entries in sucession. */
		while (me) {
			sprintf(mapent, me->mapent);

			debug(MODPREFIX "%s -> %s", name, mapent);
			status = ctxt->parse->parse_mount(root, name, name_len,
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

			debug(MODPREFIX "%s -> %s", name, mapent);
			status = ctxt->parse->parse_mount(root, name, name_len,
						  mapent, ctxt->parse->context);
		}
	}
	return status;
}

int lookup_mount(const char *root, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int status;

	chdir("/");

	status = lookup(root, name, name_len, ctxt);
	if (status == -1) {
		/* all else fails read entire map */
		if (!read_map(root, ctxt))
			return 1;

		status = lookup(root, name, name_len, ctxt);
	}
	return status;
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
