#ident "$Id: lookup_ldap.c,v 1.35 2006/03/29 10:32:36 raven Exp $"
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
#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
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
#include "nsswitch.h"
#if WITH_SASL
#include "ldap_sasl.h"
#endif

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(ldap): "

struct lookup_context {
	char *mapname;

	char *server;
	int port;
	char *base;

	/* LDAP version 2 or 3 */
	int version;

	/* LDAP lookup configuration */
	char *map_obj_class;
	char *entry_obj_class;
	char *map_attr;
	char *entry_attr;
	char *value_attr;

	/* sasl authentication information */
	cahr *auth_conf;
	char *sasl_mech;
	char *user;
	char *secret;

	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int ldap_bind_anonymous(LDAP *ldap, struct lookup_context *ctxt)
{
	int rv;

	if (ctxt->version == 2)
		rv = ldap_simple_bind_s(ldap, ctxt->base, NULL);
	else
		rv = ldap_simple_bind_s(ldap, NULL, NULL);

	if (rv != LDAP_SUCCESS) {
		ldap_unbind(ldap);
		crit(MODPREFIX "Unable to bind to the LDAP server: "
		     "%s, error %s", ctxt->server ?: "(default)",
		     ldap_err2string(rv));
		return -1;
	}

	return 0;
}

LDAP *ldap_connection_init(const char *server, int port, int *version)
{
	LDAP *ldap;
	int timeout = 8;
	int rv;

	*version = 3;

	/* Initialize the LDAP context. */
	ldap = ldap_init(server, port);
	if (!ldap) {
		crit(MODPREFIX "couldn't initialize LDAP connection"
		     " to %s", server ?: "default server");
		return NULL;
	}

	/* Use LDAPv3 */
	rv = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, version);
	if (rv != LDAP_SUCCESS) {
		/* fall back to LDAPv2 */
		ldap_unbind(ldap);
		ldap = ldap_init(server, port);
		if (!ldap) {
			crit(MODPREFIX "couldn't initialize LDAP");
			return NULL;
		}

		*version = 2;
	}

	/* Sane network connection timeout */
	rv = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
	if (rv != LDAP_SUCCESS)
		info(MODPREFIX "failed to set connection timeout to %d",
		     timeout);

	return ldap;
}

static LDAP *do_connect(struct lookup_context *ctxt)
{
	LDAP *ldap;
	int rv;

	ldap = ldap_connection_init(ctxt->server, ctxt->port, &ctxt->version);
	if (!ldap)
		return NULL;

#if WITH_SASL
	if (ctxt->sasl_mech) {
		sasl_conn_t *conn;

		debug("attempting sasl bind, mechanism %s, user %s, pass %s\n",
		      ctxt->sasl_mech, ctxt->user, ctxt->secret);

		conn = sasl_bind_mech(ldap, ctxt->server, ctxt->sasl_mech);
		if (conn)
			rv = 0;
		rv = 1;
		sasl_dispose(&conn);
	} else {
		rv = ldap_bind_anonymous(ldap, ctxt);
		debug("doing anonymous bind, ret %d\n", rv);
	}
#else
	rv = ldap_bind_anonymous(ldap, ctxt);
	debug("doing anonymous bind, ret %d\n", rv);
#endif

	if (rv != 0)
		return NULL;

	return ldap;
}

#if WITH_SASL
int get_property(xmlNodePtr node, const char *prop, char **value)
{
	xmlChar *ret;
	xmlChar *property = (xmlChar *) prop;

	if (!(ret = xmlGetProp(node, property))) {
		debug("xmlGetProp failed for prop %s\n", prop);
		return -1;
	}

	if (!(*value = strdup((char *) ret))) {
		error("strdup failed with %d\n", errno);
		xmlFree(ret);
		return -1;
	}

	xmlFree(ret);
	return 0;
}

/*
 *  For plain text and digest-md5 authentication types, we need
 *  user and password credentials.
 */
int authtype_requires_creds(const char *authtype)
{
	if (!strncmp(authtype, "PLAIN", strlen("PLAIN")) ||
	    !strncmp(authtype, "DIGEST-MD5", strlen("DIGEST-MD5")))
		return 1;
	return 0;
}

/*
 *  Returns:
 *    -1  --  The permission on the file are not correct or
 *            the xml document was mal-formed
 *     0  --  The file was non-existent
 *            the file was empty
 *            the file contained valid data, which was filled into 
 *            ctxt->sasl_mech, ctxt->user, and ctxt->secret
 *
 *  The idea is that a -1 return value should abort the program.  A 0
 *  return value requires more checking.  If ctxt->authtype is filled in,
 *  then no further action is necessary.  If it is not, the caller is free
 *  to then use another method to determine how to connec to the server.
 */
int parse_ldap_config(struct lookup_context *ctxt)
{
	int          ret, fallback = 0;
	struct stat  st;
	xmlDocPtr    doc = NULL;
	xmlNodePtr   root = NULL;
	char         *auth_conf, *authtype, *user, *secret;

	authtype = user = secret = NULL;

	auth_conf = (char *) get_default_auth_conf_file();
	if (!auth_conf) {
		debug(MODPREFIX "failed to get auth config file name.");
		return 0;
	}

	/*
	 *  Here we check that the config file exists, and that we have
	 *  permission to read it.  The XML library does not specify why a
	 *  parse happens to fail, so we have to do all of this checking
	 *  beforehand.
	 */
	memset(&st, 0, sizeof(st));
	if (stat(auth_conf, &st) == -1 || st.st_size == 0) {
		debug(MODPREFIX "stat(2) failed with error %s.",
		      strerror(errno));
		return 0;
	}

	if (!S_ISREG(st.st_mode) ||
	    st.st_uid != 0 || st.st_gid != 0 ||
	    st.st_mode != 0600) {
		error(MODPREFIX "Configuration file %s exists, but is not "
		      "usable. Please make sure that it is "
		      "owned by root, group is root, and the mode is 0600.",
		      auth_conf);
		return -1;
	}

	xmlInitParser();
	doc = xmlParseFile(auth_conf);
	if (!doc) {
		warn(MODPREFIX "xmlParseFile failed for %s.", auth_conf);
		goto out;
	}

	root = xmlDocGetRootElement(doc);
	if (!root) {
		debug(MODPREFIX "empty xml document (%s).", auth_conf);
		fallback = 1;
		goto out;
	}

	if (xmlStrcmp(root->name, (const xmlChar *)"autofs_ldap_sasl_conf")) {
		error(MODPREFIX "The root node of the XML document %s is not "
		      "autofs_ldap_sasl_conf.", auth_conf);
		goto out;
	}

	ret = get_property(root, "authtype", &authtype);
	if (ret != 0) {
		error(MODPREFIX "Failed read the authtype property from the "
		      "configuration file %s.", auth_conf);
		goto out;
	}

	if (authtype_requires_creds(authtype)) {
		ret = get_property(root, "user",  &user);
		ret |= get_property(root, "secret", &secret);
		if (ret != 0) {
			error(MODPREFIX "%s authentication type requires a "
			      "username and a secret.  Please fix your "
			      "configuration in %s.", authtype, auth_conf);
			free(authtype);
			free(user);
			free(secret);

			ret = -1;
			goto out;
		}
	}

	ctxt->auth_conf = auth_conf;
	ctxt->sasl_mech = authtype;
	ctxt->user = user;
	ctxt->secret = secret;

out:
	xmlFreeDoc(doc);
	xmlCleanupParser();

	if (fallback)
		return 0;

	return -1;
}

/*
 *  Reads in the xml configuration file and parses out the relevant
 *  information.  If there is no configuration file, then we fall back to
 *  trying all supported authentication mechanisms until one works.
 *
 *  Returns 0 on success, with authtype, user and secret filled in as
 *  appropriate.  Returns -1 on failre.
 */
int ldap_auth_init(struct lookup_context *ctxt)
{
	int ret;

	ctxt->sasl_mech = NULL;

	/*
	 *  First, check to see if a preferred authentication method was
	 *  specified by the user.  parse_ldap_config will return error
	 *  if the permissions on the file were incorrect, or if the
	 *  specified authentication type is not valid.
	 */
	ret = parse_ldap_config(ctxt);
	if (ret)
		return -1;

	/*
	 *  Initialize the sasl library.  It is okay if user and secret
	 *  are NULL, here.
	 */
	if (sasl_init(ctxt->user, ctxt->secret) != 0)
		return -1;

	/*
	 *  If sasl_mech was not filled in, it means that there was no
	 *  mechanism specified in the configuration file.  Try to auto-
	 *  select one.
	 */
	if (ctxt->sasl_mech == NULL && 
	    sasl_choose_mech(ctxt->server, ctxt->port, &ctxt->sasl_mech) != 0)
		return -1;

	return 0;
}
#endif

/*
 *  Take an input string as specified in the master map, and break it
 *  down into a basedn, servername, and port.
 */
int parse_server_string(const char *url, struct lookup_context *ctxt)
{
	char buf[MAX_ERR_BUF];
	const char *ptr;
	int l;

	ptr = url;

	debug(MODPREFIX "Attempting to parse LDAP information from string "
	      "\"%s\".", ptr);

	if (!strncmp(ptr, "//", 2)) {
		const char *s = ptr + 2;
		const char *p = NULL, *q = NULL;

		/*
		 * Isolate the server's name and possibly port.  The ':'
		 * breaks the SUN parser for submounts, so we can't actually
		 * use it.
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
		memcpy(ctxt->server, ptr, l);
		ptr += l+1;
	}

	/*
	 * For nss support we can have a map name with no
	 * type or dn info. If present a base dn must have
	 * at least one "=" to be functional.
	 */
	l = strlen(ptr);
	if (strchr(ptr, '=')) {
		char *base = malloc(l + 1);
		if (!base) {
			char *estr;
			estr = strerror_r(errno, buf, MAX_ERR_BUF);
			crit(MODPREFIX "malloc: %s", estr);
			return 0;
		}
		ctxt->base = base;
		memset(ctxt->base, 0, l + 1);
		memcpy(ctxt->base, ptr, l);
	} else {
		char *map = malloc(l + 1);
		if (!map) {
			char *estr;
			estr = strerror_r(errno, buf, MAX_ERR_BUF);
			crit(MODPREFIX "malloc: %s", estr);
			return 0;
		}
		ctxt->mapname = map;
		memset(ctxt->mapname, 0, l + 1);
		memcpy(map, ptr, l);
		debug("map %s", map);
	}

	if (ctxt->mapname)
		debug(MODPREFIX "mapname %s", ctxt->mapname);
	else
		debug(MODPREFIX "server \"%s\", port %d, base dn \"%s\"",
			ctxt->server ? ctxt->server : "(default)",
			ctxt->port, ctxt->base);

	return 1;
}

static int get_default_schema(struct lookup_context *ctxt)
{
	ctxt->map_obj_class = (char *) get_default_ldap_map_object_class();
	if (!ctxt->map_obj_class)
		return 0;

	ctxt->entry_obj_class = (char *) get_default_ldap_entry_object_class();
	if (!ctxt->entry_obj_class)
		goto free_moc;

	ctxt->map_attr = (char *) get_default_ldap_map_attribute();
	if (!ctxt->map_attr)
		goto free_eoc;

	ctxt->entry_attr = (char *) get_default_ldap_entry_attribute();
	if (!ctxt->entry_attr)
		goto free_ma;

	ctxt->value_attr = (char *) get_default_ldap_value_attribute();
	if (!ctxt->value_attr)
		goto free_ea;

	return 1;

free_ea:
	free(ctxt->entry_attr);
free_ma:
	free(ctxt->map_attr);
free_eoc:
	free(ctxt->entry_obj_class);
free_moc:
	free(ctxt->map_obj_class);

	ctxt->map_obj_class = NULL;
	ctxt->entry_obj_class = NULL;
	ctxt->map_attr = NULL;
	ctxt->entry_attr = NULL;

	return 0;
}

static void free_context(struct lookup_context *ctxt)
{
	if (ctxt->sasl_mech)
		free(ctxt->sasl_mech);
	if (ctxt->user)
		free(ctxt->user);
	if (ctxt->secret)
		free(ctxt->secret);
	if (ctxt->mapname)
		free(ctxt->mapname);
	if (ctxt->server)
		free(ctxt->server);
	if (ctxt->base)
		free(ctxt->base);
	free(ctxt);

	return;
}

/*
 * This initializes a context (persistent non-global data) for queries to
 * this module.  Return zero if we succeed.
 */
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt = NULL;
	char buf[MAX_ERR_BUF];
	int do_auth;
	LDAP *ldap = NULL;

	/* If we can't build a context, bail. */
	*context = NULL;
	ctxt = (struct lookup_context *) malloc(sizeof(struct lookup_context));
	if (ctxt == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(MODPREFIX "malloc: %s", estr);
		return 1;
	}
	memset(ctxt, 0, sizeof(struct lookup_context));

	/* If a map type isn't explicitly given, parse it like sun entries. */
	if (mapfmt == NULL)
		mapfmt = MAPFMT_DEFAULT;

	/*
	 * Parse out the server name, port, and base dn, and fill them
	 * into the proper places in the lookup context structure.
	 */
	ctxt->port = LDAP_PORT;

	if (!parse_server_string(argv[0], ctxt)) {
		error(MODPREFIX "cannot parse server string");
		free_context(ctxt);
		return 1;
	}

	/* Get default schema for queries */
	if (!get_default_schema(ctxt)) {
		error(MODPREFIX "cannot set default schema");
		free_context(ctxt);
		return 1;
	}

	do_auth = 0;
#if WITH_SASL
	/*
	 * Determine which authentication mechanism to use.  We sanity-
	 * check by binding to the server temporarily.
	 */
	do_auth = ldap_auth_init(ctxt);
#endif

	if (do_auth != 0 && (ldap = do_connect(ctxt)) == NULL) {
		free_context(ctxt);
		return 1;
	}

	/* Okay, we're done here. */
	ldap_unbind(ldap);

	/* Open the parser, if we can. */
	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parse) {
		free_context(ctxt);
		return 1;
	}

	*context = ctxt;

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int timeout = master->default_timeout;
	unsigned int logging = master->default_logging;
	int rv, l, count, blen;
	char buf[MAX_ERR_BUF];
	char *query;
	LDAPMessage *result, *e;
	char *class, *key, *info, *entry;
	char **keyValue = NULL;
	char **values = NULL;
	char *attrs[3];
	LDAP *ldap;
	char *buffer;

	class = ctxt->entry_obj_class;
	key = ctxt->map_attr;
	entry = ctxt->entry_attr;
	info = ctxt->value_attr;

	attrs[0] = entry;
	attrs[1] = info;
	attrs[2] = NULL;

	if (!ctxt->mapname && !ctxt->base) {
		error(MODPREFIX "no master map to lookup");
		return NSS_STATUS_UNAVAIL;
	}

	/* Build a query string. */
	l = strlen("(objectclass=)") + strlen(class) + 1;
	if (ctxt->mapname)
		l += strlen(key) + strlen(ctxt->mapname) + strlen("(&(=))");

	query = alloca(l);
	if (query == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(MODPREFIX "malloc: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	/*
	 * If we have a master mapname construct a query using it
	 * otherwise assume the base dn will catch it.
	 */
	memset(query, '\0', l);
	if (ctxt->mapname) {
		if (sprintf(query, "(&(objectclass=%s)(%s=%.*s))", class,
			    key, strlen(ctxt->mapname), ctxt->mapname) >= l) {
			debug(MODPREFIX "error forming query string");
		}
	} else {
		if (sprintf(query, "(objectclass=%s)", class) >= l) {
			debug(MODPREFIX "error forming query string");
		}
	}
	query[l] = '\0';

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt);
	if (!ldap)
		return NSS_STATUS_UNAVAIL;

	/* Look around. */
	debug(MODPREFIX "searching for \"%s\" under \"%s\"",
			query, ctxt->base ? ctxt->base : "(default)");

	rv = ldap_search_s(ldap, ctxt->base, LDAP_SCOPE_SUBTREE,
			   query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		debug(MODPREFIX "query failed for %s: %s", query, ldap_err2string(rv));
		ldap_unbind(ldap);
		return NSS_STATUS_NOTFOUND;
	}

	e = ldap_first_entry(ldap, result);
	if (!e) {
		debug(MODPREFIX "query succeeded, no matches for %s", query);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return NSS_STATUS_NOTFOUND;
	} else
		debug(MODPREFIX "examining entries");

	while (e) {
		keyValue = ldap_get_values(ldap, e, entry);

		if (!keyValue || !*keyValue) {
			e = ldap_next_entry(ldap, e);
			continue;
		}

		/*
		 * By definition keys must be unique within
		 * each map entry
		 */
		if (ldap_count_values(keyValue) > 1) {
			error("key %s has duplicate entries - ignoring",
				*keyValue);
			goto next;
		}

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (**keyValue == '+') {
			debug("ignoreing '+' map entry - not in file map");
			goto next;
		}

		values = ldap_get_values(ldap, e, info);
		if (!values || !*values) {
			debug(MODPREFIX "no %s defined for %s", info, query);
			goto next;
		}

		/*
		 * We require that there be only one value per key.
		 */
		count = ldap_count_values(values);
		if (count > 1) {
			error(MODPREFIX "one value per key allowed in master map");
			ldap_value_free(values);
			goto next;
		}

		blen = strlen(*keyValue) + 1 + strlen(*values) + 1;
		buffer = malloc(blen);
		if (!buffer) {
			error(MODPREFIX "could not malloc parse buffer");
			ldap_value_free(keyValue);
			ldap_value_free(values);
			return NSS_STATUS_UNAVAIL;
		}
		memset(buffer, 0, blen);

		strcpy(buffer, *keyValue);
		strcat(buffer, " ");
		strcat(buffer, *values);

		master_parse_entry(buffer, timeout, logging, age);

		free(buffer);
next:
		ldap_value_free(keyValue);
		e = ldap_next_entry(ldap, e);
	}

	/* Clean up. */
	ldap_msgfree(result);
	ldap_unbind(ldap);

	return NSS_STATUS_SUCCESS;
}

static int read_one_map(struct autofs_point *ap,
			const char *keyval, int keyvallen,
			struct lookup_context *ctxt,
			time_t age, int *result_ldap)
{
	struct mapent_cache *mc = ap->mc;
	int rv, i, l, count;
	char buf[MAX_ERR_BUF];
	char *query;
	LDAPMessage *result, *e;
	char *class, *key, *info, *entry;
	char **keyValue = NULL;
	char **values = NULL;
	char *attrs[3];
	LDAP *ldap;

	if (ctxt == NULL) {
		crit(MODPREFIX "context was NULL");
		return NSS_STATUS_UNAVAIL;
	}

	class = ctxt->entry_obj_class;
	key = ctxt->map_attr;
	entry = ctxt->entry_attr;
	info = ctxt->value_attr;

	attrs[0] = entry;
	attrs[1] = info;
	attrs[2] = NULL;

	/* Build a query string. */
	l = strlen("(objectclass=)") + strlen(class) + 1;
	if (keyvallen > 0) {
		l += strlen(key) + keyvallen + strlen("(&(=))");
	}

	query = alloca(l);
	if (query == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(MODPREFIX "malloc: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	/*
	 * If we have a mapname (keyval) construct a query using it
	 * otherwise assume the base dn will catch it.
	 */
	memset(query, 0, l);
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
	query[l] = '\0';

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt);
	if (!ldap)
		return NSS_STATUS_UNAVAIL;

	/* Look around. */
	debug(MODPREFIX "searching for \"%s\" under \"%s\"",
			query, ctxt->base ? ctxt->base : "(default)");

	rv = ldap_search_s(ldap, ctxt->base, LDAP_SCOPE_SUBTREE,
			   query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		debug(MODPREFIX "query failed for %s: %s", query, ldap_err2string(rv));
		ldap_unbind(ldap);
		*result_ldap = rv;
		return NSS_STATUS_NOTFOUND;
	}

	e = ldap_first_entry(ldap, result);
	if (!e) {
		debug(MODPREFIX "query succeeded, no matches for %s", query);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return NSS_STATUS_NOTFOUND;
	} else
		debug(MODPREFIX "examining entries");

	while (e) {
		char *mapent = NULL;

		keyValue = ldap_get_values(ldap, e, entry);

		if (!keyValue || !*keyValue) {
			e = ldap_next_entry(ldap, e);
			continue;
		}

		/*
		 * By definition keys must be unique within
		 * each map entry
		 */
		if (ldap_count_values(keyValue) > 1) {
			error("key %s has duplicate entries - ignoring",
				*keyValue);
			goto next;
		}

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (**keyValue == '+') {
			debug("ignoreing '+' map entry - not in file map");
			goto next;
		}

		values = ldap_get_values(ldap, e, info);
		if (!values || !*values) {
			debug(MODPREFIX "no %s defined for %s", info, query);
			goto next;
		}

		/*
		 * We expect that there will be only one value because
		 * questions of order of returned value entries but we
		 * accumulate values to support simple multi-mounts.
		 *
		 * If the ordering of a mount spec with another containing
		 * options or the actual order of entries causes problems
		 * it won't be supported. Perhaps someone can instruct us
		 * how to force an ordering.
		 * 
		 */
		count = ldap_count_values(values);
		for (i = 0; i < count; i++) {
			int v_len = strlen(values[i]);

			if (!mapent) {
				mapent = malloc(v_len + 1);
				if (!mapent) {
					char *estr;
					estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error("malloc: %s", estr);
					goto next;
				}
				strcpy(mapent, values[i]);
			} else {
				int new_size = strlen(mapent) + v_len + 2;
				char *new_me;
				new_me = realloc(mapent, new_size);
				if (new_me) {
					mapent = new_me;
					strcat(mapent, " ");
					strcat(mapent, values[i]);
				} else {
					char *estr;
					estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error("realloc: %s", estr);
				}
			}
		}
		ldap_value_free(values);

		debug("key %s mapent %s", *keyValue, mapent);

		if (**keyValue == '/' && strlen(*keyValue) == 1)
			**keyValue = '*';

		if (ap->type == LKP_INDIRECT && **keyValue == '/')
			goto next;

		if (ap->type == LKP_DIRECT && **keyValue != '/')
			goto next;

		debug("update key %s mapent %s", *keyValue, mapent);

		cache_writelock(mc);
		cache_update(mc, *keyValue, mapent, age);
		cache_unlock(mc);
next:
		if (mapent) {
			free(mapent);
			mapent = NULL;
		}

		ldap_value_free(keyValue);
		e = ldap_next_entry(ldap, e);
	}

	debug(MODPREFIX "done updating map");

	/* Clean up. */
	ldap_msgfree(result);
	ldap_unbind(ldap);

	return NSS_STATUS_SUCCESS;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = LDAP_SUCCESS;
	char *key;
	int keylen;
	int ret;

	key = ctxt->mapname;
	keylen = strlen(ctxt->mapname);

	if (key)
		ret = read_one_map(ap, key, keylen, ctxt, age, &rv);
	else
		ret = read_one_map(ap, NULL, 0, ctxt, age, &rv);

	if (ret != NSS_STATUS_SUCCESS) {
		switch (rv) {
		case LDAP_SIZELIMIT_EXCEEDED:
		case LDAP_UNWILLING_TO_PERFORM:
			return NSS_STATUS_UNAVAIL;
		}
	}

	return ret;
}

static int lookup_one(struct autofs_point *ap,
		char *qKey, int qKey_len, struct lookup_context *ctxt)
{
	struct mapent_cache *mc = ap->mc;
	int rv, i, l, ql, count;
	char buf[MAX_ERR_BUF];
	time_t age = time(NULL);
	char *query;
	LDAPMessage *result, *e;
	char *class, *info, *map, *entry;
	char **keyValue;
	char **values = NULL;
	char *attrs[3];
	LDAP *ldap;
	char *mapent = NULL;
	int ret = CHE_OK;

	if (ctxt == NULL) {
		crit(MODPREFIX "context was NULL");
		return CHE_FAIL;
	}

	class = ctxt->entry_obj_class;
	map = ctxt->map_attr;
	entry = ctxt->entry_attr;
	info = ctxt->value_attr;

	attrs[0] = entry;
	attrs[1] = info;
	attrs[2] = NULL;

	if (*qKey == '*' && qKey_len == 1)
		*qKey = '/';

	/* Build a query string. */
	if (ctxt->mapname) {
		l = strlen(class) 
			+ strlen(map) + strlen(ctxt->mapname)
			+ strlen(entry) + strlen(qKey) + 28;
	} else {
		l = strlen(class) + strlen(entry) + strlen(qKey) + 21;
	}

	query = alloca(l);
	if (query == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(MODPREFIX "malloc: %s", estr);
		return CHE_FAIL;
	}

	/* Look around. */
	memset(query, 0, l);
	if (ctxt->mapname) {
		/*
		 * Look for an entry in class containing map
		 * ctxt->mapname whose entry is equal to qKey.
		 */
		ql = sprintf(query,
			 "(&(&(objectclass=%s)(%s=%s)(%s=%s)))",
			 class, map, ctxt->mapname, entry, qKey);
	} else {
		/*
		 * Look for an entry in class under ctxt-base
		 * whose entry is equal to qKey.
		 */
		ql = sprintf(query,
			 "(&(objectclass=%s)(%s=%s))", class, entry, qKey);
	}
	if (ql >= l) {
		debug(MODPREFIX "error forming query string");
		return CHE_FAIL;
	}
	query[ql] = '\0';

	debug(MODPREFIX "searching for \"%s\" under \"%s\"",
			query, ctxt->base ? ctxt->base : "(default)");

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt);
	if (!ldap)
		return CHE_FAIL;

	rv = ldap_search_s(ldap, ctxt->base, LDAP_SCOPE_SUBTREE,
			   query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		crit(MODPREFIX "query failed for %s", query);
		ldap_unbind(ldap);
		return CHE_FAIL;
	}

	debug(MODPREFIX "getting first entry for %s=\"%s\"", entry, qKey);

	e = ldap_first_entry(ldap, result);
	if (!e) {
		crit(MODPREFIX "got answer, but no entry for %s", query);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return CHE_MISSING;
	}

	keyValue = ldap_get_values(ldap, e, entry);

	/* By definition keys must be unique within each map entry */
	if (ldap_count_values(keyValue) > 1) {
		error("key %s has duplicate entries", *keyValue);
		ldap_value_free(keyValue);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return CHE_FAIL;
	}

	debug(MODPREFIX "examining first entry");

	values = ldap_get_values(ldap, e, info);
	if (!values || !*values) {
		debug(MODPREFIX "no %s defined for %s", info, query);
		ldap_value_free(keyValue);
		ldap_msgfree(result);
		ldap_unbind(ldap);
		return CHE_MISSING;
	}

	count = ldap_count_values(values);
	for (i = 0; i < count; i++) {
		int v_len = strlen(values[i]);

		if (!mapent) {
			mapent = malloc(v_len + 1);
			if (!mapent) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error("malloc: %s", estr);
				continue;
			}
			strcpy(mapent, values[i]);
		} else {
			int new_size = strlen(mapent) + v_len + 2;
			char *new_me;
			new_me = realloc(mapent, new_size);
			if (new_me) {
				mapent = new_me;
				strcat(mapent, " ");
				strcat(mapent, values[i]);
			} else {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error("realloc: %s", estr);
			}
		}
	}
	ldap_value_free(values);

	if (**keyValue == '/' && strlen(*keyValue) == 1)
		**keyValue = '*';

	if (ap->type == LKP_INDIRECT && **keyValue == '/') {
		ret = CHE_MISSING;
		goto done;
	}

	if (ap->type == LKP_DIRECT && **keyValue != '/') {
		ret = CHE_MISSING;
		goto done;
	}

	cache_writelock(mc);
	ret = cache_update(mc, *keyValue, mapent, age);
	cache_unlock(mc);
done:
	if (mapent) {
		free(mapent);
		mapent = NULL;
	}

	/* Clean up. */
	ldap_value_free(keyValue);
	ldap_msgfree(result);
	ldap_unbind(ldap);

	return ret;
}

static int check_map_indirect(struct autofs_point *ap,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct mapent_cache *mc = ap->mc;
	struct mapent *me, *exists;
	time_t now = time(NULL);
	time_t t_last_read;
	int ret, need_map = 0;

	cache_readlock(mc);
	exists = cache_lookup(mc, key);
	cache_unlock(mc);

	ret = lookup_one(ap, key, strlen(key), ctxt);
	if (ret == CHE_FAIL)
		return NSS_STATUS_NOTFOUND;

	cache_readlock(mc);
	me = cache_lookup_first(mc);
	t_last_read = me ? now - me->age : ap->exp_runfreq + 1;
	cache_unlock(mc);

	if (t_last_read > ap->exp_runfreq) {
		if ((ret & CHE_UPDATED) ||
		    (exists && (ret & CHE_MISSING)))
			need_map = 1;
	}

	if (ret == CHE_MISSING) {
		char *wkey = "/";
		int wild = CHE_MISSING;

		wild = lookup_one(ap, wkey, 1, ctxt);
		if (wild == CHE_MISSING) {
			cache_writelock(mc);
			cache_delete(mc, "*");
			cache_unlock(mc);
		}

		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_writelock(mc);
		if (cache_delete(mc, key) &&
			 	wild & (CHE_MISSING | CHE_FAIL))
			rmdir_path(key);
		cache_unlock(mc);
		pthread_cleanup_pop(0);
	}

	/* Have parent update its map */
	if (need_map) {
		int status;

		status = pthread_mutex_lock(&ap->state_mutex);
		if (status)
			fatal(status);

		nextstate(ap->state_pipe[1], ST_READMAP);

		status = pthread_mutex_unlock(&ap->state_mutex);
		if (status)
			fatal(status);
	}

	if (ret == CHE_MISSING)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *mc = ap->mc;
	struct mapent *me;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	int mapent_len;
	int status = 0;
	int ret = 1;

	debug(MODPREFIX "looking up %s", name);

	key_len = snprintf(key, KEY_MAX_LEN, "%s", name);
	if (key_len > KEY_MAX_LEN)
		return NSS_STATUS_NOTFOUND;

        /*
	 * We can't check the direct mount map as if it's not in
	 * the map cache already we never get a mount lookup, so
	 * we never know about it.
	 */
	if (ap->type == LKP_INDIRECT) {
		char *lkp_key;

		cache_readlock(mc);
		me = cache_lookup(mc, key);
		if (me && me->multi)
			lkp_key = strdup(me->multi->key);
		else
			lkp_key = strdup(key);
		cache_unlock(mc);

		if (!lkp_key)
			return NSS_STATUS_UNKNOWN;

		status = check_map_indirect(ap, lkp_key, strlen(lkp_key), ctxt);
		free(lkp_key);
		if (status) {
			debug(MODPREFIX "check indirect map failure");
			return status;
		}
	}

	cache_readlock(mc);
	me = cache_lookup(mc, key);
	if (me) {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		mapent = alloca(strlen(me->mapent) + 1);
		mapent_len = sprintf(mapent, me->mapent);
		mapent[mapent_len] = '\0';
		pthread_cleanup_pop(0);
	}
	cache_unlock(mc);

	if (mapent) {
		debug(MODPREFIX "%s -> %s", key, mapent);
		ret = ctxt->parse->parse_mount(ap, key, key_len,
					 mapent, ctxt->parse->context);
	}

	if (ret)
		return NSS_STATUS_TRYAGAIN;

	return NSS_STATUS_SUCCESS;;
}

/*
 * This destroys a context for queries to this module.  It releases the parser
 * structure (unloading the module) and frees the memory used by the context.
 */
int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free_context(ctxt);
	return rv;
}
