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
#include "lookup_ldap.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(ldap): "

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int bind_ldap_anonymous(LDAP *ldap, struct lookup_context *ctxt)
{
	int rv;

	if (ctxt->version == 2)
		rv = ldap_simple_bind_s(ldap, ctxt->base, NULL);
	else
		rv = ldap_simple_bind_s(ldap, NULL, NULL);

	if (rv != LDAP_SUCCESS) {
		crit(LOGOPT_ANY,
		     MODPREFIX "Unable to bind to the LDAP server: "
		     "%s, error %s", ctxt->server ? "" : "(default)",
		     ldap_err2string(rv));
		return -1;
	}

	return 0;
}

int unbind_ldap_connection(LDAP *ldap, struct lookup_context *ctxt)
{
	int rv;

#ifdef WITH_SASL
	debug(LOGOPT_NONE, "use_tls: %d", ctxt->use_tls);
	/*
	 * The OpenSSL library can't handle having its message and error
	 * string database loaded multiple times and segfaults if the
	 * TLS environment is not reset at the right times. As there
	 * is no ldap_stop_tls call in the openldap library we have
	 * to do the job ourselves, here and in lookup_done when the
	 * module is closed.
	 */
	if (ctxt->use_tls == LDAP_TLS_RELEASE) {
		ERR_remove_state(0);
		ctxt->use_tls = LDAP_TLS_INIT;
	}
	autofs_sasl_unbind(ctxt);
#endif

	rv = ldap_unbind_ext(ldap, NULL, NULL);
	if (rv != LDAP_SUCCESS)
		error(LOGOPT_ANY,
		     "unbind failed: %s", ldap_err2string(rv));

	return rv;
}

LDAP *init_ldap_connection(struct lookup_context *ctxt)
{
	LDAP *ldap = NULL;
	int timeout = 8;
	int rv;

	ctxt->version = 3;

	/* Initialize the LDAP context. */
	/* LDAP_PORT should not be hard-coded, here.  If we are going to
	 * parse ldap strings ourselves, then we can put the port specified
	 * in the host:port format here.  Otherwise, we can just pass the
	 * host:port string to the ldap_init call and let the library handle
	 * it.   -JM
	 */
	ldap = ldap_init(ctxt->server, LDAP_PORT);
	if (!ldap) {
		crit(LOGOPT_ANY,
		     MODPREFIX "couldn't initialize LDAP connection to %s",
		     ctxt->server ? ctxt->server : "default server");
		return NULL;
	}

	/* Use LDAPv3 */
	rv = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ctxt->version);
	if (rv != LDAP_OPT_SUCCESS) {
		/* fall back to LDAPv2 */
		ldap_unbind_ext(ldap, NULL, NULL);
		ldap = ldap_init(ctxt->server, LDAP_PORT);
		if (!ldap) {
			crit(LOGOPT_ANY, MODPREFIX "couldn't initialize LDAP");
			return NULL;
		}
		ctxt->version = 2;
	}

	/* Sane network connection timeout */
	rv = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
	if (rv != LDAP_OPT_SUCCESS)
		info(LOGOPT_ANY,
		     MODPREFIX "failed to set connection timeout to %d",
		     timeout);

#ifdef WITH_SASL
	if (ctxt->use_tls) {
		if (ctxt->version == 2) {
			if (ctxt->tls_required) {
				error(LOGOPT_ANY,
				    MODPREFIX
				    "TLS required but connection is version 2");
				ldap_unbind_ext(ldap, NULL, NULL);
				return NULL;
			}
			return ldap;
		}

		rv = ldap_start_tls_s(ldap, NULL, NULL);
		if (rv != LDAP_SUCCESS) {
			unbind_ldap_connection(ldap, ctxt);
			if (ctxt->tls_required) {
				error(LOGOPT_ANY,
				      MODPREFIX
				      "TLS required but START_TLS failed: %s",
				      ldap_err2string(rv));
				return NULL;
			}
			ctxt->use_tls = LDAP_TLS_DONT_USE;
			ldap = init_ldap_connection(ctxt);
			if (ldap)
				ctxt->use_tls = LDAP_TLS_INIT;
			return ldap;
		}
		ctxt->use_tls = LDAP_TLS_RELEASE;
	}
#endif

	return ldap;
}

static LDAP *do_connect(struct lookup_context *ctxt)
{
	LDAP *ldap;
	int rv;

	ldap = init_ldap_connection(ctxt);
	if (!ldap)
		return NULL;

#ifdef WITH_SASL
	debug(LOGOPT_NONE, "auth_required: %d, sasl_mech %s",
	      ctxt->auth_required, ctxt->sasl_mech);

	if (ctxt->sasl_mech ||
	   (ctxt->auth_required & (LDAP_AUTH_REQUIRED|LDAP_AUTH_AUTODETECT))) {
		rv = autofs_sasl_bind(ldap, ctxt);
		debug(LOGOPT_NONE, MODPREFIX
		      "autofs_sasl_bind returned %d", rv);
	} else {
		rv = bind_ldap_anonymous(ldap, ctxt);
		debug(LOGOPT_NONE,
		      MODPREFIX "ldap anonymous bind returned %d", rv);
	}
#else
	rv = bind_ldap_anonymous(ldap, ctxt);
	debug(LOGOPT_NONE, MODPREFIX "ldap anonymous bind returned %d", rv);
#endif

	if (rv != 0) {
		unbind_ldap_connection(ldap, ctxt);
		return NULL;
	}

	return ldap;
}

#ifdef WITH_SASL
int get_property(xmlNodePtr node, const char *prop, char **value)
{
	xmlChar *ret;
	xmlChar *property = (xmlChar *) prop;

	if (!(ret = xmlGetProp(node, property))) {
		*value = NULL;
		return 0;
	}

	if (!(*value = strdup((char *) ret))) {
		error(LOGOPT_ANY,
		      MODPREFIX "strdup failed with %d", errno);
		xmlFree(ret);
		return -1;
	}

	xmlFree(ret);
	return 0;
}

/*
 *  For plain text, login and digest-md5 authentication types, we need
 *  user and password credentials.
 */
int authtype_requires_creds(const char *authtype)
{
	if (!strncmp(authtype, "PLAIN", strlen("PLAIN")) ||
	    !strncmp(authtype, "DIGEST-MD5", strlen("DIGEST-MD5")) ||
	    !strncmp(authtype, "LOGIN", strlen("LOGIN")))
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
 *  to then use another method to determine how to connect to the server.
 */
int parse_ldap_config(struct lookup_context *ctxt)
{
	int          ret = 0, fallback = 0;
	unsigned int auth_required = LDAP_AUTH_NOTREQUIRED;
	unsigned int tls_required = 0, use_tls = 0;
	struct stat  st;
	xmlDocPtr    doc = NULL;
	xmlNodePtr   root = NULL;
	char         *authrequired, *auth_conf, *authtype;
	char         *user = NULL, *secret = NULL;
	char         *client_princ = NULL;
	char	     *usetls, *tlsrequired;

	authtype = user = secret = NULL;

	auth_conf = (char *) defaults_get_auth_conf_file();
	if (!auth_conf) {
		error(LOGOPT_ANY,
		      MODPREFIX "failed to get auth config file name.");
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
		/* Auth config doesn't exist so disable TLS and auth */
		if (errno == ENOENT) {
			ctxt->auth_conf = auth_conf;
			ctxt->use_tls = LDAP_TLS_DONT_USE;
			ctxt->tls_required = LDAP_TLS_DONT_USE;
			ctxt->auth_required = LDAP_AUTH_NOTREQUIRED;
			ctxt->sasl_mech = NULL;
			ctxt->user = NULL;
			ctxt->secret = NULL;
			ctxt->client_princ = NULL;
			return 0;
		}
		error(LOGOPT_ANY,
		      MODPREFIX "stat(2) failed with error %s.",
		      strerror(errno));
		return 0;
	}

	if (!S_ISREG(st.st_mode) ||
	    st.st_uid != 0 || st.st_gid != 0 ||
	    (st.st_mode & 0x01ff) != 0600) {
		error(LOGOPT_ANY,
		      MODPREFIX
		      "Configuration file %s exists, but is not usable. "
		      "Please make sure that it is owned by root, group "
		      "is root, and the mode is 0600.",
		      auth_conf);
		return -1;
	}

	xmlInitParser();
	doc = xmlParseFile(auth_conf);
	if (!doc) {
		warn(LOGOPT_ANY,
		     MODPREFIX "xmlParseFile failed for %s.", auth_conf);
		goto out;
	}

	root = xmlDocGetRootElement(doc);
	if (!root) {
		debug(LOGOPT_ANY,
		      MODPREFIX "empty xml document (%s).", auth_conf);
		fallback = 1;
		goto out;
	}

	if (xmlStrcmp(root->name, (const xmlChar *)"autofs_ldap_sasl_conf")) {
		error(LOGOPT_ANY,
		      MODPREFIX
		      "The root node of the XML document %s is not "
		      "autofs_ldap_sasl_conf.", auth_conf);
		goto out;
	}

	ret = get_property(root, "usetls", &usetls);
	if (ret != 0) {
		error(LOGOPT_ANY,
		      MODPREFIX
		      "Failed read the usetls property from "
		      "the configuration file %s.", auth_conf);
		goto out;
	}

	if (!usetls)
		use_tls = LDAP_TLS_DONT_USE;
	else {
		if (!strcasecmp(usetls, "yes"))
			use_tls = LDAP_TLS_INIT;
		else if (!strcasecmp(usetls, "no"))
			use_tls = LDAP_TLS_DONT_USE;
		else {
			error(LOGOPT_ANY,
			      MODPREFIX
			      "The usetls property must have value "
			      "\"yes\" or \"no\".");
			ret = -1;
			goto out;
		}
		free(usetls);
	}

	ret = get_property(root, "tlsrequired", &tlsrequired);
	if (ret != 0) {
		error(LOGOPT_ANY,
		      MODPREFIX
		      "Failed read the tlsrequired property from "
		      "the configuration file %s.", auth_conf);
		goto out;
	}

	if (!tlsrequired)
		tls_required = LDAP_TLS_DONT_USE;
	else {
		if (!strcasecmp(tlsrequired, "yes"))
			tls_required = LDAP_TLS_REQUIRED;
		else if (!strcasecmp(tlsrequired, "no"))
			tls_required = LDAP_TLS_DONT_USE;
		else {
			error(LOGOPT_ANY,
			      MODPREFIX
			      "The tlsrequired property must have value "
			      "\"yes\" or \"no\".");
			ret = -1;
			goto out;
		}
		free(tlsrequired);
	}

	ret = get_property(root, "authrequired", &authrequired);
	if (ret != 0) {
		error(LOGOPT_ANY,
		      MODPREFIX
		      "Failed read the authrequired property from "
		      "the configuration file %s.", auth_conf);
		goto out;
	}

	if (!authrequired)
		auth_required = LDAP_AUTH_NOTREQUIRED;
	else {
		if (!strcasecmp(authrequired, "yes"))
			auth_required = LDAP_AUTH_REQUIRED;
		else if (!strcasecmp(authrequired, "no"))
			auth_required = LDAP_AUTH_NOTREQUIRED;
		else if (!strcasecmp(authrequired, "autodetect"))
			auth_required = LDAP_AUTH_AUTODETECT;
		else {
			error(LOGOPT_ANY,
			      MODPREFIX
			      "The authrequired property must have value "
			      "\"yes\", \"no\" or \"autodetect\".");
			ret = -1;
			goto out;
		}
		free(authrequired);
	}

	ret = get_property(root, "authtype", &authtype);
	if (ret != 0) {
		error(LOGOPT_ANY,
		      MODPREFIX
		      "Failed read the authtype property from the "
		      "configuration file %s.", auth_conf);
		goto out;
	}

	if (authtype && authtype_requires_creds(authtype)) {
		ret = get_property(root, "user",  &user);
		ret |= get_property(root, "secret", &secret);
		if (ret != 0 || (!user || !secret)) {
			error(LOGOPT_ANY,
			      MODPREFIX
			      "%s authentication type requires a username "
			      "and a secret.  Please fix your configuration "
			      "in %s.", authtype, auth_conf);
			free(authtype);
			if (user)
				free(user);
			if (secret)
				free(secret);

			ret = -1;
			goto out;
		}
	}

	/*
	 * We allow the admin to specify the principal to use for the
	 * client.  The default is "autofsclient/hostname@REALM".
	 */
	(void)get_property(root, "clientprinc", &client_princ);

	ctxt->auth_conf = auth_conf;
	ctxt->use_tls = use_tls;
	ctxt->tls_required = tls_required;
	ctxt->auth_required = auth_required;
	ctxt->sasl_mech = authtype;
	ctxt->user = user;
	ctxt->secret = secret;
	ctxt->client_princ = client_princ;

	debug(LOGOPT_NONE,
	      "ldap authentication configured with the following options:\n");
	debug(LOGOPT_NONE,
	      "use_tls: %u, "
	      "tls_required: %u, "
	      "auth_required: %u, "
	      "sasl_mech: %s\n",
	      use_tls, tls_required, auth_required, authtype);
	debug(LOGOPT_NONE,
	      "user: %s, "
	      "secret: %s, "
	      "client principal: %s\n",
	      user, secret ? "specified" : "unspecified",
	      client_princ);

out:
	xmlFreeDoc(doc);
	xmlCleanupParser();

	if (fallback)
		return 0;

	return ret;
}

/*
 *  Reads in the xml configuration file and parses out the relevant
 *  information.  If there is no configuration file, then we fall back to
 *  trying all supported authentication mechanisms until one works.
 *
 *  Returns 0 on success, with authtype, user and secret filled in as
 *  appropriate.  Returns -1 on failre.
 */
int auth_init(struct lookup_context *ctxt)
{
	int ret;
	LDAP *ldap;

	/*
	 *  First, check to see if a preferred authentication method was
	 *  specified by the user.  parse_ldap_config will return error
	 *  if the permissions on the file were incorrect, or if the
	 *  specified authentication type is not valid.
	 */
	ret = parse_ldap_config(ctxt);
	if (ret)
		return -1;

	if (ctxt->auth_required & LDAP_AUTH_NOTREQUIRED)
		return 0;

	ldap = init_ldap_connection(ctxt);
	if (!ldap)
		return -1;

	/*
	 *  Initialize the sasl library.  It is okay if user and secret
	 *  are NULL, here.
	 *
	 *  The autofs_sasl_init routine will figure out which mechamism
	 *  to use. If kerberos is used, it will also take care to initialize
	 *  the credential cache and the client and service principals.
	 */
	ret = autofs_sasl_init(ldap, ctxt);
	unbind_ldap_connection(ldap, ctxt);
	if (ret) {
		ctxt->sasl_mech = NULL;
		if (ctxt->auth_required & LDAP_AUTH_AUTODETECT) {
			warn(LOGOPT_NONE,
			     "no authentication mechanisms auto detected.");
			return 0;
		}
		return -1;
	}

	return 0;
}
#endif

/*
 *  Take an input string as specified in the master map, and break it
 *  down into a server name and basedn.
 */
static int parse_server_string(const char *url, struct lookup_context *ctxt)
{
	char buf[MAX_ERR_BUF], *tmp = NULL;
	const char *ptr;
	int l;

	ptr = url;

	debug(LOGOPT_NONE,
	      MODPREFIX
	      "Attempting to parse LDAP information from string \"%s\".", ptr);

	if (!strncmp(ptr, "//", 2)) {
		const char *s = ptr + 2;
		const char *q = NULL;

		/* Isolate the server(s). */
		if ((q = strchr(s, '/'))) {
			l = q - s;
			tmp = malloc(l + 1);
			if (!tmp) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
				return 0;
			}
			ctxt->server = tmp;
			memset(ctxt->server, 0, l + 1);
			memcpy(ctxt->server, s, l);
			ptr = q + 1;
		} else {
			crit(LOGOPT_ANY,
			     MODPREFIX "invalid LDAP map syntax %s", ptr);
			return 0;
/* TODO: why did I put this here, the parser shouldn't let this by
			l = strlen(ptr);
			tmp = malloc(l + 1);
			if (!tmp) {
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
				return 0;
			}
			ctxt->server = tmp;
			memset(ctxt->server, 0, l + 1);
			memcpy(ctxt->server, s, l);
*/
		}
	} else if (strchr(ptr, ':') != NULL) {
		char *q = NULL;

		/* Isolate the server(s). Include the port spec */
		q = strchr(ptr, ':');
		if (isdigit(*q))
			while (isdigit(*q))
				q++;

		if (*q != ':') {
			crit(LOGOPT_ANY,
			     MODPREFIX "invalid LDAP map syntax %s", ptr);
			return 0;
		}

		l = q - ptr;
		/* Isolate the server's name. */
		tmp = malloc(l + 1);
		if (!tmp) {
			char *estr;
			estr = strerror_r(errno, buf, MAX_ERR_BUF);
			crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
			return 0;
		}
		ctxt->server = tmp;
		memset(ctxt->server, 0, l + 1);
		memcpy(ctxt->server, ptr, l);
		ptr += l + 1;
	}

	/* TODO: why did I do this - how can the map name "and" base dn be missing? */
	if (!ptr)
		goto done;

	/*
	 * For nss support we can have a map name with no
	 * type or dn info. If present a base dn must have
	 * at least an "=" and a "," to be at all functional.
	 * If a dn is given it must be fully specified or
	 * the later LDAP calls will fail.
	 */
	l = strlen(ptr);
	if (strchr(ptr, '=')) {
		char *base;

		if (!strchr(ptr, ',')) {
			debug(LOGOPT_NONE,
			      MODPREFIX "LDAP dn not fuly specified");
			if (ctxt->server)
				free(ctxt->server);
			return 0;
		}

		base = malloc(l + 1);
		if (!base) {
			char *estr;
			estr = strerror_r(errno, buf, MAX_ERR_BUF);
			crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
			if (ctxt->server)
				free(ctxt->server);
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
			crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
			if (ctxt->server)
				free(ctxt->server);
			return 0;
		}
		ctxt->mapname = map;
		memset(ctxt->mapname, 0, l + 1);
		memcpy(map, ptr, l);
	}
done:
	if (ctxt->mapname)
		debug(LOGOPT_NONE, MODPREFIX "mapname %s", ctxt->mapname);
	else
		debug(LOGOPT_NONE, MODPREFIX "server \"%s\", base dn \"%s\"",
			ctxt->server ? ctxt->server : "(default)",
			ctxt->base);

	return 1;
}

static int get_default_schema(struct lookup_context *ctxt)
{
	ctxt->map_obj_class = (char *) defaults_get_map_obj_class();
	if (!ctxt->map_obj_class)
		return 0;

	ctxt->entry_obj_class = (char *) defaults_get_entry_obj_class();
	if (!ctxt->entry_obj_class)
		goto free_moc;

	ctxt->map_attr = (char *) defaults_get_map_attr();
	if (!ctxt->map_attr)
		goto free_eoc;

	ctxt->entry_attr = (char *) defaults_get_entry_attr();
	if (!ctxt->entry_attr)
		goto free_ma;

	ctxt->value_attr = (char *) defaults_get_value_attr();
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
	if (ctxt->map_obj_class) {
		free(ctxt->map_obj_class);
		free(ctxt->entry_obj_class);
		free(ctxt->map_attr);
		free(ctxt->entry_attr);
	}
	if (ctxt->auth_conf)
		free(ctxt->auth_conf);
	if (ctxt->sasl_mech)
		free(ctxt->sasl_mech);
	if (ctxt->user)
		free(ctxt->user);
	if (ctxt->secret)
		free(ctxt->secret);
	if (ctxt->mapname)
		free(ctxt->mapname);
	if (ctxt->qdn)
		ldap_memfree(ctxt->qdn);
	if (ctxt->server)
		free(ctxt->server);
	if (ctxt->base)
		free(ctxt->base);
	free(ctxt);

	return;
}

static int get_query_dn(LDAP *ldap, struct lookup_context *ctxt)
{
	char buf[PARSE_MAX_BUF];
	char *query, *dn;
	LDAPMessage *result, *e;
	char *class, *key;
	char *attrs[2];
	int scope;
	int rv, l;

	class = ctxt->map_obj_class;
	key = ctxt->map_attr;

	attrs[0] = LDAP_NO_ATTRS;
	attrs[1] = NULL;

	if (!ctxt->mapname && !ctxt->base) {
		error(LOGOPT_ANY, MODPREFIX "no master map to lookup");
		return 0;
	}

	/* Build a query string. */
	l = strlen("(objectclass=)") + strlen(class) + 1;
	if (ctxt->mapname)
		l += strlen(key) + strlen(ctxt->mapname) + strlen("(&(=))");

	query = alloca(l);
	if (query == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "alloca: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	/*
	 * If we have a master mapname construct a query using it
	 * otherwise assume the base dn will catch it.
	 */
	if (ctxt->mapname) {
		if (sprintf(query, "(&(objectclass=%s)(%s=%.*s))", class,
		     key, (int) strlen(ctxt->mapname), ctxt->mapname) >= l) {
			debug(LOGOPT_NONE,
			      MODPREFIX "error forming query string");
			return 0;
		}
		scope = LDAP_SCOPE_ONELEVEL;
	} else {
		if (sprintf(query, "(objectclass=%s)", class) >= l) {
			debug(LOGOPT_NONE,
			      MODPREFIX "error forming query string");
			return 0;
		}
		scope = LDAP_SCOPE_BASE;
	}
	query[l] = '\0';

	rv = ldap_search_s(ldap, ctxt->base, scope, query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		error(LOGOPT_NONE,
		      MODPREFIX "query failed for %s: %s",
		      query, ldap_err2string(rv));
		return 0;
	}

	e = ldap_first_entry(ldap, result);
	if (e) {
		dn = ldap_get_dn(ldap, e);
		debug(LOGOPT_NONE, MODPREFIX "query dn %s", dn);
		ldap_msgfree(result);
	} else {
		debug(LOGOPT_NONE,
		      MODPREFIX "query succeeded, no matches for %s",
		      query);
		ldap_msgfree(result);
		return 0;
	}

	ctxt->qdn = dn;

	return 1;
}

/*
 * This initializes a context (persistent non-global data) for queries to
 * this module.  Return zero if we succeed.
 */
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	int ret;
	LDAP *ldap = NULL;

	*context = NULL;

	/* If we can't build a context, bail. */
	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
		return 1;
	}
	memset(ctxt, 0, sizeof(struct lookup_context));

	/* If a map type isn't explicitly given, parse it like sun entries. */
	if (mapfmt == NULL)
		mapfmt = MAPFMT_DEFAULT;

	/*
	 * Parse out the server name and base dn, and fill them
	 * into the proper places in the lookup context structure.
	 */
	if (!parse_server_string(argv[0], ctxt)) {
		error(LOGOPT_ANY, MODPREFIX "cannot parse server string");
		free_context(ctxt);
		return 1;
	}

	/* Get default schema for queries */
	if (!get_default_schema(ctxt)) {
		error(LOGOPT_ANY, MODPREFIX "cannot set default schema");
		free_context(ctxt);
		return 1;
	}

#ifdef WITH_SASL
	/*
	 * Determine which authentication mechanism to use.  We sanity-
	 * check by binding to the server temporarily.
	 */
	ret = auth_init(ctxt);
	if (ret && (ctxt->auth_required & LDAP_AUTH_REQUIRED)) {
		error(LOGOPT_ANY, MODPREFIX
		      "cannot initialize authentication setup");
		free_context(ctxt);
		return 1;
	}
#endif

	ldap = do_connect(ctxt);
	if (!ldap) {
		error(LOGOPT_ANY, MODPREFIX "cannot connect to server");
		free_context(ctxt);
		return 1;
	}

	ret = get_query_dn(ldap, ctxt);
	unbind_ldap_connection(ldap, ctxt);
	if (!ret) {
		error(LOGOPT_ANY, MODPREFIX "failed to get query dn");
		free_context(ctxt);
		return 1;
	}

	/* Open the parser, if we can. */
	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parse) {
		crit(LOGOPT_ANY, MODPREFIX "failed to open parse context");
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
	char buf[PARSE_MAX_BUF];
	char *query;
	LDAPMessage *result, *e;
	char *class, *info, *entry;
	char **keyValue = NULL;
	char **values = NULL;
	char *attrs[3];
	int scope = LDAP_SCOPE_SUBTREE;
	LDAP *ldap;

	class = ctxt->entry_obj_class;
	entry = ctxt->entry_attr;
	info = ctxt->value_attr;

	attrs[0] = entry;
	attrs[1] = info;
	attrs[2] = NULL;

	l = strlen("(objectclass=)") + strlen(class) + 1;

	query = alloca(l);
	if (query == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "alloca: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	if (sprintf(query, "(objectclass=%s)", class) >= l) {
		debug(LOGOPT_NONE, MODPREFIX "error forming query string");
		return NSS_STATUS_UNAVAIL;
	}
	query[l] = '\0';

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt);
	if (!ldap)
		return NSS_STATUS_UNAVAIL;

	/* Look around. */
	debug(LOGOPT_NONE,
	      MODPREFIX "searching for \"%s\" under \"%s\"", query, ctxt->qdn);

	rv = ldap_search_s(ldap, ctxt->qdn, scope, query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		error(LOGOPT_NONE,
		      MODPREFIX "query failed for %s: %s",
		      query, ldap_err2string(rv));
		unbind_ldap_connection(ldap, ctxt);
		return NSS_STATUS_NOTFOUND;
	}

	e = ldap_first_entry(ldap, result);
	if (!e) {
		debug(LOGOPT_NONE,
		      MODPREFIX "query succeeded, no matches for %s",
		      query);
		ldap_msgfree(result);
		unbind_ldap_connection(ldap, ctxt);
		return NSS_STATUS_NOTFOUND;
	} else
		debug(LOGOPT_NONE, MODPREFIX "examining entries");

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
			error(LOGOPT_ANY,
			      MODPREFIX
			      "key %s has duplicate entries - ignoring",
			      *keyValue);
			goto next;
		}

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (**keyValue == '+') {
			warn(LOGOPT_ANY,
			     MODPREFIX
			     "ignoreing '+' map entry - not in file map");
			goto next;
		}

		values = ldap_get_values(ldap, e, info);
		if (!values || !*values) {
			debug(LOGOPT_NONE,
			      MODPREFIX "no %s defined for %s", info, query);
			goto next;
		}

		/*
		 * We require that there be only one value per key.
		 */
		count = ldap_count_values(values);
		if (count > 1) {
			error(LOGOPT_ANY,
			      MODPREFIX
			      "one value per key allowed in master map");
			ldap_value_free(values);
			goto next;
		}

		blen = strlen(*keyValue) + 1 + strlen(*values) + 1;
		if (blen > PARSE_MAX_BUF) {
			error(LOGOPT_ANY, MODPREFIX "map entry too long");
			ldap_value_free(values);
			goto next;
		}
		memset(buf, 0, PARSE_MAX_BUF);

		strcpy(buf, *keyValue);
		strcat(buf, " ");
		strcat(buf, *values);

		master_parse_entry(buf, timeout, logging, age);
next:
		ldap_value_free(keyValue);
		e = ldap_next_entry(ldap, e);
	}

	/* Clean up. */
	ldap_msgfree(result);
	unbind_ldap_connection(ldap, ctxt);

	return NSS_STATUS_SUCCESS;
}

static int read_one_map(struct autofs_point *ap,
			struct lookup_context *ctxt,
			time_t age, int *result_ldap)
{
	struct map_source *source;
	struct mapent_cache *mc;
	int rv, i, l, count;
	char buf[MAX_ERR_BUF];
	char *query;
	LDAPMessage *result, *e;
	char *class, *info, *entry;
	char **keyValue = NULL;
	char **values = NULL;
	char *attrs[3];
	int scope = LDAP_SCOPE_SUBTREE;
	LDAP *ldap;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	class = ctxt->entry_obj_class;
	entry = ctxt->entry_attr;
	info = ctxt->value_attr;

	attrs[0] = entry;
	attrs[1] = info;
	attrs[2] = NULL;

	/* Build a query string. */
	l = strlen("(objectclass=)") + strlen(class) + 1;

	query = alloca(l);
	if (query == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "malloc: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	if (sprintf(query, "(objectclass=%s)", class) >= l) {
		error(ap->logopt, MODPREFIX "error forming query string");
		return NSS_STATUS_UNAVAIL;
	}
	query[l] = '\0';

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt);
	if (!ldap)
		return NSS_STATUS_UNAVAIL;

	/* Look around. */
	debug(ap->logopt,
	      MODPREFIX "searching for \"%s\" under \"%s\"", query, ctxt->qdn);

	rv = ldap_search_s(ldap, ctxt->qdn, scope, query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		debug(ap->logopt,
		      MODPREFIX "query failed for %s: %s",
		      query, ldap_err2string(rv));
		unbind_ldap_connection(ldap, ctxt);
		*result_ldap = rv;
		return NSS_STATUS_NOTFOUND;
	}

	e = ldap_first_entry(ldap, result);
	if (!e) {
		debug(ap->logopt,
		      MODPREFIX "query succeeded, no matches for %s", query);
		ldap_msgfree(result);
		unbind_ldap_connection(ldap, ctxt);
		return NSS_STATUS_NOTFOUND;
	} else
		debug(ap->logopt, MODPREFIX "examining entries");

	while (e) {
		char *mapent = NULL;
		char *dq_key, *dq_mapent;

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
			error(ap->logopt,
			      MODPREFIX
			      "key %s has duplicate entries - ignoring",
			      *keyValue);
			goto next;
		}

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (**keyValue == '+') {
			warn(ap->logopt,
			     MODPREFIX
			     "ignoreing '+' map entry - not in file map");
			goto next;
		}

		values = ldap_get_values(ldap, e, info);
		if (!values || !*values) {
			debug(ap->logopt,
			      MODPREFIX "no %s defined for %s", info, query);
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
					error(ap->logopt,
					      MODPREFIX "malloc: %s", estr);
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
					error(ap->logopt,
					      MODPREFIX "realloc: %s", estr);
				}
			}
		}
		ldap_value_free(values);

		dq_key = dequote(*keyValue, strlen(*keyValue), ap->logopt);
		if (!dq_key)
			goto next;

		if (*dq_key == '/' && strlen(dq_key) == 1)
			*dq_key = '*';

		if (*dq_key == '/') {
			if (ap->type == LKP_INDIRECT) {
				free(dq_key);
				goto next;
			}
		} else {
			if (ap->type == LKP_DIRECT) {
				free(dq_key);
				goto next;
			}
		}

		dq_mapent = dequote(mapent, strlen(mapent), ap->logopt);
		if (!mapent) {
			free(dq_key);
			goto next;
		}

		cache_writelock(mc);
		cache_update(mc, source, dq_key, dq_mapent, age);
		cache_unlock(mc);

		free(dq_key);
		free(dq_mapent);
next:
		if (mapent) {
			free(mapent);
			mapent = NULL;
		}

		ldap_value_free(keyValue);
		e = ldap_next_entry(ldap, e);
	}

	debug(ap->logopt, MODPREFIX "done updating map");

	/* Clean up. */
	ldap_msgfree(result);
	unbind_ldap_connection(ldap, ctxt);

	return NSS_STATUS_SUCCESS;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = LDAP_SUCCESS;
	int ret;

	ret = read_one_map(ap, ctxt, age, &rv);
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
	struct map_source *source;
	struct mapent_cache *mc;
	int rv, i, l, ql, count;
	char buf[MAX_ERR_BUF];
	time_t age = time(NULL);
	char *query;
	LDAPMessage *result, *e;
	char *class, *info, *entry;
	char **keyValue;
	char **values = NULL;
	char *attrs[3];
	int scope = LDAP_SCOPE_SUBTREE;
	LDAP *ldap;
	char *mapent = NULL;
	unsigned int wild = 0;
	int ret = CHE_MISSING;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	if (ctxt == NULL) {
		crit(ap->logopt, MODPREFIX "context was NULL");
		return CHE_FAIL;
	}

	class = ctxt->entry_obj_class;
	entry = ctxt->entry_attr;
	info = ctxt->value_attr;

	attrs[0] = entry;
	attrs[1] = info;
	attrs[2] = NULL;

	if (*qKey == '*' && qKey_len == 1)
		*qKey = '/';

	/* Build a query string. */
	l = strlen(class) + 2*strlen(entry) + strlen(qKey) + 29;

	query = alloca(l);
	if (query == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(ap->logopt, MODPREFIX "malloc: %s", estr);
		return CHE_FAIL;
	}

	/*
	 * Look for an entry in class under ctxt-base
	 * whose entry is equal to qKey.
	 */
	ql = sprintf(query,
	      "(&(objectclass=%s)(|(%s=%s)(%s=/)))", class, entry, qKey, entry);
	if (ql >= l) {
		error(ap->logopt,
		      MODPREFIX "error forming query string");
		return CHE_FAIL;
	}
	query[ql] = '\0';

	debug(ap->logopt,
	      MODPREFIX "searching for \"%s\" under \"%s\"", query, ctxt->qdn);

	/* Initialize the LDAP context. */
	ldap = do_connect(ctxt);
	if (!ldap)
		return CHE_FAIL;

	rv = ldap_search_s(ldap, ctxt->qdn, scope, query, attrs, 0, &result);

	if ((rv != LDAP_SUCCESS) || !result) {
		crit(ap->logopt, MODPREFIX "query failed for %s", query);
		unbind_ldap_connection(ldap, ctxt);
		return CHE_FAIL;
	}

	debug(ap->logopt,
	      MODPREFIX "getting first entry for %s=\"%s\"", entry, qKey);

	e = ldap_first_entry(ldap, result);
	if (!e) {
		debug(ap->logopt,
		     MODPREFIX "got answer, but no entry for %s", query);
		ldap_msgfree(result);
		unbind_ldap_connection(ldap, ctxt);
		return CHE_MISSING;
	}

	while (e) {
		keyValue = ldap_get_values(ldap, e, entry);

		if (!keyValue || !*keyValue) {
			e = ldap_next_entry(ldap, e);
			continue;
		}

		/* By definition keys must be unique within each map entry */
		if (ldap_count_values(keyValue) > 1) {
			error(ap->logopt,
			      MODPREFIX "key %s has duplicate entries",
			      *keyValue);
			ret = CHE_FAIL;
			goto next;
		}

		debug(ap->logopt, MODPREFIX "examining first entry");

		values = ldap_get_values(ldap, e, info);
		if (!values || !*values) {
			debug(ap->logopt,
			      MODPREFIX "no %s defined for %s", info, query);
			goto next;
		}

		count = ldap_count_values(values);
		for (i = 0; i < count; i++) {
			int v_len = strlen(values[i]);

			if (!mapent) {
				mapent = malloc(v_len + 1);
				if (!mapent) {
					char *estr;
					estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error(ap->logopt,
					      MODPREFIX "malloc: %s", estr);
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
					error(ap->logopt,
					      MODPREFIX "realloc: %s", estr);
				}
			}
		}
		ldap_value_free(values);

		if (**keyValue == '/') {
			if (ap->type == LKP_INDIRECT) {
				if (strlen(*keyValue) == 1) {
					wild = 1;
					**keyValue = '*';
					cache_writelock(mc);
					cache_update(mc,
						source, *keyValue, mapent, age);
					cache_unlock(mc);
				}
				goto next;
			}
		} else {
			if (ap->type == LKP_DIRECT)
				goto next;
		}

		cache_writelock(mc);
		ret = cache_update(mc, source, *keyValue, mapent, age);
		cache_unlock(mc);
next:
		if (mapent) {
			free(mapent);
			mapent = NULL;
		}

		ldap_value_free(keyValue);
		e = ldap_next_entry(ldap, e);
	}

	ldap_msgfree(result);
	unbind_ldap_connection(ldap, ctxt);

	cache_writelock(mc);
	if (!wild && cache_lookup(mc, "*"))
		cache_delete(mc, "*");
	cache_unlock(mc);

	return ret;
}

static int check_map_indirect(struct autofs_point *ap,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me, *exists;
	time_t now = time(NULL);
	time_t t_last_read;
	int ret, need_map = 0;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	cache_readlock(mc);
	exists = cache_lookup_distinct(mc, key);
	if (exists && exists->source != source)
		exists = NULL;
	cache_unlock(mc);

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	ret = lookup_one(ap, key, key_len, ctxt);
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
		cache_writelock(mc);
		pthread_cleanup_push(cache_lock_cleanup, mc);
		if (cache_delete(mc, key))
			rmdir_path(ap, key);
		pthread_cleanup_pop(1);
	}

	/* Have parent update its map */
	if (ap->ghost && need_map) {
		int status;

		source->stale = 1;

		status = pthread_mutex_lock(&ap->state_mutex);
		if (status)
			fatal(status);

		nextstate(ap->state_pipe[1], ST_READMAP);

		status = pthread_mutex_unlock(&ap->state_mutex);
		if (status)
			fatal(status);
	}

	cache_readlock(mc);
	if (ret == CHE_MISSING && !cache_lookup(mc, "*")) {
		cache_unlock(mc);
		return NSS_STATUS_NOTFOUND;
	}
	cache_unlock(mc);

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	int mapent_len;
	int status = 0;
	int ret = 1;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	key_len = snprintf(key, KEY_MAX_LEN, "%s", name);
	if (key_len > KEY_MAX_LEN)
		return NSS_STATUS_NOTFOUND;

	/* Check if we recorded a mount fail for this key */
	cache_readlock(mc);
	me = cache_lookup_distinct(mc, key);
	if (me && me->status >= time(NULL)) {
		cache_unlock(mc);
		return NSS_STATUS_NOTFOUND;
	}
	cache_unlock(mc);

        /*
	 * We can't check the direct mount map as if it's not in
	 * the map cache already we never get a mount lookup, so
	 * we never know about it.
	 */
	if (ap->type == LKP_INDIRECT) {
		char *lkp_key;

		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me && me->multi)
			lkp_key = strdup(me->multi->key);
		else
			lkp_key = strdup(key);
		cache_unlock(mc);

		if (!lkp_key)
			return NSS_STATUS_UNKNOWN;

		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		status = check_map_indirect(ap, lkp_key, strlen(lkp_key), ctxt);
		free(lkp_key);
		if (status) {
			debug(ap->logopt,
			      MODPREFIX "check indirect map failure");
			return status;
		}
	}

	cache_readlock(mc);
	me = cache_lookup(mc, key);
	if (me) {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		mapent_len = strlen(me->mapent);
		mapent = alloca(mapent_len + 1);
		strcpy(mapent, me->mapent);
		pthread_cleanup_pop(0);
	}
	cache_unlock(mc);

	if (mapent) {
		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		debug(ap->logopt, MODPREFIX "%s -> %s", key, mapent);
		ret = ctxt->parse->parse_mount(ap, key, key_len,
					 mapent, ctxt->parse->context);
		if (ret) {
			time_t now = time(NULL);
			int rv = CHE_OK;

			/* Record the the mount fail in the cache */
			cache_writelock(mc);
			me = cache_lookup_distinct(mc, key);
			if (!me)
				rv = cache_update(mc, source, key, NULL, now);
			if (rv != CHE_FAIL) {
				me = cache_lookup_distinct(mc, key);
				me->status = now + NEGATIVE_TIMEOUT;
			}
			cache_unlock(mc);
		}
	}

	if (ret)
		return NSS_STATUS_TRYAGAIN;

	return NSS_STATUS_SUCCESS;
}

/*
 * This destroys a context for queries to this module.  It releases the parser
 * structure (unloading the module) and frees the memory used by the context.
 */
int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
#ifdef WITH_SASL
	EVP_cleanup();
	ERR_free_strings();

	autofs_sasl_done(ctxt);
#endif
	free_context(ctxt);
	return rv;
}
