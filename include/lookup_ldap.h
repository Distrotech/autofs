#ifndef LOOKUP_LDAP_H
#define LOOKUP_LDAP_H

#if WITH_SASL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sasl/sasl.h>
#include <libxml/tree.h>
#endif

struct lookup_context {
	char *mapname;

	char *server;
	char *base;
	char *qdn;

	/* LDAP version 2 or 3 */
	int version;

	/* LDAP lookup configuration */
	char *map_obj_class;
	char *entry_obj_class;
	char *map_attr;
	char *entry_attr;
	char *value_attr;

	/* TLS and SASL authentication information */
	char        *auth_conf;
	unsigned     use_tls;
	unsigned     tls_required;
	unsigned     auth_required;
	char        *sasl_mech;
	char        *user;
	char        *secret;

	struct parse_mod *parse;
};


#if WITH_SASL
#define LDAP_AUTH_CONF_FILE "test"

#define LDAP_TLS_DONT_USE	0
#define LDAP_TLS_REQUIRED	1
#define LDAP_TLS_INIT		1
#define LDAP_TLS_RELEASE	2

/* lookup_ldap.c */
LDAP *ldap_connection_init(struct lookup_context *ctxt);
int ldap_unbind_connection(LDAP *ldap, struct lookup_context *ctxt);
int authtype_requires_creds(const char *authtype);

/* cyrus-sasl.c */
int sasl_init(char *id, char *secret);
int sasl_choose_mech(struct lookup_context *ctxt, char **mechanism);
sasl_conn_t *sasl_bind_mech(LDAP *ldap, const char *mech);
#endif

#endif /* _lookup_ldap_h */
