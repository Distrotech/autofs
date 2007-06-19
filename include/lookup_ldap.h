#ifndef LOOKUP_LDAP_H
#define LOOKUP_LDAP_H

#ifdef WITH_SASL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sasl/sasl.h>
#include <libxml/tree.h>
#include <krb5.h>
#endif

struct lookup_context {
	char *mapname;

	char *server;
	int port;
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
	char        *client_princ;
	int          kinit_done;
	int          kinit_successful;
#ifdef WITH_SASL
	krb5_principal  krb5_client_princ;
	krb5_context krb5ctxt;
	krb5_ccache  krb5_ccache;
	sasl_conn_t  *sasl_conn;
#endif
	/* keytab file name needs to be added */

	struct parse_mod *parse;
};


#ifdef WITH_SASL
#define LDAP_AUTH_CONF_FILE "test"

#define LDAP_TLS_DONT_USE	0
#define LDAP_TLS_REQUIRED	1
#define LDAP_TLS_INIT		1
#define LDAP_TLS_RELEASE	2

#define LDAP_AUTH_NOTREQUIRED	0x0001
#define LDAP_AUTH_REQUIRED	0x0002
#define LDAP_AUTH_AUTODETECT	0x0004

/* lookup_ldap.c */
LDAP *init_ldap_connection(struct lookup_context *ctxt);
int unbind_ldap_connection(LDAP *ldap, struct lookup_context *ctxt);
int authtype_requires_creds(const char *authtype);

/* cyrus-sasl.c */
int autofs_sasl_init(LDAP *ldap, struct lookup_context *ctxt);
int autofs_sasl_bind(LDAP *ldap, struct lookup_context *ctxt);
void autofs_sasl_unbind(struct lookup_context *ctxt);
void autofs_sasl_done(struct lookup_context *ctxt);
#endif

#endif
