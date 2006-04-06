#ifndef LOOKUP_LDAP_H
#define LOOKUP_LDAP_H

#include <sasl/sasl.h>
#include <libxml/tree.h>

#define LDAP_AUTH_CONF_FILE "test"

/* lookup_ldap.c */
LDAP *ldap_connection_init(const char *server, int port,
			int *version, unsigned use_tls, unsigned tls_required);
int authtype_requires_creds(const char *authtype);

/* cyrus-sasl.c */
int sasl_init(char *id, char *secret);
int sasl_choose_mech(const char *server, int port,
		 unsigned use_tls, unsigned tls_required, char **mechanism);
sasl_conn_t *sasl_bind_mech(LDAP *ldap, const char *mech);

#endif /* _lookup_ldap_h */
