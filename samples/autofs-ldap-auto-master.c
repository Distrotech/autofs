/*
 * ident $id$
 *
 * Dump out the automount map given as an argument on the command line.
 */

#include <getopt.h>
#include <ldap.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define MAP "auto.master"
#define MAPOC "nisMap"
#define MAPKEY  "nisMapName"
#define ENTRYOC "nisObject"
#define ENTRYKEY "cn"
#define VALUE "nisMapEntry"

static int
dump_map(LDAP *ld,
	 const char *map_name,
	 const char *map_class,
	 const char *entry_class,
	 const char *map_key_attribute,
	 const char *entry_key_attribute,
	 const char *value_attribute)
{
	LDAPControl *server = NULL, *client = NULL;
	LDAPMessage *messages = NULL, *entry = NULL;
	char *attrs[3], *dn = NULL, **keys = NULL, **values = NULL;
	char filter[LINE_MAX] = "";
	int result = 0, found = 0;

	/* We only want the key and value attributes from entries which
	 * match the query we'll perform. */
	attrs[0] = strdup(map_key_attribute);
	attrs[1] = strdup(value_attribute);
	attrs[2] = NULL;

	/* Set the filter to only find the map we're looking at. */
	snprintf(filter, sizeof(filter), "(&(objectclass=%s)(%s=%s))",
		 map_class, map_key_attribute, map_name);

	/* Perform a synchronous query to find the DN of the map. */
	result = ldap_search_ext_s(ld, NULL,
				   LDAP_SCOPE_SUBTREE,
				   filter,
				   attrs, FALSE,
				   &server, &client,
				   NULL,
				   LDAP_NO_LIMIT,
				   &messages);
	if(result != LDAP_SUCCESS) {
		return 0;
	}

	/* We expected only one match.  Pull it from the results list. */
	entry = ldap_first_entry(ld, messages);
	if(entry == NULL) {
		return 0;
	}

	/* Get the DN of the map. */
	dn = ldap_get_dn(ld, entry);
	if((dn == NULL) || (strlen(dn) == 0)) {
		return 0;
	}

	/* Set the filter to only find entries in the map we're looking at. */
	snprintf(filter, sizeof(filter), "(objectclass=%s)", entry_class);

	/* Free memory used by our first query. */
	free(attrs[0]);
	free(attrs[1]);
	if(server) {
		ldap_control_free(server);
		server = NULL;
	}
	if(client) {
		ldap_control_free(client);
		client = NULL;
	}
	if(messages) {
		ldap_msgfree(messages);
		messages = NULL;
	}

	/* Reset the attribute list. */
	attrs[0] = strdup(entry_key_attribute);
	attrs[1] = strdup(value_attribute);
	attrs[2] = NULL;

	/* Now search for entries under the map's DN. */
	result = ldap_search_ext_s(ld, dn,
				   LDAP_SCOPE_SUBTREE,
				   filter,
				   attrs, FALSE,
				   &server, &client,
				   NULL,
				   LDAP_NO_LIMIT,
				   &messages);
	if(result != LDAP_SUCCESS) {
		return 0;
	}

	/* Iterate through the results, dumping them out. */
	for(entry = ldap_first_entry(ld, messages);
	    entry != NULL;
	    entry = ldap_next_entry(ld, entry)) {
		keys = ldap_get_values(ld, entry, entry_key_attribute);
		values = ldap_get_values(ld, entry, value_attribute);
		if(keys && keys[0] && values && values[0]) {
			found = 1;
			printf("%s %s\n", keys[0], values[0]);
		}
		if(keys != NULL) {
			ldap_value_free(keys);
		}
		if(values != NULL) {
			ldap_value_free(values);
		}
	}

	/* Clean up and return. */
	if(dn) {
		ldap_memfree(dn);
	}
	free(attrs[0]);
	free(attrs[1]);
	if(server) {
		ldap_control_free(server);
		server = NULL;
	}
	if(client) {
		ldap_control_free(client);
		client = NULL;
	}
	if(messages) {
		ldap_msgfree(messages);
		messages = NULL;
	}

	return found;
}

int
main(int argc, char **argv)
{
	LDAP *ld = NULL;
	int result;
	int c;
	const char *map_key = MAPKEY, *entry_key = ENTRYKEY, *value = VALUE;
	const char *map_oc = MAPOC, *entry_oc = ENTRYOC;
	const char *map = MAP;

	setlocale(LC_ALL, "");

	/* Scan through the argument list. */
	while((c = getopt(argc, argv, "m:e:n:k:v:")) != -1) {
		switch(c) {
			case 'm':
				/* This is the object class we expect maps to
				 * have.  The default is MAPOC. */
				map_oc = optarg;
				break;
			case 'e':
				/* This is the object class we entries in the
				 * map to be in.  The default is ENTRYOC. */
				entry_oc = optarg;
				break;
			case 'n':
				/* This is the attribute which we use as the
				 * key when looking up maps.  Usually we use
				 * MAP_KEY. */
				map_key = optarg;
				break;
			case 'k':
				/* This is the attribute which we use as the
				 * key when looking up entries.  Usually we use
				 * ENTRY_KEY. */
				entry_key = optarg;
				break;
			case 'v':
				/* This is the attribute which we treat as
				 * having the information we need when we
				 * look up a map.  Usually this is the
				 * VALUE attribute. */
				value = optarg;
				break;
			default:
				fprintf(stderr, "syntax: %s\n"
					"\t[-m %s] (map object class)\n"
					"\t[-e %s] (entry object class)\n"
					"\t[-n %s] (attribute used as map key)\n"
					"\t[-k %s] (attribute used as entry key)\n"
					"\t[-v %s] (attribute used as value)\n"
					"\t[%s] (map name)\n",
					strchr(argv[0], '/') ?
					strrchr(argv[0], '/') + 1 : argv[0],
					map_oc, entry_oc, map_key, entry_key,
					value, map);
				return 0;
				break;
		}
	}
	/* An argument without a flag is the name of the map to look up
	 * information in. */
	if((argv[optind] != NULL) && (strlen(argv[optind]) > 0)) {
		map = argv[optind];
	}

	/* Initialize the LDAP library, pointing it at the default server. */
	ld = ldap_init(NULL, LDAP_PORT);
	if(ld == NULL) {
		fprintf(stderr, "error initializing LDAP\n");
		return 1;
	}

	/* Try to switch to protocol 3. */
	c = 3;
	if(ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &c) != LDAP_SUCCESS) {
		/* Just retry with the default protocol version. */
		ldap_unbind(ld);
		ld = ldap_init(NULL, LDAP_PORT);
	}

	/* Connect to the server anonymously. */
	result = ldap_simple_bind_s(ld, NULL, NULL);
	if(result != LDAP_SUCCESS) {
		fprintf(stderr, "%s: error binding to server: %s\n",
			argv[0], ldap_err2string(result));
		ldap_unbind(ld);
		return 2;
	}

	/* Try to dump the map given the preferred or user-supplied schema. */
	if(!dump_map(ld, map, map_oc, entry_oc, map_key, entry_key, value)) {
		if(strcmp(map_oc, "automountMap") ||
		   strcmp(entry_oc, "automount") ||
		   strcmp(map_key, "ou") ||
		   strcmp(entry_key, "cn") ||
		   strcmp(value, "automountInformation")) {
			dump_map(ld,
				 map,
				 "automountMap",
				 "automount",
				 "ou",
				 "cn",
				 "automountInformation");
		}
	}

	/* Close the connection to the server and quit. */
	ldap_unbind(ld);
	return 0;
}
