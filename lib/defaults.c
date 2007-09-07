/* ----------------------------------------------------------------------- *
 *
 *  defaults.h - system initialization defaults.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "defaults.h"
#include "lookup_ldap.h"
#include "log.h"

#define DEFAULTS_CONFIG_FILE		AUTOFS_CONF_DIR "/autofs"
#define MAX_LINE_LEN			256

#define ENV_NAME_MASTER_MAP		"MASTER_MAP_NAME"

#define ENV_NAME_TIMEOUT		"TIMEOUT"
#define ENV_NAME_BROWSE_MODE		"BROWSE_MODE"
#define ENV_NAME_LOGGING		"LOGGING"

#define ENV_LDAP_SERVER			"LDAP_SERVER"

#define SEARCH_BASE			"SEARCH_BASE"

#define ENV_NAME_MAP_OBJ_CLASS		"MAP_OBJECT_CLASS"
#define ENV_NAME_ENTRY_OBJ_CLASS	"ENTRY_OBJECT_CLASS"
#define ENV_NAME_MAP_ATTR		"MAP_ATTRIBUTE"
#define ENV_NAME_ENTRY_ATTR		"ENTRY_ATTRIBUTE"
#define ENV_NAME_VALUE_ATTR		"VALUE_ATTRIBUTE"

#define ENV_APPEND_OPTIONS		"APPEND_OPTIONS"
#define ENV_AUTH_CONF_FILE		"AUTH_CONF_FILE"

static const char *default_master_map_name = DEFAULT_MASTER_MAP_NAME;
static const char *default_ldap_server	   = DEFAULT_LDAP_SERVER;
static const char *default_auth_conf_file  = DEFAULT_AUTH_CONF_FILE;

static char *get_env_string(const char *name)
{
	char *val, *res;

	val = getenv(name);
	if (!val)
		return NULL;

	res = strdup(val);
	if (!val)
		return NULL;

	return res;
}

static long get_env_number(const char *name)
{
	char *val;
	long res = -1;

	val = getenv(name);
	if (!val)
		return -1;

	if (isdigit(*val))
		res = atol(val);

	if (res < 0)
		return -1;

	return res;
}

static int get_env_yesno(const char *name)
{
	const char *val;
	int res = -1;

	val = getenv(name);
	if (!val)
		return -1;

	if (isdigit(*val))
		res = atoi(val);
	else if (!strcasecmp(val, "yes"))
		return 1;
	else if (!strcasecmp(val, "no"))
		return 0;

	return res;
}

/*
 * We've changed the key names so we need to check for the
 * config key and it's old name for backward conpatibility.
*/
static int check_set_config_value(const char *res, const char *name, const char *value)
{
	char *old_name;
	int ret;

	if (!strcasecmp(res, name)) {
		ret = setenv(name, value, 0);
		if (ret)
			fprintf(stderr,
			        "can't set config value for %s, "
				"error %d", name, ret);
		return 1;
	}

	old_name = alloca(strlen(name) + 9);
	strcpy(old_name, "DEFAULT_");
	strcat(old_name, name);

	if (!strcasecmp(res, old_name)) {
		ret = setenv(name, value, 0);
		if (ret)
			fprintf(stderr,
			        "can't set config value for %s, "
				"error %d", name, ret);
		return 1;
	}
	return 0;
}

static int parse_line(char *line, char **res, char **value)
{
	volatile char *key, *val, *trailer;
	int len;

	key = line;

	if (*key == '#' || !isalpha(*key))
		return 0;

	while (*key && *key == ' ')
		key++;

	if (!key)
		return 0;

	if (!(val = strchr(key, '=')))
		return 0;

	*val++ = '\0';

	while (*val && (*val == '"' || isblank(*val)))
		val++;

	len = strlen(val);

	if (val[len - 1] == '\n') {
		val[len - 1] = '\0';
		len--;
	}

	trailer = strchr(val, '#');
	if (!trailer)
		trailer = val + len - 1;
	else
		trailer--;

	while (*trailer && (*trailer == '"' || isblank(*trailer)))
		*(trailer--) = '\0';;

	*res = key;
	*value = val;

	return 1;
}

/*
 * Read config env variables and check they have been set.
 *
 * This simple minded routine assumes the config file
 * is valid bourne shell script without spaces around "="
 * and that it has valid values.
 */
unsigned int defaults_read_config(void)
{
	FILE *f;
	char buf[MAX_LINE_LEN];
	char *res;

	f = fopen(DEFAULTS_CONFIG_FILE, "r");
	if (!f)
		return 0;

	while ((res = fgets(buf, MAX_LINE_LEN, f))) {
		char *key, *value;

		if (!parse_line(res, &key, &value))
			continue;

		if (check_set_config_value(key, ENV_NAME_MASTER_MAP, value) ||
		    check_set_config_value(key, ENV_NAME_TIMEOUT, value) ||
		    check_set_config_value(key, ENV_NAME_BROWSE_MODE, value) ||
		    check_set_config_value(key, ENV_NAME_LOGGING, value) ||
		    check_set_config_value(key, ENV_LDAP_SERVER, value) ||
		    check_set_config_value(key, ENV_NAME_MAP_OBJ_CLASS, value) ||
		    check_set_config_value(key, ENV_NAME_ENTRY_OBJ_CLASS, value) ||
		    check_set_config_value(key, ENV_NAME_MAP_ATTR, value) ||
		    check_set_config_value(key, ENV_NAME_ENTRY_ATTR, value) ||
		    check_set_config_value(key, ENV_NAME_VALUE_ATTR, value) ||
		    check_set_config_value(key, ENV_APPEND_OPTIONS, value) ||
		    check_set_config_value(key, ENV_AUTH_CONF_FILE, value))
			;
	}

	if (!feof(f)) {
		fprintf(stderr, "fgets returned error %d while reading %s\n",
			ferror(f), DEFAULTS_CONFIG_FILE);
		fclose(f);
		return 0;
	}

	fclose(f);
	return 1;
}

const char *defaults_get_master_map(void)
{
	char *master;

	master = get_env_string(ENV_NAME_MASTER_MAP);
	if (!master)
		return strdup(default_master_map_name);

	return (const char *) master;
}

unsigned int defaults_get_timeout(void)
{
	long timeout;

	timeout = get_env_number(ENV_NAME_TIMEOUT);
	if (timeout < 0)
		timeout = DEFAULT_TIMEOUT;

	return (unsigned int) timeout;
}

unsigned int defaults_get_browse_mode(void)
{
	int res;

	res = get_env_yesno(ENV_NAME_BROWSE_MODE);
	if (res < 0)
		res = DEFAULT_BROWSE_MODE;

	return res;
}

unsigned int defaults_get_logging(void)
{
	char *res;
	unsigned int logging = DEFAULT_LOGGING;

	res = get_env_string(ENV_NAME_LOGGING);
	if (!res)
		return logging;

	if (!strcasecmp(res, "none"))
		logging = DEFAULT_LOGGING;
	else {
		if (!strcasecmp(res, "verbose"))
			logging |= LOGOPT_VERBOSE;

		if (!strcasecmp(res, "debug"))
			logging |= LOGOPT_DEBUG;
	}

	free(res);

	return logging;
}

const char *defaults_get_ldap_server(void)
{
	char *server;

	server = get_env_string(ENV_LDAP_SERVER);
	if (!server)
		return default_ldap_server;

	return (const char *) server;
}

struct ldap_schema *defaults_get_default_schema(void)
{
	struct ldap_schema *schema;
	char *mc, *ma, *ec, *ea, *va;

	mc = strdup(DEFAULT_MAP_OBJ_CLASS);
	if (!mc)
		return NULL;

	ma = strdup(DEFAULT_MAP_ATTR);
	if (!ma) {
		free(mc);
		return NULL;
	}

	ec = strdup(DEFAULT_ENTRY_OBJ_CLASS);
	if (!ec) {
		free(mc);
		free(ma);
		return NULL;
	}

	ea = strdup(DEFAULT_ENTRY_ATTR);
	if (!ea) {
		free(mc);
		free(ma);
		free(ec);
		return NULL;
	}

	va = strdup(DEFAULT_VALUE_ATTR);
	if (!va) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		return NULL;
	}

	schema = malloc(sizeof(struct ldap_schema));
	if (!schema) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		free(va);
		return NULL;
	}

	schema->map_class = mc;
	schema->map_attr = ma;
	schema->entry_class = ec;
	schema->entry_attr = ea;
	schema->value_attr = va;

	return schema;
}

static struct ldap_searchdn *alloc_searchdn(const char *value)
{
	struct ldap_searchdn *sdn;
	char *val;

	sdn = malloc(sizeof(struct ldap_searchdn));
	if (!sdn)
		return NULL;

	val = strdup(value);
	if (!val) {
		free(sdn);
		return NULL;
	}

	sdn->basedn = val;
	sdn->next = NULL;

	return sdn;
}

void defaults_free_searchdns(struct ldap_searchdn *sdn)
{
	struct ldap_searchdn *this = sdn;
	struct ldap_searchdn *next;

	next = this;
	while (this) {
		next = this->next;
		free(this->basedn);
		free(this);
		this = next;
	}

	return;
}

struct ldap_searchdn *defaults_get_searchdns(void)
{
	FILE *f;
	char buf[MAX_LINE_LEN];
	char *res;
	struct ldap_searchdn *sdn, *last;

	f = fopen(DEFAULTS_CONFIG_FILE, "r");
	if (!f)
		return NULL;

	sdn = last = NULL;

	while ((res = fgets(buf, MAX_LINE_LEN, f))) {
		char *key, *value;

		if (!parse_line(res, &key, &value))
			continue;

		if (!strcasecmp(key, SEARCH_BASE)) {
			struct ldap_searchdn *new = alloc_searchdn(value);

			if (!new) {
				defaults_free_searchdns(sdn);
				return NULL;
			}

			if (!last)
				last = new;
			else {
				last->next = new;
				last = new;
			}

			if (!sdn)
				sdn = new;
		}
	}

	fclose(f);
	return sdn;
}

struct ldap_schema *defaults_get_schema(void)
{
	struct ldap_schema *schema;
	char *mc, *ma, *ec, *ea, *va;

	mc = get_env_string(ENV_NAME_MAP_OBJ_CLASS);
	if (!mc)
		return NULL;

	ma = get_env_string(ENV_NAME_MAP_ATTR);
	if (!ma) {
		free(mc);
		return NULL;
	}

	ec = get_env_string(ENV_NAME_ENTRY_OBJ_CLASS);
	if (!ec) {
		free(mc);
		free(ma);
		return NULL;
	}

	ea = get_env_string(ENV_NAME_ENTRY_ATTR);
	if (!ea) {
		free(mc);
		free(ma);
		free(ec);
		return NULL;
	}

	va = get_env_string(ENV_NAME_VALUE_ATTR);
	if (!va) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		return NULL;
	}

	schema = malloc(sizeof(struct ldap_schema));
	if (!schema) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		free(va);
		return NULL;
	}

	schema->map_class = mc;
	schema->map_attr = ma;
	schema->entry_class = ec;
	schema->entry_attr = ea;
	schema->value_attr = va;

	return schema;
}

unsigned int defaults_get_append_options(void)
{
	int res;

	res = get_env_yesno(ENV_APPEND_OPTIONS);
	if (res < 0)
		res = DEFAULT_APPEND_OPTIONS;

	return res;
}

const char *defaults_get_auth_conf_file(void)
{
	char *cf;

	cf = get_env_string(ENV_AUTH_CONF_FILE);
	if (!cf)
		return strdup(default_auth_conf_file);

	return (const char *) cf;
}

