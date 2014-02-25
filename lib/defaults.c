/* ----------------------------------------------------------------------- *
 *
 *  defaults.h - system initialization defaults.
 *
 *   Copyright 2013 Red Hat, Inc.
 *   Copyright 2006, 2013 Ian Kent <raven@themaw.net>
 *   All rights reserved.
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
#include <sys/stat.h>

#include "config.h"
#include "list.h"
#include "defaults.h"
#ifdef WITH_LDAP
#include "lookup_ldap.h"
#endif
#include "log.h"
#include "automount.h"

#define AUTOFS_GLOBAL_SECTION		"autofs"

#define DEFAULT_CONFIG_FILE		AUTOFS_CONF_DIR "/autofs"
#define MAX_LINE_LEN			256

#define NAME_MASTER_MAP			"master_map_name"

#define NAME_TIMEOUT			"timeout"
#define NAME_NEGATIVE_TIMEOUT		"negative_timeout"
#define NAME_BROWSE_MODE		"browse_mode"
#define NAME_LOGGING			"logging"

#define NAME_LDAP_URI			"ldap_uri"
#define NAME_LDAP_TIMEOUT		"ldap_timeout"
#define NAME_LDAP_NETWORK_TIMEOUT	"ldap_network_timeout"

#define NAME_SEARCH_BASE		"search_base"

#define NAME_MAP_OBJ_CLASS		"map_object_class"
#define NAME_ENTRY_OBJ_CLASS		"entry_object_class"
#define NAME_MAP_ATTR			"map_attribute"
#define NAME_ENTRY_ATTR			"entry_attribute"
#define NAME_VALUE_ATTR			"value_attribute"

#define NAME_MOUNT_NFS_DEFAULT_PROTOCOL	"mount_nfs_default_protocol"
#define NAME_APPEND_OPTIONS		"append_options"
#define NAME_MOUNT_WAIT			"mount_wait"
#define NAME_UMOUNT_WAIT		"umount_wait"
#define NAME_AUTH_CONF_FILE		"auth_conf_file"

#define NAME_MAP_HASH_TABLE_SIZE	"map_hash_table_size"

/* Status returns */
#define CFG_OK		0x0000
#define CFG_FAIL	0x0001
#define CFG_EXISTS	0x0002
#define CFG_NOTFOUND	0x0004

/* Config entry flags */
#define CONF_ENV		0x00000001

#define CFG_TABLE_SIZE	128

static const char *default_master_map_name = DEFAULT_MASTER_MAP_NAME;
static const char *default_auth_conf_file  = DEFAULT_AUTH_CONF_FILE;
static const char *autofs_gbl_sec	   = AUTOFS_GLOBAL_SECTION;

struct conf_option {
	char *section;
	char *name;
	char *value;
	unsigned long flags;
	struct conf_option *next;
};

struct conf_cache {
	struct conf_option **hash;
	time_t modified;
};
static pthread_mutex_t conf_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct conf_cache *config = NULL;

static int conf_load_autofs_defaults(void);
static int conf_update(const char *, const char *, const char *, unsigned long);
static void conf_delete(const char *, const char *);
static struct conf_option *conf_lookup(const char *, const char *);


static void message(unsigned int to_syslog, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	if (to_syslog)
		vsyslog(LOG_CRIT, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);

	return;
}

static int conf_init(void)
{
	struct conf_cache *cc;
	unsigned int size = CFG_TABLE_SIZE;
	unsigned int i;

	cc = malloc(sizeof(struct conf_cache));
	if (!cc)
		return CFG_FAIL;
	cc->modified = 0;

	cc->hash = malloc(size * sizeof(struct conf_option *));
	if (!cc->hash) {
		free(cc);
		return CFG_FAIL;
	}

	for (i = 0; i < size; i++) {
		cc->hash[i] = NULL;
	}

	config = cc;

	return CFG_OK;
}

static void __conf_release(void)
{
	struct conf_cache *cc = config;
	unsigned int size = CFG_TABLE_SIZE;
	struct conf_option *co, *next;
	unsigned int i;

	for (i = 0; i < size; i++) {
		co = cc->hash[i];
		if (co == NULL)
			continue;
		next = co->next;
		free(co->section);
		free(co->name);
		if (co->value)
			free(co->value);
		free(co);

		while (next) {
			co = next;
			next = co->next;
			free(co->section);
			free(co->name);
			if (co->value)
				free(co->value);
			free(co);
		}
		cc->hash[i] = NULL;
	}

	free(cc->hash);
	free(cc);
	config = NULL;

	return;
}

void defaults_conf_release(void)
{
	pthread_mutex_lock(&conf_mutex);
	__conf_release();
	pthread_mutex_unlock(&conf_mutex);
	return;
}

static int conf_load_autofs_defaults(void)
{
	struct conf_option *co;
	const char *sec = autofs_gbl_sec;
	int ret;

	ret = conf_update(sec, NAME_MASTER_MAP,
			  DEFAULT_MASTER_MAP_NAME, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_TIMEOUT,
			  DEFAULT_TIMEOUT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_NEGATIVE_TIMEOUT,
			  DEFAULT_NEGATIVE_TIMEOUT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_BROWSE_MODE,
			  DEFAULT_BROWSE_MODE, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_LOGGING,
			  DEFAULT_LOGGING, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_LDAP_TIMEOUT,
			  DEFAULT_LDAP_TIMEOUT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_LDAP_NETWORK_TIMEOUT,
			  DEFAULT_LDAP_NETWORK_TIMEOUT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_MAP_OBJ_CLASS,
			  DEFAULT_MAP_OBJ_CLASS, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_ENTRY_OBJ_CLASS,
			  DEFAULT_ENTRY_OBJ_CLASS, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_MAP_ATTR,
			  DEFAULT_MAP_ATTR, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_ENTRY_ATTR,
			  DEFAULT_ENTRY_ATTR, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_VALUE_ATTR,
			  DEFAULT_VALUE_ATTR, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_APPEND_OPTIONS,
			  DEFAULT_APPEND_OPTIONS, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_MOUNT_WAIT,
			  DEFAULT_MOUNT_WAIT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_UMOUNT_WAIT,
			  DEFAULT_UMOUNT_WAIT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AUTH_CONF_FILE,
			  DEFAULT_AUTH_CONF_FILE, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_MOUNT_NFS_DEFAULT_PROTOCOL,
			  DEFAULT_MOUNT_NFS_DEFAULT_PROTOCOL, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	/* LDAP_URI nad SEARCH_BASE can occur multiple times */
	while ((co = conf_lookup(sec, NAME_LDAP_URI)))
		conf_delete(co->section, co->name);

	while ((co = conf_lookup(sec, NAME_SEARCH_BASE)))
		conf_delete(co->section, co->name);

	return 1;

error:
	return 0;
}

static int conf_add(const char *section, const char *key, const char *value, unsigned long flags)
{
	struct conf_option *co;
	char *sec, *name, *val, *tmp;
	unsigned int size = CFG_TABLE_SIZE;
	u_int32_t index;
	int ret;

	sec = name = val = NULL;

	co = conf_lookup(section, key);
	if (co) {
		ret = CFG_EXISTS;
		goto error;
	}

	ret = CFG_FAIL;

	/* Environment overrides file value */
	if (((flags & CFG_ENV) && (tmp = getenv(key))) || value) {
		if (tmp)
			val = strdup(tmp);
		else
			val = strdup(value);
		if (!val)
			goto error;
	}

	name = strdup(key);
	if (!key)
		goto error;

	sec = strdup(section);
	if (!sec)
		goto error;

	co = malloc(sizeof(struct conf_option));
	if (!co)
		goto error;

	co->section = sec;
	co->name = name;
	co->value = val;
	co->flags = flags;
	co->next = NULL;

	/* Don't change user set values in the environment */
	if (flags & CONF_ENV)
		setenv(name, value, 0);

	index = hash(key, size);
	if (!config->hash[index])
		config->hash[index] = co;
	else {
		struct conf_option *last = NULL, *next;
		next = config->hash[index];
		while (next) {
			last = next;
			next = last->next;
		}
		last->next = co;
	}

	return CFG_OK;

error:
	if (name)
		free(name);
	if (val)
		free(val);
	if (sec)
		free(sec);

	return ret;
}

static void conf_delete(const char *section, const char *key)
{
	struct conf_option *co, *last;
	unsigned int size = CFG_TABLE_SIZE;

	last = NULL;
	for (co = config->hash[hash(key, size)]; co != NULL; co = co->next) {
		if (strcasecmp(section, co->section))
			continue;
		if (!strcasecmp(key, co->name))
			break;
		last = co;
	}

	if (!co)
		return;

	if (last)
		last->next = co->next;

	free(co->section);
	free(co->name);
	if (co->value);
		free(co->value);
	free(co);
}

static int conf_update(const char *section,
			const char *key, const char *value,
			unsigned long flags)
{
	struct conf_option *co = NULL;
	int ret;

	ret = CFG_FAIL;
	co = conf_lookup(section, key);
	if (!co)
		ret = conf_add(section, key, value, flags);
	else {
		char *val = NULL, *tmp;
		/* Environment overrides file value */
		if (((flags & CONF_ENV) && (tmp = getenv(key))) || value) {
			if (tmp)
				val = strdup(tmp);
			else
				val = strdup(value);
			if (!val)
				goto error;
		}
		if (co->value)
			free(co->value);
		co->value = val;
		if (flags)
			co->flags = flags;
		/* Don't change user set values in the environment */
		if (flags & CONF_ENV)
			setenv(key, value, 0);
	}

	return CFG_OK;

error:
	return ret;
}

static struct conf_option *conf_lookup(const char *section, const char *key)
{
	struct conf_option *co;
	unsigned int size = CFG_TABLE_SIZE;

	if (!key || !section)
		return NULL;

	for (co = config->hash[hash(key, size)]; co != NULL; co = co->next) {
		if (strcasecmp(section, co->section))
			continue;
		if (!strcasecmp(key, co->name))
			break;
		/*
		 * Strip "DEFAULT_" and look for config entry for
		 * backward compatibility with old style config names.
		 */
		if (strlen(key) <= 8)
			continue;
		if (!strncasecmp("DEFAULT_", key, 8) &&
		    !strcasecmp(key + 8, co->name))
			break;
	}

	return co;
}

/*
 * We've changed the key names so we need to check for the
 * config key and it's old name for backward conpatibility.
*/
static int check_set_config_value(const char *res, const char *value)
{
	const char *sec = autofs_gbl_sec;
	int ret;

	if (!strcasecmp(res, NAME_LDAP_URI))
		ret = conf_add(sec, res, value, 0);
	else if (!strcasecmp(res, NAME_SEARCH_BASE))
		ret = conf_add(sec, res, value, 0);
	else
		ret = conf_update(sec, res, value, 0);

	return ret;
}

static int parse_line(char *line, char **res, char **value)
{
	char *key, *val, *trailer;
	int len;

	key = line;

	if (*key == '#' || !isalpha(*key))
		return 0;

	while (*key && *key == ' ')
		key++;

	if (!*key)
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
unsigned int defaults_read_config(unsigned int to_syslog)
{
	FILE *f;
	char buf[MAX_LINE_LEN];
	struct stat stb;
	char *res;
	int ret;

	f = open_fopen_r(DEFAULT_CONFIG_FILE);
	if (!f)
		return 0;

	pthread_mutex_lock(&conf_mutex);
	if (config) {
		if (fstat(fileno(f), &stb) != -1) {
			/* Config hasn't been updated */
			if (stb.st_mtime <= config->modified)
				goto out;
		}
	} else {
		if (conf_init()) {
			pthread_mutex_unlock(&conf_mutex);
			message(to_syslog, "failed to init config");
			return 0;
		}
	}

	/* Set configuration to defaults */
	ret = conf_load_autofs_defaults();
	if (!ret) {
		pthread_mutex_unlock(&conf_mutex);
		message(to_syslog, "failed to reset autofs default config");
		return 0;
	}

	while ((res = fgets(buf, MAX_LINE_LEN, f))) {
		char *key, *value;
		if (!parse_line(res, &key, &value))
			continue;
		check_set_config_value(key, value);
	}

	if (fstat(fileno(f), &stb) != -1)
		config->modified = stb.st_mtime;
	else
		message(to_syslog, "failed to update config modified time");

	if (!feof(f) || ferror(f)) {
		pthread_mutex_unlock(&conf_mutex);
		message(to_syslog,
			"fgets returned error %d while reading %s",
			ferror(f), DEFAULT_CONFIG_FILE);
		fclose(f);
		return 0;
	}
out:
	pthread_mutex_unlock(&conf_mutex);
	fclose(f);
	return 1;
}

static char *conf_get_string(const char *section, const char *name)
{
	struct conf_option *co;
	char *val = NULL;

	pthread_mutex_lock(&conf_mutex);
	co = conf_lookup(section, name);
	if (co && co->value)
		val = strdup(co->value);
	pthread_mutex_unlock(&conf_mutex);
	return val;
}

static long conf_get_number(const char *section, const char *name)
{
	struct conf_option *co;
	long val = -1;

	pthread_mutex_lock(&conf_mutex);
	co = conf_lookup(section, name);
	if (co && co->value)
		val = atol(co->value);
	pthread_mutex_unlock(&conf_mutex);
	return val;
}

static int conf_get_yesno(const char *section, const char *name)
{
	struct conf_option *co;
	int val = -1;

	pthread_mutex_lock(&conf_mutex);
	co = conf_lookup(section, name);
	if (co && co->value) {
		if (isdigit(*co->value))
			val = atoi(co->value);
		else if (!strcasecmp(co->value, "yes"))
			val = 1;
		else if (!strcasecmp(co->value, "no"))
			val = 0;
	}
	pthread_mutex_unlock(&conf_mutex);
	return val;
}

#ifdef WITH_LDAP
void defaults_free_uris(struct list_head *list)
{
	struct list_head *next;
	struct ldap_uri *uri;

	if (list_empty(list)) {
		free(list);
		return;
	}

	next = list->next;
	while (next != list) {
		uri = list_entry(next, struct ldap_uri, list);
		next = next->next;
		list_del(&uri->list);
		free(uri->uri);
		free(uri);
	}
	free(list);

	return;
}

static unsigned int add_uris(char *value, struct list_head *list)
{
	char *str, *tok, *ptr = NULL;
	size_t len = strlen(value) + 1;

	str = malloc(len);
	if (!str)
		return 0;
	strcpy(str, value);

	tok = strtok_r(str, " ", &ptr);
	while (tok) {
		struct ldap_uri *new;
		char *uri;

		new = malloc(sizeof(struct ldap_uri));
		if (!new)
			continue;

		uri = strdup(tok);
		if (!uri)
			free(new);
		else {
			new->uri = uri;
			list_add_tail(&new->list, list);
		}

		tok = strtok_r(NULL, " ", &ptr);
	}
	free(str);

	return 1;
}

struct list_head *defaults_get_uris(void)
{
	struct conf_option *co;
	struct list_head *list;

	list = malloc(sizeof(struct list_head));
	if (!list) {
		return NULL;
	}
	INIT_LIST_HEAD(list);

	if (defaults_read_config(0)) {
		free(list);
		return NULL;
	}

	pthread_mutex_lock(&conf_mutex);
	co = conf_lookup(autofs_gbl_sec, NAME_LDAP_URI);
	if (!co || !co->value) {
		pthread_mutex_unlock(&conf_mutex);
		free(list);
		return NULL;
	}

	while (co) {
		if (!strcasecmp(co->name, NAME_LDAP_URI))
			if (co->value)
				add_uris(co->value, list);
		co = co->next;
	}
	pthread_mutex_unlock(&conf_mutex);

	if (list_empty(list)) {
		free(list);
		list = NULL;
	}

	return list;
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
	struct conf_option *co;
	struct ldap_searchdn *sdn, *last;

	if (defaults_read_config(0))
		return NULL;

	pthread_mutex_lock(&conf_mutex);
	co = conf_lookup(autofs_gbl_sec, NAME_SEARCH_BASE);
	if (!co || !co->value) {
		pthread_mutex_unlock(&conf_mutex);
		return NULL;
	}

	sdn = last = NULL;

	while (co) {
		struct ldap_searchdn *new;

		if (!co->value || strcasecmp(co->name, NAME_SEARCH_BASE) ) {
			co = co->next;
			continue;
		}

		new = alloc_searchdn(co->value);
		if (!new) {
			pthread_mutex_unlock(&conf_mutex);
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

		co = co->next;
	}
	pthread_mutex_unlock(&conf_mutex);

	return sdn;
}

struct ldap_schema *defaults_get_schema(void)
{
	struct ldap_schema *schema;
	char *mc, *ma, *ec, *ea, *va;
	const char *sec = autofs_gbl_sec;

	mc = conf_get_string(sec, NAME_MAP_OBJ_CLASS);
	if (!mc)
		return NULL;

	ma = conf_get_string(sec, NAME_MAP_ATTR);
	if (!ma) {
		free(mc);
		return NULL;
	}

	ec = conf_get_string(sec, NAME_ENTRY_OBJ_CLASS);
	if (!ec) {
		free(mc);
		free(ma);
		return NULL;
	}

	ea = conf_get_string(sec, NAME_ENTRY_ATTR);
	if (!ea) {
		free(mc);
		free(ma);
		free(ec);
		return NULL;
	}

	va = conf_get_string(sec, NAME_VALUE_ATTR);
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
#endif

const char *defaults_get_master_map(void)
{
	char *master = conf_get_string(autofs_gbl_sec, NAME_MASTER_MAP);
	if (!master)
		return strdup(default_master_map_name);

	return (const char *) master;
}

int defaults_master_set(void)
{
	struct conf_option *co;

	pthread_mutex_lock(&conf_mutex);
	co = conf_lookup(autofs_gbl_sec, NAME_MASTER_MAP);
	pthread_mutex_unlock(&conf_mutex);
	if (co)
		return 1;
	return 0;
}

unsigned int defaults_get_timeout(void)
{
	long timeout;

	timeout = conf_get_number(autofs_gbl_sec, NAME_TIMEOUT);
	if (timeout < 0)
		timeout = atol(DEFAULT_TIMEOUT);

	return (unsigned int) timeout;
}

unsigned int defaults_get_negative_timeout(void)
{
	long n_timeout;

	n_timeout = conf_get_number(autofs_gbl_sec, NAME_NEGATIVE_TIMEOUT);
	if (n_timeout <= 0)
		n_timeout = atol(DEFAULT_NEGATIVE_TIMEOUT);

	return (unsigned int) n_timeout;
}

unsigned int defaults_get_browse_mode(void)
{
	int res;

	res = conf_get_yesno(autofs_gbl_sec, NAME_BROWSE_MODE);
	if (res < 0)
		res = atoi(DEFAULT_BROWSE_MODE);

	return res;
}

unsigned int defaults_get_logging(void)
{
	char *res;
	unsigned int logging = LOGOPT_NONE;

	res = conf_get_string(autofs_gbl_sec, NAME_LOGGING);
	if (!res)
		return logging;

	if (!strcasecmp(res, "none"))
		logging = LOGOPT_NONE;
	else {
		if (!strcasecmp(res, "verbose"))
			logging |= LOGOPT_VERBOSE;

		if (!strcasecmp(res, "debug"))
			logging |= LOGOPT_DEBUG;
	}

	free(res);

	return logging;
}

unsigned int defaults_get_ldap_timeout(void)
{
	int res;

	res = conf_get_number(autofs_gbl_sec, NAME_LDAP_TIMEOUT);
	if (res < 0)
		res = atoi(DEFAULT_LDAP_TIMEOUT);

	return res;
}

unsigned int defaults_get_ldap_network_timeout(void)
{
	int res;

	res = conf_get_number(autofs_gbl_sec, NAME_LDAP_NETWORK_TIMEOUT);
	if (res < 0)
		res = atoi(DEFAULT_LDAP_NETWORK_TIMEOUT);

	return res;
}

unsigned int defaults_get_mount_nfs_default_proto(void)
{
	int proto;

	proto = conf_get_number(autofs_gbl_sec, NAME_MOUNT_NFS_DEFAULT_PROTOCOL);
	if (proto < 2 || proto > 4)
		proto = atoi(DEFAULT_MOUNT_NFS_DEFAULT_PROTOCOL);

	return (unsigned int) proto;
}

unsigned int defaults_get_append_options(void)
{
	int res;

	res = conf_get_yesno(autofs_gbl_sec, NAME_APPEND_OPTIONS);
	if (res < 0)
		res = atoi(DEFAULT_APPEND_OPTIONS);

	return res;
}

unsigned int defaults_get_mount_wait(void)
{
	long wait;

	wait = conf_get_number(autofs_gbl_sec, NAME_MOUNT_WAIT);
	if (wait < 0)
		wait = atoi(DEFAULT_MOUNT_WAIT);

	return (unsigned int) wait;
}

unsigned int defaults_get_umount_wait(void)
{
	long wait;

	wait = conf_get_number(autofs_gbl_sec, NAME_UMOUNT_WAIT);
	if (wait < 0)
		wait = atoi(DEFAULT_UMOUNT_WAIT);

	return (unsigned int) wait;
}

const char *defaults_get_auth_conf_file(void)
{
	char *cf;

	cf = conf_get_string(autofs_gbl_sec, NAME_AUTH_CONF_FILE);
	if (!cf)
		return strdup(default_auth_conf_file);

	return (const char *) cf;
}

unsigned int defaults_get_map_hash_table_size(void)
{
	long size;

	size = conf_get_number(autofs_gbl_sec, NAME_MAP_HASH_TABLE_SIZE);
	if (size < 0)
		size = atoi(DEFAULT_MAP_HASH_TABLE_SIZE);

	return (unsigned int) size;
}

