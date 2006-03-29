#ident "$Id: defaults.c,v 1.1 2006/03/29 10:32:36 raven Exp $"
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
#include <ctype.h>
#include <string.h>

#include "defaults.h"
#include "log.h"

#define ENV_NAME_MASTER_MAP	"DEFAULT_MASTER_MAP_NAME"

#define ENV_NAME_TIMEOUT	"DEFAULT_TIMEOUT"
#define ENV_NAME_BROWSE_MODE	"DEFAULT_BROWSE_MODE"
#define ENV_NAME_LOGGING	"DEFAULT_LOGGING"

#define ENV_NAME_MAP_OBJECT_CALSS	"DEFAULT_MAP_OBJECT_CALSS"
#define ENV_NAME_ENTRY_OBJECT_CALSS	"DEFAULT_ENTRY_OBJECT_CALSS"
#define ENV_NAME_MAP_ATTRIBUTE		"DEFAULT_MAP_ATTRIBUTE"
#define ENV_NAME_ENTRY_ATTRIBUTE	"DEFAULT_ENTRY_ATTRIBUTE"
#define ENV_NAME_VALUE_ATTRIBUTE	"DEFAULT_VALUE_ATTRIBUTE"

#define ENV_AUTH_CONF_FILE		"DEFAULT_AUTH_CONF_FILE"

static const char *default_master_map_name = DEFAULT_MASTER_MAP_NAME;

static const char *default_map_object_class = DEFAULT_MAP_OBJECT_CALSS;
static const char *default_entry_object_class = DEFAULT_ENTRY_OBJECT_CALSS;
static const char *default_map_attribute = DEFAULT_MAP_ATTRIBUTE;
static const char *default_entry_attribute = DEFAULT_ENTRY_ATTRIBUTE;
static const char *default_value_attribute = DEFAULT_VALUE_ATTRIBUTE;

static const char *default_auth_conf_file = DEFAULT_AUTH_CONF_FILE;

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

const char *get_default_master_map(void)
{
	char *master;

	master = get_env_string(ENV_NAME_MASTER_MAP);
	if (!master)
		return default_master_map_name;

	return (const char *) master;
}

unsigned int get_default_timeout(void)
{
	long timeout;

	timeout = get_env_number(ENV_NAME_TIMEOUT);
	if (timeout < 0)
		timeout = DEFAULT_TIMEOUT;

	return (unsigned int) timeout;
}

unsigned int get_default_browse_mode(void)
{
	int res;

	res = get_env_yesno(ENV_NAME_BROWSE_MODE);
	if (res < 0)
		res = DEFAULT_BROWSE_MODE;

	return res;
}

unsigned int get_default_logging(void)
{
	char *res;
	unsigned int logging = DEFAULT_LOGGING;

	res = get_env_string(ENV_NAME_BROWSE_MODE);
	if (!res)
		return logging;

	if (!strcasecmp(res, "none"))
		logging = DEFAULT_LOGGING;
	else {
		if (strcasecmp(res, "verbose"))
			logging |= LOGOPT_VERBOSE;

		if (strcasecmp(res, "debug"))
			logging |= LOGOPT_DEBUG;
	}

	return logging;
}

const char *get_default_ldap_map_object_class(void)
{
	char *moc;

	moc = get_env_string(ENV_NAME_MAP_OBJECT_CALSS);
	if (!moc)
		return default_map_object_class;

	return (const char *) moc;
}

const char *get_default_ldap_entry_object_class(void)
{
	char *eoc;

	eoc = get_env_string(ENV_NAME_ENTRY_OBJECT_CALSS);
	if (!eoc)
		return default_entry_object_class;

	return (const char *) eoc;
}

const char *get_default_ldap_map_attribute(void)
{
	char *ma;

	ma = get_env_string(ENV_NAME_MAP_ATTRIBUTE);
	if (!ma)
		return default_map_attribute;

	return (const char *) ma;
}

const char *get_default_ldap_entry_attribute(void)
{
	char *ea;

	ea = get_env_string(ENV_NAME_ENTRY_ATTRIBUTE);
	if (!ea)
		return default_entry_attribute;

	return (const char *) ea;
}

const char *get_default_ldap_value_attribute(void)
{
	char *va;

	va = get_env_string(ENV_NAME_VALUE_ATTRIBUTE);
	if (!va)
		return default_value_attribute;

	return (const char *) va;
}

const char *get_default_auth_conf_file(void)
{
	char *cf;

	cf = get_env_string(ENV_AUTH_CONF_FILE);
	if (!cf)
		return default_auth_conf_file;

	return (const char *) cf;
}

