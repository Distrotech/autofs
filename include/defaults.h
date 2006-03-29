#ident "$Id: defaults.h,v 1.2 2006/03/29 11:23:27 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  defaults.h - system initialization defaults.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net>
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
 * ----------------------------------------------------------------------- */

#ifndef DEFAULTS_H
#define DEFAULTS_H

#define DEFAULT_MASTER_MAP_NAME	"/etc/auto.master"

#define DEFAULT_TIMEOUT		600
#define DEFAULT_BROWSE_MODE	1
#define DEFAULT_LOGGING		0

#define DEFAULT_MAP_OBJECT_CALSS	"nisMap"
#define DEFAULT_ENTRY_OBJECT_CALSS	"nisObject"
#define DEFAULT_MAP_ATTRIBUTE		"nisMapName"
#define DEFAULT_ENTRY_ATTRIBUTE		"cn"
#define DEFAULT_VALUE_ATTRIBUTE		"nisMapEntry"

#define DEFAULT_AUTH_CONF_FILE		AUTOFS_MAP_DIR "/autofs_ldap_auth.conf"

const char *get_default_master_map(void);
unsigned int get_default_timeout(void);
unsigned int get_default_browse_mode(void);
unsigned int get_default_logging(void);
const char *get_default_ldap_map_object_class(void);
const char *get_default_ldap_entry_object_class(void);
const char *get_default_ldap_map_attribute(void);
const char *get_default_ldap_entry_attribute(void);
const char *get_default_ldap_value_attribute(void);
const char *get_default_auth_conf_file(void);

#endif

