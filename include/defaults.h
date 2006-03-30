#ident "$Id: defaults.h,v 1.3 2006/03/30 02:09:51 raven Exp $"
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

#define DEFAULT_MAP_OBJ_CLASS		"nisMap"
#define DEFAULT_ENTRY_OBJ_CLASS		"nisObject"
#define DEFAULT_MAP_ATTR		"nisMapName"
#define DEFAULT_ENTRY_ATTR		"cn"
#define DEFAULT_VALUE_ATTR		"nisMapEntry"

#define DEFAULT_AUTH_CONF_FILE		AUTOFS_MAP_DIR "/autofs_ldap_auth.conf"

unsigned int defaults_read_config(void);
const char *defaults_get_master_map(void);
unsigned int defaults_get_timeout(void);
unsigned int defaults_get_browse_mode(void);
unsigned int defaults_get_logging(void);
const char *defaults_get_map_obj_class(void);
const char *defaults_get_entry_obj_class(void);
const char *defaults_get_map_attr(void);
const char *defaults_get_entry_attr(void);
const char *defaults_get_value_attr(void);
const char *defaults_get_auth_conf_file(void);

#endif

