%{
/* ----------------------------------------------------------------------- *
 *   
 *  master_parser.y - master map buffer parser.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>

#include "automount.h"
#include "master.h"

#define MAX_ERR_LEN	512

extern struct master *master_list;

char **add_argv(int, char **, char *);
const char **copy_argv(int, const char **);
int free_argv(int, const char **);

extern FILE *master_in;
extern char *master_text;
extern int master_lex(void);
extern int master_lineno;
extern void master_set_scan_buffer(const char *);

static char *master_strdup(char *);
static void local_init_vars(void);
static void local_free_vars(void);

static int master_error(const char *s);
static int master_notify(const char *s);
 
static char *path;
static char *type;
static char *format;
static long timeout;
static unsigned ghost;
static char **local_argv;
static int local_argc;

static char errstr[MAX_ERR_LEN];

static unsigned int verbose;
static unsigned int debug;

static int lineno;

#define YYDEBUG 0

#ifndef YYENABLE_NLS
#define YYENABLE_NLS 0
#endif
#ifndef YYLTYPE_IS_TRIVIAL
#define YYLTYPE_IS_TRIVIAL 0
#endif

#if YYDEBUG
static int master_fprintf(FILE *, char *, ...);
#undef YYFPRINTF
#define YYFPRINTF master_fprintf
#endif

%}

%union {
	char strtype[2048];
	int inttype;
	long longtype;
}

%token COMMENT
%token MAP
%token OPT_TIMEOUT OPT_NOGHOST OPT_GHOST OPT_VERBOSE OPT_DEBUG
%token COLON COMMA NL
%type <strtype> map
%type <strtype> options
%type <strtype> dn
%type <strtype> dnattrs
%type <strtype> dnattr
%type <strtype> option
%type <strtype> daemon_option
%type <strtype> mount_option
%token <strtype> PATH
%token <strtype> QUOTE
%token <strtype> NILL
%token <strtype> SPACE
%token <strtype> EQUAL
%token <strtype> MAPTYPE
%token <strtype> DNSERVER
%token <strtype> DNATTR
%token <strtype> DNNAME
%token <strtype> MAPHOSTS
%token <strtype> MAPNULL
%token <strtype> MAPNAME
%token <inttype> NUMBER
%token <strtype> OPTION

%start file

%%

file: {
		master_lineno = 0;
#if YYDEBUG != 0
		master_debug = YYDEBUG;
#endif
	} line
	;

line:
	| PATH map
	{
		path = master_strdup($1);
		if (!path) {
			local_free_vars();
			YYABORT;
		}
	}
	| PATH map options
	{
		path = master_strdup($1);
		if (!path) {
			local_free_vars();
			YYABORT;
		}
	} 
	| PATH COLON { master_notify($1); YYABORT; }
	| PATH OPTION { master_notify($2); YYABORT; }
	| PATH NILL { master_notify($2); YYABORT; }
	| PATH OPT_DEBUG { master_notify($1); YYABORT; }
	| PATH OPT_TIMEOUT { master_notify($1); YYABORT; }
	| PATH OPT_GHOST { master_notify($1); YYABORT; }
	| PATH OPT_NOGHOST { master_notify($1); YYABORT; }
	| PATH OPT_VERBOSE { master_notify($1); YYABORT; }
	| PATH { master_notify($1); YYABORT; }
	| QUOTE { master_notify($1); YYABORT; }
	| OPTION { master_notify($1); YYABORT; }
	| NILL { master_notify($1); YYABORT; }
	| COMMENT { YYABORT; }
	;

map:	PATH
	{
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, $1);
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPNAME
	{
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, $1);
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPHOSTS
	{
		type = master_strdup($1 + 1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
	}
	| MAPNULL
	{
		type = master_strdup($1 + 1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
	}
	| dnattrs
	{
		type = master_strdup("ldap");
		if (!type) {
			local_free_vars();
			YYABORT;
		}
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, $1);
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPTYPE COLON PATH
	{
		char *tmp = NULL;

		if ((tmp = strchr($1, ',')))
			*tmp++ = '\0';

		type = master_strdup($1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			format = master_strdup(tmp);
			if (!format) {
				local_free_vars();
				YYABORT;
			}
		}
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, $3);
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPTYPE COLON MAPNAME
	{
		char *tmp = NULL;

		if ((tmp = strchr($1, ',')))
			*tmp++ = '\0';

		type = master_strdup($1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			format = master_strdup(tmp);
			if (!format) {
				local_free_vars();
				YYABORT;
			}
		}
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, $3);
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPTYPE COLON dn
	{
		char *tmp = NULL;

		if ((tmp = strchr($1, ',')))
			*tmp++ = '\0';

		type = master_strdup($1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			format = master_strdup(tmp);
			if (!format) {
				local_free_vars();
				YYABORT;
			}
		}
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, $3);
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	;

dn:	DNSERVER dnattrs
	{
		strcpy($$, $1);
		strcat($$, $2);
	}
	| dnattrs
	{
		strcpy($$, $1);
	}
	|
	{
		master_notify("syntax error in dn");
		YYABORT;
	}
	;

dnattrs: DNATTR EQUAL DNNAME
	{
		if (strcasecmp($1, "cn") &&
		    strcasecmp($1, "ou") &&
		    strcasecmp($1, "automountMapName") &&
		    strcasecmp($1, "nisMapName")) {
			strcpy(errstr, $1);
			strcat(errstr, "=");
			strcat(errstr, $3);
			master_notify(errstr);
			YYABORT;
		}
		strcpy($$, $1);
		strcat($$, "=");
		strcat($$, $3);
	}
	| DNATTR EQUAL DNNAME COMMA dnattr
	{
		if (strcasecmp($1, "cn") &&
		    strcasecmp($1, "ou") &&
		    strcasecmp($1, "automountMapName") &&
		    strcasecmp($1, "nisMapName")) {
			strcpy(errstr, $1);
			strcat(errstr, "=");
			strcat(errstr, $3);
			master_notify(errstr);
			YYABORT;
		}
		strcpy($$, $1);
		strcat($$, "=");
		strcat($$, $3);
		strcat($$, ",");
		strcat($$, $5);
	}
	| DNATTR
	{
		master_notify($1);
		YYABORT;
	}
	| DNNAME
	{
		master_notify($1);
		YYABORT;
	}
	;

dnattr: DNATTR EQUAL DNNAME
	{
		if (!strcasecmp($1, "automountMapName") ||
		    !strcasecmp($1, "nisMapName")) {
			strcpy(errstr, $1);
			strcat(errstr, "=");
			strcat(errstr, $3);
			master_notify(errstr);
			YYABORT;
		}
		strcpy($$, $1);
		strcat($$, "=");
		strcat($$, $3);
	}
	| DNATTR EQUAL DNNAME COMMA dnattr
	{
		if (!strcasecmp($1, "automountMapName") ||
		    !strcasecmp($1, "nisMapName")) {
			strcpy(errstr, $1);
			strcat(errstr, "=");
			strcat(errstr, $3);
			master_notify(errstr);
			YYABORT;
		}
		strcpy($$, $1);
		strcat($$, "=");
		strcat($$, $3);
		strcat($$, ",");
		strcat($$, $5);
	}
	| DNATTR
	{
		master_notify($1);
		YYABORT;
	}
	| DNNAME
	{
		master_notify($1);
		YYABORT;
	}
	;

options: option {}
	| options COMMA option {}
	| options option {}
	| options COMMA COMMA option
	{
		master_notify($1);
		YYABORT;
	}
	| options EQUAL
	{
		master_notify($1);
		YYABORT;
	}
	;

option: daemon_option
	| mount_option {}
	| error
	{
		master_notify("bogus option");
		YYABORT;
	}
	;

daemon_option: OPT_TIMEOUT NUMBER { timeout = $2; }
	| OPT_NOGHOST	{ ghost = 0; }
	| OPT_GHOST	{ ghost = 1; }
	| OPT_VERBOSE	{ verbose = 1; }
	| OPT_DEBUG	{ debug = 1; }
	;

mount_option: OPTION
	{
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, $1);
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	;
%%

#if YYDEBUG
static int master_fprintf(FILE *f, char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_DEBUG, msg, ap);
	va_end(ap);
	return 1;
}
#endif

static char *master_strdup(char *str)
{
	char *tmp;

	tmp = strdup(str);
	if (!tmp)
		master_error("memory allocation error");
	return tmp;
}

static int master_error(const char *s)
{
	error(LOGOPT_ANY, "%s while parsing map.", s);
	return 0;
}

static int master_notify(const char *s)
{
	warn(LOGOPT_ANY, "syntax error in map near [ %s ]", s);
	return(0);
}

static void local_init_vars(void)
{
	path = NULL;
	type = NULL;
	format = NULL;
	verbose = 0;
	debug = 0;
	timeout = -1;
	ghost = defaults_get_browse_mode();
	local_argv = NULL;
	local_argc = 0;
}

static void local_free_vars(void)
{
	if (path)
		free(path);

	if (type)
		free(type);

	if (format)
		free(format);

	if (local_argv)
		free_argv(local_argc, (const char **) local_argv);
}

void master_init_scan(void)
{
	lineno = 0;
}

int master_parse_entry(const char *buffer, unsigned int default_timeout, unsigned int logging, time_t age)
{
	struct master *master = master_list;
	struct mapent_cache *nc;
	struct master_mapent *entry, *new;
	struct map_source *source;
	unsigned int logopt = logging;
	int ret;

	local_init_vars();

	lineno++;

	master_set_scan_buffer(buffer);

	ret = master_parse();
	if (ret != 0) {
		local_free_vars();
		return 0;
	}

	nc = master->nc;

	/* Add null map entries to the null map cache */
	if (type && !strcmp(type, "null")) {
		cache_writelock(nc);
		cache_update(nc, path, NULL, lineno);
		cache_unlock(nc);
		local_free_vars();
		return 1;
	}

	/* Ignore all subsequent matching nulled entries */
	cache_readlock(nc);
	if (cache_lookup_distinct(nc, path)) {
		cache_unlock(nc);
		local_free_vars();
		return 1;
	}
	cache_unlock(nc);

	if (debug || verbose) {
		logopt = (debug ? LOGOPT_DEBUG : 0);
		logopt |= (verbose ? LOGOPT_VERBOSE : 0);
	}

	if (timeout < 0)
		timeout = default_timeout;

	new = NULL;
	entry = master_find_mapent(master, path);
	if (!entry) {
		new = master_new_mapent(master, path, age);
		if (!new) {
			local_free_vars();
			return 0;
		}
		entry = new;
	} else {
		if (entry->age && entry->age == age) {
			if (strcmp(path, "/-")) {
				warn(LOGOPT_VERBOSE,
				     "ignoring duplicate indirect mount %s",
				     path);
				local_free_vars();
				return 0;
			}
		}
	}

	if (!entry->ap) {
		ret = master_add_autofs_point(entry, timeout, logopt, ghost, 0);
		if (!ret) {
			error(LOGOPT_ANY, "failed to add autofs_point");
			if (new)
				master_free_mapent(new);
			local_free_vars();
			return 0;
		}
		set_mnt_logging(entry->ap);
	} else {
		struct autofs_point *ap = entry->ap;
		time_t tout = timeout;

		/*
		 * Second and subsequent instances of a mount point
		 * use the ghost, log and timeout of the first
		 */
		if (entry->age < age) {
			ap->ghost = ghost;
			ap->logopt = logopt;
			ap->exp_timeout = timeout;
			ap->exp_runfreq = (ap->exp_timeout + CHECK_RATIO - 1) / CHECK_RATIO;
			if (ap->ioctlfd != -1 && ap->type == LKP_INDIRECT)
				ioctl(ap->ioctlfd, AUTOFS_IOC_SETTIMEOUT, &tout);
		}
		set_mnt_logging(ap);
	}

/*
	source = master_find_map_source(entry, type, format,
					local_argc, (const char **) local_argv); 
	if (!source)
		source = master_add_map_source(entry, type, format, age, 
					local_argc, (const char **) local_argv);
	else
		source->age = age;
*/
	source = master_add_map_source(entry, type, format, age, 
					local_argc, (const char **) local_argv);
	if (!source) {
		error(LOGOPT_ANY, "failed to add source");
		if (new)
			master_free_mapent(new);
		local_free_vars();
		return 0;
	}

	if (!source->mc) {
		source->mc = cache_init(source);
		if (!source->mc) {
			error(LOGOPT_ANY, "failed to init source cache");
			if (new)
				master_free_mapent(new);
			local_free_vars();
			return 0;
		}
	}
	source->master_line = lineno;

	entry->age = age;
	entry->current = NULL;

	if (new)
		master_add_mapent(master, entry);

	local_free_vars();

	return 1;
}

