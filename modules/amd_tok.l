%{
/* ----------------------------------------------------------------------- *
 *
 *  Copyright 2013 Ian Kent <raven@themaw.net>
 *  Copyright 2013 Red Hat, Inc.
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *  USA; either version 2 of the License, or (at your option) any later
 *  version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#ifdef ECHO
# undef ECHO
#endif
static void amd_echo(void);	/* forward definition */
#define ECHO amd_echo()
int amd_wrap(void);

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "amd_parse.tab.h"

int amd_lex(void);
int mad_wrap(void);

#define YY_SKIP_YYWRAP

#ifndef YY_STACK_USED
#define YY_STACK_USED 0
#endif
#ifndef YY_ALWAYS_INTERACTIVE
#define YY_ALWAYS_INTERACTIVE 0
#endif
#ifndef YY_NEVER_INTERACTIVE
#define YY_NEVER_INTERACTIVE 0
#endif
#ifndef YY_MAIN
#define YY_MAIN 0
#endif

void amd_set_scan_buffer(const char *);
static const char *line = NULL;

#ifdef FLEX_SCANNER
static const char *line_pos = NULL;
static const char *line_lim = NULL;
int amd_yyinput(char *, int);

#undef YY_INPUT
#define YY_INPUT(b, r, ms) (r = amd_yyinput(b, ms))
#else
#undef input
#undef unput
#define input()  (*(char *) line++)
#define unput(c) (*(char *) --line = c)
#endif

%}

%option nounput

%x MAPOPTVAL FSOPTVAL MNTOPTVAL SELOPTVAL

NL		\r?\n
OPTWS		[[:blank:]]*
OTHR		[^!;:=/|\- \t\r\n#]*

MACRO		(\$\{([[:alpha:]_/]([[:alnum:]_\-])([[:alnum:]_\-/])*)\})
QSTR		(\"([^"\\]|\\.)*\")
OSTR		([[:alpha:]]([[:alnum:]_\-])+)
FSTR		([[:alnum:]_/\.]([[:alnum:]_\-/\.]|(\\.))*)
VSTR		(([[:alnum:]_\-\:/\.])+)
SSTR		([[:alpha:]]([[:alnum:]\-\.])+)

FOPT		(({QSTR}|{FSTR}|{MACRO})+)
OPTS		({OSTR}(=({VSTR}|{QSTR}|{MACRO})+)?)
SOPT		(({SSTR}|{QSTR}|{MACRO})+)

MAPOPT		(fs|type|maptype|pref|sublink|delay)
MNTOPT		(opts|addopts|remopts)
FSOPTS		(rhost|rfs|dev|cachedir)
MAPTYPE		(file|nis|nisplus|ldap|hesiod|exec|ndbm|passwd|union)
FSTYPE		(auto|nfs|link|host|nfsx|ufs|xfs|efs)

OSSEL		(arch|karch|os|osver|full_os|vendor)
HSTSEL		(host|hostd|xhost|domain|byte|cluster)
NETSEL		(netnumber|network|wire|netgrp|netgrpd|in_network)
USRSEL		(uid|gid)
MAPSEL		(key|map|path)
OTRSEL		(exists|autodir|dollar)
BOLSEL		(true|false)
SELOPT		({OSSEL}|{HSTSEL}|{NETSEL}|{BOLSEL}|{USRSEL}|{MAPSEL}|{OTRSEL})

CUTSEP		(\|\||\/)

%%

<INITIAL>{
	{NL} |
	\x00 { }

	{MAPOPT} {
		BEGIN(MAPOPTVAL);
		strcpy(amd_lval.strtype, amd_text);
		return MAP_OPTION;

	}

	{FSOPTS} {
		BEGIN(FSOPTVAL);
		strcpy(amd_lval.strtype, amd_text);
		return FS_OPTION;
	}

	{MNTOPT} {
		BEGIN(MNTOPTVAL);
		strcpy(amd_lval.strtype, amd_text);
		return MNT_OPTION;
	}

	{SELOPT} {
		BEGIN(SELOPTVAL);
		strcpy(amd_lval.strtype, amd_text);
		return SELECTOR;
	}

	{CUTSEP} { return CUT; }

	"-" { return HYPHEN; }

	{OPTWS} { return SPACE; }

	#.*  { return COMMENT; }

	{OTHR} {
		strcpy(amd_lval.strtype, amd_text);
		return OTHER;
	}
}

<MAPOPTVAL>{
	{NL} |
	\x00 {
		BEGIN(INITIAL);
		yyless(1);
	}

	";" {
		BEGIN(INITIAL);
		return SEPERATOR;
	}

	{OPTWS} {
		BEGIN(INITIAL);
		return SPACE;
	}

	":=" { return OPTION_ASSIGN; }

	{FSTYPE} {
		strcpy(amd_lval.strtype, amd_text);
		return FS_TYPE;
	}

	{MAPTYPE} {
		strcpy(amd_lval.strtype, amd_text);
		return MAP_TYPE;
	}

	{FOPT} {
		strcpy(amd_lval.strtype, amd_text);
		return FS_OPT_VALUE;
	}
}

<FSOPTVAL>{
	{NL} |
	\x00 {
		BEGIN(INITIAL);
		yyless(1);
	}

	";" {
		BEGIN(INITIAL);
		return SEPERATOR;
	}

	{OPTWS} {
		BEGIN(INITIAL);
		return SPACE;
	}

	":=" { return OPTION_ASSIGN; }

	{FOPT} {
		strcpy(amd_lval.strtype, amd_text);
		return FS_OPT_VALUE;
	}
}

<MNTOPTVAL>{
	{NL} |
	\x00 {
		BEGIN(INITIAL);
		yyless(1);
	}

	";" {
		BEGIN(INITIAL);
		return SEPERATOR;
	}

	{OPTWS} {
		BEGIN(INITIAL);
		return SPACE;
	}

	":=" { return OPTION_ASSIGN; }

	"," { return COMMA; }

	{OPTS} {
		strcpy(amd_lval.strtype, amd_text);
		return OPTION;
	}
}

<SELOPTVAL>{
	{NL} |
	\x00 {
		BEGIN(INITIAL);
		yyless(1);
	}

	";" {
		BEGIN(INITIAL);
		return SEPERATOR;
	}

	{OPTWS} {
		BEGIN(INITIAL);
		return SPACE;
	}

	"==" { return IS_EQUAL; }

	"!=" { return NOT_EQUAL; }

	{SOPT} {
		strcpy(amd_lval.strtype, amd_text);
		return SELECTOR_VALUE;
	}
}

%%

#include "automount.h"

int amd_wrap(void)
{
	return 1;
}

static void amd_echo(void)
{
	logmsg("%s\n", amd_text);
	return;
}

#ifdef FLEX_SCANNER

void amd_set_scan_buffer(const char *buffer)
{
	line = buffer;
	line_pos = &line[0];
	/*
	 * Ensure buffer is 1 greater than string and is zeroed before
	 * the parse so we can fit the extra NULL which allows us to
	 * explicitly match an end of line within the buffer (ie. the
	 * need for 2 NULLS when parsing in memeory buffers).
	 */
	line_lim = line + strlen(buffer) + 1;
}

#define amd_min(a,b) (((a) < (b)) ? (a) : (b))

int amd_yyinput(char *buffer, int max_size)
{
	int n = amd_min(max_size, line_lim - line_pos);

	if (n > 0) {
		memcpy(buffer, line_pos, n);
		line_pos += n;
	}
	return n;
}

#else

void amd_set_scan_buffer(const char *buffer)
{
	line = buffer;
}

#endif
