%{
/* ----------------------------------------------------------------------- *
 *   
 *  "$Id: master_tok.l,v 1.2 2006/03/26 17:26:32 raven Exp $"
 *
 *  master_tok.l - master map tokenizer.
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

#ifdef ECHO
# undef ECHO
#endif /* ECHO */
static void master_echo(void);	/* forward definition */
#define ECHO master_echo()

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "master_parse.tab.h"

/*
 * There are some things that need to be defined only if useing GNU flex.
 * These must not be defined if using standard lex
 */
#ifdef FLEX_SCANNER
int master_lineno;
#endif

int master_lex(void);
int master_wrap(void);

/* no need for yywrap() */
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

void master_set_scan_buffer(const char *);
const char *line = NULL;

#ifdef FLEX_SCANNER
const char *line_pos = NULL;
const char *line_lim = NULL;
int my_yyinput(char *, int);

#undef YY_INPUT
#define YY_INPUT(b, r, ms) (r = my_yyinput(b, ms))
#else
#undef input
#undef unput
#define input()  (*(char *) line++)
#define unput(c) (*(char *) --line = c)
#endif

char buff[1024];
char *bptr;

%}

%option nounput

%x PATHSTR MAPSTR DNSTR OPTSTR

WS		[[:blank:]]+
OPTWS		[[:blank:]]*
NL		\r?\n
CONT		\\\n{OPTWS}

OPTIONSTR	([\-]?([[:alpha:]_]([[:alnum:]_\-])*(=([[:alnum:]_\-])+)*)+)
MACROSTR	(-D{OPTWS}([[:alpha:]_]([[:alnum:]_\-])*)=([[:alnum:]_\-])+)
NUMBER		[0-9]+

DNSERVSTR1	([[:alpha:]][[:alnum:]\-.]*(:[0-9]+)?:)
DNSERVSTR2	(\/\/[[:alpha:]][[:alnum:]\-.]*(:[0-9]+)?\/)
DNSERVSTR3	(([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}(:[0-9]+)?:)
DNSERVSTR4	(\/\/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}(:[0-9]+)?\/)
DNSERVERSTR	{DNSERVSTR1}|{DNSERVSTR2}|{DNSERVSTR3}|{DNSERVSTR4}
DNATTRSTR	(cn|nisMapName|automountMapName|ou|dc|o|c)
DNNAMESTR	([[:alnum:]_.\-]+)

INTMAP		(-hosts|-null)
MTYPE           ((file|program|yp|nis|nisplus|ldap|hesiod|userdir)(,(sun|hesiod))?)


OPTTOUT		(-t{OPTWS}|-t{OPTWS}={OPTWS}|--timeout{OPTWS}|--timeout{OPTWS}={OPTWS})

%%

<INITIAL>{
	{NL} { }
	{WS} { }

	#.*  { return COMMENT; }

	"+" {
		BEGIN(MAPSTR);
		bptr = buff;
		yyless(0);
	}

	"/" {
		BEGIN(PATHSTR);
		bptr = buff;
		yyless(0);
	}

	"-" {
		BEGIN(OPTSTR);
		yyless(0);
	}
}

<PATHSTR>{
	\x00 {
		BEGIN(INITIAL);
		*bptr++ = *master_text;
		strcpy(master_lval.strtype, buff);
		return NILL;
	}

	{WS}/{INTMAP} {
		BEGIN(MAPSTR);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return(PATH);
	}

	{WS}/{DNATTRSTR}= {
		BEGIN(MAPSTR);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return(PATH);
	}

	{WS}/"-" {
		BEGIN(OPTSTR);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		bptr = buff;
		return(PATH);
	}

	{WS}/{OPTIONSTR} {
		BEGIN(OPTSTR);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		bptr = buff;
		return(PATH);
	}

	\\.  { *bptr++ = *(master_text + 1); }
	\"   {
		BEGIN(INITIAL);
		*bptr++ = *master_text;
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return QUOTE;
	}

	{WS} {
		BEGIN(MAPSTR);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		bptr = buff;
		return(PATH);
	}

	<<EOF>> {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return(PATH);
	}

	{NL} {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return PATH;
	}


	.    { *bptr++ = *master_text; }
}

<MAPSTR>{
	{OPTWS}\\\n{OPTWS} {}

	{MTYPE}/":" {
		strcpy(master_lval.strtype, master_text);
		return(MAPTYPE);
	}

	":"	{ return(COLON); }

	"-hosts" {
		BEGIN(OPTSTR);
		strcpy(master_lval.strtype, master_text);
		return MAPHOSTS;
	}

	"-null" {
		BEGIN(OPTSTR);
		strcpy(master_lval.strtype, master_text);
		return MAPNULL;
	}

	"//" {
		BEGIN(DNSTR);
		yyless(0);
	}

	{DNSERVERSTR} {
		BEGIN(DNSTR);
		yyless(0);
	}

	{DNATTRSTR}= {
		BEGIN(DNSTR);
		yyless(0);
	}

	"/" {
		BEGIN(PATHSTR);
		bptr = buff;
		yyless(0);
	}

	{OPTWS}/{NL} {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		bptr = buff;
		return(MAPNAME);
	}

	\\. { *bptr++ = *(master_text + 1); }

	{WS} {
		BEGIN(OPTSTR);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		bptr = buff;
		return(MAPNAME);
	}

	{NL} |
	<<EOF>> {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return(MAPNAME);
	}

	.	{ *bptr++ = *master_text; }
}

<DNSTR>{
	{OPTWS}\\\n{OPTWS} {}

	{DNSERVERSTR} {
		strcpy(master_lval.strtype, master_text);
		return DNSERVER;
	}

	{DNATTRSTR} {
		strcpy(master_lval.strtype, master_text);
		return DNATTR;
	}

	"=" {
		return EQUAL;
	}

	{DNNAMESTR} {
		strcpy(master_lval.strtype, master_text);
		return DNNAME;
	}

	{OPTWS}","{OPTWS} {
		return COMMA;
	}

	{WS}"=" |
	"="{WS} {
		BEGIN(INITIAL);
		strcpy(master_lval.strtype, master_text);
		return SPACE;
	}

	{WS}    { BEGIN(OPTSTR); }

	{NL} |
	<<EOF>>	{ BEGIN(INITIAL); }
}

<OPTSTR>{
	{OPTWS}\\\n{OPTWS} {}

	{OPTTOUT} { return(OPT_TIMEOUT); }

	-D{OPTWS}

	{NUMBER} {
		master_lval.longtype = atol(master_text);
		return(NUMBER);
	}

	-?nobrowse		{ return(OPT_NOGHOST); }
	-g|--ghost|-?browse	{ return(OPT_GHOST); }
	-v|--verbose		{ return(OPT_VERBOSE); }
	-d|--debug		{ return(OPT_DEBUG); }

	{OPTWS}","{OPTWS}	{ return(COMMA); }

	{OPTWS} {}

	{MACROSTR} {
		strcpy(master_lval.strtype, master_text);
		return(OPTION);
	}

	{OPTIONSTR} {
		strcpy(master_lval.strtype, master_text);
		return(OPTION);
	}

	"="	{
		strcpy(master_lval.strtype, master_text);
		return(EQUAL);
	}

	{WS}	{}
	{NL} |
	<<EOF>>	{ BEGIN(INITIAL); }
}

%%

#include "automount.h"

int master_wrap(void)
{
	return 1;
}

static void master_echo(void)
{
	debug(LOGOPT_NONE, "%s", master_text);
	return;
}

#ifdef FLEX_SCANNER

void master_set_scan_buffer(const char *buffer)
{
	line = buffer;
	line_pos = &line[0];
	line_lim = line + strlen(buffer);
}

#define min(a,b) (((a) < (b)) ? (a) : (b))

int my_yyinput(char *buffer, int max_size)
{
	int n = min(max_size, line_lim - line_pos);

	if (n > 0) {
		memcpy(buffer, line_pos, n);
		line_pos += n;
	}
	return n;
}

#else

void master_set_scan_buffer(const char *buffer)
{
	line = buffer;
}

#endif
