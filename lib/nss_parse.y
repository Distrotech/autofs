%{
/* ----------------------------------------------------------------------- *
 *   
 *  "$Id: nss_parse.y,v 1.5 2006/03/21 04:28:53 raven Exp $"
 *
 *  nss_parser.y - nsswitch parser.
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
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <limits.h>

#include "automount.h"
#include "nsswitch.h"
#include "nss_parse.tab.h"

static struct list_head *nss_list;
static struct nss_source *src;
struct nss_action act[NSS_STATUS_MAX];

#define YYDEBUG 0

#ifndef YYENABLE_NLS
#define YYENABLE_NLS 0
#endif
#ifndef YYLTYPE_IS_TRIVIAL
#define YYLTYPE_IS_TRIVIAL 0
#endif

extern int nss_lineno;
extern int nss_lex(void);
extern FILE *nss_in;

static int nss_error(const char *s);

%}

%union {
char strval[128];
}

%token LBRACKET RBRACKET EQUAL BANG NL
%token <strval> SOURCE
%token <strval> STATUS
%token <strval> ACTION
%token <strval> OTHER

%start file

%%

file: {
#if YYDEBUG != 0
		nss_debug = YYDEBUG;
#endif
	} sources NL
	;

sources: nss_source
	| nss_source sources
	;

nss_source: SOURCE
{
	src = add_source(nss_list, $1);
} | SOURCE LBRACKET status_exp_list RBRACKET
{
	enum nsswitch_status a;

	src = add_source(nss_list, $1);
	for (a = 0; a < NSS_STATUS_MAX; a++) {
		if (act[a].action != NSS_ACTION_UNKNOWN) {
			src->action[a].action = act[a].action;
			src->action[a].negated = act[a].negated;
		}
	}
} | SOURCE LBRACKET status_exp_list SOURCE { nss_error($4); YYABORT; }
  | SOURCE LBRACKET status_exp_list OTHER { nss_error($4); YYABORT; }
  | SOURCE LBRACKET status_exp_list NL { nss_error("no closing bracket"); YYABORT; }
  | SOURCE LBRACKET OTHER { nss_error($3); YYABORT; }
  | SOURCE OTHER { nss_error("no opening bracket"); YYABORT; }
  | error OTHER { nss_error($2); YYABORT; };

status_exp_list: status_exp
		| status_exp status_exp_list

status_exp: STATUS EQUAL ACTION
{
	set_action(act, $1, $3, 0);
} | BANG STATUS EQUAL ACTION
{
	set_action(act, $2, $4, 1);
} | STATUS EQUAL OTHER {nss_error($3); YYABORT; }
  | STATUS OTHER {nss_error($2); YYABORT; }
  | BANG STATUS EQUAL OTHER {nss_error($4); YYABORT; }
  | BANG STATUS OTHER {nss_error($3); YYABORT; }
  | BANG OTHER {nss_error($2); YYABORT; };

%%

static int nss_error(const char *s)
{
	msg("syntax error in nsswitch config near [ %s ]\n", s);
	return(0);
}

int nsswitch_parse(struct list_head *list)
{
	FILE *nsswitch;
	int status;

	nsswitch = fopen(NSSWITCH_FILE, "r");
	if (!nsswitch) {
		error(LOGOPT_ANY, "couldn't open %s\n", NSSWITCH_FILE);
		return 1;
	}
	nss_in = nsswitch;

	nss_list = list;
	status = nss_parse();
	nss_list = NULL;
	if (status)
		return 1;

	return 0;
}
