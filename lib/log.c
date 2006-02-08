#ident "$Id: log.c,v 1.1 2006/02/08 16:50:32 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  log.c - applcation logging routines.
 *
 *   Copyright 2004 Denis Vlasenko <vda@port.imtp.ilyichevsk.odessa.ua>
 *				 - All Rights Reserved
 *   Copyright 2005 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "automount.h"

/* re-entrant syslog default context data */
#define AUTOFS_SYSLOG_CONTEXT {-1, 0, 0, LOG_PID, (const char *) 0, LOG_DAEMON, 0xff};

/*
struct syslog_data syslog_context = AUTOFS_SYSLOG_CONTEXT;
struct syslog_data *slc = &syslog_context;
*/

static unsigned int syslog_open = 0;

/* log notification level */
static unsigned int do_verbose = 0;		/* Verbose feedback option */
static unsigned int do_debug = 0;		/* Full debug output */

static void null(const char *msg, ...) { }

void (*log_info)(const char* msg, ...) = null;
void (*log_notice)(const char* msg, ...) = null;
void (*log_warn)(const char* msg, ...) = null;
void (*log_error)(const char* msg, ...) = null;
void (*log_crit)(const char* msg, ...) = null;
void (*log_debug)(const char* msg, ...) = null;

void set_log_norm(void)
{
	do_verbose = 0;
	do_debug = 0;
}

void set_log_verbose(void)
{
	do_verbose = 1;
}

unsigned int is_log_verbose(void)
{
	return do_verbose;
}

void set_log_debug(void)
{
	do_debug = 1;
}

unsigned int is_log_debug(void)
{
	return do_debug;
}

static void syslog_info(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_INFO, msg, ap);
	va_end(ap);
}

static void syslog_notice(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_NOTICE, msg, ap);
	va_end(ap);
}

static void syslog_warn(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_WARNING, msg, ap);
	va_end(ap);
}

static void syslog_err(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_ERR, msg, ap);
	va_end(ap);
}

static void syslog_crit(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_CRIT, msg, ap);
	va_end(ap);
}

static void syslog_debug(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_DEBUG, msg, ap);
	va_end(ap);
}

static void to_stderr(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	fputc('\n',stderr);
	va_end(ap);
}

void log_to_syslog()
{
	if (!syslog_open) {
		syslog_open = 1;
		openlog("automount", LOG_PID, LOG_DAEMON);
	}

	if (do_debug)
		log_debug = syslog_debug;
	else
		log_debug = null;

	if (do_verbose || do_debug) {
		log_info = syslog_info;
		log_notice = syslog_notice;
		log_warn = syslog_warn;
	} else {
		log_info = null;
		log_notice = null;
		log_warn = null;
	}

	log_error = syslog_err;
	log_crit = syslog_crit;
}

void log_to_stderr()
{
	if (syslog_open) {
		syslog_open = 0;
		closelog();
	}

	if (do_debug)
		log_debug = to_stderr;
	else
		log_debug = null;

	if (do_verbose || do_debug) {
		log_info = to_stderr;
		log_notice = to_stderr;
		log_warn = to_stderr;
	} else {
		log_info = null;
		log_notice = null;
		log_warn = null;
	}

	log_error = to_stderr;
	log_crit = to_stderr;
}
