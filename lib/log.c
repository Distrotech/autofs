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
 *  This module has been adapted from patches submitted by:
 *	Denis Vlasenko <vda@port.imtp.ilyichevsk.odessa.ua>
 *	Thanks Denis.
 *
 * ----------------------------------------------------------------------- */

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "automount.h"

/*
struct syslog_data syslog_context = AUTOFS_SYSLOG_CONTEXT;
struct syslog_data *slc = &syslog_context;
*/

static unsigned int syslog_open = 0;
static unsigned int logging_to_syslog = 0;

/* log notification level */
static unsigned int do_verbose = 0;		/* Verbose feedback option */
static unsigned int do_debug = 0;		/* Full debug output */

static void null(unsigned int logopt, const char *msg, ...) { }

void (*log_info)(unsigned int logopt, const char* msg, ...) = null;
void (*log_notice)(unsigned int logopt, const char* msg, ...) = null;
void (*log_warn)(unsigned int logopt, const char* msg, ...) = null;
void (*log_error)(unsigned int logopt, const char* msg, ...) = null;
void (*log_crit)(unsigned int logopt, const char* msg, ...) = null;
void (*log_debug)(unsigned int logopt, const char* msg, ...) = null;

void set_log_norm(void)
{
	do_verbose = 0;
	do_debug = 0;
}

void set_log_verbose(void)
{
	do_verbose = 1;
}

void set_log_debug(void)
{
	do_debug = 1;
}

static void syslog_info(unsigned int logopt, const char *msg, ...)
{
	unsigned int opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
	va_list ap;

	if (!do_debug && !do_verbose && !opt_log)
		return;

	va_start(ap, msg);
	vsyslog(LOG_INFO, msg, ap);
	va_end(ap);
}

static void syslog_notice(unsigned int logopt, const char *msg, ...)
{
	unsigned int opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
	va_list ap;

	if (!do_debug && !do_verbose && !opt_log)
		return;

	va_start(ap, msg);
	vsyslog(LOG_NOTICE, msg, ap);
	va_end(ap);
}

static void syslog_warn(unsigned int logopt, const char *msg, ...)
{
	unsigned int opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
	va_list ap;

	if (!do_debug && !do_verbose && !opt_log)
		return;

	va_start(ap, msg);
	vsyslog(LOG_WARNING, msg, ap);
	va_end(ap);
}

static void syslog_err(unsigned int logopt, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_ERR, msg, ap);
	va_end(ap);
}

static void syslog_crit(unsigned int logopt, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_CRIT, msg, ap);
	va_end(ap);
}

static void syslog_debug(unsigned int logopt, const char *msg, ...)
{
	va_list ap;

	if (!do_debug && !(logopt & LOGOPT_DEBUG))
		return;

	va_start(ap, msg);
	vsyslog(LOG_DEBUG, msg, ap);
	va_end(ap);
}

static void to_stderr(unsigned int logopt, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	fputc('\n',stderr);
	va_end(ap);
}

void set_mnt_logging(struct autofs_point *ap)
{
	unsigned int opt_verbose = ap->logopt & LOGOPT_VERBOSE;
	unsigned int opt_debug = ap->logopt & LOGOPT_DEBUG;

	if (opt_debug) {
		if (logging_to_syslog)
			log_debug = syslog_debug;
		else
			log_debug = to_stderr;
	}

	if (opt_verbose || opt_debug) {
		if (logging_to_syslog) {
			log_info = syslog_info;
			log_notice = syslog_notice;
			log_warn = syslog_warn;
		} else {
			log_info = to_stderr;
			log_notice = to_stderr;
			log_warn = to_stderr;
		}
	}
}

void log_to_syslog(void)
{
	char buf[MAX_ERR_BUF];
	int nullfd;

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

	logging_to_syslog = 1;

	/* Redirect all our file descriptors to /dev/null */
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		syslog_crit(LOGOPT_ANY, "cannot open /dev/null: %s", estr);
		exit(1);
	}

	if (dup2(nullfd, STDIN_FILENO) < 0 ||
	    dup2(nullfd, STDOUT_FILENO) < 0 ||
	    dup2(nullfd, STDERR_FILENO) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		syslog_crit(LOGOPT_ANY,
			    "redirecting file descriptors failed: %s", estr);
		exit(1);
	}

	if (nullfd > 2)
		close(nullfd);
}

void log_to_stderr(void)
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

	logging_to_syslog = 0;
}
