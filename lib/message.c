/* ----------------------------------------------------------------------- *
 *
 *  message.c - message control subroutines
 *
 *   Copyright 2002-2003 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <syslog.h>
#include <stdarg.h>
#include <alloca.h>

static int do_verbose = 0;
static int do_debug = 0;

void enable_verbose(void)
{
	do_verbose = 1;
	return;
}

void disable_verbose(void)
{
	do_verbose = 0;
	return;
}

int get_verbose(void)
{
	return do_verbose;
}

void enable_debug(void)
{
	do_debug = 1;
	return;
}

void disable_debug(void)
{
	do_debug = 0;
	return;
}

int get_debug(void)
{
	return do_debug;
}

void info(char *msg, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;

	if (!do_verbose && !do_debug)
		return;

	va_start(arg, msg);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc)))
		return;

	va_start(arg, msg);
	p = argv;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	vsyslog(LOG_INFO, msg, (va_list) argv);

	return;
}

void warn(char *msg, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;

	if (!do_verbose && !do_debug)
		return;

	va_start(arg, msg);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc)))
		return;

	va_start(arg, msg);
	p = argv;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	vsyslog(LOG_WARNING, msg, (va_list) argv);

	return;
}

void error(char *msg, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;

	va_start(arg, msg);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc)))
		return;

	va_start(arg, msg);
	p = argv;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	vsyslog(LOG_ERR, msg, (va_list) argv);

	return;
}

void crit(char *msg, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;

	va_start(arg, msg);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc)))
		return;

	va_start(arg, msg);
	p = argv;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	vsyslog(LOG_CRIT, msg, (va_list) argv);

	return;
}

void debug(char *msg, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;

	if (!do_debug)
		return;

	va_start(arg, msg);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc)))
		return;

	va_start(arg, msg);
	p = argv;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	vsyslog(LOG_DEBUG, msg, (va_list) argv);

	return;
}

