#ident "$Id: log.h,v 1.1 2006/03/29 10:32:36 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  log.c - applcation logging declarations.
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

#ifndef LOG_H
#define LOG_H

/* Define logging functions */

#define LOGOPT_NONE	0x0000
#define LOGOPT_DEBUG	0x0001
#define LOGOPT_VERBOSE	0x0002

extern void set_log_norm(void);
extern void set_log_verbose(void);
extern unsigned int is_log_verbose(void);
extern void set_log_debug(void);
extern unsigned int is_log_debug(void);

extern void log_to_syslog(void);
extern void log_to_stderr(void);
 
typedef void logger(const char* msg, ...);

extern void (*log_info)(const char* msg, ...);
extern void (*log_notice)(const char* msg, ...);
extern void (*log_warn)(const char* msg, ...);
extern void (*log_error)(const char* msg, ...);
extern void (*log_crit)(const char* msg, ...);
extern void (*log_debug)(const char* msg, ...);

#define msg(msg, args...)	\
	do { log_info(msg, ##args); } while (0)

#define debug(msg, args...)	\
	do { log_debug("%s: " msg,  __FUNCTION__, ##args); } while (0)

#define info(msg, args...)	\
	do { log_info("%s: " msg,  __FUNCTION__, ##args); } while (0)

#define notice(msg, args...)	\
	do { log_notice("%s: " msg,  __FUNCTION__, ##args); } while (0)

#define warn(msg, args...)	\
	do { log_warn("%s: " msg,  __FUNCTION__, ##args); } while (0)

#define error(msg, args...)	\
	do { log_error("%s: " msg,  __FUNCTION__, ##args); } while (0)

#define crit(msg, args...)	\
	do { log_crit("%s: " msg,  __FUNCTION__, ##args); } while (0)

#define fatal(status)						    \
	do {							    \
		if (status == EDEADLK) {			    \
			log_crit("%s: deadlock detected "	    \
				 "at line %d in %s, dumping core.", \
				 __FUNCTION__, __LINE__, __FILE__); \
			dump_core();				    \
		}						    \
		log_crit("unexpected pthreads error: %d at %d "	    \
			 "in %s", status, __LINE__, __FILE__);	    \
		abort();					    \
	} while(0)

#ifndef NDEBUG
#define assert(x)							\
do {									\
	if (!(x)) {							\
		crit(__FILE__ ":%d: assertion failed: " #x, __LINE__);	\
	}								\
} while(0)
#else
#define assert(x)	do { } while(0)
#endif

#endif

