#ident "$Id: lock.c,v 1.2 2005/01/09 11:51:36 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  lock.c - autofs lockfile management
 *
 *   Copyright 2004 Ian Kent <raven@themaw.net>
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
 *   This code has adapted from that found in mount/fstab.c of the
 *   util-linux package.
 *
 * ----------------------------------------------------------------------- */

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <alloca.h>
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>

#include "automount.h"

static void setup_locksigs(void);
static void reset_locksigs(void);

/*
 * If waiting for 30 secs is not enough then there's
 * probably no good the requestor continuing anyway?
 */
#define LOCK_TIMEOUT    30
#define LOCK_RETRIES    3
#define MAX_PIDSIZE	20

#define LOCK_FILE     AUTOFS_LOCK

/* Flag for already existing lock file. */
static int we_created_lockfile = 0;

/* Flag to indicate that signals have been set up. */
static int signals_have_been_setup = 0;

/* Save previous actions */
static struct sigaction actions[NSIG];
static struct itimerval timer = {{0, 0}, {LOCK_TIMEOUT, 0}};
static time_t alarm_remaining;

/* Flag to identify we got a TERM signal */
static int got_term = 0;

/* file descriptor of lock file */
static int fd = -1;

/* Ignore all signals except for SIGTERM */
static void handler(int sig)
{
	if (sig == SIGQUIT || sig == SIGTERM ||
	    sig == SIGUSR2 || sig == SIGINT)
		got_term = 1;
}

static void setlkw_timeout(int sig)
{
     /* nothing, fcntl will fail anyway */
}

static int lock_is_owned(int fd)
{
	char pidbuf[MAX_PIDSIZE];
	int pid = 0;
	int ret, got;

	got = read(fd, pidbuf, MAX_PIDSIZE);
	if (got > 0)
		sscanf(pidbuf, "%d", &pid);

	if (pid) {
		ret = kill(pid, SIGCONT);
		/* 
		 * If lock file exists but is not owned we return
		 * unowned status so we can get rid of it and
		 * continue.
		 */
		if (ret == -1 && errno == ESRCH)
			return 0;
	} else {
		/*
		 * Odd, no pid in file - so what should we do?
		 * Assume something bad happened to owner and
		 * return unowned status.
		 */
		return 0;
	}
	return 1;
}

static void setup_locksigs(void)
{
	int sig = 0;
	struct sigaction sa;

	sa.sa_handler = handler;
	sa.sa_flags = 0;
	sigfillset(&sa.sa_mask);

	sigprocmask(SIG_BLOCK, &sa.sa_mask, NULL);
	alarm_remaining = alarm(0);

	while (sigismember(&sa.sa_mask, ++sig) != -1
			&& sig != SIGCHLD) {
		sigaction(sig, &sa, &actions[sig]);
	}

	sigaction(SIGUSR1, &sa, &actions[SIGUSR1]);
	sigaction(SIGUSR2, &sa, &actions[SIGUSR2]);
	
	sa.sa_handler = setlkw_timeout;
	sigaction(SIGVTALRM, &sa, &actions[SIGVTALRM]);

	signals_have_been_setup = 1;
	sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);
}

static void reset_locksigs(void)
{
	int sig = 0;
	sigset_t fullset;
	
	sigfillset(&fullset);
	sigprocmask(SIG_BLOCK, &fullset, NULL);

	while (sigismember(&fullset, ++sig) != -1
			&& sig != SIGCHLD) {
		sigaction(sig, &actions[sig], NULL);
	}

	sigaction(SIGUSR1, &actions[SIGUSR1], NULL);
	sigaction(SIGUSR2, &actions[SIGUSR2], NULL);
	sigaction(SIGVTALRM, &actions[SIGVTALRM], NULL);
	
	signals_have_been_setup = 0;
	alarm(alarm_remaining);
	sigprocmask(SIG_UNBLOCK, &fullset, NULL);
}

/* Remove lock file. */
void release_lock(void)
{
	if (we_created_lockfile) {
		close(fd);
		fd = -1;
		unlink (LOCK_FILE);
		we_created_lockfile = 0;
	}

	if (signals_have_been_setup)
		reset_locksigs();
}

/*
 * Aquire lock file taking account of autofs signals.
 */
int aquire_lock(void)
{
	int tries = 3;
	char *linkf;
	int len;

	if (!signals_have_been_setup)
		setup_locksigs();

	len = strlen(LOCK_FILE) + MAX_PIDSIZE;
	linkf = alloca(len + 1);
	snprintf(linkf, len, "%s.%d", LOCK_FILE, getpid());

	/* Repeat until it was us who made the link */
	while (!we_created_lockfile) {
		struct flock flock;
		int errsv, i, j;

		i = open(linkf, O_WRONLY|O_CREAT, 0);
		if (i < 0) {
			release_lock();
			return(0);
		}
		close(i);

		j = link(linkf, LOCK_FILE);
		errsv = errno;

		(void) unlink(linkf);

		if (j < 0 && errsv != EEXIST) {
			release_lock();
			return 0;
		}

		/* Maybe someone has this open from last time */
		if (fd < 0)
			fd = open(LOCK_FILE, O_RDWR);

		if (fd < 0) {
			int errsv = errno;
			/* Maybe the file was just deleted? */
			if (errno == ENOENT && tries-- > 0)
				continue;
			release_lock();
			return 0;
		}

		flock.l_type = F_WRLCK;
		flock.l_whence = SEEK_SET;
		flock.l_start = 0;
		flock.l_len = 0;

		if (j == 0) {
			char pidbuf[MAX_PIDSIZE];
			int pidlen;

			/* We made the link. Now claim the lock. */
			if (fcntl(fd, F_SETLK, &flock) == -1) {
				warn("aquire_lock: Can't get lock for %s: %s\n",
				       LOCK_FILE, strerror(errno));
				/* proceed anyway */
			}

			pidlen = sprintf(pidbuf, "%d\n", getpid());
			write(fd, pidbuf, pidlen);

			we_created_lockfile = 1;
		} else {
			static int tries = 0;

			/*
			 * Someone else made the link.
			 * If the lock file is not owned by anyone
			 * clean it up and try again, otherwise we
			 * wait.
			 */
			if (!lock_is_owned(fd)) {
				close(fd);
				fd = -1;
				unlink(LOCK_FILE);
				continue;
			}

			setitimer(ITIMER_VIRTUAL, &timer, NULL);
			if (fcntl(fd, F_SETLKW, &flock) == -1) {
				int errsv = errno;

				/* Limit the number of iterations */
				if (errsv == EINTR || tries++ > LOCK_RETRIES) {
					char *error = (errsv == EINTR) ?
						"timed out" : strerror(errno);

					crit("aquire_lock: can't lock lock file %s: %s",
						LOCK_FILE, error);

					close(fd);
					fd = -1;
					return 0;
				}

			}
		}

		if (got_term) {
			got_term = 0;
			if (we_created_lockfile)
				release_lock();
			else {
				close(fd);
				fd = -1;
			}
			return(0);
		}
	}

	reset_locksigs();
	return 1;
}

