/* ----------------------------------------------------------------------- *
 * 
 *  spawn.c - run programs synchronously with output redirected to syslog
 *   
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2005 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "automount.h"

#ifdef ENABLE_MOUNT_LOCKING
static pthread_mutex_t spawn_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

inline void dump_core(void)
{
	sigset_t segv;

	sigemptyset(&segv);
	sigaddset(&segv, SIGSEGV);
	pthread_sigmask(SIG_UNBLOCK, &segv, NULL);
	sigprocmask(SIG_UNBLOCK, &segv, NULL);

	raise(SIGSEGV);
}

/*
 * Used by subprocesses which exec to avoid carrying over the main
 * daemon's signalling environment
 */
void reset_signals(void)
{
	struct sigaction sa;
	sigset_t allsignals;
	int i;

	sigfillset(&allsignals);
	sigprocmask(SIG_BLOCK, &allsignals, NULL);

	/* Discard all pending signals */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	for (i = 1; i < NSIG; i++)
		if (i != SIGKILL && i != SIGSTOP)
			sigaction(i, &sa, NULL);

	sa.sa_handler = SIG_DFL;

	for (i = 1; i < NSIG; i++)
		if (i != SIGKILL && i != SIGSTOP)
			sigaction(i, &sa, NULL);

	/* Ignore the user signals that may be sent so that we
	 *  don't terminate execed program by mistake */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	sigprocmask(SIG_UNBLOCK, &allsignals, NULL);
}

#define ERRBUFSIZ 2047		/* Max length of error string excl \0 */

#ifdef ENABLE_MOUNT_LOCKING
void spawn_unlock(void *arg)
{
	int *use_lock = (int *) arg;

	if (*use_lock) {
		if (pthread_mutex_unlock(&spawn_mutex))
			warn(LOGOPT_NONE, "failed to unlock spawn_mutex");
	}
	return;
}
#endif

static int do_spawn(logger *log, int use_lock, const char *prog, const char *const *argv)
{
	pid_t f;
	int status, pipefd[2];
	char errbuf[ERRBUFSIZ + 1], *p, *sp;
	int errp, errn;
	int cancel_state;
	sigset_t allsigs, tmpsig, oldsig;

	if (pipe(pipefd))
		return -1;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	sigfillset(&allsigs);
	pthread_sigmask(SIG_BLOCK, &allsigs, &oldsig);

#ifdef ENABLE_MOUNT_LOCKING
	if (use_lock) {
		if (pthread_mutex_lock(&spawn_mutex)) {
			log(LOGOPT_ANY, "failed to lock spawn_mutex");
			pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
			pthread_setcancelstate(cancel_state, NULL);
			return -1;
		}
	}
#endif

	f = fork();
	if (f == 0) {
		reset_signals();
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);

		execv(prog, (char *const *) argv);
		_exit(255);	/* execv() failed */
	} else {
		tmpsig = oldsig;

		sigaddset(&tmpsig, SIGCHLD);
		pthread_sigmask(SIG_SETMASK, &tmpsig, NULL);

		close(pipefd[1]);

		if (f < 0) {
			close(pipefd[0]);
			pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
#ifdef ENABLE_MOUNT_LOCKING
			spawn_unlock(&use_lock);
#endif
			pthread_setcancelstate(cancel_state, NULL);
			return -1;
		}

		errp = 0;
		do {
			while ((errn =
				read(pipefd[0], errbuf + errp, ERRBUFSIZ - errp)) == -1
			       && errno == EINTR);

			if (errn > 0) {
				errp += errn;

				sp = errbuf;
				while (errp && (p = memchr(sp, '\n', errp))) {
					*p++ = '\0';
					if (sp[0])	/* Don't output empty lines */
						log(LOGOPT_ANY, ">> %s", sp);
					errp -= (p - sp);
					sp = p;
				}

				if (errp && sp != errbuf)
					memmove(errbuf, sp, errp);

				if (errp >= ERRBUFSIZ) {
					/* Line too long, split */
					errbuf[errp] = '\0';
					log(LOGOPT_ANY, ">> %s", errbuf);
					errp = 0;
				}
			}
		} while (errn > 0);

		close(pipefd[0]);

		if (errp > 0) {
			/* End of file without \n */
			errbuf[errp] = '\0';
			log(LOGOPT_ANY, ">> %s", errbuf);
		}

		if (waitpid(f, &status, 0) != f)
			status = -1;	/* waitpid() failed */

		pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
#ifdef ENABLE_MOUNT_LOCKING
		spawn_unlock(&use_lock);
#endif
		pthread_setcancelstate(cancel_state, NULL);

		return status;
	}
}

int spawnv(logger *log, const char *prog, const char *const *argv)
{
	return do_spawn(log, 0, prog, argv);
}

int spawnl(logger *log, const char *prog, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;

	va_start(arg, prog);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc)))
		return -1;

	va_start(arg, prog);
	p = argv;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	return do_spawn(log, 0, prog, (const char **) argv);
}

#ifdef ENABLE_MOUNT_LOCKING
int spawnll(logger *log, const char *prog, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;

	va_start(arg, prog);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc)))
		return -1;

	va_start(arg, prog);
	p = argv;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	return do_spawn(log, 1, prog, (const char **) argv);
}
#endif
