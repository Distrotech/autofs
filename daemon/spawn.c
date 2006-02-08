#ident "$Id: spawn.c,v 1.15 2006/02/08 16:49:20 raven Exp $"
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

/* Make gcc happy */
pid_t getpgid(pid_t);

/*
 * SIGCHLD handling.
 *
 * We need to manage SIGCHLD process wide so that when we fork
 * programs we can reap the exit status in the calling thread by
 * blocking the signal. There is also the need to be able to reap
 * the exit status for child processes that are asynchronous to
 * the main program such as submount processes.
 * 
 * The method used to achieve this in our threaded environment
 * is to define a signal handler thread for SIGCHLD (and SIGCONT)
 * and, before we fork, tell it not to wait for signals so that
 * the waitpid in the subroutine that forks and execs can reap the
 * exit status.
 *
 * An added complication is that more than one thread at a time
 * may be forking program execution so we can't just simply tell
 * the handler to start listening for the signal again when done.
 * To deal with this a usage counter is used to identify when
 * there are no more threads that need to obtain an exit status
 * and we can tell the handler to start listening for the signal
 * again.
 */
struct sigchld_mutex {
	pthread_mutex_t mutex;
	pthread_cond_t ready;
	pthread_t thid;
	unsigned int catch;
	unsigned int count;
};

/* Start out catching SIGCHLD signals */
static struct sigchld_mutex sm = {PTHREAD_MUTEX_INITIALIZER,
				  PTHREAD_COND_INITIALIZER,
				  0, 1, 0};

void *sigchld(void *dummy)
{
	pid_t pid;
	sigset_t sigchld;
	int sig;
	int status;

	sigemptyset(&sigchld);
	sigaddset(&sigchld, SIGCHLD);
	sigaddset(&sigchld, SIGCONT);

	while (1) {
		sigwait(&sigchld, &sig);

		status = pthread_mutex_lock(&sm.mutex);
		if (status) {
			error("failed to lock SIGCHLD handler mutex");
			continue;
		}

		/*
		 * We could receive SIGCONT from two sources at the same
		 * time. For example if we are a submount process whose startup
		 * up is now complete and from a thread performing a fork and
		 * exec (via sigchld_block below). So we are being told to
		 * continue at the same time as we are bieng told to wait on
		 * the condition. In this case catching the signal is enough
		 * for us to continue and we also wait on the condition
		 * (sm.catch == 0).
		 */
		if (!sm.catch) {
			status = pthread_cond_wait(&sm.ready, &sm.mutex);
			if (status)
				error("SIGCHLD condition wait failed");
		}

		if (sig != SIGCONT)
			while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
				debug("received SIGCHLD from %d", pid);

		status = pthread_mutex_unlock(&sm.mutex);
		if (status)
			error("failed to unlock SIGCHLD handler mutex");
	}
}

int sigchld_start_handler(void)
{
	int status;

	status = pthread_create(&sm.thid, NULL, sigchld, NULL);
	if (status) {
		error("failed to create SIGCHLD handler thread");
		return 0;
	}
	return 1;
}

int sigchld_block(void)
{
	int status;

	status = pthread_mutex_lock(&sm.mutex);
	if (status) {
		error("failed to lock SIGCHLD mutex");
		return 0;
	}

	/*
	 * If this is the first request to block then disable
	 * signal catching and tell the handler.
	 */
	if (sm.count == 0) {
		sm.catch = 0;
		pthread_kill(sm.thid, SIGCONT);
	}

	sm.count++;

	status = pthread_mutex_unlock(&sm.mutex);
	if (status)
		error("failed to unlock SIGCHLD mutex");

	return 1;
}

int sigchld_unblock(void)
{
	int status;

	status = pthread_mutex_lock(&sm.mutex);
	if (status) {
		error("failed to lock SIGCHLD mutex");
		return 0;
	}

	sm.count--;

	/*
	 * If this is the last request for blocking then enable
	 * signal catching and tell the handler.
	 */
	if (sm.count == 0) {
		sm.catch = 1;
		status = pthread_cond_signal(&sm.ready);
		if (status)
			error("SIGCHLD condition signal failed");
	}

	status = pthread_mutex_unlock(&sm.mutex);
	if (status)
		error("failed to unlock SIGCHLD mutex");
	
	return 1;
}

/*
 * Used by subprocesses which exec to avoid carrying over the main
 * daemon's rather weird signalling environment
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
		sigaction(i, &sa, NULL);

	sa.sa_handler = SIG_DFL;

	for (i = 1; i < NSIG; i++)
		sigaction(i, &sa, NULL);

	/* Ignore the user signals that may be sent so that we
	 *  don't terminate execed program by mistake */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	sigprocmask(SIG_UNBLOCK, &allsignals, NULL);
}

/*
 * Used by subprocesses which don't exec to avoid carrying over the
 * main daemon's rather weird signalling environment.  Signals are
 * mostly ignored so that "/bin/kill -x automount" (where x is
 * typically SIGTERM or SIGUSR1) only affects the main process.
 */
void ignore_signals(void)
{
	struct sigaction sa;
	sigset_t allsignals;
	int i;

	sigfillset(&allsignals);
	sigprocmask(SIG_BLOCK, &allsignals, NULL);

	/* Discard all pending signals and ignore them */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	for (i = 1; i < NSIG; i++)
		sigaction(i, &sa, NULL);

	/* Default handler for SIGCHLD so that waitpid() still works */
	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);

	sigprocmask(SIG_UNBLOCK, &allsignals, NULL);
}

/* Throw away an unwanted pending signal */
void discard_pending(int sig)
{
	struct sigaction sa, oldsa;

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(sig, &sa, &oldsa);
	sigaction(sig, &oldsa, NULL);
}

/*
 * Process group signals each child in the process group the given signal.
 * For us we must signal deepest mount path to shortest to avoid mount
 * busy on exit.
 */
int signal_children(int sig)
{
	struct mnt_list *mnts = get_mnt_list(_PROC_MOUNTS, "/", 0);
	struct mnt_list *next;
	pid_t pgrp = getpgrp();
	int ret = -1;

	if (!mnts) {
		warn("no mounts found");
		goto out;
	}

	debug("send sig %d to process group %d", sig, pgrp);

	next = mnts;
	while (next) {
		/* 30 * 100000000 ns = 5 secs */
		int tries = 30;
		int status;
		struct mnt_list *this = next;
		pid_t pid = this->pid;

		next = this->next;

		if (!pid)
			continue;

		/* Don't signal ourselves */
		if (pid == pgrp)
			continue;

		/* Only signal members of our process group */
		if (getpgid(pid) != pgrp)
			continue;

		if (strncmp(this->fs_type, "autofs", 6))
			continue;

		/* Gone in between */
		if (kill(pid, SIGCONT) == -1 && errno == ESRCH)
			continue;

		debug("signal %s %d", this->path, pid);

		status = kill(pid, sig);
		if (status)
			goto out;

		while (tries--) {
			struct timespec t = { 0, 100000000L };
			struct timespec r;

		again:
			status = nanosleep(&t, &r);
			/* For a prune event delay a little and pass it on */
/*
			if (sig == SIGUSR1)
				break;
*/
			if (kill(pid, SIGCONT) == -1 && errno == ESRCH)
				break;

			if (status == -1 && errno == EINTR) {
				memcpy(&t, &r, sizeof(struct timespec));
				goto again;
			}
		}

		if (sig != SIGUSR1 && tries < 0) {
			warn("%d did nor exit - giving up.", pid);
			goto out;
		}
	}
	ret = 0;
out:
	free_mnt_list(mnts);
	return ret;
}

#define ERRBUFSIZ 2047		/* Max length of error string excl \0 */

static int do_spawn(int logpri, int use_lock, const char *prog, const char *const *argv)
{
	pid_t f;
	int status, pipefd[2];
	char errbuf[ERRBUFSIZ + 1], *p, *sp;
	int errp, errn;
	sigset_t allsignals, tmpsig, oldsig;
	int sig;

	if (use_lock)
		if (!aquire_lock())
			return -1;

	sigchld_block();

	if (pipe(pipefd))
		return -1;

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
		close(pipefd[1]);

		if (f < 0) {
			close(pipefd[0]);
			sigchld_unblock();
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
						syslog(logpri, ">> %s", sp);
					errp -= (p - sp);
					sp = p;
				}

				if (errp && sp != errbuf)
					memmove(errbuf, sp, errp);

				if (errp >= ERRBUFSIZ) {
					/* Line too long, split */
					errbuf[errp] = '\0';
					syslog(logpri, ">> %s", errbuf);
					errp = 0;
				}
			}
		} while (errn > 0);

		close(pipefd[0]);

		if (errp > 0) {
			/* End of file without \n */
			errbuf[errp] = '\0';
			syslog(logpri, ">> %s", errbuf);
		}

		if (waitpid(f, &status, 0) != f)
			status = -1;	/* waitpid() failed */

		sigchld_unblock();

		if (use_lock)
			release_lock();

		return status;
	}
}

int spawnv(int logpri, const char *prog, const char *const *argv)
{
	return do_spawn(logpri, 0, prog, argv);
}

int spawnl(int logpri, const char *prog, ...)
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

	return do_spawn(logpri, 0, prog, (const char **) argv);
}

int spawnll(int logpri, const char *prog, ...)
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

	return do_spawn(logpri, 1, prog, (const char **) argv);
}
