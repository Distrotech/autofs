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
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "automount.h"

static pthread_mutex_t spawn_mutex = PTHREAD_MUTEX_INITIALIZER;

#define SPAWN_OPT_NONE		0x0000
#define SPAWN_OPT_LOCK		0x0001
#define SPAWN_OPT_ACCESS	0x0002

#define MTAB_LOCK_RETRIES	3

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

static int do_spawn(unsigned logopt, unsigned int options, const char *prog, const char *const *argv)
{
	pid_t f;
	int ret, status, pipefd[2];
	char errbuf[ERRBUFSIZ + 1], *p, *sp;
	int errp, errn;
	int cancel_state;
	unsigned int use_lock = options & SPAWN_OPT_LOCK;
	unsigned int use_access = options & SPAWN_OPT_ACCESS;
	sigset_t allsigs, tmpsig, oldsig;
	struct thread_stdenv_vars *tsv;
	pid_t euid = 0;
	gid_t egid = 0;

	if (pipe(pipefd))
		return -1;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	sigfillset(&allsigs);
	pthread_sigmask(SIG_BLOCK, &allsigs, &oldsig);

	if (use_lock) {
		status = pthread_mutex_lock(&spawn_mutex);
		if (status)
			fatal(status);
	}

	tsv = pthread_getspecific(key_thread_stdenv_vars);
	if (tsv) {
		euid = tsv->uid;
		egid = tsv->gid;
	}

	f = fork();
	if (f == 0) {
		reset_signals();
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);

		/* Bind mount - check target exists */
		if (use_access) {
			char **pargv = (char **) argv;
			int argc = 0;
			pid_t pgrp = getpgrp();

			/* what to mount must always be second last */
			while (*pargv++)
				argc++;
			argc -= 2;

			/*
			 * Pretend to be requesting user and set non-autofs
			 * program group to trigger mount
			 */
			if (euid) {
				seteuid(euid);
				setegid(egid);
			}
			setpgrp();

			/* Trigger the recursive mount */
			if (access(argv[argc], F_OK) == -1)
				_exit(errno);

			seteuid(0);
			setegid(0);
			setpgid(0, pgrp);
		}

		execv(prog, (char *const *) argv);
		_exit(255);	/* execv() failed */
	} else {
		tmpsig = oldsig;

		sigaddset(&tmpsig, SIGCHLD);
		pthread_sigmask(SIG_SETMASK, &tmpsig, NULL);

		close(pipefd[1]);

		if (f < 0) {
			close(pipefd[0]);
			if (use_lock) {
				status = pthread_mutex_unlock(&spawn_mutex);
				if (status)
					fatal(status);
			}
			pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
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
						warn(logopt, ">> %s", sp);
					errp -= (p - sp);
					sp = p;
				}

				if (errp && sp != errbuf)
					memmove(errbuf, sp, errp);

				if (errp >= ERRBUFSIZ) {
					/* Line too long, split */
					errbuf[errp] = '\0';
					warn(logopt, ">> %s", errbuf);
					errp = 0;
				}
			}
		} while (errn > 0);

		close(pipefd[0]);

		if (errp > 0) {
			/* End of file without \n */
			errbuf[errp] = '\0';
			warn(logopt, ">> %s", errbuf);
		}

		if (waitpid(f, &ret, 0) != f)
			ret = -1;	/* waitpid() failed */

		if (use_lock) {
			status = pthread_mutex_unlock(&spawn_mutex);
			if (status)
				fatal(status);
		}
		pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
		pthread_setcancelstate(cancel_state, NULL);

		return ret;
	}
}

int spawnv(unsigned logopt, const char *prog, const char *const *argv)
{
	return do_spawn(logopt, SPAWN_OPT_NONE, prog, argv);
}

int spawnl(unsigned logopt, const char *prog, ...)
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

	return do_spawn(logopt, SPAWN_OPT_NONE, prog, (const char **) argv);
}

int spawn_mount(unsigned logopt, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;
	char prog[] = PATH_MOUNT;
	char arg0[] = PATH_MOUNT;
	/* In case we need to use the fake option to mount */
	char arg_fake[] = "-f";
	unsigned int options;
	unsigned int retries = MTAB_LOCK_RETRIES;
	int ret, printed = 0;

	/* If we use mount locking we can't validate the location */
#ifdef ENABLE_MOUNT_LOCKING
	options = SPAWN_OPT_LOCK;
#else
	options = SPAWN_OPT_NONE;
#endif

	va_start(arg, logopt);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	/* Alloc 1 extra slot in case we need to use the "-f" option */
	if (!(argv = alloca(sizeof(char *) * argc + 2)))
		return -1;

	argv[0] = arg0;

	va_start(arg, logopt);
	p = argv + 1;
	while ((*p = va_arg(arg, char *))) {
		if (options == SPAWN_OPT_NONE && !strcmp(*p, "-o")) {
			*(++p) = va_arg(arg, char *);
			if (!*p)
				break;
			if (strstr(*p, "loop"))
				options = SPAWN_OPT_ACCESS;
		}
		p++;
	}
	va_end(arg);

	while (retries--) {
		ret = do_spawn(logopt, options, prog, (const char **) argv);
		if (ret & MTAB_NOTUPDATED) {
			struct timespec tm = {3, 0};

			/*
			 * If the mount succeeded but the mtab was not
			 * updated, then retry the mount with the -f (fake)
			 * option to just update the mtab.
			 */
			if (!printed) {
				debug(logopt, "mount failed with error code 16"
				      ", retrying with the -f option");
				printed = 1;
			}

			/*
			 * Move the last two args so do_spawn() can find the
			 * mount target.
			 */
			if (!argv[argc]) {
				argv[argc + 1] = NULL;
				argv[argc] = argv[argc - 1];
				argv[argc - 1] = argv[argc - 2];
				argv[argc - 2] = arg_fake;
			}

			nanosleep(&tm, NULL);

			continue;
		}
		break;
	}

	/* This is not a fatal error */
	if (ret == MTAB_NOTUPDATED) {
		/*
		 * Version 5 requires that /etc/mtab be in sync with
		 * /proc/mounts. If we're unable to update matb after
		 * retrying then we have no choice but umount the mount
		 * and return a fail.
		 */
		warn(logopt,
		     "Unable to update the mtab file, forcing mount fail!");
		umount(argv[argc]);
		ret = MNT_FORCE_FAIL;
	}

	return ret;
}

/*
 * For bind mounts that depend on the target being mounted (possibly
 * itself an automount) we attempt to mount the target using an access
 * call. For this to work the location must be the second last arg.
 *
 * NOTE: If mount locking is enabled this type of recursive mount cannot
 *	 work.
 */
int spawn_bind_mount(unsigned logopt, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;
	char prog[] = PATH_MOUNT;
	char arg0[] = PATH_MOUNT;
	char bind[] = "--bind";
	/* In case we need to use the fake option to mount */
	char arg_fake[] = "-f";
	unsigned int options;
	unsigned int retries = MTAB_LOCK_RETRIES;
	int ret, printed = 0;

	/* If we use mount locking we can't validate the location */
#ifdef ENABLE_MOUNT_LOCKING
	options = SPAWN_OPT_LOCK;
#else
	options = SPAWN_OPT_ACCESS;
#endif

	/*
	 * Alloc 2 extra slots, one for the bind option and one in case
	 * we need to use the "-f" option
	 */
	va_start(arg, logopt);
	for (argc = 2; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc + 2)))
		return -1;

	argv[0] = arg0;
	argv[1] = bind;

	va_start(arg, logopt);
	p = argv + 2;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	while (retries--) {
		ret = do_spawn(logopt, options, prog, (const char **) argv);
		if (ret & MTAB_NOTUPDATED) {
			struct timespec tm = {3, 0};

			/*
			 * If the mount succeeded but the mtab was not
			 * updated, then retry the mount with the -f (fake)
			 * option to just update the mtab.
			 */
			if (!printed) {
				debug(logopt, "mount failed with error code 16"
				      ", retrying with the -f option");
				printed = 1;
			}

			/*
			 * Move the last two args so do_spawn() can find the
			 * mount target.
			 */
			if (!argv[argc]) {
				argv[argc + 1] = NULL;
				argv[argc] = argv[argc - 1];
				argv[argc - 1] = argv[argc - 2];
				argv[argc - 2] = arg_fake;
			}

			nanosleep(&tm, NULL);

			continue;
		}
		break;
	}

	/* This is not a fatal error */
	if (ret == MTAB_NOTUPDATED) {
		/*
		 * Version 5 requires that /etc/mtab be in sync with
		 * /proc/mounts. If we're unable to update matb after
		 * retrying then we have no choice but umount the mount
		 * and return a fail.
		 */
		warn(logopt,
		     "Unable to update the mtab file, forcing mount fail!");
		umount(argv[argc]);
		ret = MNT_FORCE_FAIL;
	}

	return ret;
}

int spawn_umount(unsigned logopt, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;
	char prog[] = PATH_UMOUNT;
	char arg0[] = PATH_UMOUNT;
	unsigned int options;
	unsigned int retries = MTAB_LOCK_RETRIES;
	int ret, printed = 0;

#ifdef ENABLE_MOUNT_LOCKING
	options = SPAWN_OPT_LOCK;
#else
	options = SPAWN_OPT_NONE;
#endif

	va_start(arg, logopt);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	if (!(argv = alloca(sizeof(char *) * argc + 1)))
		return -1;

	argv[0] = arg0;

	va_start(arg, logopt);
	p = argv + 1;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	while (retries--) {
		ret = do_spawn(logopt, options, prog, (const char **) argv);
		if (ret & MTAB_NOTUPDATED) {
			/*
			 * If the mount succeeded but the mtab was not
			 * updated, then retry the umount just to update
			 * the mtab.
			 */
			if (!printed) {
				debug(logopt, "mount failed with error code 16"
				      ", retrying with the -f option");
				printed = 1;
			}
		} else {
			/*
			 * umount does not support the "fake" option.  Thus,
			 * if we got a return value of MTAB_NOTUPDATED the
			 * first time, that means the umount actually
			 * succeeded.  Then, a following umount will fail
			 * due to the fact that nothing was mounted on the
			 * mount point. So, report this as success.
			 */
			if (retries < MTAB_LOCK_RETRIES - 1)
				ret = 0;
			break;
		}
	}

	/* This is not a fatal error */
	if (ret == MTAB_NOTUPDATED) {
		warn(logopt, "Unable to update the mtab file, /proc/mounts "
		     "and /etc/mtab will differ");
		ret = 0;
	}

	return ret;
}

