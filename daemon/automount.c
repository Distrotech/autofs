#ident "$Id: automount.c,v 1.4 2003/09/10 14:27:41 raven Exp $"
/* ----------------------------------------------------------------------- *
 *
 *  automount.c - Linux automounter daemon
 *   
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <mntent.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <linux/auto_fs4.h>

#ifndef NDEBUG
#define assert(x)	do { if (!(x)) { syslog(LOG_CRIT, __FILE__ ":%d: assertion failed: " #x, __LINE__); } } while(0)
#else
#define assert(x)	do { } while(0)
#endif

#include "automount.h"

#if 0
#define DEBUG
#endif

#ifdef DEBUG
#define DB(x)		do { x; } while(0)
#else
#define DB(x)		do { } while(0)
#endif

const char *program;		        /* Initialized with argv[0] */
const char *version = VERSION_STRING;	/* Program version */

static pid_t my_pgrp;		        /* The "magic" process group */
static pid_t my_pid;		        /* The pid of this process */
static char *pid_file = NULL;	        /* File in which to keep pid */

int kproto_version;		        /* Kernel protocol version used */

static int submount = 0;

/*
 * State machine for daemon
 * 
 * READY - reads from pipe; performs mount/umount operations
 * PRUNE - generates prune events in subprocess; reads from pipe
 * EXPIRE - generates expire events in subprocess; reads from pipe
 * SHUTDOWN_PENDING - as prune, but goes to SHUTDOWN when done
 * SHUTDOWN - unmount autofs, exit
 *
 * Signals TERM, USR1, USR2 and ALRM are blocked in all states except
 * READY.  SIGCHLD is blocked when protecting the manipulating mount list.
 */
enum states {
	ST_INVAL = -1,
	ST_INIT,
	ST_READY,
	ST_EXPIRE,
	ST_PRUNE,
	ST_SHUTDOWN_PENDING,
	ST_SHUTDOWN,
};

sigset_t ready_sigs;		/* signals only accepted in ST_READY */
sigset_t lock_sigs;		/* signals blocked for locking */
sigset_t sigchld_mask;

struct pending_mount {
  pid_t pid;		/* Which process is mounting for us */
  unsigned long wait_queue_token;	/* Associated kernel wait token */
  volatile struct pending_mount *next;
};

static struct autofs_point {
  char *path;		/* Mount point name */
  int pipefd;		/* File descriptor for pipe */
  int ioctlfd;		/* File descriptor for ioctls */
  dev_t dev;		/* "Device" number assigned by kernel */
  unsigned exp_timeout;	/* Timeout for expiring mounts */
  unsigned exp_runfreq;	/* Frequency for polling for timeouts */
  volatile pid_t exp_process; /* Process that is currently expiring */
  volatile struct pending_mount *mounts; /* Pending mount queue */
  struct lookup_mod *lookup; /* Lookup module */
  enum states state;
  int state_pipe[2];
} ap;

volatile struct pending_mount *junk_mounts = NULL;

#define DEFAULT_TIMEOUT (5*60)	/* 5 minutes */
#define CHECK_RATIO     4	/* exp_runfreq = exp_timeout/CHECK_RATIO */

static void cleanup_exit(int exit_code);
static int handle_packet_expire(const struct autofs_packet_expire *pkt);

int mkdir_path(const char *path, mode_t mode)
{
	char *buf = alloca(strlen(path)+1);
	const char *cp = path, *lcp = path;
	char *bp = buf;

	do
		if (cp != path && (*cp == '/' || *cp == '\0')) {
			memcpy(bp, lcp, cp-lcp);
			bp += cp-lcp;
			lcp = cp;
			*bp = '\0';
			if (mkdir(buf, mode) == -1) {
				/* If it already exists, make sure it's a directory */
				if (errno == EEXIST) {
					struct stat st;

					if (stat(buf, &st) == 0 &&
					    !S_ISDIR(st.st_mode))
						errno = ENOTDIR;
					else
						continue;
				}
				return -1;
			}
		}
	while(*cp++ != '\0');
	return 0;
}

/* Remove as much as possible of a path */
int rmdir_path(const char *path)
{
	int len = strlen(path);
	char *buf = alloca(len+1);
	char *cp;
	int first = 1;

	strcpy(buf, path);
	cp = buf+len;

	do {
		*cp = '\0';

		/* Last element of path may be non-dir;
		   all others are directories */
		if (rmdir(buf) == -1 &&
		    (!first || unlink(buf) == -1))
			return -1;

		first = 0;
	} while((cp = strrchr(buf, '/')) != NULL && cp != buf);

	return 0;
}

static int umount_ent(const char *root, const char *name)
{
  char path_buf[PATH_MAX];
  struct stat st;
  int rv = 0;
  
  sprintf(path_buf, "%s/%s", root, name);
  if ( !lstat(path_buf,&st) ) {
    if ( S_ISDIR(st.st_mode) ) {
      if ( st.st_dev != ap.dev ) {
	rv = spawnl(LOG_DEBUG, PATH_UMOUNT,
		    PATH_UMOUNT, path_buf, NULL);
      }
    }
  }
  return rv;
}	

/* Like ftw, except fn gets called twice: before a directory is
   entered, and after.  If the before call returns 0, the directory
   isn't entered. */
static int walk_tree(const char *base, int (*fn)(const char *file, 
						 const struct stat *st,
						 int, void *),
		     int incl, void *arg)
{
	char buf[PATH_MAX+1];
	struct stat st;
	
	if (lstat(base, &st) != -1 &&
	    (fn)(base, &st, 0, arg)) {
		if (S_ISDIR(st.st_mode)) {
			DIR *dir = opendir(base);
			struct dirent *de;

			if (dir == NULL)
				return -1;

			while((de = readdir(dir)) != NULL) {
				if (strcmp(de->d_name, ".") == 0 ||
				    strcmp(de->d_name, "..") == 0)
					continue;

				sprintf(buf, "%s/%s", base, de->d_name);
				if (walk_tree(buf, fn, 1, arg)) {
					closedir(dir);
					return -1;
				}
			}
			closedir(dir);
		}
		if (incl)
			(fn)(base, &st, 1, arg);
	}
	return 0;
}

static int rm_unwanted_fn(const char *file, const struct stat *st, 
			  int when, void *arg)
{
  int rmsymlink = *(int *)arg;

  if (when == 0) {
    if (st->st_dev != ap.dev)
      return 0;
  } else {
    DB(syslog(LOG_INFO, "rm_unwanted: %s\n", file));
    if (S_ISDIR(st->st_mode))
      rmdir(file);
    else if (!S_ISLNK(st->st_mode) || rmsymlink)
      unlink(file);
  }

  return 1;
}

static void rm_unwanted(const char *path, int incl, int rmsymlink)
{
	walk_tree(path, rm_unwanted_fn, incl, &rmsymlink);
}

/* umount all filesystems mounted under path.  If incl is true, then
   it also tries to umount path itself */
static int umount_multi(const char *path, int incl)
{
  int left;
  struct mntent *mnt;
  FILE *mtab;
  struct mntlist {
	  const char *path;
	  struct mntlist *next;
  } *mntlist = NULL, *mptr;
  int pathlen = strlen(path);

  DB(syslog(LOG_INFO, "umount_multi: path=%s incl=%d\n", path, incl));

  mtab = setmntent(_PATH_MOUNTED, "r");
  if (!mtab) {
    syslog(LOG_ERR, "umount_multi: setmntent: %m");
    return -1;
  }

  /* Construct a list of eligible dirs ordered longest->shortest
     so that umount will work */
  while((mnt = getmntent(mtab)) != NULL) {
    int len = strlen(mnt->mnt_dir);
    struct mntlist *m, **prev;
    char *p;

    if ((!incl && len <= pathlen) || 
	strncmp(mnt->mnt_dir, path, pathlen) != 0)
      continue;

    prev = &mntlist;
    for(mptr = mntlist; mptr != NULL; prev = &mptr->next, mptr = mptr->next)
      if (len > strlen(mptr->path))
	break;

    m = alloca(sizeof(*m));
    p = alloca(len+1);
    strcpy(p, mnt->mnt_dir);
    m->path = p;
    m->next = *prev;
    *prev = m;
  }

  endmntent(mtab);

  left = 0;
  for(mptr = mntlist; mptr != NULL; mptr = mptr->next) {
    DB(syslog(LOG_INFO, "umount_multi: unmounting dir=%s\n", mptr->path));
    if (umount_ent("", mptr->path)) {
      left++;
    }
  }

  /* Delete detritus like unwanted mountpoints and symlinks */
  if (left == 0)
    rm_unwanted(path, incl, 1);

  return left;
}	

static int umount_all(int force)
{
  int left;

  chdir("/");
  
  left = umount_multi(ap.path, 0);

  if (force && left)
    syslog(LOG_WARNING, "could not unmount %d dirs under %s",
	   left, ap.path);

  return left;
}

static int do_umount_autofs(void)
{
  int rv;
  int i;
  const int retries = 3;

  if (ap.ioctlfd >= 0) {
    ioctl(ap.ioctlfd, AUTOFS_IOC_CATATONIC, 0);
    close(ap.ioctlfd);
    close(ap.state_pipe[0]);
    close(ap.state_pipe[1]);
  }
  if (ap.pipefd >= 0)
    close(ap.pipefd);
  for(i = 0; i < retries; i++) {
    struct stat st;
    int ret;

    rv = spawnl(LOG_INFO, PATH_UMOUNT, PATH_UMOUNT, ap.path, NULL);
    ret = stat(ap.path, &st);
    if (rv == 0 ||							/* umount worked */
	(ret == -1 && errno == ENOENT) ||				/* directory isn't there */
	(ret == 0 && (!S_ISDIR(st.st_mode) || st.st_dev != ap.dev))) {	/* is there, but it's not ours */
      rv = 0; 
      break;
    }
    if (i < retries-1) {
      syslog(LOG_INFO, "umount %s failed: retrying...\n", ap.path);
      sleep(1);
    }
  }
  if (rv != 0 || i == retries) {
    syslog(LOG_ERR, "can't unmount %s\n", ap.path);
    DB(kill(0, SIGSTOP));
  } else {
    if (i != 0)
      syslog(LOG_INFO, "umount %s succeeded\n", ap.path);
    if (submount)
      rm_unwanted(ap.path, 1, 1);
  }

  free(ap.path);

  return rv;
}

static int umount_autofs(int force)
{
  if ( ap.state == ST_INIT )
    return -1;
  if ( umount_all(force) && !force )
    return -1;
  return do_umount_autofs();
}

static int mount_autofs(char *path)
{
  int pipefd[2];
  char options[128];
  char our_name[128];
  struct stat st;
  
  if ( ap.state != ST_INIT ) {
    /* This can't happen */
    syslog(LOG_ERR, "mount_autofs: already mounted");
    return -1;
  }
  
  if ( path[0] != '/' ) {
    errno = EINVAL;	/* Must be an absolute pathname */
    return -1;
  }
  
  ap.path = strdup(path);
  if ( !ap.path ) {
    errno = ENOMEM;
    return -1;
  }
  ap.pipefd = ap.ioctlfd = -1;
  
  /* In case the directory doesn't exist, try to mkdir it */
  if (mkdir_path(path, 0555) < 0 && errno != EEXIST && errno != EROFS)
    return -1;
  
  /* Pipe for kernel communications */
  if ( pipe(pipefd) < 0 )
    return -1;
  
  /* Pipe state changes from signal handler to main loop */
  if (pipe(ap.state_pipe) < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }

  sprintf(options, "fd=%d,pgrp=%u,minproto=2,maxproto=%d", pipefd[1],
	  (unsigned)my_pgrp, AUTOFS_MAX_PROTO_VERSION);
  sprintf(our_name, "automount(pid%u)", (unsigned)my_pid);
  
  if (spawnl(LOG_DEBUG, PATH_MOUNT, PATH_MOUNT, "-t", "autofs", "-o",
	     options, our_name, path, NULL) != 0) {
    syslog(LOG_CRIT, "cannot find autofs in kernel");
    close(pipefd[0]);
    close(pipefd[1]);
    close(ap.state_pipe[0]);
    close(ap.state_pipe[1]);
    return -1;
  }

  close(pipefd[1]);	/* Close kernel pipe end */
  ap.pipefd = pipefd[0];
  
  ap.ioctlfd = open(path, O_RDONLY); /* Root directory for ioctl()'s */
  if ( ap.ioctlfd < 0 ) {
    umount_autofs(1);
    return -1;
  }
  
  stat(path,&st);
  ap.dev = st.st_dev;	/* Device number for mount point checks */
  
  ap.mounts = NULL;	/* No pending mounts */
  ap.state = ST_READY;
  
  return 0;
}

static void nextstate(enum states next)
{
  if (write(ap.state_pipe[1], &next, sizeof(next)) != sizeof(next))
    syslog(LOG_ERR, "nextstate: write failed %m");
}

/* Deal with all the signal-driven events in the state machine */
static void sig_statemachine(int sig)
{
	int save_errno = errno;
	enum states next = ap.state;

	switch(sig) {
	default:		/* all the "can't happen" signals */
		syslog(LOG_ERR, "process %d got unexpected signal %d!",
		       getpid(), sig);
		/* FALLTHROUGH */

	case SIGTERM:
	case SIGUSR2:
		if (ap.state != ST_SHUTDOWN)
			nextstate(next = ST_SHUTDOWN_PENDING);
		break;

	case SIGUSR1:
		assert(ap.state == ST_READY);
		nextstate(next = ST_PRUNE);
		break;

	case SIGALRM:
		assert(ap.state == ST_READY);
		nextstate(next = ST_EXPIRE);
		break;
	}

	DB(syslog(LOG_INFO, "sig %d switching from %d to %d",
		  sig, ap.state, next));
	errno = save_errno;
}

static int send_ready(unsigned int wait_queue_token)
{
  if (wait_queue_token == 0)
    return 0;
  DB(syslog(LOG_NOTICE, "send_ready: token=%d\n", wait_queue_token));
  if ( ioctl(ap.ioctlfd, AUTOFS_IOC_READY, wait_queue_token) < 0 ) {
    syslog(LOG_ERR, "AUTOFS_IOC_READY: %m");
    return 1;
  }
  return 0;
}

static int send_fail(unsigned int wait_queue_token)
{
  if (wait_queue_token == 0)
    return 0;
  DB(syslog(LOG_NOTICE, "send_fail: token=%d\n", wait_queue_token));
  if ( ioctl(ap.ioctlfd, AUTOFS_IOC_FAIL, wait_queue_token) < 0 ) {
    syslog(LOG_ERR, "AUTOFS_IOC_FAIL: %m");
    return 1;
  }
  return 0;
}

/* Handle exiting children (either from SIGCHLD or synchronous wait at
   shutdown), and return the next state the system should enter as a
   result.  */
static enum states handle_child(int hang)
{
	pid_t pid;
	int status;
	enum states next = ST_INVAL;

	while((pid = waitpid(-1, &status, hang ? 0 : WNOHANG)) > 0) {
		struct pending_mount volatile *mt, * volatile *mtp;

		DB(syslog(LOG_INFO,
			  "handle_child: got pid %d, sig %d (%d), stat %d\n", 
			  pid, WIFSIGNALED(status), 
			  WTERMSIG(status),
			  WEXITSTATUS(status)));

		/* Check to see if expire process finished */
		if (pid == ap.exp_process) {
			int success;

			if (!WIFEXITED(status))
				continue;

			success = !WIFSIGNALED(status) &&
					(WEXITSTATUS(status) == 0);

			ap.exp_process = 0;

			switch(ap.state) {
			case ST_EXPIRE:
				alarm(ap.exp_runfreq);
				/* FALLTHROUGH */
			case ST_PRUNE:
				/* If we're a submount and we've just
                                   pruned or expired everything away,
                                   try to shut down */
				if (submount && success &&
				    ap.state != ST_SHUTDOWN) {
					next = ST_SHUTDOWN_PENDING;
					break;
				}
				/* FALLTHROUGH */
			case ST_READY:
				next = ST_READY;
				break;

			case ST_SHUTDOWN_PENDING:
				next = ST_SHUTDOWN;
				/* Failed shutdown returns to ready */
				if (!success) {
					syslog(LOG_WARNING,
					       "shutdown failed: filesystem still busy");
					next = ST_READY;
				}
				break;

			default:
				syslog(LOG_ERR, "bad state %d", ap.state);
			}

			if (next != ST_INVAL)
				DB(syslog(LOG_INFO, "sigchld: exp %d finished, switching from %d to %d",
					  pid, ap.state, next));

			continue;
		}
		
		/* Run through pending mount/unmounts and see what (if
                   any) has finished, and tell the kernel about it */
		for(mtp = &ap.mounts; (mt = *mtp); mtp = &mt->next) {
			if (mt->pid == pid) {
				if (!WIFEXITED(status) && !WIFSIGNALED(status))
					break;
				DB(syslog(LOG_INFO,
					  "sig_child: found pending op pid %d: signalled %d (sig %d), exit status %d",
					  pid, WIFSIGNALED(status), 
					  WTERMSIG(status),
					  WEXITSTATUS(status)));

				if (WIFSIGNALED(status) || 
				    WEXITSTATUS(status) != 0)
					send_fail(mt->wait_queue_token);
				else
					send_ready(mt->wait_queue_token);

				/* Delete from list and add to freelist,
				   since we can't call free() here */
				*mtp  = mt->next;
				mt->next = junk_mounts;
				junk_mounts = mt;
				break;
			}
		}
	}

	return next;
}

/* Reap children */
static void sig_child(int sig)
{
	int save_errno = errno;
	enum states next;

	if (sig != SIGCHLD)
		return;

	next = handle_child(0);
	if (next != ST_INVAL)
		nextstate(next);
	errno = save_errno;
}

static int st_ready(void)
{
	DB(syslog(LOG_INFO, "st_ready(): state = %d\n",
		  ap.state));

	ap.state = ST_READY;
	sigprocmask(SIG_UNBLOCK, &lock_sigs, NULL);

	return 0;
}

static int counter_fn(const char *file, const struct stat *st, 
		      int when, void *arg)
{
	int *countp = (int *)arg;
	
	if (S_ISLNK(st->st_mode) || 
	    (S_ISDIR(st->st_mode) && st->st_dev != ap.dev)) {
		(*countp)++;
		return 0;
	}

	return 1;
}

/* Count mounted filesystems and symlinks */
static int count_mounts(const char *path)
{
	int count = 0;

	if (walk_tree(path, counter_fn, 0, &count) == -1)
		return -1;

	return count;
}

enum expire {
	EXP_ERROR,
	EXP_STARTED,
	EXP_DONE,
	EXP_PARTIAL
};

/*
 * Generate expiry messages.  If "now" is true, timeouts are ignored.
 *
 * Returns: ERROR	- error
 *          STARTED	- expiry process started
 *          DONE	- nothing to expire
 *          PARTIAL	- partial expire
 */
static enum expire expire_proc(int now)
{
	pid_t f;
	sigset_t old;

	if (kproto_version < 4) {
		if (now)
			umount_all(0);
		else {
			struct autofs_packet_expire pkt;

			while(ioctl(ap.ioctlfd, AUTOFS_IOC_EXPIRE, &pkt) == 0)
				handle_packet_expire(&pkt);
		}

		if (count_mounts(ap.path) != 0)
			return EXP_PARTIAL;
		return EXP_DONE;
	}

	assert(ap.exp_process == 0);

	/* Block SIGCHLD and SIGALRM between forking and setting up
           exp_process */
	sigprocmask(SIG_BLOCK, &lock_sigs, &old);

	switch (f = fork()) {
		int count;
	case 0:
		ignore_signals();
		close(ap.pipefd);
		close(ap.state_pipe[0]);
		close(ap.state_pipe[1]);

		/* Generate expire messages until there's
		   nothing more to expire */
		while(ioctl(ap.ioctlfd, AUTOFS_IOC_EXPIRE_MULTI, &now) == 0)
			;

		/* EXPIRE_MULTI is synchronous, so we can
                   be sure the umounts are done by the time we reach
                   here */
		if ((count = count_mounts(ap.path))) {
			DB(syslog(LOG_INFO,
				  "expire_proc: %d remaining in %s\n",
				  count, ap.path));
			exit(1);
		}
		exit(0);

	case -1:
		syslog(LOG_ERR, "expire: fork failed: %m");
		sigprocmask(SIG_SETMASK, &old, NULL);
		return EXP_ERROR;

	default:
		DB(syslog(LOG_INFO, "expire_proc: exp_proc=%d", f));
		ap.exp_process = f;
		sigprocmask(SIG_SETMASK, &old, NULL);
		return EXP_STARTED;
	}
}

static int st_prepare_shutdown(void)
{
	int exp;

	DB(syslog(LOG_INFO, "prep_shutdown: state = %d\n",
		  ap.state));

	assert(ap.state == ST_READY || (submount && ap.state == ST_EXPIRE));

	/* Turn off timeouts */
	alarm(0);

	/* Prevent any new mounts */
	ap.state = ST_SHUTDOWN_PENDING;

	sigprocmask(SIG_SETMASK, &lock_sigs, NULL);
	
	if (!submount) {
		/* Kill off any pending (u)mounts (signal the whole group) */
		kill(0, SIGTERM);

		/* ignore the self-signal so there's no loop if we
		   fail to shut down */
		discard_pending(SIGTERM);
	}

	/* Unmount everything */
	exp = expire_proc(1);

	DB(syslog(LOG_INFO, "prep_shutdown: expire returns %d\n", exp));
	switch(exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		return st_ready();
	case EXP_DONE:
		/* All expired: go straight to exit */
		ap.state = ST_SHUTDOWN;
		return 1;
	case EXP_STARTED:
		/* Wait until expiry process finishes */
		sigprocmask(SIG_SETMASK, &ready_sigs, NULL);
		return 0;
	}
	return 1;
}

static int st_prune(void)
{
	DB(syslog(LOG_INFO, "st_prune(): state = %d\n",
		  ap.state));

	assert(ap.state == ST_READY);

	switch(expire_proc(1)) {
	case EXP_DONE:
		if (submount)
			return st_prepare_shutdown();
		/* FALLTHROUGH */
	case EXP_ERROR:
	case EXP_PARTIAL:
		return 1;

	case EXP_STARTED:
		ap.state = ST_PRUNE;
		sigprocmask(SIG_SETMASK, &ready_sigs, NULL);
		return 0;
	}
	return 1;
}

static int st_expire(void)
{
	DB(syslog(LOG_INFO, "st_expire(): state = %d\n",
		  ap.state));

	assert(ap.state == ST_READY);

	switch(expire_proc(0)) {
	case EXP_DONE:
		if (submount)
			return st_prepare_shutdown();
		/* FALLTHROUGH */
	case EXP_ERROR:
	case EXP_PARTIAL:
		alarm(ap.exp_runfreq);
		return 1;

	case EXP_STARTED:
		ap.state = ST_EXPIRE;
		sigprocmask(SIG_SETMASK, &ready_sigs, NULL);
		return 0;
	}
	return 1;
}

static int fullread(int fd, void *ptr, size_t len)
{
	char *buf = (char *)ptr;

	while(len > 0) {
		size_t r = read(fd, buf, len);
		
		if (r == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		buf += r;
		len -= r;
	}

	return len;
}

static int get_pkt(int fd, union autofs_packet_union *pkt)
{
  sigset_t old;
  struct pollfd fds[2];

  fds[0].fd = fd;
  fds[0].events = POLLIN;
  fds[1].fd = ap.state_pipe[0];
  fds[1].events = POLLIN;

  for(;;) {
    if (poll(fds, 2, -1) == -1) {
      if (errno == EINTR)
	continue;
      syslog(LOG_ERR, "get_pkt: poll failed: %m");
      return -1;
    }

    if (fds[1].revents & POLLIN) {
      enum states next_state;
      int ret = 1;

      if (fullread(ap.state_pipe[0], &next_state, sizeof(next_state)))
	continue;

      sigprocmask(SIG_BLOCK, &lock_sigs, &old);

      if (next_state != ap.state) {
        DB(syslog(LOG_INFO, "get_pkt: state %d, next %d",
		  ap.state, next_state));
	switch(next_state) {
	case ST_READY:
	  ret = st_ready();
	  break;
	case ST_PRUNE:
	  ret = st_prune();
	  break;
	case ST_EXPIRE:
	  ret = st_expire();
	  break;
	case ST_SHUTDOWN_PENDING:
	  ret = st_prepare_shutdown();
	  break;
	case ST_SHUTDOWN:
	  assert(ap.state == ST_SHUTDOWN ||
		 ap.state == ST_SHUTDOWN_PENDING);
	  ap.state = ST_SHUTDOWN;
	  break;

	default:
	  syslog(LOG_ERR, "get_pkt: bad next state %d", next_state);
	}
      }
      if (ret)
        sigprocmask(SIG_SETMASK, &old, NULL);
      if (ap.state == ST_SHUTDOWN)
	return -1;
    }

    if (fds[0].revents & POLLIN)
      return fullread(fd, pkt, sizeof(*pkt));
  }
}

static int handle_packet_missing(const struct autofs_packet_missing *pkt)
{
  struct stat st;
  sigset_t oldsig;
  pid_t f;

  DB(syslog(LOG_INFO, "handle_packet_missing: token %d, name %s\n", 
	    pkt->wait_queue_token, pkt->name));

  /* Ignore packet if we're trying to shut down */
  if (ap.state == ST_SHUTDOWN_PENDING ||
      ap.state == ST_SHUTDOWN) {
	  send_fail(pkt->wait_queue_token);
	  return 0;
  }

  chdir(ap.path);
  if ( lstat(pkt->name,&st) == -1 ||
       (S_ISDIR(st.st_mode) && st.st_dev == ap.dev) ) {
    /* Need to mount or symlink */
    struct pending_mount *mt;

    chdir("/");
    /* Block SIGCHLD while mucking with linked lists */
    sigprocmask(SIG_BLOCK, &sigchld_mask, NULL);
    if ( (mt = (struct pending_mount *) junk_mounts) ) {
      junk_mounts = junk_mounts->next;
    } else if ( !(mt = malloc(sizeof(struct pending_mount))) ) {
      syslog(LOG_ERR, "handle_packet: malloc: %m");
      send_fail(pkt->wait_queue_token);
      return 1;
    }
    sigprocmask(SIG_UNBLOCK, &sigchld_mask, NULL);

    syslog(LOG_INFO, "attempting to mount entry %s/%s",
	   ap.path, pkt->name);

    sigprocmask(SIG_BLOCK, &lock_sigs, &oldsig);

    f = fork();
    if ( f == -1 ) {
      sigprocmask(SIG_SETMASK, &oldsig, NULL);
      syslog(LOG_ERR, "handle_packet_missing: fork: %m");
      send_fail(pkt->wait_queue_token);
      return 1;
    } else if ( !f ) {
      int err;
      char buf[PATH_MAX+1];

      ignore_signals();		/* Set up a sensible signal environment */
      close(ap.pipefd);
      close(ap.ioctlfd);
      close(ap.state_pipe[0]);
      close(ap.state_pipe[1]);

      err = ap.lookup->lookup_mount(ap.path, pkt->name, pkt->len,
				    ap.lookup->context);

      sprintf(buf, "%s/%.*s", ap.path, pkt->len, pkt->name);

      /* If at first you don't succeed, hide all evidence you ever tried */
      if (err) {
	umount_multi(buf, 1);
	rm_unwanted(buf, 1, 0);
      }

      _exit(err ? 1 : 0);
    } else {
      /* Important: set up data structures while signals still blocked */
      mt->pid = f;
      mt->wait_queue_token = pkt->wait_queue_token;
      mt->next = ap.mounts;
      ap.mounts = mt;

      sigprocmask(SIG_SETMASK, &oldsig, NULL);
    }
  } else {
    /* Already there (can happen if a process connects to a
       directory while we're still working on it) */
    /* XXX For v4, this would be the wrong thing to do if it could
       happen.  It should add the new wait_queue_token to the pending
       mount structure so that it gets sent a ready when its really
       done.  In practice, the kernel keeps any other processes
       blocked until the initial mount request is done. -JSGF */
    send_ready(pkt->wait_queue_token);
  }
  chdir("/");
  return 0;
}

static void do_expire(const char *name, int namelen)
{
  char buf[PATH_MAX];

  sprintf(buf, "%s/%.*s", ap.path, namelen, name);
  syslog(LOG_DEBUG, "running expiration on path %s", buf);

  if ( umount_multi(buf, 1) == 0 ) {
    syslog(LOG_NOTICE, "expired %s", buf);
  } else {
    /* Oops - umounted some things, but not all; try and
       recover before anyone notices by remounting
       everything.
       
       This should never happen because the kernel checks
       whether the umount will work before telling us about
       it.
    */
    if (ap.lookup->lookup_mount(ap.path, name, namelen, 
				ap.lookup->context))
      syslog(LOG_ERR, "failed to recover from partial expiry of %s\n", buf);
  }
}

static int handle_expire(const char *name, int namelen, autofs_wqt_t token)
{
  sigset_t olds;
  pid_t f;
  struct pending_mount *mt;

  chdir("/");			/* make sure we're out of the way */

  /* Temporarily block SIGCHLD and SIGALRM between forking and setting
     pending (u)mount info */
  
  sigprocmask(SIG_BLOCK, &lock_sigs, &olds);
  
  /* Reclaim from doomed list if there is one */
  if ( (mt = (struct pending_mount *) junk_mounts) ) {
    junk_mounts = junk_mounts->next;
  } else if ( !(mt = malloc(sizeof(struct pending_mount))) ) {
    sigprocmask(SIG_SETMASK, &olds, NULL);
    syslog(LOG_ERR, "handle_expire: malloc: %m");
    return 1;
  }

  f = fork();
  if ( f == -1 ) {
    sigprocmask(SIG_SETMASK, &olds, NULL);
    syslog(LOG_ERR, "handle_expire: fork: %m");
    return 1;
  }
  if ( f > 0 ) {
    mt->pid = f;
    mt->wait_queue_token = token;
    mt->next = ap.mounts;
    ap.mounts = mt;

    sigprocmask(SIG_SETMASK, &olds, NULL);
    return 0;
  }
  
  /* This is the actual expire run, run as a subprocess */
  
  ignore_signals();
  close(ap.pipefd);
  close(ap.ioctlfd);
  close(ap.state_pipe[0]);
  close(ap.state_pipe[1]);

  do_expire(name, namelen);

  exit(0);
}

static int handle_packet_expire(const struct autofs_packet_expire *pkt)
{
	return handle_expire(pkt->name, pkt->len, 0);
}

static int handle_packet_expire_multi(const struct autofs_packet_expire_multi *pkt)
{
	int ret;

	DB(syslog(LOG_INFO, "handle_packet_expire_multi: token %d, name %s\n", 
		  pkt->wait_queue_token, pkt->name));

	ret = handle_expire(pkt->name, pkt->len, pkt->wait_queue_token);

	if (ret != 0)
		send_fail(pkt->wait_queue_token);
	return ret;
}

static int handle_packet(void)
{
  union autofs_packet_union pkt;

  if (get_pkt(ap.pipefd, &pkt))
    return -1;

  DB(syslog(LOG_INFO, "handle_packet: type = %d\n", pkt.hdr.type));
  switch(pkt.hdr.type) {
  case autofs_ptype_missing:
    return handle_packet_missing(&pkt.missing);
  case autofs_ptype_expire:
    return handle_packet_expire(&pkt.expire);
  case autofs_ptype_expire_multi:
    return handle_packet_expire_multi(&pkt.expire_multi);
  }
  syslog(LOG_ERR, "handle_packet: unknown packet type %d\n", pkt.hdr.type);
  return -1;
}

static void become_daemon(void)
{
  FILE *pidfp;
  pid_t pid;
  int nullfd;
  
  /* Don't BUSY any directories unnecessarily */
  chdir("/");
  
  /* Detach from foreground process */
  if ( !submount ) {
    pid = fork();
    if ( pid > 0 )
      exit(0);
    else if ( pid < 0 ) {
      fprintf(stderr, "%s: Could not detach process\n", program);
      exit(1);
    }
  }
  
  /* Open syslog */ 
  openlog("automount", LOG_PID, LOG_DAEMON);

  /* Initialize global data */
  my_pid = getpid();

  /* Make our own process group for "magic" reason: processes that share
     our pgrp see the raw filesystem behine the magic.  So if we are a 
     submount, don't change -- otherwise we won't be able to actually
     perform the mount.  A pgrp is also useful for controlling all the
     child processes we generate. */
  if ( !submount && setpgrp() ) {
    syslog(LOG_CRIT, "setpgrp: %m");
    exit(1);
  }
  my_pgrp = getpgrp();

  /* Redirect all our file descriptors to /dev/null */
  if ( (nullfd = open("/dev/null", O_RDWR)) < 0 ) {
    syslog(LOG_CRIT, "cannot open /dev/null: %m");
    exit(1);
  }
  
  if ( dup2(nullfd, STDIN_FILENO) < 0 ||
       dup2(nullfd, STDOUT_FILENO) < 0 ||
       dup2(nullfd, STDERR_FILENO) < 0 ) {
    syslog(LOG_CRIT, "redirecting file descriptors failed: %m");
    exit(1);
  }
  close(nullfd);

  /* Write pid file if requested */
  if ( pid_file ) {
    if ( (pidfp = fopen(pid_file, "wt")) ) {
      fprintf(pidfp, "%lu\n", (unsigned long) my_pid);
      fclose(pidfp);
    } else {
      syslog(LOG_WARNING, "failed to write pid file %s: %m", pid_file);
      pid_file = NULL;
    }
  }
}

/*
 * cleanup_exit() is valid to call once we have daemonized
 */

static void cleanup_exit(int exit_code)
{
  if ( ap.lookup )
    close_lookup(ap.lookup);

  if ( pid_file )
    unlink(pid_file);

  closelog();

  exit(exit_code);
}

static unsigned long getnumopt(char *str, char option)
{
  unsigned long val;
  char *end;

  val = strtoul(str, &end, 0);
  if ( ! *str || *end ) {
    fprintf(stderr, "%s: option -%c requires a numeric argument, got %s\n",
	    program, option, str);
    exit(1);
  }
  return val;
}

unsigned get_timeout(void) {
  return ap.exp_timeout;
}

static void usage(void)
{
  fprintf(stderr, "Usage: %s [options] path map_type [args...]\n", program);
}

int main(int argc, char *argv[])
{
  char *path, *map, *mapfmt;
  const char **mapargv;
  struct sigaction sa;
  int mapargc, opt;
  static const struct option long_options[] = {
    {"help",     0, 0, 'h'},
    {"pid-file", 1, 0, 'p'},
    {"timeout",  1, 0, 't'},
    {"version",  0, 0, 'v'},
    {"submount", 0, &submount, 1},
    {0,0,0,0}
  };
  
  program = argv[0];
  
  memset(&ap, 0, sizeof ap);	/* Initialize ap so we can test for null */
  ap.exp_timeout = DEFAULT_TIMEOUT;
  
  opterr = 0;
  while ( (opt = getopt_long(argc, argv, "+hp:t:v", long_options,
			     NULL)) != EOF ) {
    switch( opt ) {
    case 'h':
      usage();
      exit(0);
    case 'p':
      pid_file = optarg;
      break;
    case 't':
      ap.exp_timeout = getnumopt(optarg, opt);
      break;
    case 'v':
      printf("Linux automount version %s\n", version);
      exit(0);
    case '?':
    case ':':
      printf("%s: Ambiguous or unknown options\n", program);
      exit(1);
    }
  }
  
  if ( geteuid() != 0 ) {
    fprintf(stderr, "%s: This program must be run by root.\n", program);
    exit(1);
  }
  
  /* Remove the options */
  argv += optind;
  argc -= optind;
  
  if ( argc < 2 ) {
    usage();
    exit(1);
  }
  
  become_daemon();
  
  path    = argv[0];
  map     = argv[1];
  mapargv = (const char **) &argv[2];
  mapargc = argc-2;
  
  syslog(LOG_INFO, "starting automounter version %s, path = %s, "
	 "maptype = %s, mapname = %s", version, path, map,
	 (mapargc < 1) ? "none" : mapargv[0]);
  
  if ( mapargc ) {
    int i;
    syslog(LOG_DEBUG, "Map argc = %d", mapargc);
    for ( i = 0 ; i < mapargc ; i++ )
      syslog(LOG_DEBUG, "Map argv[%d] = %s", i, mapargv[i]);
  }
  
  if ( (mapfmt = strchr(map,',')) )
    *(mapfmt++) = '\0';
  
  if ( !(ap.lookup = open_lookup(map, "", mapfmt, mapargc, mapargv)) )
    cleanup_exit(1);
  
  /* Signals which are only used in ST_READY state */
  sigemptyset(&ready_sigs);
  sigaddset(&ready_sigs, SIGUSR1);
  sigaddset(&ready_sigs, SIGUSR2);
  sigaddset(&ready_sigs, SIGTERM);
  sigaddset(&ready_sigs, SIGALRM);

  /* Signals which are blocked to do locking */
  memcpy(&lock_sigs, &ready_sigs, sizeof(lock_sigs));
  sigaddset(&lock_sigs, SIGCHLD);
  
  sigemptyset(&sigchld_mask);
  sigaddset(&sigchld_mask, SIGCHLD);
  

  /* The following signals cause state transitions */
  sa.sa_handler = sig_statemachine;
  memcpy(&sa.sa_mask, &ready_sigs, sizeof(sa.sa_mask));
  sa.sa_flags = SA_RESTART;

  /* SIGTERM and SIGUSR2 are synonymous */
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGUSR2, &sa, NULL);

  /* The SIGALRM handler controls expiration of entries. */
  sigaction(SIGALRM, &sa, NULL);

  /* SIGUSR1 causes a prune event */
  sigaction(SIGUSR1, &sa, NULL);

  /* The following signals cause a shutdown event to occur, but if we
     get more than one, permit the signal to proceed so we don't loop.
     This is basically the complete list of "this shouldn't happen"
     signals. */
  sa.sa_flags = SA_ONESHOT|SA_RESTART;
  sigaction(SIGIO, &sa, NULL);
  sigaction(SIGXCPU, &sa, NULL);
  sigaction(SIGXFSZ, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
#ifndef DEBUG
  /* When debugging, these signals should be in the default state; when
     in production, we want to at least attempt to catch them and shut down. */
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
  sigaction(SIGPROF, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
#ifdef SIGSYS
  sigaction(SIGSYS, &sa, NULL);
#endif
#ifdef SIGSTKFLT
  sigaction(SIGSTKFLT, &sa, NULL);
#endif
#ifdef SIGLOST
  sigaction(SIGLOST, &sa, NULL);
#endif
#ifdef SIGEMT
  sigaction(SIGEMT, &sa, NULL);
#endif
#endif /* DEBUG */
  
  /* The SIGCHLD handler causes state transitions as processes exit
     (expire and mount) */
  sa.sa_handler = sig_child;
  memcpy(&sa.sa_mask, &lock_sigs, sizeof(sa.sa_mask));
  sa.sa_flags = SA_NOCLDSTOP;	/* Don't need info about stopped children */
  sigaction(SIGCHLD, &sa, NULL);
  
  /* The following signals shouldn't occur, and are ignored */
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGVTALRM, &sa, NULL);
  sigaction(SIGURG, &sa, NULL);
  sigaction(SIGWINCH, &sa, NULL);
#ifdef SIGPWR
  sigaction(SIGPWR, &sa, NULL);
#endif
#ifdef SIGUNUSED
  sigaction(SIGUNUSED, &sa, NULL);
#endif
  
  if (mount_autofs(path) < 0) {
    syslog(LOG_CRIT, "%s: mount failed!", path);
    cleanup_exit(1);
  }	

  /* If this ioctl() doesn't work, it is kernel version 2 */
  if ( ioctl(ap.ioctlfd, AUTOFS_IOC_PROTOVER, &kproto_version) ) {
    syslog(LOG_DEBUG, "kproto: %m");
    kproto_version = 2;
  }
  
  syslog(LOG_INFO, "using kernel protocol version %d", kproto_version);
  
  if ( kproto_version < 3 ) {
    ap.exp_timeout = ap.exp_runfreq = 0;
    syslog(LOG_INFO, "kernel does not support timeouts");
  } else {
    unsigned long timeout;
    
    ap.exp_runfreq = (ap.exp_timeout+CHECK_RATIO-1) / CHECK_RATIO;
    
    timeout = ap.exp_timeout;

    syslog(LOG_INFO, "using timeout %ld seconds; freq %d secs",
	   timeout, ap.exp_runfreq);

    ioctl(ap.ioctlfd, AUTOFS_IOC_SETTIMEOUT, &timeout);
    
    /* We often start several automounters at the same time.  Add some
       randomness so we don't all expire at the same time. */
    if ( ap.exp_timeout )
      alarm(ap.exp_runfreq + my_pid % ap.exp_runfreq);
  }

  /* Initialization successful.  If we're a submount, send outselves
     SIGSTOP to let our parent know that we have grown up and don't
     need supervision anymore. */
  if ( submount )
    kill(my_pid, SIGSTOP);
  
  while ( ap.state != ST_SHUTDOWN ) {
    if (handle_packet() && errno != EINTR)
      break;
  }
  
  syslog(LOG_INFO, "shutting down, path = %s", path);
  /* Mop up remaining kids */
  handle_child(1);

  /* Close down */
  umount_autofs(1);

  cleanup_exit(0);
}
