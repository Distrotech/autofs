#ident "$Id: automount.h,v 1.23 2006/02/21 18:48:11 raven Exp $"
/*
 * automount.h
 *
 * Header file for automounter modules
 *
 */

#ifndef AUTOMOUNT_H
#define AUTOMOUNT_H

#include <sys/types.h>
#include <paths.h>
#include <limits.h>
#include <time.h>
#include <linux/types.h>
#include <pthread.h>
#include <errno.h>
#include "config.h"
#include "list.h"

#include <linux/auto_fs4.h>

/* OpenBSD re-entrant syslog */
#include "syslog.h"

/* We MUST have the paths to mount(8) and umount(8) */
#ifndef HAVE_MOUNT
#error Failed to locate mount(8)!
#endif

#ifndef HAVE_UMOUNT
#error Failed to locate umount(8)!
#endif

/* The -s (sloppy) option to mount is good, if we have it... */

#ifdef HAVE_SLOPPY_MOUNT
#define SLOPPYOPT "-s",		/* For use in spawnl() lists */
#define SLOPPY    "-s "		/* For use in strings */
#else
#define SLOPPYOPT
#define SLOPPY
#endif

#define DEFAULT_TIMEOUT (5*60)			/* 5 minutes */
#define CHECK_RATIO	4			/* exp_runfreq = exp_timeout/CHECK_RATIO */
#define AUTOFS_LOCK	"/var/lock/autofs"	/* To serialize access to mount */
#define MOUNTED_LOCK	_PATH_MOUNTED "~"	/* mounts' lock file */
#define MTAB_NOTUPDATED 0x1000			/* mtab succeded but not updated */
#define NOT_MOUNTED     0x0100			/* path notmounted */
#define _PROC_MOUNTS	"/proc/mounts"

/* Constants for lookup modules */

#define LKP_FAIL	0x0001

#define LKP_INDIRECT	0x0002
#define LKP_DIRECT	0x0004
#define LKP_NOMATCH	0x0008
#define LKP_MATCH	0x0010
#define LKP_NEXT	0x0020
#define LKP_MOUNT	0x0040
#define LKP_WILD	0x0080
#define LKP_LOOKUP	0x0100
#define LKP_GHOST	0x0200
#define LKP_REREAD	0x0400
#define LKP_EMPTY	0x0800
#define LKP_ERR_FORMAT	0x1000
#define LKP_ERR_MOUNT	0x2000
#define LKP_NOTSUP	0x4000

#define MAX_ERR_BUF	128

#ifdef DEBUG
#define DB(x)           do { x; } while(0)
#else
#define DB(x)           do { } while(0)
#endif

/* Forward declaraion */
struct autofs_point; 

/*
 * State machine for daemon
 * 
 * READY - reads from pipe; performs mount/umount operations
 * PRUNE - generates prune events in subprocess; reads from pipe
 * READMAP - read read map for maps taht use cache
 * EXPIRE - generates expire events in subprocess; reads from pipe
 * SHUTDOWN_PENDING - as prune, but goes to SHUTDOWN when done
 * SHUTDOWN - unmount autofs, exit
 *
 * Signals TERM, USR1, USR2, HUP and ALRM are blocked in all states except
 * READY.  SIGCHLD is blocked when protecting the manipulating mount list.
 */
enum states {
	ST_INVAL = -1,
	ST_INIT,
	ST_READY,
	ST_EXPIRE,
	ST_PRUNE,
	ST_READMAP,
	ST_SHUTDOWN_PENDING,
	ST_SHUTDOWN,
};

/* mapent cache definition */

#define CHE_FAIL	0x0000
#define CHE_OK		0x0001
#define CHE_UPDATED	0x0002
#define CHE_RMPATH	0x0004
#define CHE_MISSING	0x0008

struct mapent_cache {
	struct mapent_cache *next;
	pthread_mutex_t mutex;
	unsigned int count;
	struct list_head multi_list;
	/* Need to know owner if we're a multi mount */
	struct mapent_cache *multi;
	char *key;
	char *mapent;
	time_t age;
	/* For direct mounts per entry context is kept here */
	int dir_created;
	int ioctlfd;		/* File descriptor for ioctls */
	dev_t dev;
	ino_t ino;
};

void cache_lock_cleanup(void *arg);
int cache_readlock(void);
int cache_writelock(void);
int cache_unlock(void);
void cache_init(void);
void cache_set_ino_index(const char *key, dev_t dev, ino_t ino);
void cache_set_ino(struct mapent_cache *me, dev_t dev, ino_t ino);
struct mapent_cache *cache_lookup_ino(dev_t dev, ino_t ino);
struct mapent_cache *cache_lookup(const char *key);
struct mapent_cache *cache_lookup_first(void);
struct mapent_cache *cache_lookup_next(struct mapent_cache *me);
struct mapent_cache *cache_lookup_key_next(struct mapent_cache *me);
struct mapent_cache *cache_lookup_offset(const char *prefix, const char *offset, int start, struct list_head *head);
struct mapent_cache *cache_partial_match(const char *prefix);
int cache_add(const char *key, const char *mapent, time_t age);
int cache_add_offset(const char *mkey, const char *key, const char *mapent, time_t age);
int cache_update(const char *key, const char *mapent, time_t age);
int cache_delete(const char *key);
int cache_delete_offset_list(const char *key);
void cache_clean(const char *root, time_t age);
void cache_release(void);
struct mapent_cache *cache_enumerate(struct mapent_cache *me);
char *cache_get_offset(const char *prefix, char *offset, int start, struct list_head *head, struct list_head **pos);

/* Utility functions */

int sigchld_start_handler(void);
int sigchld_block(void);
int sigchld_unblock(void);
int aquire_lock(void);
void release_lock(void);
int spawnl(int logpri, const char *prog, ...);
#ifdef ENABLE_MOUNT_LOCKING
int spawnll(int logpri, const char *prog, ...);
#else
#define spawnll	spawnl
#endif
int spawnv(int ogpri, const char *prog, const char *const *argv);
void reset_signals(void);
void ignore_signals(void);
void discard_pending(int sig);
int signal_children(int sig);
int do_mount(struct autofs_point *ap, const char *root, const char *name,
	     int name_len, const char *what, const char *fstype,
	     const char *options);
int mkdir_path(const char *path, mode_t mode);
int rmdir_path(const char *path);

/* Prototype for module functions */

/* lookup module */

#define AUTOFS_LOOKUP_VERSION 5

#define KEY_MAX_LEN    NAME_MAX
#define MAPENT_MAX_LEN 4095

int lookup_nss_read_map(struct autofs_point *ap, time_t age);
int lookup_enumerate(struct autofs_point *ap,
	int (*fn)(struct autofs_point *,struct mapent_cache *, int), time_t now);
int lookup_ghost(struct autofs_point *ap);
int lookup_nss_mount(struct autofs_point *ap, const char *name, int name_len);

#ifdef MODULE_LOOKUP
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context);
int lookup_read_map(struct autofs_point *, time_t, void *context);
int lookup_mount(struct autofs_point *, const char *, int, void *);
int lookup_done(void *);
#endif
typedef int (*lookup_init_t) (const char *, int, const char *const *, void **);
typedef int (*lookup_read_map_t) (struct autofs_point *, time_t, void *context);
typedef int (*lookup_mount_t) (struct autofs_point *, const char *, int, void *);
typedef int (*lookup_done_t) (void *);

struct lookup_mod {
	lookup_init_t lookup_init;
	lookup_read_map_t lookup_read_map;
	lookup_mount_t lookup_mount;
	lookup_done_t lookup_done;
	void *dlhandle;
	void *context;
};

struct lookup_mod *open_lookup(const char *name, const char *err_prefix,
			       const char *mapfmt, int argc, const char *const *argv);
int close_lookup(struct lookup_mod *);

/* parse module */

#define AUTOFS_PARSE_VERSION 5

#ifdef MODULE_PARSE
int parse_init(int argc, const char *const *argv, void **context);
int parse_mount(struct autofs_point *ap, const char *name,
		int name_len, const char *mapent, void *context);
int parse_done(void *);
#endif
typedef int (*parse_init_t) (int, const char *const *, void **);
typedef int (*parse_mount_t) (struct autofs_point *, const char *, int, const char *, void *);
typedef int (*parse_done_t) (void *);

struct parse_mod {
	parse_init_t parse_init;
	parse_mount_t parse_mount;
	parse_done_t parse_done;
	void *dlhandle;
	void *context;
};

struct parse_mod *open_parse(const char *name, const char *err_prefix,
			     int argc, const char *const *argv);
int close_parse(struct parse_mod *);

/* mount module */

#define AUTOFS_MOUNT_VERSION 4

#ifdef MODULE_MOUNT
int mount_init(void **context);
int mount_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context);
int mount_done(void *context);
#endif
typedef int (*mount_init_t) (void **);
typedef int (*mount_mount_t) (struct autofs_point *, const char *, const char *, int,
				const char *, const char *, const char *, void *);
typedef int (*mount_done_t) (void *);

struct mount_mod {
	mount_init_t mount_init;
	mount_mount_t mount_mount;
	mount_done_t mount_done;
	void *dlhandle;
	void *context;
};

struct mount_mod *open_mount(const char *name, const char *err_prefix);
int close_mount(struct mount_mod *);

/* buffer management */

int _strlen(const char *str, size_t max);
int cat_path(char *buf, size_t len, const char *dir, const char *base);
int ncat_path(char *buf, size_t len,
              const char *dir, const char *base, size_t blen);

/* rpc helper subs */
#define RPC_PING_FAIL           0x0000
#define RPC_PING_V2             NFS2_VERSION
#define RPC_PING_V3             NFS3_VERSION
#define RPC_PING_UDP            0x0100
#define RPC_PING_TCP            0x0200
/*
 * Close options to allow some choice in how and where the TIMED_WAIT
 *  happens.
 */
#define RPC_CLOSE_DEFAULT	0x0000
#define RPC_CLOSE_ACTIVE	RPC_CLOSE_DEFAULT
#define RPC_CLOSE_NOLINGER	0x0001
#

unsigned int rpc_ping(const char *host,
		      long seconds, long micros, unsigned int option);
int rpc_time(const char *host, 
	     unsigned int ping_vers, unsigned int ping_proto,
	     long seconds, long micros, unsigned int option, double *result);

/* mount table utilities */
struct mnt_list {
	char *path;
	char *fs_type;
	pid_t pid;
	time_t last_access;
	struct mnt_list *next;
	struct list_head list;
};

int make_options_string(char *options, int options_len, int kernel_pipefd, char *extra);
struct mnt_list *get_mnt_list(const char *table, const char *path, int include);
struct mnt_list *reverse_mnt_list(struct mnt_list *list);
struct mnt_list *get_base_mnt_list(struct mnt_list *list);
void free_mnt_list(struct mnt_list *list);
int is_mounted(const char *table, const char *path);
int has_fstab_option(const char *path, const char *opt);
int allow_owner_mount(const char *);
char *find_mnt_ino(const char *table, dev_t dev, ino_t ino);
char *get_offset(const char *prefix, char *offset,
                 struct list_head *head, struct list_head **pos);
void add_ordered_list(struct mnt_list *ent, struct list_head *head);

/* file utility functions */

int xopen(const char *path, int flags);

/* Core automount definitions */

struct readmap_args {
	struct autofs_point *ap;	/* autofs mount we are working on */
	time_t now;		/* Time when map is read */
	int status;			/* Return status */
};

struct expire_cond {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	struct autofs_point *ap;
	unsigned int signaled;
	unsigned int    when;
};

extern struct expire_cond ec;

struct expire_args {
	struct autofs_point *ap;	/* autofs mount we are working on */
	unsigned int when;		/* Immediate expire ? */
	int status;			/* Return status */
};

struct pending_args {
	struct autofs_point *ap;	/* autofs mount we are working on */
	int status;			/* Return status */
	int type;			/* Type of packet */
	int ioctlfd;			/* Mount ioctl fd */
	char name[KEY_MAX_LEN];		/* Name field of the request */
	dev_t dev;			/* device number of mount */
	unsigned int len;		/* Name field len */
	uid_t uid;			/* uid of requestor */
	gid_t gid;			/* gid of requestor */
	unsigned long wait_queue_token;	/* Associated kernel wait token */
};

struct kernel_mod_version {
	unsigned int major;
	unsigned int minor;
};

struct autofs_point {
	char *path;			/* Mount point name */
	int pipefd;			/* File descriptor for pipe */
	int kpipefd;			/* Kernel end descriptor for pipe */
	int ioctlfd;			/* File descriptor for ioctls */
	dev_t dev;			/* "Device" number assigned by kernel */
	char *maptype;			/* Type of map "file", "NIS", etc */
	char *mapfmt;			/* Format of map default "Sun" */
	int mapargc;			/* Map options arg count */
	const char **mapargv;			/* Map options args */
	unsigned int type;		/* Type of map direct or indirect */
	time_t exp_timeout;		/* Timeout for expiring mounts */
	time_t exp_runfreq;		/* Frequency for polling for timeouts */
	unsigned ghost;			/* Enable/disable gohsted directories */
	struct kernel_mod_version kver;	/* autofs kernel module version */
	pthread_t exp_thread;		/* Process that is currently expiring */
	struct lookup_mod *lookup;	/* Lookup module */
	enum states state;
	int state_pipe[2];
	unsigned dir_created;		/* Was a directory created for this
					   mount? */
};

/* Standard functions used by daemon or modules */

int umount_multi(struct autofs_point *ap, const char *path, int incl);
int send_ready(int ioctlfd, unsigned int wait_queue_token);
int send_fail(int ioctlfd, unsigned int wait_queue_token);
/*int handle_expire(const char *name, int namelen,
			int ioctlfd, autofs_wqt_t token); */
int umount_offsets(const char *path);
int do_expire(struct autofs_point *ap, const char *name, int namelen);
void *expire_proc_indirect(void *);
void *expire_proc_direct(void *);
int expire_offsets_direct(struct autofs_point *ap, struct mapent_cache *me, int now);
int mount_autofs_indirect(struct autofs_point *ap, char *path);
int mount_autofs_direct(struct autofs_point *ap, char *path);
int mount_autofs_offset(struct autofs_point *ap, struct mapent_cache *me, int is_autofs_fs);
int umount_autofs(struct autofs_point *ap, int force);
int umount_autofs_indirect(struct autofs_point *ap);
int umount_autofs_direct(struct autofs_point *ap);
int umount_autofs_offset(struct mapent_cache *me);
int handle_packet_expire_indirect(struct autofs_point *ap, autofs_packet_expire_indirect_t *pkt);
int handle_packet_expire_direct(struct autofs_point *ap, autofs_packet_expire_direct_t *pkt);
int handle_packet_missing_indirect(struct autofs_point *ap, autofs_packet_missing_indirect_t *pkt);
int handle_packet_missing_direct(struct autofs_point *ap, autofs_packet_missing_direct_t *pkt);
void rm_unwanted(const char *path, int incl, int rmsymlink);
int count_mounts(const char *path);
void expire_cleanup(void *arg);
void cleanup_exit(const char *path, int exit_code);

/* Define logging functions */

extern void set_log_norm(void);
extern void set_log_verbose(void);
extern unsigned int is_log_verbose(void);
extern void set_log_debug(void);
extern unsigned int is_log_debug(void);

extern void log_to_syslog(void);
 
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

