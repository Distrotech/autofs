#ident "$Id: automount.h,v 1.19 2005/11/27 04:08:54 raven Exp $"
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

#ifdef DEBUG
#define DB(x)           do { x; } while(0)
#else
#define DB(x)           do { } while(0)
#endif

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

void cache_init(void);
void cache_set_ino_index(const char *key, dev_t dev, ino_t ino);
struct mapent_cache *cache_lookup_ino(dev_t dev, ino_t ino);
struct mapent_cache *cache_lookup(const char *key);
struct mapent_cache *cache_lookup_next(struct mapent_cache *me);
struct mapent_cache *cache_lookup_first(void);
struct mapent_cache *cache_lookup_offset(const char *prefix, const char *offset, int start, struct list_head *head);
struct mapent_cache *cache_partial_match(const char *prefix);
int cache_add(const char *key, const char *mapent, time_t age);
int cache_add_offset(const char *mkey, const char *key, const char *mapent, time_t age);
int cache_update(const char *key, const char *mapent, time_t age);
int cache_delete(const char *table, const char *root, const char *key, int rmpath);
int cache_delete_offset(const char *table, const char *root, const char *key);
void cache_clean(const char *table, const char *root, time_t age);
void cache_release(void);
int cache_enumerate(int (*fn)(struct mapent_cache *, int), int arg);
int cache_ghost(const char *root, int is_ghosted);
char *cache_get_offset(const char *prefix, char *offset, int start, struct list_head *head, struct list_head **pos);

/* Utility functions */

int aquire_lock(void);
void release_lock(void);
int spawnll(int logpri, const char *prog, ...);
int spawnl(int logpri, const char *prog, ...);
int spawnv(int logpri, const char *prog, const char *const *argv);
void reset_signals(void);
void ignore_signals(void);
void discard_pending(int sig);
int signal_children(int sig);
int do_mount(const char *root, const char *name, int name_len,
	     const char *what, const char *fstype, const char *options);
int mkdir_path(const char *path, mode_t mode);
int rmdir_path(const char *path);

/* Prototype for module functions */

/* lookup module */

#define AUTOFS_LOOKUP_VERSION 4

#define KEY_MAX_LEN    NAME_MAX
#define MAPENT_MAX_LEN 4095

#ifdef MODULE_LOOKUP
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context);
int lookup_enumerate(const char *, int (*fn)(struct mapent_cache *, int), time_t, void *);
int lookup_ghost(const char *, int, time_t, void *);
int lookup_mount(const char *, const char *, int, void *);
int lookup_done(void *);
#endif
typedef int (*lookup_init_t) (const char *, int, const char *const *, void **);
typedef int (*lookup_enumerate_t) (const char *, int (*fn)(struct mapent_cache *, int), time_t, void *);
typedef int (*lookup_ghost_t) (const char *, int, time_t, void *);
typedef int (*lookup_mount_t) (const char *, const char *, int, void *);
typedef int (*lookup_done_t) (void *);

struct lookup_mod {
	lookup_init_t lookup_init;
	lookup_enumerate_t lookup_enumerate;
	lookup_ghost_t lookup_ghost;
	lookup_mount_t lookup_mount;
	lookup_done_t lookup_done;
	void *dlhandle;
	void *context;
};

struct lookup_mod *open_lookup(const char *name, const char *err_prefix,
			       const char *mapfmt, int argc, const char *const *argv);
int close_lookup(struct lookup_mod *);

/* parse module */

#define AUTOFS_PARSE_VERSION 3

#ifdef MODULE_PARSE
int parse_init(int argc, const char *const *argv, void **context);
int parse_mount(const char *root, const char *name,
		int name_len, const char *mapent, int parse_context,
		void *context);
int parse_done(void *);
#endif
typedef int (*parse_init_t) (int, const char *const *, void **);
typedef int (*parse_mount_t) (const char *, const char *, int, const char *, int, void *);
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
int mount_mount(const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context);
int mount_done(void *context);
#endif
typedef int (*mount_init_t) (void **);
typedef int (*mount_mount_t) (const char *, const char *, int, const char *, const char *,
			      const char *, void *);
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

unsigned int rpc_ping(const char *host, long seconds, long micros);
int rpc_time(const char *host, 
	     unsigned int ping_vers, unsigned int ping_proto,
	     long seconds, long micros, double *result);

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

struct pending_mount {
	pid_t pid;			/* Which process is mounting for us */
	struct mapent_cache *me;	/* Map entry descriptor */
	int ioctlfd;			/* fd to send ioctls to kernel */
	int type;			/* Type of packet */
	unsigned long wait_queue_token;	/* Associated kernel wait token */
	volatile struct pending_mount *next;
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
	unsigned int type;		/* Type of map direct or indirect */
	time_t exp_timeout;		/* Timeout for expiring mounts */
	time_t exp_runfreq;		/* Frequency for polling for timeouts */
	unsigned ghost;			/* Enable/disable gohsted directories */
	struct kernel_mod_version kver;		/* autofs kernel module version */
	volatile pid_t exp_process;		/* Process that is currently expiring */
	volatile struct pending_mount *mounts;	/* Pending mount queue */
	struct lookup_mod *lookup;		/* Lookup module */
	enum states state;
	int state_pipe[2];
	unsigned dir_created;		/* Was a directory created for this
					   mount? */
};

extern struct autofs_point ap; 

/* Standard function used by daemon or modules */

int umount_multi(const char *path, int incl);
int send_ready(int ioctlfd, unsigned int wait_queue_token);
int send_fail(int ioctlfd, unsigned int wait_queue_token);
int handle_expire(const char *name, int namelen,
			int ioctlfd, autofs_wqt_t token);
int expire_proc_indirect(int now);
int expire_proc_direct(struct mapent_cache *me, int now);
int expire_offsets_direct(struct mapent_cache *me, int now);
int mount_autofs_indirect(char *path);
int mount_autofs_direct(char *path);
int mount_autofs_offset(struct mapent_cache *me, int is_autofs_fs);
int umount_autofs(int force);
int umount_autofs_indirect(void);
int umount_autofs_direct(void);
int umount_autofs_offset(struct mapent_cache *me);
int handle_packet_expire_indirect(const struct autofs_packet_expire_indirect *pkt);
int handle_packet_expire_direct(const struct autofs_packet_expire_direct *pkt);
int handle_packet_missing_indirect(const struct autofs_packet_missing_indirect *pkt);
int handle_packet_missing_direct(const struct autofs_packet_missing_direct *pkt);
void rm_unwanted(const char *path, int incl, int rmsymlink);
int count_mounts(const char *path);
void cleanup_exit(const char *path, int exit_code);

/* log notification */
extern int do_verbose;		/* Verbose feedback option */
extern int do_debug;		/* Enable full debug output */

/* Define non-reentrant logging macros */

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
 
#define msg(msg, args...)			\
do {						\
	if (do_verbose || do_debug)		\
		syslog(LOG_INFO, msg, ##args);	\
} while (0)

#define debug(msg, args...)			\
do {						\
	if (do_debug)				\
		syslog(LOG_DEBUG, "%s: " msg,	\
			__FUNCTION__ , ##args);	\
} while (0)

#define info(msg, args...)			\
do {						\
	if (do_verbose || do_debug)		\
		syslog(LOG_INFO, "%s: " msg,	\
			__FUNCTION__ , ##args);	\
} while (0)

#define notice(msg, args...)			\
do {						\
	if (do_verbose || do_debug)		\
		syslog(LOG_NOTICE, "%s: " msg,	\
			__FUNCTION__ , ##args);	\
} while (0)

#define warn(msg, args...)			\
do {						\
	if (do_verbose || do_debug)		\
		syslog(LOG_WARNING, "%s: " msg,	\
			__FUNCTION__ , ##args);	\
} while (0)

#define error(msg, args...)			\
do {						\
	syslog(LOG_ERR, "%s: " msg,		\
			__FUNCTION__ , ##args);	\
} while (0)

#define crit(msg, args...)			\
do {						\
	syslog(LOG_CRIT, "%s: " msg,		\
		__FUNCTION__ , ##args);		\
} while (0)

#define alert(msg, args...)			\
do {						\
	syslog(LOG_ALERT, "%s: " msg,		\
		__FUNCTION__ , ##args);		\
} while (0)

#define emerg(msg, args...)			\
do {						\
	syslog(LOG_EMERG, "%s: " msg,		\
		__FUNCTION__ , ##args);		\
} while (0)

/* Define reentrant logging macros for signal handlers */

#ifndef NDEBUG
#define assert_r(context, x)						\
do {									\
	if (!(x)) {							\
		 crit_r(context,					\
			__FILE__ ":%d: assertion failed: ", __LINE__);	\
	}								\
} while(0)
#else
#define assert_r(context, x)	do { } while(0)
#endif

#define debug_r(context, msg, args...)				\
do {								\
	if (do_debug)						\
		syslog_r(LOG_DEBUG, context, "%s: " msg,	\
			 __FUNCTION__ , ##args);		\
} while (0)

#define warn_r(context, msg, args...)			  \
do {							  \
	if (do_verbose || do_debug)			  \
		syslog_r(LOG_WARNING, context, "%s: " msg, \
			 __FUNCTION__ , ##args);	  \
} while (0)

#define error_r(context, msg, args...)			\
do {							\
	syslog_r(LOG_ERR, context, "%s: " msg,		\
		 __FUNCTION__ , ##args);		\
} while (0)

#define crit_r(context, msg, args...)			\
do {							\
	syslog_r(LOG_CRIT, context, "%s: " msg, 	\
		__FUNCTION__ , ##args);			\
} while (0)

#endif

