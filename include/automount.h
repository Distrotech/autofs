#ident "$Id: automount.h,v 1.42 2006/03/26 04:56:22 raven Exp $"
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
#include <syslog.h>
#include <linux/types.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include "config.h"
#include "list.h"

#include <linux/auto_fs4.h>

#include "state.h"
#include "master.h"

#if WITH_DMALLOC
#include <dmalloc.h>
#endif

/* OpenBSD re-entrant syslog
#include "syslog.h"
*/

#define ENABLE_CORES	1

/* We MUST have the paths to mount(8) and umount(8) */
#ifndef HAVE_MOUNT
#error Failed to locate mount(8)!
#endif

#ifndef HAVE_UMOUNT
#error Failed to locate umount(8)!
#endif

#ifndef HAVE_MODPROBE
#error Failed to locate modprobe(8)!
#endif

#define FS_MODULE_NAME  "autofs4"
int load_autofs4_module(void);

/* The -s (sloppy) option to mount is good, if we have it... */

#ifdef HAVE_SLOPPY_MOUNT
#define SLOPPYOPT "-s",		/* For use in spawnl() lists */
#define SLOPPY    "-s "		/* For use in strings */
#else
#define SLOPPYOPT
#define SLOPPY
#endif

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

/* mapent cache definition */

#define CHE_FAIL	0x0000
#define CHE_OK		0x0001
#define CHE_UPDATED	0x0002
#define CHE_RMPATH	0x0004
#define CHE_MISSING	0x0008
#define CHE_COMPLETED	0x0010

#define HASHSIZE      77

struct mapent_cache {
	pthread_rwlock_t rwlock;
	unsigned int size;
	struct list_head *ino_index;
	struct mapent **hash;
};

struct mapent {
	struct mapent *next;
	struct list_head ino_index;
	struct list_head multi_list;
	/* Need to know owner if we're a multi mount */
	struct mapent *multi;
	char *key;
	char *mapent;
	time_t age;
	/* For direct mounts per entry context is kept here */
	int dir_created;
	/* File descriptor for ioctls */
	int ioctlfd;
	dev_t dev;
	ino_t ino;
};

void cache_lock_cleanup(void *arg);
int cache_readlock(struct mapent_cache *mc);
int cache_writelock(struct mapent_cache *mc);
int cache_unlock(struct mapent_cache *mc);
struct mapent_cache *cache_init(struct autofs_point *ap);
int cache_set_ino_index(struct mapent_cache *mc, const char *key, dev_t dev, ino_t ino);
/* void cache_set_ino(struct mapent *me, dev_t dev, ino_t ino); */
struct mapent *cache_lookup_ino(struct mapent_cache *mc, dev_t dev, ino_t ino);
struct mapent *cache_lookup_first(struct mapent_cache *mc);
struct mapent *cache_lookup_next(struct mapent_cache *mc, struct mapent *me);
struct mapent *cache_lookup_key_next(struct mapent *me);
struct mapent *cache_lookup(struct mapent_cache *mc, const char *key);
struct mapent *cache_lookup_offset(const char *prefix, const char *offset, int start, struct list_head *head);
struct mapent *cache_partial_match(struct mapent_cache *mc, const char *prefix);
int cache_add(struct mapent_cache *mc, const char *key, const char *mapent, time_t age);
int cache_add_offset(struct mapent_cache *mc, const char *mkey, const char *key, const char *mapent, time_t age);
int cache_update(struct mapent_cache *mc, const char *key, const char *mapent, time_t age);
int cache_delete(struct mapent_cache *mc, const char *key);
int cache_delete_offset_list(struct mapent_cache *mc, const char *key);
void cache_release(struct autofs_point *ap);
struct mapent *cache_enumerate(struct mapent_cache *mc, struct mapent *me);
char *cache_get_offset(const char *prefix, char *offset, int start, struct list_head *head, struct list_head **pos);

/* Utility functions */

char **add_argv(int argc, char **argv, char *str);
const char **copy_argv(int argc, const char **argv);
int compare_argv(int argc1, const char **argv1, int argc2, const char **argv2);
int free_argv(int argc, const char **argv);

void dump_core(void);
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

int lookup_nss_read_master(struct master *master, time_t age);
int lookup_nss_read_map(struct autofs_point *ap, time_t age);
int lookup_enumerate(struct autofs_point *ap,
	int (*fn)(struct autofs_point *,struct mapent *, int), time_t now);
int lookup_ghost(struct autofs_point *ap);
int lookup_nss_mount(struct autofs_point *ap, const char *name, int name_len);
int lookup_prune_cache(struct autofs_point *ap, time_t age);

#ifdef MODULE_LOOKUP
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context);
int lookup_read_master(struct master *master, time_t age, void *context);
int lookup_read_map(struct autofs_point *, time_t, void *context);
int lookup_mount(struct autofs_point *, const char *, int, void *);
int lookup_done(void *);
#endif
typedef int (*lookup_init_t) (const char *, int, const char *const *, void **);
typedef int (*lookup_read_master_t) (struct master *master, time_t, void *);
typedef int (*lookup_read_map_t) (struct autofs_point *, time_t, void *);
typedef int (*lookup_mount_t) (struct autofs_point *, const char *, int, void *);
typedef int (*lookup_done_t) (void *);

struct lookup_mod {
	lookup_init_t lookup_init;
	lookup_read_master_t lookup_read_master;
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

unsigned int rpc_ping(const char *host,
		      long seconds, long micros, unsigned int option);
int rpc_time(const char *host, 
	     unsigned int ping_vers, unsigned int ping_proto,
	     long seconds, long micros, unsigned int option, double *result);

/* mount table utilities */
struct mnt_list {
	char *path;
	char *fs_type;
	char *opts;
	pid_t pid;
	struct mnt_list *next;
	struct list_head list;
};

char *make_options_string(char *path, int kernel_pipefd, char *extra);
char *make_mnt_name_string(char *path);
struct mnt_list *get_mnt_list(const char *table, const char *path, int include);
struct mnt_list *reverse_mnt_list(struct mnt_list *list);
void free_mnt_list(struct mnt_list *list);
int is_mounted(const char *table, const char *path);
int has_fstab_option(const char *path, const char *opt);
char *find_mnt_ino(const char *table, dev_t dev, ino_t ino);
char *get_offset(const char *prefix, char *offset,
                 struct list_head *head, struct list_head **pos);
void add_ordered_list(struct mnt_list *ent, struct list_head *head);

/* Core automount definitions */

#define MNT_DETACH	0x00000002	/* Just detach from the tree */

struct startup_cond {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	unsigned int done;
	unsigned int status;
};

struct master_readmap_cond {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	pthread_t thid;		 /* map reader thread id */
	struct master *master;
	time_t age;		 /* Last time read */
	enum states state;	 /* Next state */
	unsigned int signaled;   /* Condition has been signaled */
	unsigned int busy;	 /* Map read in progress. */
};

extern struct master_readmap_cond mc;

struct pending_args {
	pthread_barrier_t barrier;
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

struct thread_stdenv_vars {
	uid_t uid;
	gid_t gid;
	char *user;
	char *group;
	char *home;
};

extern pthread_key_t key_thread_stdenv_vars;

struct kernel_mod_version {
	unsigned int major;
	unsigned int minor;
};

struct autofs_point {
	pthread_t thid;
	char *path;			/* Mount point name */
	int pipefd;			/* File descriptor for pipe */
	int kpipefd;			/* Kernel end descriptor for pipe */
	int ioctlfd;			/* File descriptor for ioctls */
	dev_t dev;			/* "Device" number assigned by kernel */
	struct master_mapent *entry;	/* Master map entry for this mount */
	unsigned int type;		/* Type of map direct or indirect */
	time_t exp_timeout;		/* Timeout for expiring mounts */
	time_t exp_runfreq;		/* Frequency for polling for timeouts */
	unsigned ghost;			/* Enable/disable gohsted directories */
	unsigned logopt;		/* Per map loggin */
	struct kernel_mod_version kver;	/* autofs kernel module version */
	pthread_t exp_thread;		/* Process that is currently expiring */
	struct lookup_mod *lookup;	/* Lookup module */
	pthread_mutex_t state_mutex;	/* Protect state transitions */
	struct list_head state_queue;	/* Pending state transitions */
	enum states state;		/* Current state */
	int state_pipe[2];		/* State change router pipe */
	unsigned dir_created;		/* Directory created for this mount? */
	unsigned int submount;		/* Is this a submount */
	struct autofs_point *parent;	/* Owner of mounts list for submount */
	pthread_mutex_t mounts_mutex;	/* Protect mount lists */
	struct list_head mounts;	/* List of autofs mounts */
	struct list_head submounts;	/* List of child submounts */
	struct mapent_cache *mc;	/* Mapentry lookup table for this path */
};

/* Standard functions used by daemon or modules */

void *handle_mounts(void *arg);
int umount_multi(struct autofs_point *ap, const char *path, int incl);
int send_ready(int ioctlfd, unsigned int wait_queue_token);
int send_fail(int ioctlfd, unsigned int wait_queue_token);
int do_expire(struct autofs_point *ap, const char *name, int namelen);
void *expire_proc_indirect(void *);
void *expire_proc_direct(void *);
int expire_offsets_direct(struct autofs_point *ap, struct mapent *me, int now);
int mount_autofs_indirect(struct autofs_point *ap);
int mount_autofs_direct(struct autofs_point *ap);
int mount_autofs_offset(struct autofs_point *ap, struct mapent *me, int is_autofs_fs);
int umount_autofs(struct autofs_point *ap, int force);
int umount_autofs_indirect(struct autofs_point *ap);
int umount_autofs_direct(struct autofs_point *ap);
int umount_autofs_offset(struct autofs_point *ap, struct mapent *me);
int handle_packet_expire_indirect(struct autofs_point *ap, autofs_packet_expire_indirect_t *pkt);
int handle_packet_expire_direct(struct autofs_point *ap, autofs_packet_expire_direct_t *pkt);
int handle_packet_missing_indirect(struct autofs_point *ap, autofs_packet_missing_indirect_t *pkt);
int handle_packet_missing_direct(struct autofs_point *ap, autofs_packet_missing_direct_t *pkt);
void rm_unwanted(const char *path, int incl, dev_t dev);
int count_mounts(struct autofs_point *ap, const char *path);

/* Expire alarm handling routines */
int alarm_start_handler(void);
int alarm_add(struct autofs_point *ap, time_t seconds);
void alarm_delete(struct autofs_point *ap);

/* Define logging functions */

#define LOGOPT_DEBUG	0x0001
#define LOGOPT_VERBOSE	0x0002

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

