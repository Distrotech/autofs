/* -*- c -*-
 * linux/include/linux/auto_fs4.h
 *
 * Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#ifndef _LINUX_AUTO_FS4_H
#define _LINUX_AUTO_FS4_H

/* Include common v3 definitions */
#include <linux/auto_fs.h>

/* autofs v4 definitions */
#undef AUTOFS_PROTO_VERSION
#undef AUTOFS_MIN_PROTO_VERSION
#undef AUTOFS_MAX_PROTO_VERSION

#define AUTOFS_PROTO_VERSION		5
#define AUTOFS_MIN_PROTO_VERSION	3
#define AUTOFS_MAX_PROTO_VERSION	5

#define AUTOFS_PROTO_SUBVERSION         0

/* Mask for expire behaviour */
#define AUTOFS_EXP_IMMEDIATE		1
#define AUTOFS_EXP_LEAVES		2

/* Daemon notification packet types */

enum autofs_notify
{
        NFY_NONE,
        NFY_MOUNT,
        NFY_EXPIRE
};

/* Kernel protocol version 4 packet types */
#define autofs_ptype_expire_multi	2	/* Expire entry (umount request) */
/* Kernel protocol version 5 packet types */
#define autofs_ptype_missing_indirect	3	/* Indirect mount mount request */
#define autofs_ptype_expire_indirect	4	/* Indirect mount expire request */
#define autofs_ptype_missing_direct	5	/* Direct mount mount request */
#define autofs_ptype_expire_direct	6	/* Direct mount expire request */

/* v4 multi expire (via pipe) */
struct autofs_packet_expire_multi {
	struct autofs_packet_hdr hdr;
        autofs_wqt_t wait_queue_token;
	int len;
	char name[NAME_MAX+1];
};

/* v5 indirect mount request */
struct autofs_packet_missing_indirect {
	struct autofs_packet_hdr hdr;
        autofs_wqt_t wait_queue_token;
	__u32 dev;
	__u32 ino;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t tgid;
	int len;
	char name[NAME_MAX+1];
};

/* v5 indirect mount expire request */
struct autofs_packet_expire_indirect {
	struct autofs_packet_hdr hdr;
        autofs_wqt_t wait_queue_token;
	__u32 dev;
	__u32 ino;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t tgid;
	int len;
	char name[NAME_MAX+1];
};

/* v5 direct mount request */
struct autofs_packet_missing_direct {
	struct autofs_packet_hdr hdr;
        autofs_wqt_t wait_queue_token;
	__u32 dev;
	__u32 ino;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t tgid;
	int len;
	char name[NAME_MAX+1];
};

/* v5 direct mount expire request */
struct autofs_packet_expire_direct {
	struct autofs_packet_hdr hdr;
        autofs_wqt_t wait_queue_token;
	__u32 dev;
	__u32 ino;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t tgid;
	int len;
	char name[NAME_MAX+1];
};

union autofs_packet_union {
	struct autofs_packet_hdr hdr;
	struct autofs_packet_expire expire;
	struct autofs_packet_missing missing;
	struct autofs_packet_expire_multi expire_multi;
	struct autofs_packet_missing_indirect missing_indirect;
	struct autofs_packet_missing_direct missing_direct;
	struct autofs_packet_expire_indirect expire_indirect;
	struct autofs_packet_expire_direct expire_direct;
};

#define AUTOFS_IOC_EXPIRE_MULTI		_IOW(0x93,0x66,int)
#define AUTOFS_IOC_EXPIRE_DIRECT	AUTOFS_IOC_EXPIRE_MULTI
#define AUTOFS_IOC_PROTOSUBVER		_IOR(0x93,0x67,int)
#define AUTOFS_IOC_ASKREGHOST           _IOR(0x93,0x68,int)
#define AUTOFS_IOC_TOGGLEREGHOST        _IOR(0x93,0x69,int)
#define AUTOFS_IOC_ASKUMOUNT		_IOR(0x93,0x70,int)

#endif /* _LINUX_AUTO_FS4_H */
