/* ----------------------------------------------------------------------- *
 *   
 *  parse_subs.c - misc parser subroutines
 *                automounter map
 * 
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/vfs.h>
#include "automount.h"

/*
 * Skip whitespace in a string; if we hit a #, consider the rest of the
 * entry a comment.
 */
const char *skipspace(const char *whence)
{
	while (1) {
		switch (*whence) {
		case ' ':
		case '\b':
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
			whence++;
			break;
		case '#':	/* comment: skip to end of string */
			while (*whence != '\0')
				whence++;
			/* FALLTHROUGH */

		default:
			return whence;
		}
	}
}

/*
 * Check a string to see if a colon appears before the next '/'.
 */
int check_colon(const char *str)
{
	char *ptr = (char *) str;

	/* Colon escape */
	if (*ptr == ':')
		return 1;

	while (*ptr && *ptr != ':' && *ptr != '/') {
		ptr++;
	}

	if (!*ptr || *ptr == '/')
		return 0;

	return 1;
}

/* Get the length of a chunk delimitered by whitespace */
int chunklen(const char *whence, int expect_colon)
{
	char *str = (char *) whence;
	int n = 0;
	int quote = 0;

	for (; *str; str++, n++) {
		switch (*str) {
		case '\\':
			if( quote ) {
				break;
			} else {
				quote = 1;
				continue;
			}
		case '"':
			if (quote)
				break;
			while (*str) {
				str++;
				n++;
				if (*str == '"')
					break;
				if (*str == ':')
					expect_colon = 0;
			}
			break;
		case ':':
			if (expect_colon)
				expect_colon = 0;
			continue;
		case ' ':
		case '\t':
			/* Skip space or tab if we expect a colon */
			if (expect_colon)
				continue;
		case '\b':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case '\0':
			if (!quote)
				return n;
			/* FALLTHROUGH */
		default:
			break;
		}
		quote = 0;
	}

	return n;
}

/*
 * Compare str with pat.  Return 0 if compare equal or
 * str is an abbreviation of pat of no less than mchr characters.
 */
int strmcmp(const char *str, const char *pat, int mchr)
{
	int nchr = 0;

	while (*str == *pat) {
		if (!*str)
			return 0;
		str++;
		pat++;
		nchr++;
	}

	if (!*str && nchr > mchr)
		return 0;

	return *pat - *str;
}

char *dequote(const char *str, int origlen, unsigned int logopt)
{
	char *ret = malloc(origlen + 1);
	char *cp = ret;
	const char *scp;
	int len = origlen;
	int quote = 0, dquote = 0;
	int i, j;

	if (ret == NULL)
		return NULL;

	/* first thing to do is strip white space from the end */
	i = len - 1;
	while (isspace(str[i])) {
		/* of course, we have to keep escaped white-space */
		j = i - 1;
		if (j > 0 && (str[j] == '\\' || str[j] == '"'))
			break;
		i--;
		len--;
	}

	for (scp = str; len > 0 && *scp; scp++, len--) {
		if (!quote) {
			if (*scp == '"') {
				if (dquote)
					dquote = 0;
				else
					dquote = 1;
				continue;
			}

			if (!dquote) {
				if (*scp == '\\') {
					quote = 1;
					continue;
				}
			}
		}
		quote = 0;
		*cp++ = *scp;
	}
	*cp = '\0';

	if (dquote) {
		debug(logopt, "unmatched quote in %.*s", origlen, str);
		free(ret);
		return NULL;
	}

	return ret;
}

int span_space(const char *str, unsigned int maxlen)
{
	const char *p = str;
	unsigned int len = 0;

	while (*p && !isblank(*p) && len < maxlen) {
		if (*p == '"') {
			while (*p++ && len++ < maxlen) {
				if (*p == '"')
					break;
			}
		} else if (*p == '\\') {
			p += 2;
			len += 2;
			continue;
		}
		p++;
		len++;
	}
	return len;
}

char *sanitize_path(const char *path, int origlen, unsigned int type, unsigned int logopt)
{
	char *slash, *cp, *s_path;
	const char *scp;
	int len = origlen;
	unsigned int seen_slash = 0, quote = 0, dquote = 0;

	if (type & (LKP_INDIRECT | LKP_DIRECT)) {
		slash = strchr(path, '/');
		if (slash) {
			if (type == LKP_INDIRECT)
				return NULL;
			if (*path != '/')
				return NULL;
		} else {
			if (type == LKP_DIRECT)
				return NULL;
		}
	}

	s_path = malloc(origlen + 1);
	if (!s_path)
		return NULL;

	for (cp = s_path, scp = path; len > 0; scp++, len--) {
		if (!quote) {
			if (*scp == '"') {
				if (dquote)
					dquote = 0;
				else
					dquote = 1;
				continue;
			}

			if (!dquote) {
				/* Badness in string - go away */
				if (*scp < 32) {
					free(s_path);
					return NULL;
				}

				if (*scp == '\\') {
					quote = 1;
					continue;
				} 
			}

			/*
			 * Not really proper but we get problems with
			 * paths with multiple slashes. The kernel
			 * compresses them so when we get a query there
			 * should be only single slashes.
			 */
			if (*scp == '/') {
				if (seen_slash)
					continue;
				seen_slash = 1;
			} else
				seen_slash = 0;
		}
		quote = 0;
		*cp++ = *scp;
	}
	*cp = '\0';

	if (dquote) {
		debug(logopt, "unmatched quote in %.*s", origlen, path);
		free(s_path);
		return NULL;
	}

	/* Remove trailing / but watch out for a quoted / alone */
	if (strlen(cp) > 1 && origlen > 1 && *(cp - 1) == '/')
		*(cp - 1) = '\0';

	return s_path;
}

int umount_ent(struct autofs_point *ap, const char *path)
{
	struct stat st;
	struct statfs fs;
	int sav_errno;
	int status, is_smbfs = 0;
	int ret, rv = 1;

	ret = statfs(path, &fs);
	if (ret == -1) {
		warn(ap->logopt, "could not stat fs of %s", path);
		is_smbfs = 0;
	} else {
		int cifsfs = fs.f_type == (__SWORD_TYPE) CIFS_MAGIC_NUMBER;
		int smbfs = fs.f_type == (__SWORD_TYPE) SMB_SUPER_MAGIC;
		is_smbfs = (cifsfs | smbfs) ? 1 : 0;
	}

	status = lstat(path, &st);
	sav_errno = errno;

	if (status < 0)
		warn(ap->logopt, "lstat of %s failed with %d", path, status);

	/*
	 * lstat failed and we're an smbfs fs returning an error that is not
	 * EIO or EBADSLT or the lstat failed so it's a bad path. Return
	 * a fail.
	 *
	 * EIO appears to correspond to an smb mount that has gone away
	 * and EBADSLT relates to CD changer not responding.
	 */
	if (!status && (S_ISDIR(st.st_mode) && st.st_dev != ap->dev)) {
		rv = spawn_umount(ap->logopt, path, NULL);
	} else if (is_smbfs && (sav_errno == EIO || sav_errno == EBADSLT)) {
		rv = spawn_umount(ap->logopt, path, NULL);
	}

	/* We are doing a forced shutcwdown down so unlink busy mounts */
	if (rv && (ap->state == ST_SHUTDOWN_FORCE || ap->state == ST_SHUTDOWN)) {
		ret = stat(path, &st);
		if (ret == -1 && errno == ENOENT) {
			warn(ap->logopt, "mount point does not exist");
			return 0;
		}

		if (ret == 0 && !S_ISDIR(st.st_mode)) {
			warn(ap->logopt, "mount point is not a directory");
			return 0;
		}

		if (ap->state == ST_SHUTDOWN_FORCE) {
			info(ap->logopt, "forcing umount of %s", path);
			rv = spawn_umount(ap->logopt, "-l", path, NULL);
		}

		/*
		 * Verify that we actually unmounted the thing.  This is a
		 * belt and suspenders approach to not eating user data.
		 * We have seen cases where umount succeeds, but there is
		 * still a file system mounted on the mount point.  How
		 * this happens has not yet been determined, but we want to
		 * make sure to return failure here, if that is the case,
		 * so that we do not try to call rmdir_path on the
		 * directory.
		 */
		if (!rv && is_mounted(_PATH_MOUNTED, path, MNTS_REAL)) {
			crit(ap->logopt,
			     "the umount binary reported that %s was "
			     "unmounted, but there is still something "
			     "mounted on this path.", path);
			rv = -1;
		}
	}

	return rv;
}

int mount_multi_triggers(struct autofs_point *ap, char *root, struct mapent *me, const char *base)
{
	char path[PATH_MAX + 1];
	char *offset = path;
	struct mapent *oe;
	struct list_head *pos = NULL;
	unsigned int fs_path_len;
	unsigned int mounted;
	int start;

	fs_path_len = strlen(root) + strlen(base);
	if (fs_path_len > PATH_MAX)
		return -1;

	strcpy(path, root);
	strcat(path, base);

	mounted = 0;
	start = strlen(root);
	offset = cache_get_offset(base, offset, start, &me->multi_list, &pos);
	while (offset) {
		int plen = fs_path_len + strlen(offset);

		if (plen > PATH_MAX) {
			warn(ap->logopt, "path loo long");
			goto cont;
		}

		oe = cache_lookup_offset(base, offset, start, &me->multi_list);
		if (!oe)
			goto cont;

		debug(ap->logopt, "mount offset %s", oe->key);

		if (mount_autofs_offset(ap, oe) < 0)
			warn(ap->logopt, "failed to mount offset");
		else
			mounted++;
cont:
		offset = cache_get_offset(base,
				offset, start, &me->multi_list, &pos);
	}

	return mounted;
}

int umount_multi_triggers(struct autofs_point *ap, char *root, struct mapent *me, const char *base)
{
	char path[PATH_MAX + 1];
	char *offset;
	struct mapent *oe;
	struct list_head *mm_root, *pos;
	const char o_root[] = "/";
	const char *mm_base;
	int left, start;

	left = 0;
	start = strlen(root);

	mm_root = &me->multi->multi_list;

	if (!base)
		mm_base = o_root;
	else
		mm_base = base;

	pos = NULL;
	offset = path;

	/* Make sure "none" of the offsets have an active mount. */
	while ((offset = cache_get_offset(mm_base, offset, start, mm_root, &pos))) {
		char *oe_base;

		oe = cache_lookup_offset(mm_base, offset, start, &me->multi_list);
		/* root offset is a special case */
		if (!oe || (strlen(oe->key) - start) == 1)
			continue;

		/*
		 * Check for and umount subtree offsets resulting from
		 * nonstrict mount fail.
		 */
		oe_base = oe->key + strlen(root);
		left += umount_multi_triggers(ap, root, oe, oe_base);

		if (oe->ioctlfd != -1)
			left++;
	}

	if (left)
		return left;

	pos = NULL;
	offset = path;

	/* Make sure "none" of the offsets have an active mount. */
	while ((offset = cache_get_offset(mm_base, offset, start, mm_root, &pos))) {
		oe = cache_lookup_offset(mm_base, offset, start, &me->multi_list);
		/* root offset is a special case */
		if (!oe || (strlen(oe->key) - start) == 1)
			continue;

		debug(ap->logopt, "umount offset %s", oe->key);

		if (umount_autofs_offset(ap, oe)) {
			warn(ap->logopt, "failed to umount offset");
			left++;
		}
	}

	if (!left && me->multi == me) {
		struct mapent_cache *mc = me->mc;
		int status;

		/*
		 * Special case.
		 * If we can't umount the root container then we can't
		 * delete the offsets from the cache and we need to put
		 * the offset triggers back.
		 */
		if (is_mounted(_PATH_MOUNTED, root, MNTS_REAL)) {
			info(ap->logopt, "unmounting dir = %s", root);
			if (umount_ent(ap, root)) {
				if (!mount_multi_triggers(ap, root, me, "/"))
					warn(ap->logopt,
					     "failed to remount offset triggers");
				return left++;
			}
		}

		/* We're done - clean out the offsets */
		status = cache_delete_offset_list(mc, me->key);
		if (status != CHE_OK)
			warn(ap->logopt, "couldn't delete offset list");
	}

	return left;
}

