/* ----------------------------------------------------------------------- *
 *
 *  Copyright 2013 Ian Kent <raven@themaw.net>
 *  Copyright 2013 Red Hat, Inc.
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *  USA; either version 2 of the License, or (at your option) any later
 *  version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <malloc.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <sys/mount.h>
#include <linux/fs.h>

#define MODULE_PARSE
#include "automount.h"

#define MODPREFIX "parse(amd): "

int parse_version = AUTOFS_PARSE_VERSION;	/* Required by protocol */

static struct mount_mod *mount_nfs = NULL;
static int init_ctr = 0;
static pthread_mutex_t instance_mutex = PTHREAD_MUTEX_INITIALIZER;

static void instance_mutex_lock(void)
{
	int status = pthread_mutex_lock(&instance_mutex);
	if (status)
		fatal(status);
}

static void instance_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&instance_mutex);
	if (status)
		fatal(status);
}

extern const char *global_options;

struct parse_context {
	char *optstr;		/* Mount options */
	char *macros;		/* Map wide macro defines */
	struct substvar *subst;	/* $-substitutions */
};

struct multi_mnt {
	char *path;
	char *options;
	char *location;
	struct multi_mnt *next;
};

/* Default context */

static struct parse_context default_context = {
	NULL,			/* No mount options */
	NULL,			/* No map wide macros */
	NULL			/* The substvar local vars table */
};

/* Free all storage associated with this context */
static void kill_context(struct parse_context *ctxt)
{
	macro_lock();
	macro_free_table(ctxt->subst);
	macro_unlock();
	if (ctxt->optstr)
		free(ctxt->optstr);
	if (ctxt->macros)
		free(ctxt->macros);
	free(ctxt);
}

int parse_init(int argc, const char *const *argv, void **context)
{
	struct parse_context *ctxt;
	char buf[MAX_ERR_BUF];

	sel_hash_init();

	/* Set up context and escape chain */

	if (!(ctxt = (struct parse_context *) malloc(sizeof(struct parse_context)))) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		*context = NULL;
		return 1;
	}
	*context = (void *) ctxt;

	*ctxt = default_context;

	/* We only need this once.  NFS mounts are so common that we cache
	   this module. */
	instance_mutex_lock();
	if (mount_nfs)
		init_ctr++;
	else {
		if ((mount_nfs = open_mount("nfs", MODPREFIX))) {
			init_ctr++;
		} else {
			kill_context(ctxt);
			*context = NULL;
			instance_mutex_unlock();
			return 1;
		}
	}
	instance_mutex_unlock();

	return 0;
}

static void update_with_defaults(struct amd_entry *defaults,
				 struct amd_entry *entry,
				 struct substvar *sv)
{
	const struct substvar *v;
	unsigned long fstype = entry->flags & AMD_MOUNT_TYPE_MASK;
	char *tmp;

	if (fstype == AMD_MOUNT_TYPE_NONE) {
		unsigned long deftype = defaults->flags & AMD_MOUNT_TYPE_MASK;
		if (deftype != AMD_MOUNT_TYPE_NONE)
			entry->flags |= (defaults->flags & AMD_MOUNT_TYPE_MASK);
		else {
			entry->flags = AMD_MOUNT_TYPE_NFS;
			tmp = strdup("nfs");
			if (tmp)
				entry->type = tmp;
		}
	}

	if (!entry->type && defaults->type) {
		tmp = strdup(defaults->type);
		if (tmp)
			entry->type = tmp;
	}

	if (!entry->map_type && defaults->map_type) {
		tmp = strdup(defaults->map_type);
		if (tmp)
			entry->map_type = tmp;
	}

	if (!entry->pref && defaults->pref) {
		tmp = strdup(defaults->pref);
		if (tmp)
			entry->pref = tmp;
	}

	if (!entry->fs && defaults->fs) {
		tmp = strdup(defaults->fs);
		if (tmp)
			entry->fs = tmp;
	}

	if (!entry->rfs && defaults->rfs) {
		tmp = strdup(defaults->rfs);
		if (tmp)
			entry->rfs = tmp;
	}

	if (!entry->rhost && defaults->rhost) {
		tmp = strdup(defaults->rhost);
		if (tmp)
			entry->rhost = tmp;
	}

	if (!entry->opts && defaults->opts) {
		tmp = merge_options(defaults->opts, entry->opts);
		if (tmp)
			entry->opts = tmp;
	}

	if (!entry->addopts && defaults->addopts) {
		tmp = merge_options(defaults->addopts, entry->addopts);
		if (tmp)
			entry->addopts = tmp;
	}

	if (!entry->remopts && defaults->remopts) {
		tmp = merge_options(defaults->remopts, entry->remopts);
		if (tmp)
			entry->remopts = tmp;
	}

	return;
}

static char *normalize_hostname(unsigned int logopt, const char *host,
				unsigned int flags, struct substvar *sv)
{
	struct addrinfo hints, *ni;
	char *name;
	int ret;

	if (!(flags & CONF_NORMALIZE_HOSTNAMES))
		name = strdup(host);
	else {
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_CANONNAME;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;

		ret = getaddrinfo(host, NULL, &hints, &ni);
		if (ret) {
			error(logopt, "hostname lookup failed: %s", gai_strerror(ret));
			return NULL;
		}
		name = strdup(ni->ai_canonname);
		freeaddrinfo(ni);
	}

	if (!name)
		return NULL;

	if (flags & CONF_DOMAIN_STRIP) {
		const struct substvar *v = macro_findvar(sv, "hostd", 5);
		if (v) {
			char *d1 = strchr(name, '.');
			if (d1) {
				char *d2 = strchr(v->val, '.');
				if (d2 && !strcmp(d1, d2))
					*d1 = '\0';
			}
		}
	}

	return name;
}

static struct substvar *expand_entry(struct autofs_point *ap,
				     struct amd_entry *entry,
				     unsigned int flags,
				     struct substvar *sv)
{
	unsigned int logopt = ap->logopt;
	char *expand;

	if (entry->rhost) {
		char *host = strdup(entry->rhost);
		char *nn;
		if (!host) {
			error(ap->logopt, MODPREFIX
			      "failed to allocate storage for rhost");
			goto next;
		}
		if (expand_selectors(ap, host, &expand, sv)) {
			free(host);
			host = expand;
		}
		nn = normalize_hostname(ap->logopt, host, flags, sv);
		if (!nn)
			sv = macro_addvar(sv, "rhost", 5, host);
		else {
			sv = macro_addvar(sv, "rhost", 5, nn);
			free(host);
			host = nn;
		}
		debug(logopt, MODPREFIX
		      "rhost expand(\"%s\") -> %s", entry->rhost, host);
		free(entry->rhost);
		entry->rhost = host;
	}
next:
	if (entry->sublink) {
		if (expand_selectors(ap, entry->sublink, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "sublink expand(\"%s\") -> %s",
			      entry->sublink, expand);
			free(entry->sublink);
			entry->sublink = expand;
		}
		sv = macro_addvar(sv, "sublink", 7, entry->sublink);
	}

	if (entry->rfs) {
		if (expand_selectors(ap, entry->rfs, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "rfs expand(\"%s\") -> %s", entry->rfs, expand);
			free(entry->rfs);
			entry->rfs = expand;
		}
		sv = macro_addvar(sv, "rfs", 3, entry->rfs);
	}

	if (entry->fs) {
		if (expand_selectors(ap, entry->fs, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "fs expand(\"%s\") -> %s", entry->fs, expand);
			free(entry->fs);
			entry->fs = expand;
		}
		sv = macro_addvar(sv, "fs", 2, entry->fs);
	}

	if (entry->opts) {
		if (expand_selectors(ap, entry->opts, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "ops expand(\"%s\") -> %s", entry->opts, expand);
			free(entry->opts);
			entry->opts = expand;
		}
		sv = macro_addvar(sv, "opts", 4, entry->opts);
	}

	if (entry->addopts) {
		if (expand_selectors(ap, entry->addopts, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "addopts expand(\"%s\") -> %s",
			      entry->addopts, expand);
			free(entry->addopts);
			entry->addopts = expand;
		}
		sv = macro_addvar(sv, "addopts", 7, entry->addopts);
	}

	if (entry->remopts) {
		if (expand_selectors(ap, entry->remopts, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "remopts expand(\"%s\") -> %s",
			      entry->remopts, expand);
			free(entry->remopts);
			entry->remopts = expand;
		}
		sv = macro_addvar(sv, "remopts", 7, entry->remopts);
	}

	return sv;
}

static void expand_merge_options(struct autofs_point *ap,
				 struct amd_entry *entry,
				 struct substvar *sv)
{
	char *tmp;

	if (entry->opts) {
		if (!expand_selectors(ap, entry->opts, &tmp, sv))
			error(ap->logopt, MODPREFIX "failed to expand opts");
		else {
			free(entry->opts);
			entry->opts = tmp;
		}
	}

	if (entry->addopts) {
		if (!expand_selectors(ap, entry->addopts, &tmp, sv))
			error(ap->logopt, MODPREFIX "failed to expand addopts");
		else {
			free(entry->addopts);
			entry->addopts = tmp;
		}
	}

	if (entry->remopts) {
		if (!expand_selectors(ap, entry->remopts, &tmp, sv))
			error(ap->logopt, MODPREFIX "failed to expand remopts");
		else {
			free(entry->remopts);
			entry->remopts = tmp;
		}
	}

	return;
}

static struct substvar *merge_entry_options(struct autofs_point *ap,
					    struct amd_entry *entry,
				            struct substvar *sv)
{
	char *tmp;

	if (!entry->addopts)
		return sv;

	if (entry->opts && entry->remopts &&
	    !strcmp(entry->opts, entry->remopts)) {
		expand_merge_options(ap, entry, sv);
		tmp = merge_options(entry->opts, entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "merge remopts \"%s\" addopts \"%s\" => \"%s\"",
			      entry->opts, entry->addopts, tmp);
			free(entry->opts);
			entry->opts = tmp;
			sv = macro_addvar(sv, "opts", 4, entry->opts);
		}
		tmp = strdup(entry->opts);
		if (tmp) {
			free(entry->remopts);
			entry->remopts = tmp;
			sv = macro_addvar(sv, "remopts", 7, entry->remopts);
		}
		return sv;
	}

	expand_merge_options(ap, entry, sv);

	if (entry->opts && entry->addopts) {
		tmp = merge_options(entry->opts, entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "merge opts \"%s\" addopts \"%s\" => \"%s\"",
			      entry->opts, entry->addopts, tmp);
			free(entry->opts);
			entry->opts = tmp;
			sv = macro_addvar(sv, "opts", 4, entry->opts);
		}
	} else if (entry->addopts) {
		tmp = strdup(entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "opts add addopts \"%s\" => \"%s\"", entry->addopts, tmp);
			entry->opts = tmp;
			sv = macro_addvar(sv, "opts", 4, entry->opts);
		}
	}

	expand_merge_options(ap, entry, sv);

	if (entry->remopts && entry->addopts) {
		tmp = merge_options(entry->remopts, entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "merge remopts \"%s\" addopts \"%s\" => \"%s\"",
			      entry->remopts, entry->addopts, tmp);
			free(entry->remopts);
			entry->remopts = tmp;
			sv = macro_addvar(sv, "remopts", 7, entry->remopts);
		}
	} else if (entry->addopts) {
		tmp = strdup(entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "remopts add addopts \"%s\" => \"%s\"",
			     entry->addopts, tmp);
			entry->remopts = tmp;
			sv = macro_addvar(sv, "remopts", 7, entry->remopts);
		}
	}

	return sv;
}

static int do_auto_mount(struct autofs_point *ap, const char *name,
			 struct amd_entry *entry, unsigned int flags)
{
	char target[PATH_MAX + 1];
	int ret;

	if (!entry->map_type)
		strcpy(target, entry->fs);
	else {
		strcpy(target, entry->map_type);
		strcat(target, ",amd:");
		strcat(target, entry->fs);
	}

	ret = do_mount(ap, ap->path,
		       name, strlen(name), target, "autofs", NULL);
	if (!ret) {
		struct autofs_point *sm;
		sm = master_find_submount(ap, entry->path);
		if (sm) {
			sm->pref = entry->pref;
			entry->pref = NULL;
		}
	}

	return ret;
}

static int do_link_mount(struct autofs_point *ap, const char *name,
			 struct amd_entry *entry, unsigned int flags)
{
	char target[PATH_MAX + 1];
	int ret;

	if (entry->sublink)
		strcpy(target, entry->sublink);
	else
		strcpy(target, entry->fs);

	if (!(flags & CONF_AUTOFS_USE_LOFS))
		goto symlink;

	/* For a sublink this might cause an external mount */
	ret = do_mount(ap, ap->path,
		       name, strlen(name), target, "bind", entry->opts);
	if (!ret)
		goto out;

	debug(ap->logopt, MODPREFIX "bind mount failed, symlinking");

symlink:
	ret = do_mount(ap, ap->path,
		       name, strlen(name), target, "bind", "symlink");
	if (!ret)
		goto out;

	error(ap->logopt, MODPREFIX
	      "failed to symlink %s to %s", entry->path, target);

	if (entry->sublink) {
		/* failed to complete sublink mount */
		if (ext_mount_remove(&entry->ext_mount, entry->fs))
			umount_ent(ap, entry->fs);
	}
out:
	return ret;
}

static int do_nfs_mount(struct autofs_point *ap, const char *name,
			struct amd_entry *entry, unsigned int flags)
{
	char target[PATH_MAX + 1];
	int ret = 0;

	strcpy(target, entry->rhost);
	strcat(target, ":");
	strcat(target, entry->rfs);

	if (!entry->sublink) {
		ret = mount_nfs->mount_mount(ap, ap->path, name, strlen(name),
					     target, entry->type, entry->opts,
					     mount_nfs->context);
	} else {
		if (!is_mounted(_PATH_MOUNTED, entry->fs, MNTS_REAL)) {
			ret = mount_nfs->mount_mount(ap, entry->fs, "/", 1,
						target, entry->type, entry->opts,
						mount_nfs->context);
			if (ret)
				goto out;
		}
		/* We might be using an external mount */
		ext_mount_add(&entry->ext_mount, entry->fs);
		ret = do_link_mount(ap, name, entry, flags);
	}
out:
	return ret;
}

static int do_host_mount(struct autofs_point *ap, const char *name,
			 struct amd_entry *entry, struct map_source *source,
			 unsigned int flags)
{
	struct lookup_mod *lookup;
	struct mapent *me;
	const char *argv[2];
	int ret = 1;

	argv[0] = entry->opts;
	argv[1] = NULL;

	lookup = open_lookup("hosts", MODPREFIX, NULL, 1, argv);
	if (!lookup) {
		debug(ap->logopt, "open lookup module hosts failed");
		goto out;
	}

	me = cache_lookup_distinct(source->mc, name);
	if (me)
		cache_push_mapent(me, NULL);

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	ret = lookup->lookup_mount(ap, name, strlen(name), lookup->context);

	close_lookup(lookup);
out:
	return ret;
}

static int amd_mount(struct autofs_point *ap, const char *name,
		     struct amd_entry *entry, struct map_source *source,
		     struct substvar *sv, unsigned int flags,
		     struct parse_context *ctxt)
{
	unsigned long fstype = entry->flags & AMD_MOUNT_TYPE_MASK;
	int ret = 1;

	switch (fstype) {
	case AMD_MOUNT_TYPE_AUTO:
		ret = do_auto_mount(ap, name, entry, flags);
		break;

	case AMD_MOUNT_TYPE_NFS:
		ret = do_nfs_mount(ap, name, entry, flags);
		break;

	case AMD_MOUNT_TYPE_LINK:
		ret = do_link_mount(ap, name, entry, flags);
		break;

	case AMD_MOUNT_TYPE_HOST:
		ret = do_host_mount(ap, name, entry, source, flags);
		break;

	default:
		info(ap->logopt,
		     MODPREFIX "unkown file system type %x", fstype);
		break;
	}

	return ret;
}

void dequote_entry(struct autofs_point *ap, struct amd_entry *entry)
{
	char *res;

	if (entry->pref) {
		res = dequote(entry->pref, strlen(entry->pref), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "pref dequote(\"%.*s\") -> %s",
			      strlen(entry->pref), entry->pref, res);
			free(entry->pref);
			entry->pref = res;
		}
	}

	if (entry->sublink) {
		res = dequote(entry->sublink, strlen(entry->sublink), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "sublink dequote(\"%.*s\") -> %s",
			      strlen(entry->sublink), entry->sublink, res);
			free(entry->sublink);
			entry->sublink = res;
		}
	}

	if (entry->fs) {
		res = dequote(entry->fs, strlen(entry->fs), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "fs dequote(\"%.*s\") -> %s",
			      strlen(entry->fs), entry->fs, res);
			free(entry->fs);
			entry->fs = res;
		}
	}

	if (entry->rfs) {
		res = dequote(entry->rfs, strlen(entry->rfs), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "rfs dequote(\"%.*s\") -> %s",
			      strlen(entry->rfs), entry->rfs, res);
			free(entry->rfs);
			entry->rfs = res;
		}
	}

	if (entry->opts) {
		res = dequote(entry->opts, strlen(entry->opts), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "ops dequote(\"%.*s\") -> %s",
			      strlen(entry->opts), entry->opts, res);
			free(entry->opts);
			entry->opts = res;
		}
	}

	if (entry->remopts) {
		res = dequote(entry->remopts, strlen(entry->remopts), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "remopts dequote(\"%.*s\") -> %s",
			      strlen(entry->remopts), entry->remopts, res);
			free(entry->remopts);
			entry->remopts = res;
		}
	}

	if (entry->addopts) {
		res = dequote(entry->addopts, strlen(entry->addopts), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "addopts dequote(\"%.*s\") -> %s",
			      strlen(entry->addopts), entry->addopts, res);
			free(entry->addopts);
			entry->addopts = res;
		}
	}

	return;
}

static void normalize_sublink(unsigned int logopt,
			      struct amd_entry *entry, struct substvar *sv)
{
	char *new;
	size_t len;

	if (entry->sublink && *entry->sublink != '/') {
		len = strlen(entry->fs) + strlen(entry->sublink) + 2;
		new = malloc(len);
		if (!new) {
			error(logopt, MODPREFIX
			      "error: couldn't allocate storage for sublink");
			return;
		}
		strcpy(new, entry->fs);
		strcat(new, "/");
		strcat(new, entry->sublink);
		debug(logopt, MODPREFIX
		      "rfs dequote(\"%.*s\") -> %s",
		      strlen(entry->sublink), entry->sublink, new);
		free(entry->sublink);
		entry->sublink = new;
	}
	return;
}

/*
 * Set the prefix.
 *
 * This is done in a couple of places, here is as good a place as
 * any to describe it.
 *
 * If a prefix is present in the map entry then use it.
 *
 * A pref option with the value none is required to use no prefix,
 * otherwise the prefix of the parent map, if any, will be used.
 */
static void update_prefix(struct autofs_point *ap,
			  struct amd_entry *entry, const char *name)
{
	size_t len;
	char *new;

	if (!entry->pref && ap->pref) {
		len = strlen(ap->pref) + strlen(name) + 2;
		new = malloc(len);
		if (new) {
			strcpy(new, ap->pref);
			strcat(new, name);
			strcat(new, "/");
			entry->pref = new;
		}
	}
	return;
}

static struct amd_entry *dup_defaults_entry(struct amd_entry *defaults)
{
	struct amd_entry *entry;
	char *tmp;

	entry = malloc(sizeof(struct amd_entry));
	if (!entry)
		return NULL;
	memset(entry, 0, sizeof(struct amd_entry));

	entry->flags = defaults->flags;

	if (defaults->type) {
		tmp = strdup(defaults->type);
		if (tmp)
			entry->type = tmp;
	}

	if (defaults->map_type) {
		tmp = strdup(defaults->map_type);
		if (tmp)
			entry->map_type = tmp;
	}

	if (defaults->pref) {
		tmp = strdup(defaults->pref);
		if (tmp)
			entry->pref = tmp;
	}

	if (defaults->fs) {
		tmp = strdup(defaults->fs);
		if (tmp)
			entry->fs = tmp;
	}

	if (defaults->rfs) {
		tmp = strdup(defaults->rfs);
		if (tmp)
			entry->rfs = tmp;
	}

	if (defaults->rhost) {
		tmp = strdup(defaults->rhost);
		if (tmp)
			entry->rhost = tmp;
	}

	if (defaults->opts) {
		tmp = strdup(defaults->opts);
		if (tmp)
			entry->opts = tmp;
	}

	if (defaults->addopts) {
		tmp = strdup(defaults->addopts);
		if (tmp)
			entry->addopts = tmp;
	}

	if (defaults->remopts) {
		tmp = strdup(defaults->remopts);
		if (tmp)
			entry->remopts = tmp;
	}

	INIT_LIST_HEAD(&entry->list);

	return entry;
}

struct amd_entry *make_default_entry(struct autofs_point *ap,
				     struct substvar *sv)
{
	char *defaults = "opts:=rw,defaults";
	struct amd_entry *defaults_entry;
	struct list_head dflts;

	INIT_LIST_HEAD(&dflts);
	if (amd_parse_list(ap, defaults, &dflts, &sv))
		return NULL;
	defaults_entry = list_entry(dflts.next, struct amd_entry, list);
	list_del_init(&defaults_entry->list);
	/* The list should now be empty .... */
	free_amd_entry_list(&dflts);
	return defaults_entry;
}

static struct amd_entry *select_default_entry(struct autofs_point *ap,
					      struct list_head *entries,
					      struct substvar *sv)
{
	unsigned long flags = conf_amd_get_flags(ap->path);
	struct amd_entry *defaults_entry = NULL;
	struct amd_entry *entry_default = NULL;
	struct list_head *p, *head;

	if (!(flags & CONF_SELECTORS_IN_DEFAULTS))
		goto no_sel;

	head = entries;
	p = head->next;
	while (p != head) {
		struct amd_entry *this = list_entry(p, struct amd_entry, list);

		p = p->next;

		if (this->flags & AMD_DEFAULTS_MERGE) {
			if (entry_default)
				free_amd_entry(entry_default);
			list_del_init(&this->list);
			entry_default = this;
			continue;
		} else if (this->flags & AMD_DEFAULTS_RESET) {
			struct amd_entry *new;
			new = dup_defaults_entry(defaults_entry);
			if (new) {
				free_amd_entry(entry_default);
				entry_default = new;
			}
			list_del_init(&this->list);
			free_amd_entry(this);
			continue;
		}
	}

	/* Not strickly amd semantics but ... */
	if (!defaults_entry && entry_default) {
		defaults_entry = entry_default;
		goto done;
	}

	if (!defaults_entry) {
		debug(ap->logopt, MODPREFIX
		      "no matching selector(s) found in defaults, "
		      "using internal defaults");
		goto ret_default;
	}

	goto done;

no_sel:
	if (list_empty(entries))
		goto ret_default;

	defaults_entry = list_entry(entries->next, struct amd_entry, list);
	list_del_init(&defaults_entry->list);
	if (!list_empty(entries)) {
		free_amd_entry(defaults_entry);
		goto ret_default;
	}
done:
	/*merge_entry_options(ap, defaults_entry, sv);*/
	/*normalize_sublink(ap->logopt, defaults_entry, sv);*/
	return defaults_entry;

ret_default:
	return make_default_entry(ap, sv);
}

static struct amd_entry *get_defaults_entry(struct autofs_point *ap,
					    const char *defaults,
					    struct substvar *sv)
{
	struct amd_entry *entry;
	struct list_head dflts;

	INIT_LIST_HEAD(&dflts);

	entry = NULL;
	if (!defaults)
		goto out;
	else {
		char *expand;
		if (!expand_selectors(ap, defaults, &expand, sv))
			goto out;
		if (amd_parse_list(ap, expand, &dflts, &sv))
			goto out;
		entry = select_default_entry(ap, &dflts, sv);
		free(expand);
	}

	return entry;
out:
	return make_default_entry(ap, sv);
}

int parse_mount(struct autofs_point *ap, const char *name,
		int name_len, const char *mapent, void *context)
{
	struct parse_context *ctxt = (struct parse_context *) context;
	unsigned int flags = conf_amd_get_flags(ap->path);
	struct substvar *sv = NULL;
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me;
	struct list_head entries, *p, *head;
	struct amd_entry *defaults_entry;
	struct amd_entry *cur_defaults;
	char *defaults;
	char *pmapent;
	int len, rv = 1;
	int cur_state;
	int ret;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	if (!mapent) {
		warn(ap->logopt, MODPREFIX "error: empty map entry");
		return 1;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);

	len = expand_selectors(ap, mapent, &pmapent, sv);
	if (!len) {
		macro_free_table(sv);
		pthread_setcancelstate(cur_state, NULL);
		return 1;
	}

	pthread_setcancelstate(cur_state, NULL);

	debug(ap->logopt, MODPREFIX "expanded mapent: %s", pmapent);

	defaults = conf_amd_get_map_defaults(ap->path);
	if (defaults) {
		debug(ap->logopt, MODPREFIX
		      "using map_defaults %s for %s", defaults, ap->path);
	} else if ((me = cache_lookup_distinct(mc, "/defaults"))) {
		defaults = strdup(me->mapent);
		if (defaults)
			debug(ap->logopt, MODPREFIX
			      "using /defaults %s from map", defaults);
		else {
			char buf[MAX_ERR_BUF];
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "malloc: %s", estr);
		}
	}

	defaults_entry = get_defaults_entry(ap, defaults, sv);
	if (!defaults_entry) {
		error(ap->logopt, MODPREFIX "failed to get a defaults entry");
		if (defaults)
			free(defaults);
		free(pmapent);
		macro_free_table(sv);
		return 1;
	}
	if (defaults)
		free(defaults);

	INIT_LIST_HEAD(&entries);

	ret = amd_parse_list(ap, pmapent, &entries, &sv);
	if (ret) {
		error(ap->logopt,
		      MODPREFIX "failed to parse entry: %s", pmapent);
		free(pmapent);
		goto done;
	}

	free(pmapent);

	if (list_empty(&entries)) {
		error(ap->logopt, MODPREFIX "no location found after parse");
		goto done;
	}

	cur_defaults = dup_defaults_entry(defaults_entry);
	if (!cur_defaults) {
		error(ap->logopt, MODPREFIX
		      "failed to duplicate defaults entry");
		goto done;
	}

	head = &entries;
	p = head->next;
	while (p != head) {
		struct amd_entry *this = list_entry(p, struct amd_entry, list);
		p = p->next;

		if (this->flags & AMD_DEFAULTS_MERGE) {
			free_amd_entry(cur_defaults);
			list_del_init(&this->list);
			cur_defaults = this;
			continue;
		} else if (this->flags & AMD_DEFAULTS_RESET) {
			struct amd_entry *new;
			new = dup_defaults_entry(defaults_entry);
			if (new) {
				free_amd_entry(cur_defaults);
				cur_defaults = new;
			}
			list_del_init(&this->list);
			free_amd_entry(this);
			continue;
		}

		update_with_defaults(cur_defaults, this, sv);
		sv = expand_entry(ap, this, flags, sv);
		sv = merge_entry_options(ap, this, sv);
		normalize_sublink(ap->logopt, this, sv);
		update_prefix(ap, this, name);

		dequote_entry(ap, this);

		rv = amd_mount(ap, name, this, source, sv, flags, ctxt);
		if (!rv)
			break;
	}
	free_amd_entry(cur_defaults);

	if (rv)
		debug(ap->logopt, "no more locations to try, returning fail");
done:
	free_amd_entry_list(&entries);
	free_amd_entry(defaults_entry);
	macro_free_table(sv);

	return rv;
}

int parse_done(void *context)
{
	int rv = 0;
	struct parse_context *ctxt = (struct parse_context *) context;

	instance_mutex_lock();
	if (--init_ctr == 0) {
		rv = close_mount(mount_nfs);
		mount_nfs = NULL;
	}
	instance_mutex_unlock();
	if (ctxt)
		kill_context(ctxt);

	return rv;
}
