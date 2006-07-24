/*
 * lookup_nisplus.c
 *
 * Module for Linux automountd to access a NIS+ automount map
 */

#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/nis.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(nisplus): "

struct lookup_context {
	const char *domainname;
	const char *mapname;
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "%s", estr);
		return 1;
	}

	if (argc < 1) {
		crit(LOGOPT_ANY, MODPREFIX "No map name");
		free(ctxt);
		return 1;
	}
	ctxt->mapname = argv[0];

	/* 
	 * nis_local_directory () returns a pointer to a static buffer.
	 * We don't need to copy or free it.
	 */
	ctxt->domainname = nis_local_directory();
	if (!ctxt->domainname) {
		crit(LOGOPT_ANY, MODPREFIX "NIS+ domain not set");
		free(ctxt);
		return 1;
	}

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parse) {
		crit(LOGOPT_ANY, MODPREFIX "failed to open parse context");
		free(ctxt);
		return 1;
	}
	*context = ctxt;

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int timeout = master->default_timeout;
	unsigned int logging =  master->default_logging;
	char *tablename;
	nis_result *result;
	nis_object *this;
	unsigned int current, result_count;
	char *path, *ent;
	char *buffer;
	char buf[MAX_ERR_BUF];

	tablename = alloca(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "alloca: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}
	sprintf(tablename, "%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	/* check that the table exists */
	result = nis_lookup(tablename, FOLLOW_PATH | FOLLOW_LINKS);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(LOGOPT_ANY,
		     MODPREFIX "couldn't locat nis+ table %s", ctxt->mapname);
		return NSS_STATUS_NOTFOUND;
	}

	sprintf(tablename, "[],%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(LOGOPT_ANY,
		     MODPREFIX "couldn't enumrate nis+ map %s", ctxt->mapname);
		return NSS_STATUS_UNAVAIL;
	}

	current = 0;
	result_count = NIS_RES_NUMOBJ(result);

	while (result_count--) {
		this = &result->objects.objects_val[current++];
		path = ENTRY_VAL(this, 0);
		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (*path == '+')
			continue;

		ent = ENTRY_VAL(this, 1);

		buffer = malloc(ENTRY_LEN(this, 0) + 1 + ENTRY_LEN(this, 1) + 1);
		if (!buffer) {
			error(LOGOPT_ANY,
			      MODPREFIX "could not malloc parse buffer");
			continue;
		}

		strcat(buffer, path);
		strcat(buffer, " ");
		strcat(buffer, ent);

		master_parse_entry(buffer, timeout, logging, age);

		free(buffer);
	}

	nis_freeresult(result);

	return NSS_STATUS_SUCCESS;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	unsigned int current, result_count;
	char *key, *mapent;
	char buf[MAX_ERR_BUF];

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	tablename = alloca(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "alloca: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}
	sprintf(tablename, "%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	/* check that the table exists */
	result = nis_lookup(tablename, FOLLOW_PATH | FOLLOW_LINKS);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(ap->logopt,
		     MODPREFIX "couldn't locat nis+ table %s", ctxt->mapname);
		return NSS_STATUS_NOTFOUND;
	}

	sprintf(tablename, "[],%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(ap->logopt,
		     MODPREFIX "couldn't enumrate nis+ map %s", ctxt->mapname);
		return NSS_STATUS_UNAVAIL;
	}

	current = 0;
	result_count = NIS_RES_NUMOBJ(result);

	while (result_count--) {
		char *s_key;
		size_t len;

		this = &result->objects.objects_val[current++];
		key = ENTRY_VAL(this, 0);
		len = ENTRY_LEN(this, 0);

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (*key == '+')
			continue;

		s_key = sanitize_path(key, len, ap->type, ap->logopt);
		if (!s_key)
			continue;

		mapent = ENTRY_VAL(this, 1);

		cache_writelock(mc);
		cache_update(mc, source, s_key, mapent, age);
		cache_unlock(mc);

		free(s_key);
	}

	nis_freeresult(result);

	source->age = age;

	return NSS_STATUS_SUCCESS;
}

static int lookup_one(struct autofs_point *ap,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	char *mapent;
	time_t age = time(NULL);
	int ret;
	char buf[MAX_ERR_BUF];

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	tablename = alloca(strlen(key) +
			strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "alloca: %s", estr);
		return -1;
	}
	sprintf(tablename, "[key=%s],%s.org_dir.%s", key, ctxt->mapname,
		ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		if (result->status == NIS_NOTFOUND ||
		    result->status == NIS_S_NOTFOUND)
			return CHE_MISSING;

		return -result->status;
	}

	
	this = NIS_RES_OBJECT(result);
	mapent = ENTRY_VAL(this, 1);
	cache_writelock(mc);
	ret = cache_update(mc, source, key, mapent, age);
	cache_unlock(mc);

	nis_freeresult(result);

	return ret;
}

static int lookup_wild(struct autofs_point *ap, struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	char *mapent;
	time_t age = time(NULL);
	int ret;
	char buf[MAX_ERR_BUF];

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	tablename = alloca(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		crit(LOGOPT_ANY, MODPREFIX "alloca: %s", estr);
		return -1;
	}
	sprintf(tablename, "[key=*],%s.org_dir.%s", ctxt->mapname,
		ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		if (result->status == NIS_NOTFOUND ||
		    result->status == NIS_S_NOTFOUND)
			return CHE_MISSING;

		return -result->status;
	}

	this = NIS_RES_OBJECT(result);
	mapent = ENTRY_VAL(this, 1);
	cache_writelock(mc);
	ret = cache_update(mc, source, "*", mapent, age);
	cache_unlock(mc);

	nis_freeresult(result);

	return ret;
}

static int check_map_indirect(struct autofs_point *ap,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me, *exists;
	time_t now = time(NULL);
	time_t t_last_read;
	int need_map = 0;
	int ret = 0;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	cache_readlock(mc);
	exists = cache_lookup_distinct(mc, key);
	if (exists && exists->source != source)
		exists = NULL;
	cache_unlock(mc);

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	/* check map and if change is detected re-read map */
	ret = lookup_one(ap, key, key_len, ctxt);
	if (ret == CHE_FAIL)
		return NSS_STATUS_NOTFOUND;

	if (ret < 0) {
		warn(ap->logopt,
		     MODPREFIX "lookup for %s failed: %s",
		     key, nis_sperrno(-ret));
		return NSS_STATUS_UNAVAIL;
	}

	cache_readlock(mc);
	me = cache_lookup_first(mc);
	t_last_read = me ? now - me->age : ap->exp_runfreq + 1;
	cache_unlock(mc);

	if (t_last_read > ap->exp_runfreq)
		if ((ret & CHE_UPDATED) ||
		    (exists && (ret & CHE_MISSING)))
			need_map = 1;

	if (ret == CHE_MISSING) {
		int wild = CHE_MISSING;

		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		wild = lookup_wild(ap, ctxt);
		if (wild == CHE_UPDATED || CHE_OK)
			return NSS_STATUS_SUCCESS;

		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_writelock(mc);
		if (wild == CHE_MISSING)
			cache_delete(mc, "*");

		if (cache_delete(mc, key) && wild & (CHE_MISSING | CHE_FAIL))
			rmdir_path(ap, key);
		pthread_cleanup_pop(1);
	}

	/* Have parent update its map */
	if (ap->ghost && need_map) {
		int status;

		source->stale = 1;

		status = pthread_mutex_lock(&ap->state_mutex);
		if (status)
			fatal(status);

		nextstate(ap->state_pipe[1], ST_READMAP);

		status = pthread_mutex_unlock(&ap->state_mutex);
		if (status)
			fatal(status);
	}

	if (ret == CHE_MISSING)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	int mapent_len;
	struct mapent *me;
	int status;
	int ret = 1;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	key_len = snprintf(key, KEY_MAX_LEN, "%s", name);
	if (key_len > KEY_MAX_LEN)
		return NSS_STATUS_NOTFOUND;

	cache_readlock(mc);
	me = cache_lookup_distinct(mc, key);
	if (me && me->status >= time(NULL)) {
		cache_unlock(mc);
		return NSS_STATUS_NOTFOUND;
	}
	cache_unlock(mc);

	/*
	 * We can't check the direct mount map as if it's not in
	 * the map cache already we never get a mount lookup, so
	 * we never know about it.
	 */
	if (ap->type == LKP_INDIRECT) {
		char *lkp_key;

		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me && me->multi)
			lkp_key = strdup(me->multi->key);
		else
			lkp_key = strdup(key);
		cache_unlock(mc);

		if (!lkp_key)
			return NSS_STATUS_UNKNOWN;

		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		status = check_map_indirect(ap, lkp_key, strlen(lkp_key), ctxt);
		if (status) {
			debug(ap->logopt,
			      MODPREFIX "check indirect map failure");
			return status;
		}
	}

	cache_readlock(mc);
	me = cache_lookup(mc, key);
	if (me) {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		mapent_len = strlen(me->mapent);
		mapent = alloca(mapent_len + 1);
		strcpy(mapent, me->mapent);
		pthread_cleanup_pop(0);
	}
	cache_unlock(mc);

	if (mapent) {
		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		debug(ap->logopt, MODPREFIX "%s -> %s", key, mapent);
		ret = ctxt->parse->parse_mount(ap, key, key_len,
					       mapent, ctxt->parse->context);
		if (ret) {
			time_t now = time(NULL);
			int rv = CHE_OK;

			cache_writelock(mc);
			me = cache_lookup_distinct(mc, key);
			if (!me)
				rv = cache_update(mc, source, key, NULL, now);
			if (rv != CHE_FAIL) {
				me = cache_lookup_distinct(mc, key);
				me->status = time(NULL) + NEGATIVE_TIMEOUT;
			}
			cache_unlock(mc);
		}
	}

	if (ret)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	return rv;
}
