
#ifndef __NSSWITCH_H
#define __NSSWITCH_H

#include "list.h"

#define NSSWITCH_FILE "/etc/nsswitch.conf"

enum nsswitch_status {
	NSS_STATUS_UNKNOWN = -1,
	NSS_STATUS_SUCCESS,
	NSS_STATUS_NOTFOUND,
	NSS_STATUS_UNAVAIL,
	NSS_STATUS_TRYAGAIN,
	NSS_STATUS_MAX
};

enum nsswitch_action {
	NSS_ACTION_UNKNOWN = 0,
	NSS_ACTION_CONTINUE,
	NSS_ACTION_RETURN
};

struct nss_action {
	enum nsswitch_action action;
	int negated;
};

struct nss_source {
	char *source;
	struct nss_action action[NSS_STATUS_MAX];
	struct list_head list;
}; 

int set_action(struct nss_action *a, char *status, char *action, int negated);
struct nss_source *add_source(struct list_head *head, char *source);
int free_sources(struct list_head *list);

int nsswitch_parse(struct list_head *list);

#endif
