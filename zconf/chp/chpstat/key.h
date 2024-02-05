/*
 * Registry for supported data keys
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef KEY_H
#define KEY_H

#include <stdbool.h>

#include "lib/zt_common.h"

#define KEY_META_API_LEVEL	"meta.api_level"
#define KEY_META_VERSION	"meta.version"
#define KEY_META_HOST		"meta.host"
#define KEY_META_TIME		"meta.time"
#define KEY_META_TIME_EPOCH	"meta.time_epoch"
#define KEY_ITERATION		"iteration"
#define KEY_TIME		"time"
#define KEY_TIME_EPOCH		"time_epoch"
#define KEY_CHPID		"chpid"
#define KEY_TYPE		"type"
#define KEY_CMG			"cmg"
#define KEY_SHARED		"shared"
#define KEY_SPEED		"speed"

/**
 * enum util_fmt_t - Key group identifiers.
 * @KEY_GRP_META - Tool-related meta data
 * @KEY_GRP_ITERATION - Iteration-related data
 * @KEY_GRP_CHP - Channel-path related data
 * @KEY_GRP_CHARS - Group for channel-patch measurement characteristics data
 * @KEY_GRP_UTIL - Group for unprocessed utilization data
 * @KEY_GRP_METRICS - Group for performance metrics
 */
enum key_group_t {
	KEY_GRP_META      = (1 << 0),
	KEY_GRP_ITERATION = (1 << 1),
	KEY_GRP_CHP       = (1 << 2),
	KEY_GRP_CHARS     = (1 << 3),
	KEY_GRP_UTIL      = (1 << 4),
	KEY_GRP_METRICS   = (1 << 5),
};

#define KEY_GRP_ALL	(KEY_GRP_META | KEY_GRP_ITERATION | KEY_GRP_CHP | \
			 KEY_GRP_CHARS | KEY_GRP_UTIL | KEY_GRP_METRICS)

/**
 * struct key_t - A single data key
 * @name: Key name
 * @cmg_mask: List (bitmask) of CMGs for which this key is defined
 * @cmg_str: List (text) of CMGs for which this key is defined
 * @group: Key group this key belongs to
 * @found: Flag indicating whether key is provided by CMGS of selected CHPIDs
 */
struct key_t {
	char *name;
	u32 cmg_mask;
	char *cmg_str;
	enum key_group_t group;
	bool found;
};

#define key_for_each(c) \
	for (unsigned int __i = 0; ((c) = key_get_by_index(__i, false)); \
	     __i++)
#define key_for_each_selected(c) \
	for (unsigned int __i = 0; ((c) = key_get_by_index(__i, true)); \
	     __i++)

const char *key_group_to_str(enum key_group_t group);
struct key_t *key_get_by_index(unsigned int i, bool selected);
struct key_t *key_get_by_name(const char *name);
void key_select(struct key_t *key);
void key_select_by_groups(int groups, bool found);
void key_select_by_cmg(int cmg);
void key_select_all(void);
void key_sort_selected(void);
int key_get_selected_groups(void);

void key_init(bool all);
void key_exit(void);
struct key_t *_get_key(int i);

#endif /* KEY_H */
