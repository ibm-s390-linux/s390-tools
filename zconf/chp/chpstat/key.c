/*
 * Registry for supported data keys
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "key.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "cmg.h"
#include "lib/util_libc.h"
#include "lib/zt_common.h"

static struct key_t *keys;
static unsigned int num_keys;

static struct key_t **selected_keys;
static unsigned int num_selected_keys;

#define GET_CMG_MASK(c)		((u32)(1 << (c)))
#define CMG_ALL_MASK		((u32)0xffffffff)
#define IS_CMG_MASK(c, n)	((c) & GET_CMG_MASK(n))

static char *mask_to_cmg_str(u32 mask)
{
	char *str;
	int i;

	if (mask == CMG_ALL_MASK)
		return util_strdup("all");
	str = util_strdup("");
	for (i = 1; i <= 32; i++) {
		if (!IS_CMG_MASK(mask, i))
			continue;
		if (*str)
			util_concatf(&str, ",");
		util_concatf(&str, "%d", i);
	}

	return str;
}

const char *key_group_to_str(enum key_group_t group)
{
	switch (group) {
	case KEY_GRP_META:
		return "meta";
	case KEY_GRP_ITERATION:
		return "iteration";
	case KEY_GRP_CHP:
		return "channel_path";
	case KEY_GRP_CHARS:
		return "characteristics";
	case KEY_GRP_UTIL:
		return "utilization";
	case KEY_GRP_METRICS:
		return "metrics";
	default:
		return "";
	}
}

static void add_key(const char *name, enum key_group_t group, bool found,
		    u32 cmg_mask)
{
	struct key_t *key;

	key = key_get_by_name(name);
	if (!key) {
		util_expand_array(&keys, &num_keys);
		key        = &keys[num_keys - 1];
		key->name  = util_strdup(name);
		key->group = group;
	}
	key->found    |= found;
	key->cmg_mask |= cmg_mask;
	free(key->cmg_str);
	key->cmg_str = mask_to_cmg_str(key->cmg_mask);
}

static void add_generic_keys(void)
{
	add_key(KEY_META_API_LEVEL,  KEY_GRP_META, true, CMG_ALL_MASK);
	add_key(KEY_META_VERSION,    KEY_GRP_META, true, CMG_ALL_MASK);
	add_key(KEY_META_HOST,	     KEY_GRP_META, true, CMG_ALL_MASK);
	add_key(KEY_META_TIME,	     KEY_GRP_META, true, CMG_ALL_MASK);
	add_key(KEY_META_TIME_EPOCH, KEY_GRP_META, true, CMG_ALL_MASK);
	add_key(KEY_ITERATION,	     KEY_GRP_ITERATION, true, CMG_ALL_MASK);
	add_key(KEY_TIME,	     KEY_GRP_ITERATION, true, CMG_ALL_MASK);
	add_key(KEY_TIME_EPOCH,	     KEY_GRP_ITERATION, true, CMG_ALL_MASK);
	add_key(KEY_CHPID,	     KEY_GRP_CHP, true, CMG_ALL_MASK);
	add_key(KEY_TYPE,	     KEY_GRP_CHP, true, CMG_ALL_MASK);
	add_key(KEY_CMG,	     KEY_GRP_CHP, true, CMG_ALL_MASK);
	add_key(KEY_SHARED,	     KEY_GRP_CHP, true, CMG_ALL_MASK);
	add_key(KEY_SPEED,	     KEY_GRP_CHP, true, CMG_ALL_MASK);
}

static void add_cmg_keys(bool all)
{
	enum key_group_t groups[] = { KEY_GRP_UTIL, KEY_GRP_CHARS,
				      KEY_GRP_METRICS };
	unsigned int i, j;
	struct cmg_t *cmg;
	char **cmg_keys;

	cmg_for_each(cmg) {
		for (i = 0; i < ARRAY_SIZE(groups); i++) {
			cmg_keys = cmg_get_keys(cmg, groups[i]);
			for (j = 0; cmg_keys[j]; j++) {
				add_key(cmg_keys[j], groups[i],
					cmg->found || all,
					GET_CMG_MASK(cmg->cmg));
			}
			cmg_free_keys(cmg_keys);
		}
	}
}

void key_init(bool all)
{
	add_generic_keys();
	add_cmg_keys(all);
}

void key_exit(void)
{
	unsigned int i;

	for (i = 0; i < num_keys; i++) {
		free(keys[i].name);
		free(keys[i].cmg_str);
	}
	free(keys);
	free(selected_keys);
}

static int cmp_keys(const void *a, const void *b)
{
	const struct key_t * const *a_key = a;
	const struct key_t * const *b_key = b;

	return strcmp((*a_key)->name, (*b_key)->name);
}

void key_sort_selected(void)
{
	qsort(selected_keys, num_selected_keys, sizeof(struct key_t *),
	      cmp_keys);
}

struct key_t *key_get_by_index(unsigned int i, bool selected)
{
	if (selected)
		return i < num_selected_keys ? selected_keys[i] : NULL;
	return i < num_keys ? &keys[i] : NULL;
}

struct key_t *key_get_by_name(const char *name)
{
	struct key_t *key;

	key_for_each(key) {
		if (strcmp(key->name, name) == 0)
			return key;
	}
	return NULL;
}

void key_select(struct key_t *key)
{
	struct key_t *k;

	/* Prevent duplicates. */
	key_for_each_selected(k) {
		if (k == key)
			return;
	}
	util_add_array(&selected_keys, &num_selected_keys, key);
}

void key_select_by_groups(int groups, bool found)
{
	struct key_t *key;

	key_for_each(key) {
		if (found && !key->found)
			continue;
		if (!(groups & (int)key->group))
			continue;
		key_select(key);
	}
}

void key_select_by_cmg(int cmg)
{
	struct key_t *key;

	key_for_each(key) {
		if (IS_CMG_MASK(key->cmg_mask, cmg))
			key_select(key);
	}
}

void key_select_all(void)
{
	struct key_t *key;

	key_for_each(key)
		key_select(key);
}

int key_get_selected_groups(void)
{
	struct key_t *key;
	int groups = 0;

	key_for_each_selected(key)
		groups |= (int)key->group;

	return groups;
}
