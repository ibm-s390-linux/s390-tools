/*
 * Registry for CMG types
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "cmg.h"
#include "misc.h"

#include "lib/util_libc.h"

static struct cmg_t **cmgs;
static unsigned int num_cmgs;

/* Register new CMG-object @cmg. */
void cmg_add(struct cmg_t *cmg)
{
	unsigned int i;

	for (i = 0; i < num_cmgs; i++) {
		if (cmgs[i]->cmg == cmg->cmg)
			errx(EXIT_RUNTIME, "Internal error: CMG %d registered "
			     "multiple times", cmg->cmg);
	}

	util_expand_array(&cmgs, &num_cmgs);
	cmgs[num_cmgs - 1] = cmg;
}

void cmg_exit(void)
{
	free(cmgs);
}

/* Return CMG-object for @cmg. */
struct cmg_t *cmg_get(int cmg)
{
	unsigned int i;

	for (i = 0; i < num_cmgs; i++) {
		if (cmg == cmgs[i]->cmg)
			return cmgs[i];
	}
	return NULL;
}

struct cmg_t *_cmg_get_by_index(unsigned int i)
{
	return (i < num_cmgs) ? cmgs[i] : NULL;
}

void cmg_free_keys(char **keys)
{
	int i;

	if (!keys)
		return;
	for (i = 0; keys[i]; i++)
		free(keys[i]);
	free(keys);
}

void cmg_free_pairs(struct cmg_pair_t *pairs)
{
	int i;

	if (!pairs)
		return;
	for (i = 0; pairs[i].key; i++)
		free(pairs[i].key);
	free(pairs);
}

char **cmg_get_keys(struct cmg_t *cmg, int groups)
{
	struct cmg_pair_t *pairs;
	struct cmg_data_t data;
	char **keys = NULL;
	unsigned int i, num = 0;

	/* Get key-value pairs for dummy data. */
	memset(&data, 0, sizeof(data));
	pairs = cmg->get_values(&data, groups);

	/* Convert pair array to key array. */
	for (i = 0; pairs[i].key; i++)
		util_add_array(&keys, &num, util_strdup(pairs[i].key));
	util_add_array(&keys, &num, NULL);

	cmg_free_pairs(pairs);

	return keys;
}
