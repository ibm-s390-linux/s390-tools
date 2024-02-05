/*
 * Helper functions for implementing CMG types
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "cmg_helper.h"
#include "cmg.h"

#include "lib/util_base.h"
#include "lib/util_libc.h"

/* Convert time ticks to seconds. */
double tick_to_s(u32 t)
{
	return CM_TICK * t;
}

/* Get 32 bit delta of counters @curr and @last. Take into account that both
 * counters might have wrapped. Counter width is @width bits. */
u32 get_delta(u32 last, u32 curr, int width)
{
	if (curr >= last)
		return curr - last;

	/* Counter wrapped - add [last..max] + [0..curr] */
	return (u32)((u64)(1ULL << width) - last + curr);
}

/* Get 64 bit delta of counters @curr and @last. Take into account that both
 * counters might have wrapped. Counter width is @width bits. */
u64 get_delta64(u64 last, u64 curr, int width)
{
	u64 max;

	if (curr >= last)
		return curr - last;

	/* Counter wrapped - add [last..max] + [0..curr] */
	max = (width == 64) ? ULLONG_MAX : (1ULL << width) - 1;
	return (max - last + curr) + 1;
}

/* Check whether word at @offset is valid according to @cuiv. */
bool _cue_valid(u8 cuiv, int offset)
{
	int num;
	u8 mask;

	num = offset / (int)sizeof(u32);
	mask = 0x80 >> num;

	return (cuiv & mask) != 0;
}

static struct cmg_pair_t *add_pair(struct cmg_pair_t **array, unsigned int *num,
				   bool valid, const char *key,
				   enum column_id_t col, enum cmg_unit_t unit,
				   enum cmg_value_type_t type)
{
	struct cmg_pair_t pair;

	memset(&pair, 0, sizeof(pair));
	pair.valid     = valid;
	pair.key       = util_strdup(key);
	pair.col       = col;
	pair.unit      = unit;
	pair.type      = type;
	util_add_array(array, num, pair);

	return &((*array)[*num - 1]);
}

void _pr_u32(struct cmg_pair_t **array, unsigned int *num, bool valid,
	     const char *key, enum column_id_t col, enum cmg_unit_t unit,
	     u32 value)
{
	struct cmg_pair_t *pair;

	pair = add_pair(array, num, valid, key, col, unit, CMG_U32);
	pair->value_u32 = value;
}

void _pr_u64(struct cmg_pair_t **array, unsigned int *num, bool valid,
	     const char *key, enum column_id_t col, enum cmg_unit_t unit,
	     u64 value)
{
	struct cmg_pair_t *pair;

	pair = add_pair(array, num, valid, key, col, unit, CMG_U64);
	pair->value_u64 = value;
}

void _pr_double(struct cmg_pair_t **array, unsigned int *num, bool valid,
		const char *key, enum column_id_t col, enum cmg_unit_t unit,
		double value)
{
	struct cmg_pair_t *pair;

	pair = add_pair(array, num, valid, key, col, unit, CMG_FLOAT);
	pair->value_double = value;
}
