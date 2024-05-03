/*
 * Helper functions for implementing CMG types
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CMG_HELPER_H
#define CMG_HELPER_H

#include <stdbool.h>

#include "cmg.h"
#include "column.h"

#include "lib/util_base.h"

/* Duration of channel-path measurement timestamp tick. */
#define CM_TICK			((double)0.000128)

/* Initialization value for metrics fields. */
#define METRICS_INIT		-1.0

/* Check whether member @field of struct @s is valid according to s->cuiv. */
#define cue_valid(s, field) \
	(_cue_valid((s)->cuiv, offsetof(__typeof__(*s), field)))

/* Check whether member @field of struct @a and @b is valid according to
 * a->cuiv and b->cuiv. */
#define cue_valid2(a, b, field) \
	((_cue_valid((a)->cuiv, offsetof(__typeof__(*a), field))) && \
	 (_cue_valid((b)->cuiv, offsetof(__typeof__(*b), field))))

#define field_delta(field, a, b) \
	get_delta((a)->field, (b)->field, 32)

#define field_delta64(field, a, b) \
	get_delta64((a)->field, (b)->field, 64)

#define pr_u32(a, n, s, field) \
	_pr_u32((a), (n), true, STRINGIFY(field), COL_NONE, CMG_NUMBER, \
		(s)->field)

#define pr_cond_u32(a, n, v, s, field) \
	_pr_u32((a), (n), (v), STRINGIFY(field), COL_NONE, CMG_NUMBER, \
		(s)->field)

#define pr_cond_u32_col(a, n, v, s, field, c) \
	_pr_u32((a), (n), (v), STRINGIFY(field), (c), CMG_NUMBER, \
		(s)->field)

#define pr_cue_u32(a, n, s, field) \
	pr_cond_u32(a, n, cue_valid(s, field), s, field)

#define pr_u64(a, n, s, field) \
	_pr_u64((a), (n), true, STRINGIFY(field), COL_NONE, CMG_NUMBER, \
		(s)->field)

#define pr_cond_u64(a, n, v, s, field) \
	_pr_u64((a), (n), (v), STRINGIFY(field), COL_NONE, CMG_NUMBER, \
		(s)->field)

/* pr_metric(array_ptr, num_ptr, struct, field, unit, column_id) */
#define pr_metric(a, n, s, field, u, c) \
	_pr_double((a), (n), ((s)->field != METRICS_INIT), STRINGIFY(field), \
		   c, u, (s)->field)

double tick_to_s(u32 t);
u32 get_delta(u32 last, u32 curr, int width);
u64 get_delta64(u64 last, u64 curr, int width);
bool _cue_valid(u8 cuiv, int offset);

void _pr_u32(struct cmg_pair_t **a, unsigned int *n, bool valid,
	     const char *key, enum column_id_t col, enum cmg_unit_t unit,
	     u32 value);
void _pr_u64(struct cmg_pair_t **a, unsigned int *n, bool valid,
	     const char *key, enum column_id_t col, enum cmg_unit_t unit,
	     u64 value);
void _pr_double(struct cmg_pair_t **a, unsigned int *n, bool valid,
		const char *key, enum column_id_t col, enum cmg_unit_t unit,
		double value);

#endif /* CMG_HELPER_H */
