/*
 * Support for CMG 1 channel-path statistics
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "cmg.h"
#include "cmg_helper.h"
#include "column.h"
#include "key.h"

#include "lib/util_base.h"
#include "lib/zt_common.h"

/* Macros to convert generic cmg_data_t into CMG-specific ones. */
#define get_cue(d, x)	((struct cue1_t *)&((d)->x.cue))
#define get_metrics(d)	((struct metrics1_t *)&((d)->metrics))

/* CMG 1 format Channel-Utilization-Entry. */
struct cue1_t {
	u8 cuiv;
	u32 timestamp:24;
	u32 channel_path_busy_time_cpc;
	u32 channel_path_busy_time;
} __packed;

STATIC_ASSERT(sizeof(struct cue1_t) <= sizeof(cue_t));

/* Metrics based on CMG 1 format CUEs. */
struct metrics1_t {
	double interval;
	double util_total;
	double util_part;
};

STATIC_ASSERT(sizeof(struct metrics1_t) <= sizeof(metrics_t));

/* IDs of columns that should be shown by default in table output. */
static const enum column_id_t default_column_ids[] = {
	COL_CHPID,
	COL_TYPE,
	COL_CMG,
	COL_SHARED,
	COL_SPEED,
	COL_UTIL_PART,
	COL_UTIL_TOTAL,
	/* End of list. */
	COL_END
};

static void pr_cue(struct cmg_pair_t **a, unsigned int *n,
		   struct cmg_data_t *data)
{
	struct cue1_t *cue = get_cue(data, util_b);

	pr_u32(a, n, cue, timestamp);
	pr_cue_u32(a, n, cue, channel_path_busy_time_cpc);
	pr_cue_u32(a, n, cue, channel_path_busy_time);
}

static void pr_metrics(struct cmg_pair_t **a, unsigned int *n,
		       struct cmg_data_t *data)
{
	struct metrics1_t *metrics = get_metrics(data);

	pr_metric(a, n, metrics, interval,     CMG_NUMBER,  COL_INTERVAL);
	pr_metric(a, n, metrics, util_total,   CMG_PERCENT, COL_UTIL_TOTAL);
	pr_metric(a, n, metrics, util_part,    CMG_PERCENT, COL_UTIL_PART);
}

static struct cmg_pair_t *get_values(struct cmg_data_t *data, int groups)
{
	struct cmg_pair_t *array = NULL;
	unsigned int num = 0;

	if (groups & KEY_GRP_UTIL)
		pr_cue(&array, &num, data);
	if (groups & KEY_GRP_METRICS)
		pr_metrics(&array, &num, data);

	/* Add terminating null-element. */
	util_expand_array(&array, &num);
	array[num - 1].key = NULL;

	return array;
}

/* Initialize metrics in @m. */
static void init_metrics(struct metrics1_t *m)
{
	m->interval   = METRICS_INIT;
	m->util_total = METRICS_INIT;
	m->util_part  = METRICS_INIT;
}

/* Recalculate metrics in @data. */
static void update_metrics(struct cmg_data_t *data)
{
	struct metrics1_t *m = get_metrics(data);
	struct cue1_t *a = get_cue(data, util_a);
	struct cue1_t *b = get_cue(data, util_b);
	u32 ticks, delta;

	init_metrics(m);

	ticks = get_delta(a->timestamp, b->timestamp, CUE_TS_WIDTH);
	if (ticks == 0)
		return;

	/* interval = t2 - t1 */
	m->interval = tick_to_s(ticks);

	/* util_total = 100.0 * ticks_busy_cpc / ticks_total */
	if (cue_valid2(a, b, channel_path_busy_time_cpc)) {
		delta = field_delta(channel_path_busy_time_cpc, a, b);
		m->util_total = 100.0 * delta / ticks;
	}
	/* util_part = 100.0 * ticks_busy / ticks_total */
	if (cue_valid2(a, b, channel_path_busy_time)) {
		delta = field_delta(channel_path_busy_time, a, b);
		m->util_part = 100.0 * delta / ticks;
	}
}

/* Object defining this CMG. */
static struct cmg_t cmg1 = {
	.cmg                    = 1,
	.selected               = false,
	.found                  = 0,
	.has_cmcb               = false,
	.default_column_ids     = default_column_ids,
	.get_values             = &get_values,
	.update_metrics         = &update_metrics,
};

/* Add to CMG registry. */
static void __attribute__((constructor)) cmg1_ctr(void)
{
	cmg_add(&cmg1);
}
