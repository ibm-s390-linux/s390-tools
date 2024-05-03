/*
 * Support for CMG 4 channel-path statistics
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

/* Macros to convert generic cmg_data_t into CMG-specific ones. */
#define get_cmcb(d)		((struct cmcb4_t *)&((d)->cmcb))
#define get_cue(d, x)		((struct cue4_t *)&((d)->x.cue))
#define get_ext_cue(d, x)	((struct ext_cue4_t *)&((d)->x.ext_cue))
#define get_metrics(d)		((struct metrics4_t *)&((d)->metrics))

/* CMG 4 format Channel-Measurement-Characteristics Block (CMCB). */
struct cmcb4_t {
	u8 reserved[9];
	u8 dpu_id;
	u32 reserved2:16;
	u32 max_bus_cycles;
	u32 max_channel_work_units;
	u32 max_write_data_units;
	u32 max_read_data_units;
	u8  dpu_num_cores;
	u32 data_unit_size:24;
} __packed;

STATIC_ASSERT(sizeof(struct cmcb4_t) <= sizeof(cmcb_t));

/* CMG 4 format Channel-Utilization-Entry (CUE). */
struct cue4_t {
	u8 cuiv;
	u32 timestamp:24;
	u32 bus_cycles_cpc;
	u32 channel_work_units_cpc;
	u32 channel_work_units;
	u32 data_units_written_cpc;
	u32 data_units_written;
	u32 data_units_read_cpc;
	u32 data_units_read;
} __packed;

STATIC_ASSERT(sizeof(struct cue4_t) <= sizeof(cue_t));

/* CMG 4 format Extended Channel-Utilization-Entry. */
struct ext_cue4_t {
	u32 dpu_channel_exec_time_cpc;
	u32 dpu_exec_time_cpc;
} __packed;

STATIC_ASSERT(sizeof(struct ext_cue4_t) <= sizeof(ext_cue_t));

/* Metrics based on CMG 4 format CUEs. */
struct metrics4_t {
	double interval;
	double util_total;
	double util_part;
	double util_bus;
	double read_total;
	double read_part;
	double write_total;
	double write_part;
	/* Extended CUE metrics. */
	double dpu_util;
	double dpu_util_total;
	double dpu_util_part;
};

STATIC_ASSERT(sizeof(struct metrics4_t) <= sizeof(metrics_t));

/* IDs of columns that should be shown by default in table output. */
static const enum column_id_t default_column_ids[] = {
	COL_CHPID,
	COL_TYPE,
	COL_CMG,
	COL_SHARED,
	COL_SPEED,
	COL_UTIL_PART,
	COL_UTIL_TOTAL,
	COL_UTIL_BUS,
	COL_DPU_ID,
	COL_DPU_UTIL_PART,
	COL_DPU_UTIL_TOTAL,
	COL_DPU_UTIL,
	COL_READ_PART,
	COL_READ_TOTAL,
	COL_WRITE_PART,
	COL_WRITE_TOTAL,
	/* End of list. */
	COL_END
};

static void pr_chars(struct cmg_pair_t **a, unsigned int *n,
		     struct cmg_data_t *data)
{
	struct cmcb4_t *cmcb = get_cmcb(data);

	pr_cond_u32_col(a, n, data->full_cmcb, cmcb, dpu_id, COL_DPU_ID);
	pr_u32(a, n, cmcb, max_bus_cycles);
	pr_u32(a, n, cmcb, max_channel_work_units);
	pr_u32(a, n, cmcb, max_write_data_units);
	pr_u32(a, n, cmcb, max_read_data_units);
	pr_u32(a, n, cmcb, dpu_num_cores);
	pr_u32(a, n, cmcb, data_unit_size);
}

static void pr_cue(struct cmg_pair_t **a, unsigned int *n,
		   struct cmg_data_t *data)
{
	struct cue4_t *cue = get_cue(data, util_b);

	pr_u32(a, n, cue, timestamp);
	pr_cue_u32(a, n, cue, bus_cycles_cpc);
	pr_cue_u32(a, n, cue, channel_work_units_cpc);
	pr_cue_u32(a, n, cue, channel_work_units);
	pr_cue_u32(a, n, cue, data_units_written_cpc);
	pr_cue_u32(a, n, cue, data_units_written);
	pr_cue_u32(a, n, cue, data_units_read_cpc);
	pr_cue_u32(a, n, cue, data_units_read);
}

static void pr_ext_cue(struct cmg_pair_t **a, unsigned int *n,
		       struct cmg_data_t *data)
{
	struct ext_cue4_t *ext_cue = get_ext_cue(data, util_b);
	bool v = data->util_b.extended;

	pr_cond_u32(a, n, v, ext_cue, dpu_channel_exec_time_cpc);
	pr_cond_u32(a, n, v, ext_cue, dpu_exec_time_cpc);
}

static void pr_metrics(struct cmg_pair_t **a, unsigned int *n,
		       struct cmg_data_t *data)
{
	struct metrics4_t *metrics = get_metrics(data);

	pr_metric(a, n, metrics, interval,     CMG_NUMBER,  COL_INTERVAL);
	pr_metric(a, n, metrics, util_total,   CMG_PERCENT, COL_UTIL_TOTAL);
	pr_metric(a, n, metrics, util_part,    CMG_PERCENT, COL_UTIL_PART);
	pr_metric(a, n, metrics, util_bus,     CMG_PERCENT, COL_UTIL_BUS);
	pr_metric(a, n, metrics, read_total,   CMG_BPS,     COL_READ_TOTAL);
	pr_metric(a, n, metrics, read_part,    CMG_BPS,     COL_READ_PART);
	pr_metric(a, n, metrics, write_total,  CMG_BPS,     COL_WRITE_TOTAL);
	pr_metric(a, n, metrics, write_part,   CMG_BPS,     COL_WRITE_PART);
	/* Extended CUE metrics. */
	pr_metric(a, n, metrics, dpu_util,       CMG_PERCENT, COL_DPU_UTIL);
	pr_metric(a, n, metrics, dpu_util_total, CMG_PERCENT,
		  COL_DPU_UTIL_TOTAL);
	pr_metric(a, n, metrics, dpu_util_part,  CMG_PERCENT,
		  COL_DPU_UTIL_PART);
}

static struct cmg_pair_t *get_values(struct cmg_data_t *data, int groups)
{
	struct cmg_pair_t *array = NULL;
	unsigned int num = 0;

	if (groups & KEY_GRP_CHARS)
		pr_chars(&array, &num, data);
	if (groups & KEY_GRP_UTIL) {
		pr_cue(&array, &num, data);
		pr_ext_cue(&array, &num, data);
	}
	if (groups & KEY_GRP_METRICS)
		pr_metrics(&array, &num, data);

	/* Add terminating null-element. */
	util_expand_array(&array, &num);
	array[num - 1].key = NULL;

	return array;
}

/* Initialize metrics in @m. */
static void init_metrics(struct metrics4_t *m)
{
	m->interval       = METRICS_INIT;
	m->util_total     = METRICS_INIT;
	m->util_part      = METRICS_INIT;
	m->util_bus       = METRICS_INIT;
	m->read_total     = METRICS_INIT;
	m->read_part      = METRICS_INIT;
	m->write_total    = METRICS_INIT;
	m->write_part     = METRICS_INIT;
	/* Extended CUE metrics. */
	m->dpu_util       = METRICS_INIT;
	m->dpu_util_total = METRICS_INIT;
	m->dpu_util_part  = METRICS_INIT;
}

/* Calculate metrics base on CMG 4 CUEs. */
static void calc_metrics(struct cmg_data_t *data, double seconds)
{
	struct metrics4_t *m = get_metrics(data);
	struct cmcb4_t *cmcb = get_cmcb(data);
	struct cue4_t *a = get_cue(data, util_a);
	struct cue4_t *b = get_cue(data, util_b);
	double delta, max;

	/* util_total = 100.0 * work_units_cpc / max_work_units */
	if (cue_valid2(a, b, channel_work_units_cpc)) {
		delta = field_delta(channel_work_units_cpc, a, b);
		max = cmcb->max_channel_work_units * seconds;
		if (max != 0.0)
			m->util_total = 100.0 * delta / max;
	}
	/* util_part = 100.0 * work_units / max_work_units */
	if (cue_valid2(a, b, channel_work_units)) {
		delta = field_delta(channel_work_units, a, b);
		max = cmcb->max_channel_work_units * seconds;
		if (max != 0.0)
			m->util_part = 100.0 * delta / max;
	}
	/* util_bus = 100.0 * bus_cycles_cpc / max_bus_cycles */
	if (cue_valid2(a, b, bus_cycles_cpc)) {
		delta = field_delta(bus_cycles_cpc, a, b);
		max = cmcb->max_bus_cycles * seconds;
		if (max != 0.0)
			m->util_bus = 100.0 * delta / max;
	}
	/* read_total = data_units_read_cpc * unit_size / seconds */
	if (cue_valid2(a, b, data_units_read_cpc)) {
		delta = field_delta(data_units_read_cpc, a, b);
		m->read_total = (double)delta * cmcb->data_unit_size / seconds;
	}
	/* read_part = data_units_read * unit_size / seconds */
	if (cue_valid2(a, b, data_units_read)) {
		delta = field_delta(data_units_read, a, b);
		m->read_part = (double)delta * cmcb->data_unit_size / seconds;
	}
	/* write_total = data_units_written_cpc * unit_size / seconds */
	if (cue_valid2(a, b, data_units_written_cpc)) {
		delta = field_delta(data_units_written_cpc, a, b);
		m->write_total = (double)delta * cmcb->data_unit_size / seconds;
	}
	/* write_part = data_units_written * unit_size / seconds */
	if (cue_valid2(a, b, data_units_written)) {
		delta = field_delta(data_units_written, a, b);
		m->write_part = (double)delta * cmcb->data_unit_size / seconds;
	}
}

/* Calculate metrics base on CMG 4 extended CUEs. */
static void calc_ext_metrics(struct cmg_data_t *data, double seconds)
{
	struct metrics4_t *m = get_metrics(data);
	struct ext_cue4_t *ext_a = get_ext_cue(data, util_a);
	struct ext_cue4_t *ext_b = get_ext_cue(data, util_b);
	struct cue4_t *a = get_cue(data, util_a);
	struct cue4_t *b = get_cue(data, util_b);
	struct cmcb4_t *cmcb = get_cmcb(data);
	double delta, delta2;

	/* These metrics require extended CUEs. */
	if (!data->util_a.extended || !data->util_b.extended)
		return;

	if (cmcb->dpu_num_cores == 0)
		return;

	/* dpu_util = dpu_exec_time_cpc / (t * dpu_num_cores) */
	delta = field_delta(dpu_exec_time_cpc, ext_a, ext_b);
	m->dpu_util = delta / (seconds * cmcb->dpu_num_cores);

	/* dpu_util_total = dpu_channel_exec_time_cpc / (t * dpu_num_cores) */
	delta = field_delta(dpu_channel_exec_time_cpc, ext_a, ext_b);
	m->dpu_util_total = delta / (seconds * cmcb->dpu_num_cores);

	/* dpu_util_part = dpu_util_total * channel_work_units /
	 *                                  channel_work_units_cpc */
	if (cue_valid2(a, b, channel_work_units) &&
	    cue_valid2(a, b, channel_work_units_cpc)) {
		delta = field_delta(channel_work_units, a, b);
		delta2 = field_delta(channel_work_units_cpc, a, b);
		if (delta2 != 0.0)
			m->dpu_util_part = m->dpu_util_total * delta / delta2;
	}
}

/* Recalculate metrics in @data. */
static void update_metrics(struct cmg_data_t *data)
{
	struct metrics4_t *m = get_metrics(data);
	struct cue4_t *a = get_cue(data, util_a);
	struct cue4_t *b = get_cue(data, util_b);
	u32 ticks;

	init_metrics(m);

	ticks = get_delta(a->timestamp, b->timestamp, CUE_TS_WIDTH);
	if (ticks == 0)
		return;

	/* interval = t2 - t1 */
	m->interval = tick_to_s(ticks);

	calc_metrics(data, m->interval);
	calc_ext_metrics(data, m->interval);
}

/* Object defining this CMG. */
static struct cmg_t cmg4 = {
	.cmg                    = 4,
	.selected               = false,
	.found                  = 0,
	.has_cmcb               = true,
	.default_column_ids     = default_column_ids,
	.get_values             = &get_values,
	.update_metrics         = &update_metrics,
};

/* Add to CMG registry. */
static void __attribute__((constructor)) cmg4_ctr(void)
{
	cmg_add(&cmg4);
}
