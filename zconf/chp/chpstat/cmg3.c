/*
 * Support for CMG 3 channel-path statistics
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
#define get_cmcb(d)		((struct cmcb3_t *)&((d)->cmcb))
#define get_cue(d, x)		((struct cue3_t *)&((d)->x.cue))
#define get_metrics(d)		((struct metrics3_t *)&((d)->metrics))

/* CMG 3 format Channel-Measurement-Characteristics Block (CMCB). */
struct cmcb3_t {
	u32 data_unit_size;
	u32 data_unit_size_cpc;
	u32 msg_unit_size;
	u32 msg_unit_size_cpc;
} __packed;

STATIC_ASSERT(sizeof(struct cmcb3_t) <= sizeof(cmcb_t));

/* CMG 3 format Channel-Utilization-Entry (CUE). */
struct cue3_t {
	u8 cuiv;
	u32 timestamp:24;
	u32 msg_units_sent;
	u32 msg_units_sent_cpc;
	u32 unsuccessful_attempts_to_send;
	u32 unavailable_receive_buffers;
	u32 unavailable_receive_buffers_cpc;
	u32 data_units_sent;
	u32 data_units_sent_cpc;
} __packed;

STATIC_ASSERT(sizeof(struct cue3_t) <= sizeof(cue_t));

/* Metrics based on CMG 3 format CUEs. */
struct metrics3_t {
	double interval;
	double write_total;
	double write_part;
	double msg_rate_total;
	double msg_rate_part;
	double msg_size_total;
	double msg_size_part;
	double send_fail_part;
	double rcv_fail_total;
	double rcv_fail_part;
};

STATIC_ASSERT(sizeof(struct metrics3_t) <= sizeof(metrics_t));

/* IDs of columns that should be shown by default in table output. */
static const enum column_id_t default_column_ids[] = {
	COL_CHPID,
	COL_TYPE,
	COL_CMG,
	COL_SHARED,
	COL_SPEED,
	COL_WRITE_PART,
	COL_WRITE_TOTAL,
	COL_MSG_RATE_PART,
	COL_MSG_RATE_TOTAL,
	COL_MSG_SIZE_PART,
	COL_MSG_SIZE_TOTAL,
	COL_SEND_FAIL_PART,
	COL_RCV_FAIL_PART,
	COL_RCV_FAIL_TOTAL,
	/* End of list. */
	COL_END
};

static void pr_chars(struct cmg_pair_t **a, unsigned int *n,
		     struct cmg_data_t *data)
{
	struct cmcb3_t *cmcb = get_cmcb(data);

	pr_u32(a, n, cmcb, data_unit_size);
	pr_u32(a, n, cmcb, data_unit_size_cpc);
	pr_u32(a, n, cmcb, msg_unit_size);
	pr_u32(a, n, cmcb, msg_unit_size_cpc);
}

static void pr_cue(struct cmg_pair_t **a, unsigned int *n,
		   struct cmg_data_t *data)
{
	struct cue3_t *cue = get_cue(data, util_b);

	pr_u32(a, n, cue, timestamp);
	pr_cue_u32(a, n, cue, msg_units_sent);
	pr_cue_u32(a, n, cue, msg_units_sent_cpc);
	pr_cue_u32(a, n, cue, unsuccessful_attempts_to_send);
	pr_cue_u32(a, n, cue, unavailable_receive_buffers);
	pr_cue_u32(a, n, cue, unavailable_receive_buffers_cpc);
	pr_cue_u32(a, n, cue, data_units_sent);
	pr_cue_u32(a, n, cue, data_units_sent_cpc);
}

static void pr_metrics(struct cmg_pair_t **a, unsigned int *n,
		       struct cmg_data_t *data)
{
	struct metrics3_t *m = get_metrics(data);

	pr_metric(a, n, m, write_part,     CMG_BPS,    COL_WRITE_PART);
	pr_metric(a, n, m, write_total,    CMG_BPS,    COL_WRITE_TOTAL);
	pr_metric(a, n, m, msg_rate_part,  CMG_NUMBER, COL_MSG_RATE_PART);
	pr_metric(a, n, m, msg_rate_total, CMG_NUMBER, COL_MSG_RATE_TOTAL);
	pr_metric(a, n, m, msg_size_part,  CMG_NUMBER, COL_MSG_SIZE_PART);
	pr_metric(a, n, m, msg_size_total, CMG_NUMBER, COL_MSG_SIZE_TOTAL);
	pr_metric(a, n, m, send_fail_part, CMG_NUMBER, COL_SEND_FAIL_PART);
	pr_metric(a, n, m, rcv_fail_part,  CMG_NUMBER, COL_RCV_FAIL_PART);
	pr_metric(a, n, m, rcv_fail_total, CMG_NUMBER, COL_RCV_FAIL_TOTAL);
}

static struct cmg_pair_t *get_values(struct cmg_data_t *data, int groups)
{
	struct cmg_pair_t *array = NULL;
	unsigned int num = 0;

	if (groups & KEY_GRP_CHARS)
		pr_chars(&array, &num, data);
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
static void init_metrics(struct metrics3_t *m)
{
	m->interval       = METRICS_INIT;
	m->write_total    = METRICS_INIT;
	m->write_part     = METRICS_INIT;
	m->msg_rate_total = METRICS_INIT;
	m->msg_rate_part  = METRICS_INIT;
	m->msg_size_total = METRICS_INIT;
	m->msg_size_part  = METRICS_INIT;
	m->send_fail_part = METRICS_INIT;
	m->rcv_fail_total = METRICS_INIT;
	m->rcv_fail_part  = METRICS_INIT;
}

/* Calculate metrics base on CMG 3 CUEs. */
static void calc_metrics(struct cmg_data_t *data, double seconds)
{
	u32 data_size, data_size_cpc, msg_size, msg_size_cpc;
	struct metrics3_t *m = get_metrics(data);
	struct cmcb3_t *cmcb = get_cmcb(data);
	struct cue3_t *a = get_cue(data, util_a);
	struct cue3_t *b = get_cue(data, util_b);
	double delta, delta2;

	/* When not valid (reported as 0) some CMCB fields have default values
	 * or can be derived from related fields. */
	data_size     = cmcb->data_unit_size ? : 1;
	data_size_cpc = cmcb->data_unit_size_cpc ? : data_size;
	msg_size      = cmcb->msg_unit_size ? : 1;
	msg_size_cpc  = cmcb->msg_unit_size_cpc ? : msg_size;

	/*
	 * Amount of bytes per second sent in messages by all partitions
	 *
	 * write_total = data_units_sent_cpc * data_unit_size_cpc / seconds
	 */
	if (cue_valid2(a, b, data_units_sent_cpc)) {
		delta = field_delta(data_units_sent_cpc, a, b);
		m->write_total = delta * data_size_cpc / seconds;
	}

	/*
	 * Amount of bytes per second sent in messages by this partition
	 *
	 * write_part = data_units_sent * data_unit_size / seconds
	 */
	if (cue_valid2(a, b, data_units_sent)) {
		delta = field_delta(data_units_sent, a, b);
		m->write_part = delta * data_size / seconds;
	}

	/*
	 * Rate of messages sent per second by all partitions
	 *
	 * msg_rate_total = msg_units_sent_cpc * msg_unit_size_cpc / seconds
	 */
	if (cue_valid2(a, b, msg_units_sent_cpc)) {
		delta = field_delta(msg_units_sent_cpc, a, b);
		m->msg_rate_total = delta * msg_size_cpc / seconds;
	}

	/*
	 * Rate of messages sent per second by this partition
	 *
	 * msg_rate_part = msg_units_sent * msg_unit_size / seconds
	 */
	if (cue_valid2(a, b, msg_units_sent)) {
		delta = field_delta(msg_units_sent, a, b);
		m->msg_rate_part = delta * msg_size / seconds;
	}

	/*
	 * Average size of messages sent by all partitions
	 *
	 * msg_size_total = data_units_sent_cpc * data_unit_size_cpc /
	 *                  (msg_units_sent_cpc * msg_unit_size_cpc)
	 */
	if (cue_valid2(a, b, data_units_sent_cpc) &&
	    cue_valid2(a, b, msg_units_sent_cpc)) {
		delta = field_delta(data_units_sent_cpc, a, b);
		delta2 = field_delta(msg_units_sent_cpc, a, b);
		if (delta2 != 0.0) {
			m->msg_size_total = delta * data_size_cpc /
					    (delta2 * msg_size_cpc);
		}
	}

	/*
	 * Average size of messages sent by this partition
	 *
	 * msg_size_part = data_units_sent * data_unit_size /
	 *                 (msg_units_sent * msg_unit_size)
	 */
	if (cue_valid2(a, b, data_units_sent) &&
	    cue_valid2(a, b, msg_units_sent)) {
		delta = field_delta(data_units_sent, a, b);
		delta2 = field_delta(msg_units_sent, a, b);
		if (delta2 != 0.0) {
			m->msg_size_part = delta * data_size /
					   (delta2 * msg_size);
		}
	}

	/*
	 * Number of failed message send attempts per second by this partition
	 *
	 * send_fail_part = unsuccessful_attempts_to_send / seconds
	 */
	if (cue_valid2(a, b, unsuccessful_attempts_to_send)) {
		delta = field_delta(unsuccessful_attempts_to_send, a, b);
		m->send_fail_part = delta / seconds;
	}

	/*
	 * Rate of messages per second that could not be received by all
	 * partitions due to unavailable receive buffers
	 *
	 * rcv_fail_total = unavailable_receive_buffers_cpc / seconds
	 */
	if (cue_valid2(a, b, unavailable_receive_buffers_cpc)) {
		delta = field_delta(unavailable_receive_buffers_cpc, a, b);
		m->rcv_fail_total = delta / seconds;
	}

	/*
	 * Rate of messages per second that could not be received by this
	 * partition due to unavailable receive buffers
	 *
	 * rcv_fail_part = unavailable_receive_buffers / seconds
	 */
	if (cue_valid2(a, b, unavailable_receive_buffers)) {
		delta = field_delta(unavailable_receive_buffers, a, b);
		m->rcv_fail_part = delta / seconds;
	}
}

/* Recalculate metrics in @data. */
static void update_metrics(struct cmg_data_t *data)
{
	struct metrics3_t *m = get_metrics(data);
	struct cue3_t *a = get_cue(data, util_a);
	struct cue3_t *b = get_cue(data, util_b);
	u32 ticks;

	init_metrics(m);

	ticks = get_delta(a->timestamp, b->timestamp, CUE_TS_WIDTH);
	if (ticks == 0)
		return;

	/* interval = t2 - t1 */
	m->interval = tick_to_s(ticks);

	calc_metrics(data, m->interval);
}

/* Object defining this CMG. */
static struct cmg_t cmg3 = {
	.cmg                    = 3,
	.selected               = false,
	.found                  = 0,
	.has_cmcb               = true,
	.default_column_ids     = default_column_ids,
	.get_values             = &get_values,
	.update_metrics         = &update_metrics,
};

/* Add to CMG registry. */
static void __attribute__((constructor)) cmg3_ctr(void)
{
	cmg_add(&cmg3);
}
