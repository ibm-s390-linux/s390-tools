/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Table unit module: Provide different units for data
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include "table.h"

#define L_VISUAL_ROW_CNT	45
#define L_COL_FMT_STR_0		"%.0lf"
#define L_COL_FMT_STR_2		"%.2lf"
#define L_COL_NOT_SET_STR	"-"

/*
 * Helper: Divide value and format it
 */
static int l_unit_raw_div(struct table_col *col, struct table_entry *e,
			  unsigned int divisor, const char *fmt_str)
{
	double v1;

	if (!e->set)
		return snprintf(e->str, sizeof(e->str), L_COL_NOT_SET_STR);
	switch (col->type) {
	case TABLE_COL_TYPE_U64:
		v1 = ((double) e->d.u64.v1) / divisor;
		break;
	case TABLE_COL_TYPE_S64:
		v1 = ((double) e->d.s64.v1) / divisor;
		break;
	default:
		assert(0);
	}
	return snprintf(e->str, sizeof(e->str), fmt_str, v1);
}

/*
 * Helper: Format value as is
 */
static int l_unit_raw(struct table_col *col, struct table_entry *e)
{
	if (!e->set)
		return snprintf(e->str, sizeof(e->str), L_COL_NOT_SET_STR);
	switch (col->type) {
	case TABLE_COL_TYPE_U64:
		return snprintf(e->str, sizeof(e->str), "%llu", e->d.u64.v1);
	case TABLE_COL_TYPE_S64:
		return snprintf(e->str, sizeof(e->str), "%lld", e->d.s64.v1);
	default:
		assert(0);
		return 0;
	}
}

/*
 * Format: String
 */
static int l_str(struct table_col *col, struct table_entry *e)
{
	col->p->needs_quotes = 1;
	return strlen(e->str);
}

struct table_col_unit table_col_unit_str = {
	.fn	= l_str,
	.hotkey	= 'S',
	.str	= "str",
	.desc	= "String",
};

/*
 * Format: Count
 */
static int l_unit_cnt(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw(col, e);
}

struct table_col_unit table_col_unit_cnt = {
	.fn	= l_unit_cnt,
	.hotkey	= '#',
	.str	= "#",
	.desc	= "Count",
};

/*
 * Format: Kibibytes
 */
static int l_unit_kib(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw(col, e);
}

struct table_col_unit table_col_unit_kib = {
	.fn	= l_unit_kib,
	.hotkey	= 'k',
	.str	= "KiB",
	.desc	= "Kibibyte (1.024 bytes)",
};

/*
 * Format: Mebibytes
 */
static int l_unit_mib(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw_div(col, e, 1024, L_COL_FMT_STR_2);
}

struct table_col_unit table_col_unit_mib = {
	.fn	= l_unit_mib,
	.hotkey	= 'M',
	.str	= "MiB",
	.desc	= "Mebibyte (1.048.576 bytes)",
};

/*
 * Format: Gibibytes
 */
static int l_unit_gib(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw_div(col, e, 1024 * 1024, L_COL_FMT_STR_2);
}

struct table_col_unit table_col_unit_gib = {
	.fn	= l_unit_gib,
	.hotkey	= 'g',
	.str	= "GiB",
	.desc	= "Gibibyte (1.073.741.824 bytes)",
};

/*
 * Format: Microseconds
 */
static int l_unit_us(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw(col, e);
}

struct table_col_unit table_col_unit_us = {
	.fn	= l_unit_us,
	.hotkey	= 'u',
	.str	= "us",
};

/*
 * Format: Milliseconds
 */
static int l_unit_ms(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw_div(col, e, USEC_PER_MSEC, L_COL_FMT_STR_2);
}

struct table_col_unit table_col_unit_ms = {
	.fn	= l_unit_ms,
	.hotkey	= 'm',
	.str	= "ms",
};

/*
 * Format: Percent (Hundreds)
 */
static int l_unit_perc(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw_div(col, e, (USEC_PER_SEC / 100), L_COL_FMT_STR_2);
}

struct table_col_unit table_col_unit_perc = {
	.fn	= l_unit_perc,
	.hotkey	= '%',
	.str	= "%",
	.desc	= "Percent",
};

/*
 * Format: Seconds
 */
static int l_unit_s(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw_div(col, e, USEC_PER_SEC, L_COL_FMT_STR_2);
}

struct table_col_unit table_col_unit_s = {
	.fn	= l_unit_s,
	.hotkey	= 's',
	.str	= "s",
	.desc	= "Seconds",
};

/*
 * Format: Minutes
 */
static int l_unit_m(struct table_col *col, struct table_entry *e)
{
	return l_unit_raw_div(col, e, USEC_PER_SEC * 60, L_COL_FMT_STR_0);
}

static struct table_col_unit table_col_unit_m = {
	.fn	= l_unit_m,
	.hotkey	= 'm',
	.str	= "m",
	.desc	= "Minutes",
};

/*
 * Format: Hours:Minutes
 */
static int l_unit_hm_u64(char *str, u64 v1, int negative)
{
	u64 time_tmp, time_h, time_m;

	time_tmp = v1 / (USEC_PER_SEC * 60);
	time_h = time_tmp / 60;
	time_m = time_tmp - time_h * 60;

	if (negative)
		return sprintf(str, "-%llu:%02llu", time_h, time_m);
	else
		return sprintf(str, "%llu:%02llu", time_h, time_m);
}

static int l_unit_hm(struct table_col *col, struct table_entry *e)
{
	col->p->needs_quotes = 1;

	if (!e->set)
		return snprintf(e->str, sizeof(e->str), L_COL_NOT_SET_STR);

	switch (col->type) {
	case TABLE_COL_TYPE_U64:
		return l_unit_hm_u64(e->str, e->d.u64.v1, 0);
	case TABLE_COL_TYPE_S64:
		if (e->d.s64.v1 < 0)
			return l_unit_hm_u64(e->str, -e->d.s64.v1, 1);
		else
			return l_unit_hm_u64(e->str, e->d.s64.v1, 0);
	default:
		assert(0);
		return 0;
	}
}

struct table_col_unit table_col_unit_hm = {
	.fn	= l_unit_hm,
	.hotkey	= 'H',
	.str	= "hm",
	.desc	= "Hours:Minutes",
};

/*
 * Format: Days:Hours:Minutes
 */
static int l_unit_dhm_u64(char *str, u64 v1, int negative)
{
	u64 time_tmp, time_d, time_h, time_m;

	time_tmp = v1 / (USEC_PER_SEC * 60);
	time_d = time_tmp / (60 * 24);
	time_h = time_tmp / 60 - time_d * 24;
	time_m = time_tmp - time_h * 60 - time_d * 60 * 24;

	if (negative)
		return sprintf(str, "-%llu:%02llu:%02llu", time_d, time_h,
			       time_m);
	else
		return sprintf(str, "%llu:%02llu:%02llu", time_d, time_h,
			       time_m);
}

static int l_unit_dhm(struct table_col *col, struct table_entry *e)
{
	col->p->needs_quotes = 1;

	if (!e->set)
		return snprintf(e->str, sizeof(e->str), L_COL_NOT_SET_STR);

	switch (col->type) {
	case TABLE_COL_TYPE_U64:
		return l_unit_dhm_u64(e->str, e->d.u64.v1, 0);
	case TABLE_COL_TYPE_S64:
		if (e->d.s64.v1 < 0)
			return l_unit_dhm_u64(e->str, -e->d.s64.v1, 1);
		else
			return l_unit_dhm_u64(e->str, e->d.s64.v1, 0);
	default:
		assert(0);
		return 0;
	}
}

struct table_col_unit table_col_unit_dhm = {
	.fn	= l_unit_dhm,
	.hotkey	= 'D',
	.str	= "dhm",
	.desc	= "Days:Hours:Minutes",
};

/*
 * Format: Visualization with bar chart
 */
static int l_unit_vis(struct table_col *col, struct table_entry *e)
{
	double val1_perc, val2_perc;
	int val1_nr, val2_nr;
	int i;

	assert(col->type == TABLE_COL_TYPE_U64);

	sprintf(e->str, "|");
	val1_perc = util_usecs_to_secs(e->d.u64.v1);
	val2_perc = util_usecs_to_secs(e->d.u64.v2);
	val1_nr = (val1_perc * L_VISUAL_ROW_CNT) + 0.5;
	val2_nr = (val2_perc * L_VISUAL_ROW_CNT) + 0.5;

	if (val1_nr > L_VISUAL_ROW_CNT)
		val1_nr = L_VISUAL_ROW_CNT;
	if (val1_nr + val2_nr > L_VISUAL_ROW_CNT)
		val2_nr = L_VISUAL_ROW_CNT - val1_nr;

	for (i = 0; i < val1_nr; i++)
		strcat(e->str, "#");
	for (i = 0; i < val2_nr; i++)
		strcat(e->str, "-");
	for (i = 0; i < L_VISUAL_ROW_CNT - val1_nr - val2_nr; i++)
		strcat(e->str, " ");
	strcat(e->str, "|");

	return strlen(e->str);
}

struct table_col_unit table_col_unit_vis = {
	.fn	= l_unit_vis,
	.hotkey	= 'v',
	.str	= "vis",
	.desc	= "Visualization with bar chart",
};

/*
 * Families
 */
struct table_col_unit *table_col_unit_fam_str[] = {
	&table_col_unit_str,
	NULL,
};

struct table_col_unit *table_col_unit_fam_cnt[] = {
	&table_col_unit_cnt,
	NULL,
};

struct table_col_unit *table_col_unit_fam_mem[] = {
	&table_col_unit_kib,
	&table_col_unit_mib,
	&table_col_unit_gib,
	NULL,
};

struct table_col_unit *table_col_unit_fam_time_diff[] = {
	&table_col_unit_us,
	&table_col_unit_ms,
	&table_col_unit_perc,
	&table_col_unit_s,
	NULL,
};

struct table_col_unit *table_col_unit_fam_time[] = {
	&table_col_unit_us,
	&table_col_unit_ms,
	&table_col_unit_s,
	&table_col_unit_m,
	&table_col_unit_hm,
	&table_col_unit_dhm,
	NULL,
};

struct table_col_unit *table_col_unit_fam_vis[] = {
	&table_col_unit_vis,
	NULL,
};
