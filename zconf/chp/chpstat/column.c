/*
 * Registry for supported table columns
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>
#include <stdbool.h>

#include "column.h"

#include "lib/util_base.h"
#include "lib/util_libc.h"

/*
 * Use group header for adjacent columns of the same type to improve
 * readability.
 *
 * Single header: UTIL      Group header: UTILIZATION
 *                PART                    PART  TOTAL
 */
#define HDR1_CHP_SINGLE		""
#define HDR1_CHP_GROUP		"CHANNEL-PATH"
#define HDR1_UTIL_SINGLE	"UTIL"
#define HDR1_UTIL_GROUP		"UTILIZATION(%)"
#define HDR1_READ_SINGLE	"READ"
#define HDR1_READ_GROUP		"READ"
#define HDR1_WRITE_SINGLE	"WRITE"
#define HDR1_WRITE_GROUP	"WRITE"
#define HDR1_FICON_SINGLE	"FICON"
#define HDR1_FICON_GROUP	"FICON-OPS"
#define HDR1_HPF_SINGLE		"HPF"
#define HDR1_HPF_GROUP		"HPF-OPS"
#define HDR1_MSGR_SINGLE	"RATE"
#define HDR1_MSGR_GROUP		"MSG-RATE"
#define HDR1_MSGSZ_SINGLE	"SIZE"
#define HDR1_MSGSZ_GROUP	"MSG-SIZE"
#define HDR1_MSG_RCVF_SINGLE	"RFAIL"
#define HDR1_MSG_RCVF_GROUP	"RECEIVE-FAIL"
#define HDR1_DPU_UTIL_SINGLE	"DPU"
#define HDR1_DPU_UTIL_GROUP	"DPU UTILIZATION(%)"

static struct column_t columns[] = {
	{
		COL_CHPID,
		"chpid",
		COL_OTHER,
		"Channel-path ID",
		"ID",
		HDR1_CHP_SINGLE,
		HDR1_CHP_GROUP,
		0,
		0,
	},
	{
		COL_TYPE,
		"type",
		COL_OTHER,
		"Channel-path type",
		"TYP",
		HDR1_CHP_SINGLE,
		HDR1_CHP_GROUP,
		0,
		0,
	},
	{
		COL_CMG,
		"cmg",
		COL_OTHER,
		"Channel-measurement group",
		"CMG",
		HDR1_CHP_SINGLE,
		HDR1_CHP_GROUP,
		0,
		0,
	},
	{
		COL_SPEED,
		"speed",
		COL_OTHER,
		"Operational speed",
		"SPEED",
		HDR1_CHP_SINGLE,
		HDR1_CHP_GROUP,
		0,
		0,
	},
	{
		COL_SHARED,
		"shared",
		COL_OTHER,
		"Shared channel-path indicator",
		"SHR",
		HDR1_CHP_SINGLE,
		HDR1_CHP_GROUP,
		0,
		0,
	},
	{
		COL_INTERVAL,
		"interval",
		COL_OTHER,
		"Cumulated statistics update interval",
		"INT",
		HDR1_CHP_SINGLE,
		HDR1_CHP_GROUP,
		0,
		0,
	},
	{
		COL_UTIL_PART,
		"util_part",
		COL_PERCENT,
		"Partition channel-path utilization in %",
		"PART",
		HDR1_UTIL_SINGLE,
		HDR1_UTIL_GROUP,
		5,
		0,
	},
	{
		COL_UTIL_TOTAL,
		"util_total",
		COL_PERCENT,
		"Total channel-path utilization in %",
		"TOTAL",
		HDR1_UTIL_SINGLE,
		HDR1_UTIL_GROUP,
		5,
		0,
	},
	{
		COL_UTIL_BUS,
		"util_bus",
		COL_PERCENT,
		"Bus utilization in %",
		"BUS",
		HDR1_UTIL_SINGLE,
		HDR1_UTIL_GROUP,
		0,
		0,
	},
	{
		COL_UTIL_DATA,
		"util_data",
		COL_PERCENT,
		"Data bandwidth utilization in %",
		"DATA",
		HDR1_UTIL_SINGLE,
		HDR1_UTIL_GROUP,
		0,
		0,
	},
	{
		COL_READ_PART,
		"read_part",
		COL_BPS,
		"Partition read throughput in B/s",
		"PART",
		HDR1_READ_SINGLE,
		HDR1_READ_GROUP,
		5,
		0,
	},
	{
		COL_READ_TOTAL,
		"read_total",
		COL_BPS,
		"Total read throughput in B/s",
		"TOTAL",
		HDR1_READ_SINGLE,
		HDR1_READ_GROUP,
		5,
		0,
	},
	{
		COL_WRITE_PART,
		"write_part",
		COL_BPS,
		"Partition write throughput in B/s",
		"PART",
		HDR1_WRITE_SINGLE,
		HDR1_WRITE_GROUP,
		5,
		0,
	},
	{
		COL_WRITE_TOTAL,
		"write_total",
		COL_BPS,
		"Total write throughput in B/s",
		"TOTAL",
		HDR1_WRITE_SINGLE,
		HDR1_WRITE_GROUP,
		5,
		0,
	},
	{
		COL_FICON_RATE,
		"ficon_rate",
		COL_NUMBER,
		"FICON operations per second",
		"RATE",
		HDR1_FICON_SINGLE,
		HDR1_FICON_GROUP,
		0,
		0,
	},
	{
		COL_FICON_ACTIVE,
		"ficon_active",
		COL_NUMBER,
		"Avg. concurrently active FICON operations",
		"ACTV",
		HDR1_FICON_SINGLE,
		HDR1_FICON_GROUP,
		0,
		0,
	},
	{
		COL_FICON_DEFER,
		"ficon_defer",
		COL_NUMBER,
		"Deferred FICON operations per second",
		"DEFER",
		HDR1_FICON_SINGLE,
		HDR1_FICON_GROUP,
		0,
		0,
	},
	{
		COL_HPF_RATE,
		"hpf_rate",
		COL_NUMBER,
		"HPF operations per second",
		"RATE",
		HDR1_HPF_SINGLE,
		HDR1_HPF_GROUP,
		0,
		0,
	},
	{
		COL_HPF_ACTIVE,
		"hpf_active",
		COL_NUMBER,
		"Avg. concurrently active HPF operations",
		"ACTV",
		HDR1_HPF_SINGLE,
		HDR1_HPF_GROUP,
		0,
		0,
	},
	{
		COL_HPF_DEFER,
		"hpf_defer",
		COL_NUMBER,
		"Deferred HPF operations per second",
		"DEFER",
		HDR1_HPF_SINGLE,
		HDR1_HPF_GROUP,
		0,
		0,
	},
	{
		COL_MSG_RATE_PART,
		"msg_rate_part",
		COL_NUMBER,
		"Partition message send rate per second",
		"PART",
		HDR1_MSGR_SINGLE,
		HDR1_MSGR_GROUP,
		5,
		0,
	},
	{
		COL_MSG_RATE_TOTAL,
		"msg_rate_total",
		COL_NUMBER,
		"Total message send rate per second",
		"TOTAL",
		HDR1_MSGR_SINGLE,
		HDR1_MSGR_GROUP,
		5,
		0,
	},
	{
		COL_MSG_SIZE_PART,
		"msg_size_part",
		COL_NUMBER,
		"Partition avg. send message size",
		"PART",
		HDR1_MSGSZ_SINGLE,
		HDR1_MSGSZ_GROUP,
		5,
		0,
	},
	{
		COL_MSG_SIZE_TOTAL,
		"msg_size_total",
		COL_NUMBER,
		"Total avg. send message size",
		"TOTAL",
		HDR1_MSGSZ_SINGLE,
		HDR1_MSGSZ_GROUP,
		5,
		0,
	},
	{
		COL_SEND_FAIL_PART,
		"send_fail_part",
		COL_NUMBER,
		"Partition message send fail rate per second",
		"PART",
		"SNDFAIL",
		"SNDFAIL",
		0,
		0,
	},
	{
		COL_RCV_FAIL_PART,
		"rcv_fail_part",
		COL_NUMBER,
		"Partition message receive fail rate per second",
		"PART",
		HDR1_MSG_RCVF_SINGLE,
		HDR1_MSG_RCVF_GROUP,
		5,
		0,
	},
	{
		COL_RCV_FAIL_TOTAL,
		"rcv_fail_total",
		COL_NUMBER,
		"Total message receive fail rate per second",
		"TOTAL",
		HDR1_MSG_RCVF_SINGLE,
		HDR1_MSG_RCVF_GROUP,
		5,
		0,
	},
	{
		COL_DPU_ID,
		"dpu_id",
		COL_OTHER,
		"DPU ID associated with channel-path",
		"ID",
		HDR1_DPU_UTIL_SINGLE,
		HDR1_DPU_UTIL_GROUP,
		0,
		0,
	},
	{
		COL_DPU_UTIL,
		"dpu_util",
		COL_PERCENT,
		"Full DPU utilization in %",
		"FULL",
		HDR1_DPU_UTIL_SINGLE,
		HDR1_DPU_UTIL_GROUP,
		0,
		0,
	},
	{
		COL_DPU_UTIL_PART,
		"dpu_util_part",
		COL_PERCENT,
		"Partition channel-path DPU utilization in %",
		"PART",
		HDR1_DPU_UTIL_SINGLE,
		HDR1_DPU_UTIL_GROUP,
		5,
		0,
	},
	{
		COL_DPU_UTIL_TOTAL,
		"dpu_util_total",
		COL_PERCENT,
		"Total channel-path DPU utilization in %",
		"TOTAL",
		HDR1_DPU_UTIL_SINGLE,
		HDR1_DPU_UTIL_GROUP,
		5,
		0,
	},
};

/* Columns selected by default. */
static const int default_columns[] = {
	COL_CHPID,
	COL_TYPE,
	COL_CMG,
	COL_SHARED,
	COL_SPEED,
	COL_UTIL_PART,
	COL_UTIL_TOTAL,
	COL_UTIL_BUS,
	COL_DPU_ID,
	COL_READ_PART,
	COL_READ_TOTAL,
	COL_WRITE_PART,
	COL_WRITE_TOTAL,
	/* End of list. */
	COL_END
};

static struct column_t **selected_cols;
static unsigned int num_selected_cols;
static bool hdr_updated;

struct column_t *column_get_by_index(unsigned int i, bool selected)
{
	if (selected)
		return i < num_selected_cols ? selected_cols[i] : NULL;
	return i < ARRAY_SIZE(columns) ? &columns[i] : NULL;
}

/*
 * Retrieve column object by @name or %NULL if column does not exist.
 */
struct column_t *column_get_by_name(const char *name)
{
	struct column_t *col;

	column_for_each(col) {
		if (strcasecmp(col->name, name) == 0)
			return col;
	}

	return NULL;
}

/*
 * Add the specified column to the list of selected columns. Discard duplicate
 * selections of the same column.
 */
void column_select(struct column_t *col)
{
	struct column_t *c;

	/* Silently filter out double selection of columns to prevent problems
	 * with non-unique util_rec name fields. */
	column_for_each_selected(c) {
		if (c == col)
			return;
	}

	util_add_array(&selected_cols, &num_selected_cols, col);
}

void column_select_id_list(const int *ids)
{
	struct column_t *col;
	int i;

	for (i = 0; ids[i] != COL_END; i++) {
		column_for_each(col) {
			if (col->id == ids[i]) {
				column_select(col);
				break;
			}
		}
	}
}

void column_select_default(void)
{
	column_select_id_list(default_columns);
}

void column_select_all(void)
{
	struct column_t *col;

	column_for_each(col)
		column_select(col);
}

void column_update_bps_suffix(bool auto_scale, char suffix_char)
{
	struct column_t *col;
	char *str;

	if (auto_scale)
		util_asprintf(&str, "(B/s)");
	else if (suffix_char)
		util_asprintf(&str, "(%ciB/s)", suffix_char);
	else
		str = util_strdup("(*)");

	column_for_each(col) {
		if (col->unit != COL_BPS) {
			col->hdr1_group = util_strdup(col->hdr1_group);
			continue;
		}
		util_asprintf(&col->hdr1_group, "%s%s", col->hdr1_group, str);
	}
	free(str);

	hdr_updated = true;
}

void column_exit(void)
{
	struct column_t *col;

	if (hdr_updated) {
		column_for_each(col)
			free(col->hdr1_group);
	}
	free(selected_cols);
}
