/*
 * Registry for supported table columns
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef COLUMN_H
#define COLUMN_H

#include <stdbool.h>

enum column_id_t {
	COL_NONE = -1,
	COL_CHPID,
	COL_TYPE,
	COL_CMG,
	COL_SHARED,
	COL_SPEED,
	COL_INTERVAL,
	COL_TIMESTAMP,
	COL_UTIL_PART,
	COL_UTIL_TOTAL,
	COL_UTIL_BUS,
	COL_READ_PART,
	COL_READ_TOTAL,
	COL_WRITE_PART,
	COL_WRITE_TOTAL,
	COL_FICON_RATE,
	COL_FICON_ACTIVE,
	COL_FICON_DEFER,
	COL_HPF_RATE,
	COL_HPF_ACTIVE,
	COL_HPF_DEFER,
	COL_MSG_RATE_PART,
	COL_MSG_RATE_TOTAL,
	COL_MSG_SIZE_PART,
	COL_MSG_SIZE_TOTAL,
	COL_SEND_FAIL_PART,
	COL_RCV_FAIL_PART,
	COL_RCV_FAIL_TOTAL,
	/* Special value indicating no column. */
	COL_END
};

enum col_unit_t {
	COL_OTHER,
	COL_NUMBER,
	COL_PERCENT,
	COL_BPS,
};

struct column_t {
	enum column_id_t id;
	const char *name;
	enum col_unit_t unit;
	const char *desc;
	const char *hdr2;
	const char *hdr1_single;
	char *hdr1_group;
	unsigned int width;
};

#define column_for_each(c) \
	for (unsigned int __i = 0; ((c) = column_get_by_index(__i, false)); \
	     __i++)
#define column_for_each_selected(c) \
	for (unsigned int __i = 0; ((c) = column_get_by_index(__i, true)); \
	     __i++)

struct column_t *column_get_by_index(unsigned int i, bool selected);
struct column_t *column_get_by_name(const char *name);

void column_select(struct column_t *col);
void column_select_id_list(const int *ids);
void column_select_default(void);
void column_select_all(void);

void column_update_bps_suffix(bool auto_scale, char suffix_char);
void column_exit(void);

#endif /* COLUMN_H */
