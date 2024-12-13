/*
 * Registry for CMG types
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CMG_H
#define CMG_H

#include <stdbool.h>

#include "lib/util_base.h"
#include "lib/util_list.h"
#include "column.h"

#define CMCB_SIZE		(8 * sizeof(u32))
#define PARTIAL_CMCB_OFFSET	(3 * sizeof(u32))
#define PARTIAL_CMCB_SIZE	(CMCB_SIZE - PARTIAL_CMCB_OFFSET)
#define CUE_SIZE		(8 * sizeof(u32))
#define EXT_CUE_SIZE		(16 * sizeof(u32))
#define METRICS_SIZE		(18 * sizeof(double))

/* Bit-width of CUE timestamp field. */
#define CUE_TS_WIDTH	24

typedef union {
	struct {
		u8 cuiv;
		u32 timestamp:24;
	} common __packed;
	u8 data[CUE_SIZE];
} cue_t;
typedef u8 ext_cue_t[EXT_CUE_SIZE];
typedef u8 cmcb_t[CMCB_SIZE];
typedef u8 metrics_t[METRICS_SIZE];

struct util_t {
	cue_t cue;
	ext_cue_t ext_cue;
	bool extended;
};

/* CMG-specific CHPID data. */
struct cmg_data_t {
	cmcb_t cmcb;
	bool full_cmcb;
	struct util_t util_a;
	struct util_t util_b;
	metrics_t metrics;
};

enum cmg_unit_t {
	CMG_NUMBER,
	CMG_PERCENT,
	CMG_BPS,
};

enum cmg_value_type_t {
	CMG_U32,
	CMG_U64,
	CMG_FLOAT,
};

struct cmg_pair_t {
	/* Key. */
	char *key;
	enum column_id_t col;
	/* Value. */
	bool valid;
	enum cmg_unit_t unit;
	enum cmg_value_type_t type;
	union {
		u32 value_u32;
		u64 value_u64;
		double value_double;
	};
};

struct cmg_t {
	int cmg;

	/* Flag indicating whether this CMG was selected on the command line. */
	bool selected;

	/* Counter indicating number of CHPIDs found with this CMG. */
	int found;

	/* Indicator whether this CMG requires a CMCB. */
	const bool has_cmcb;

	/* Array of default column IDs to be displayed for this CMG. */
	const enum column_id_t *default_column_ids;

	/* Return array of key-value pairs. */
	struct cmg_pair_t *(*get_values)(struct cmg_data_t *data, int groups);

	/* Update the metrics found in @data. */
	void (*update_metrics)(struct cmg_data_t *data);

};

/* Iterate over all supported CMG data types. */
#define cmg_for_each(c) \
	for (unsigned int __i = 0; ((c) = _cmg_get_by_index(__i)); __i++)

void cmg_add(struct cmg_t *cmg);
struct cmg_t *cmg_get(int cmg);
struct cmg_t *_cmg_get_by_index(unsigned int i);

void cmg_exit(void);
void cmg_free_keys(char **keys);
void cmg_free_pairs(struct cmg_pair_t *pairs);
char **cmg_get_keys(struct cmg_t *cmg, int groups);

#endif /* CMG_H */
