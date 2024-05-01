/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Table module: Provide line mode and curses base table
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TABLE_H
#define TABLE_H

#include <assert.h>
#include <string.h>

#include "lib/util_list.h"
#include "helper.h"

#define TABLE_STR_MAX		64
#define TABLE_HEADING_SIZE	20

struct table_col;
struct table_entry;

/*
 * Table Column Unit
 */
struct table_col_unit {
	int 			(*fn)(struct table_col*, struct table_entry *);
	const char		*str;
	char 			*desc;
	char			hotkey;
};

/* Predefined units */
extern struct table_col_unit table_col_unit_str;
extern struct table_col_unit table_col_unit_cnt;
extern struct table_col_unit table_col_unit_kib;
extern struct table_col_unit table_col_unit_mib;
extern struct table_col_unit table_col_unit_gib;
extern struct table_col_unit table_col_unit_us;
extern struct table_col_unit table_col_unit_ms;
extern struct table_col_unit table_col_unit_s;
extern struct table_col_unit table_col_unit_hm;
extern struct table_col_unit table_col_unit_dhm;
extern struct table_col_unit table_col_unit_perc;
extern struct table_col_unit table_col_unit_vis;

/* Predefined families */
extern struct table_col_unit *table_col_unit_fam_str[];
extern struct table_col_unit *table_col_unit_fam_cnt[];
extern struct table_col_unit *table_col_unit_fam_mem[];
extern struct table_col_unit *table_col_unit_fam_time[];
extern struct table_col_unit *table_col_unit_fam_time_diff[];
extern struct table_col_unit *table_col_unit_fam_vis[];

/*
 * Table Column Type
 */
enum table_col_type {
	TABLE_COL_TYPE_U64,
	TABLE_COL_TYPE_S64,
	TABLE_COL_TYPE_STR,
};

/*
 * Table Column Alignment
 */
enum table_col_align {
	TABLE_COL_ALIGN_LEFT,
	TABLE_COL_ALIGN_RIGHT,
};

/*
 * Table Column Aggregation
 */
enum table_col_agg {
	TABLE_COL_AGG_SUM,
	TABLE_COL_AGG_MAX,
	TABLE_COL_AGG_NONE,
};

static inline const char *table_col_agg_str(enum table_col_agg agg)
{
	switch (agg) {
	case TABLE_COL_AGG_SUM:
		return "sum";
	case TABLE_COL_AGG_MAX:
		return "max";
	case TABLE_COL_AGG_NONE:
		return "none";
	}
	return NULL;
}

/*
 * Table Column
 */
struct table_col_priv {
	unsigned int	max_width;
	int		col_nr;
	int		enabled;
	char		head_first[TABLE_HEADING_SIZE];
	char		head_char[2];
	char		head_last[TABLE_HEADING_SIZE];
	int		rsort;
	int		needs_quotes;
};

/*
 * Table Column Specification
 */
struct table_col_spec {
	char	hotkey;
	char	*unit_str;
};

/*
 * Table Column
 */
struct table_col {
	enum table_col_type	type;
	struct table_col_unit	*unit;
	struct table_col_unit	**unit_fam;
	enum table_col_align	align;
	enum table_col_agg	agg;
	char			hotkey;
	char			head[TABLE_HEADING_SIZE];
	struct table_col_priv	*p;
};

static inline int table_col_enabled(struct table_col *col)
{
	return col->p->enabled;
}

static inline int table_col_needs_quotes(struct table_col *col)
{
	return col->p->needs_quotes;
}

/*
 * Table Column Constructor Macros
 */
#define TABLE_COL_STR(l, h) \
{	\
	.type		= TABLE_COL_TYPE_STR, \
	.unit		= &table_col_unit_str, \
	.unit_fam	= table_col_unit_fam_str, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_NONE, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_STR_LEFT(l, h) \
{	\
	.type		= TABLE_COL_TYPE_STR, \
	.unit		= &table_col_unit_str, \
	.unit_fam	= table_col_unit_fam_str, \
	.align		= TABLE_COL_ALIGN_LEFT, \
	.agg		= TABLE_COL_AGG_NONE, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_CNT_SUM(l, h) \
{	\
	.type		= TABLE_COL_TYPE_U64, \
	.unit		= &table_col_unit_cnt, \
	.unit_fam	= table_col_unit_fam_cnt, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_SUM, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_CNT_NONE(l, h) \
{	\
	.type		= TABLE_COL_TYPE_U64, \
	.unit		= &table_col_unit_cnt, \
	.unit_fam	= table_col_unit_fam_cnt, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_NONE, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_CNT_MAX(l, h) \
{	\
	.type		= TABLE_COL_TYPE_U64, \
	.unit		= &table_col_unit_cnt, \
	.unit_fam	= table_col_unit_fam_cnt, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_MAX, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_MEM_SUM(f, l, h) \
{	\
	.type		= TABLE_COL_TYPE_U64, \
	.unit		= &f, \
	.unit_fam	= table_col_unit_fam_mem, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_SUM, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_TIME_SUM(f, l, h) \
{	\
	.type		= TABLE_COL_TYPE_U64, \
	.unit		= &f, \
	.unit_fam	= table_col_unit_fam_time, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_SUM, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_TIME_DIFF_SUM(f, l, h) \
{	\
	.type		= TABLE_COL_TYPE_U64, \
	.unit		= &f, \
	.unit_fam	= table_col_unit_fam_time_diff, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_SUM, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_STIME_SUM(f, l, h) \
{	\
	.type		= TABLE_COL_TYPE_S64, \
	.unit		= &f, \
	.unit_fam	= table_col_unit_fam_time, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_SUM, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_STIME_DIFF_SUM(f, l, h) \
{	\
	.type		= TABLE_COL_TYPE_S64, \
	.unit		= &f, \
	.unit_fam	= table_col_unit_fam_time_diff, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_SUM, \
	.hotkey		= l, \
	.head		= h, \
}

#define TABLE_COL_TIME_MAX(f, l, h) \
{	\
	.type		= TABLE_COL_TYPE_U64, \
	.unit		= &f, \
	.unit_fam	= table_col_unit_fam_time, \
	.align		= TABLE_COL_ALIGN_RIGHT, \
	.agg		= TABLE_COL_AGG_MAX, \
	.hotkey		= l, \
	.head		= h, \
}

/*
 * Set reverse sort property for column
 */
static inline void table_col_rsort(struct table_col *col)
{
	col->p->rsort = 1;
}

/*
 * Column member access macros
 */
#define table_col_hotkey(col) ((col)->hotkey)
#define table_col_head(col) ((col)->head)
#define table_col_unit_str(col) ((col)->unit->str)

/*
 * Table Entry
 */
struct table_entry {
	union {
		struct {
			u64	v1;
			u64	v2;
		} u64;
		struct {
			s64	v1;
			s64	v2;
		} s64;
	} d;
	int			set;
	char			str[TABLE_STR_MAX];
};

/*
 * Table Row
 */
struct table_row {
	struct util_list_node	list;
	struct table_entry	*entries;
	int			marked;
};

/*
 * Table Mark Key
 */
struct table_mark_key {
	struct util_list_node	list;
	char			str[TABLE_STR_MAX];
};

/*
 * Table
 */
struct table {
	struct util_list	row_list;
	int 			col_cnt;
	struct table_col	**col_vec;
	struct table_col	*col_selected;
	struct table_row	*row_last;
	int			row_cnt;
	int			row_cnt_marked;
	int			row_cnt_extra;
	int 			row_nr_begin;
	int 			row_nr_select;
	int			ready;
	struct util_list	mark_key_list;
	int			attr_sorted_table;
	int			attr_first_bold;
	int			attr_with_units;
	int			mode_sort_inverse;
	int			mode_select;
	int			mode_hide_unmarked;
};

/*
 * Return if we are in select mode
 */
static inline int table_mode_select(struct table *t)
{
	return t->mode_select;
}

/*
 * Table croll units
 */
enum table_scroll_unit {
	TABLE_SCROLL_LINE,
	TABLE_SCROLL_PAGE,
	TABLE_SCROLL_LAST,
};

/*
 * Prototypes
 */
extern struct table *table_new(int extra_rows, int sorted, int first_bold,
			       int with_units);
extern void table_reset(struct table *t);
extern void table_rebuild(struct table *t);
extern void table_finish(struct table *t);
extern void table_print(struct table *t);
extern void table_process_input(struct table *t, int c);

extern void table_col_unit_next(struct table *t, char hotkey);
extern void table_col_unit_prev(struct table *t, char hotkey);
extern int table_col_unit_set(struct table *t, char hotkey, const char *unit);
extern void table_col_add(struct table *t, struct table_col *col);
extern int table_col_select(struct table *t, char hotkey);
extern void table_col_select_next(struct table *t);
extern void table_col_select_prev(struct table *t);
extern void table_col_enable_toggle(struct table *t, char hotkey);

extern void table_row_del_all(struct table *t);
extern void table_row_add(struct table *t, struct table_row *row);
extern void table_row_mark(struct table *t, struct table_row *row);
extern void table_row_mark_del_all(struct table *t);
extern void table_row_mark_toggle(struct table *t, struct table_row *row);
extern void table_row_mark_toggle_by_key(struct table *t, const char *mark_key);
extern void table_row_select_down(struct table *t, enum table_scroll_unit unit);
extern void table_row_select_up(struct table *t, enum table_scroll_unit unit);
extern void table_row_select_key_get(struct table *t, char str[TABLE_STR_MAX]);
extern struct table_row *table_row_alloc(struct table *t);

extern void table_scroll_down(struct table *t, enum table_scroll_unit unit);
extern void table_scroll_up(struct table *t, enum table_scroll_unit unit);

/*
 * Entry add functions
 */
static inline void table_row_entry_u64_add(struct table_row *table_row,
					   struct table_col *table_col,
					   u64 value)
{
	table_row->entries[table_col->p->col_nr].d.u64.v1 = value;
	table_row->entries[table_col->p->col_nr].set = 1;
}

static inline void table_row_entry_s64_add(struct table_row *table_row,
					   struct table_col *table_col,
					   s64 value)
{
	table_row->entries[table_col->p->col_nr].d.s64.v1 = value;
	table_row->entries[table_col->p->col_nr].set = 1;
}

static inline void table_row_entry_u64_add_pair(struct table_row *table_row,
						struct table_col *table_col,
						u64 value1, u64 value2)
{
	table_row->entries[table_col->p->col_nr].d.u64.v1 = value1;
	table_row->entries[table_col->p->col_nr].d.u64.v2 = value2;
	table_row->entries[table_col->p->col_nr].set = 1;
}

static inline void table_row_entry_str_add(struct table_row *table_row,
					   struct table_col *table_col,
					   const char *str)
{
	assert(strlen(str) < TABLE_STR_MAX);
	strcpy(table_row->entries[table_col->p->col_nr].str, str);
	table_row->entries[table_col->p->col_nr].set = 1;
}

/*
 * Interate over all mark keys
 */
#define table_iterate_mark_keys(t, key) \
	util_list_iterate(&t->mark_key_list, key)

#endif /* TABLE_H */
