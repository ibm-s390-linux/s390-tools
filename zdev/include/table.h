/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TABLE_H
#define TABLE_H

#include "exit_code.h"

#define COLUMN(a, b, c, d, e) \
	{ \
		.name = (a), \
		.align = (b), \
		.id = (c), \
		.def = (d), \
		.desc = (e), \
	}

#define COLUMN_ARRAY(...) \
	((struct column[]) { __VA_ARGS__, { .name = NULL } })

/* Alignment of table cell text. */
typedef enum {
	align_right,
	align_left,
} align_t;

/**
 * column - Definition of a table column
 * @name: Name of column. A name ending with ':' indicates that it can be
 *        followed by arbitrary text (e.g. ATTR:online)
 * @desc: Description of column
 * @align: Alignment of column values.
 * @id: ID of column. This value is passed to get_value_cb_t
 * @def: If set, include column in default table
 */
struct column {
	const char *name;
	const char *desc;
	align_t align;
	int id;
	unsigned int def:1;
};

struct util_list;

/**
 * table_value_cb_t - Retrieve table cell value
 * @item: Item for which a cell value should be retrieved
 * @id: Column ID of the column to retrieve for the item
 * @heading: The full heading of the column
 * @data: Arbitrary data pointer passed to table_print()
 *
 * This callback function should retrieve the specified table cell value
 * and return it as a newly allocated string to the caller. It may return
 * %NULL if no value of the specified type is defined for the specified item.
 */
typedef char *(*table_value_cb_t)(void *item, int id, const char *heading,
				  void *data);

struct column *table_get_column(struct column *, const char *);
exit_code_t table_print(struct column *, table_value_cb_t, void *,
			struct util_list *, struct util_list *, int, int, int,
			int);
exit_code_t table_check_columns(struct column *, struct util_list *);
void table_print_columns(struct column *, struct util_list *, int, int);
void table_set_default(struct column *, int, int);

#endif /* TABLE_H */
