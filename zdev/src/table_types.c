/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "devtype.h"
#include "misc.h"
#include "subtype.h"
#include "table.h"
#include "table_types.h"

/* Column IDs for the types table. */
enum table_types_id {
	table_types_name,
	table_types_title,
};

/* Definition of output table for --list-types. */
static struct column *table_types = COLUMN_ARRAY(
	COLUMN("TYPE",		align_left, table_types_name, 1, ""),
	COLUMN("DESCRIPTION",	align_left, table_types_title, 1, "")
);

/* Retrieve value of a cell for devtype/subtype name @item in column @id in the
 * types table. */
static char *table_types_get_value(void *item, int id, const char *heading,
				   void *data)
{
	char *name = item;
	struct devtype *dt;
	struct subtype *st;

	switch (id) {
	case table_types_name:
		return misc_strdup(name);
	case table_types_title:
		st = subtype_find(name);
		if (st)
			return misc_strdup(st->title);
		dt = devtype_find(name);
		if (dt)
			return misc_strdup(dt->title);
		break;
	default:
		break;
	}

	return NULL;
}

/* Build list of items in table. Note that we're adding names here instead
 * of the actual object because of the different types (devtype/subtype). */
static struct util_list *table_types_build(void)
{
	struct util_list *items;
	int i, j;
	struct devtype *dt;
	struct subtype *st;

	items = ptrlist_new();
	for (i = 0; devtypes[i]; i++) {
		dt = devtypes[i];
		if (*(dt->title))
			ptrlist_add(items, misc_strdup(dt->name));
		for (j = 0; dt->subtypes[j]; j++) {
			st = dt->subtypes[j];
			ptrlist_add(items, misc_strdup(st->name));
		}
	}

	return items;
}

/* Perform --list-types. */
exit_code_t table_types_show(struct util_list *columns, int headings, int pairs)
{
	struct util_list *items;
	exit_code_t rc;

	items = table_types_build();
	rc = table_print(table_types, table_types_get_value, NULL,
			 items, columns, headings, pairs, 0, 0, 0);
	ptrlist_free(items, 1);

	return rc;
}
