/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "attrib.h"
#include "ccw.h"
#include "devtype.h"
#include "misc.h"
#include "subtype.h"
#include "table.h"
#include "table_attribs.h"

/* Column IDs for the types table. */
enum table_attribs_id {
	table_attribs_name,
	table_attribs_desc,
};

/* Definition of output table for --list-types. */
static struct column *table_attribs = COLUMN_ARRAY(
	COLUMN("NAME",		align_left, table_attribs_name, 1, ""),
	COLUMN("DESCRIPTION",	align_left, table_attribs_desc, 1, "")
);

/* Return a newly allocated struct table_attrib. */
struct table_attrib *table_attrib_new(struct subtype *st, struct attrib *a)
{
	struct table_attrib *t;

	t = misc_malloc(sizeof(struct table_attrib));
	t->st = st;
	t->attrib = a;

	return t;
}

/* Retrieve value of a cell for devtype/subtype name @item in column @id in the
 * types table. */
static char *table_attribs_get_value(void *item, int id, const char *heading,
				     void *data)
{
	struct table_attrib *t = item;
	struct attrib *a = t->attrib;

	switch (id) {
	case table_attribs_name:
		return misc_strdup(a->name);
	case table_attribs_desc:
		return misc_strdup(a->title);
	}

	return NULL;
}

static struct util_list *get_subtypes(struct util_list *attribs)
{
	struct ptrlist_node *p, *q;
	struct table_attrib *t;
	struct util_list *list;

	list = ptrlist_new();

	util_list_iterate(attribs, p) {
		t = p->ptr;
		util_list_iterate(list, q) {
			if (t->st == q->ptr)
				break;
		}
		if (!q)
			ptrlist_add(list, t->st);
	}

	return list;
}

struct util_list *get_subtype_attribs(struct util_list *all, struct subtype *st)
{
	struct util_list *subattribs;
	struct ptrlist_node *p;
	struct table_attrib *t;

	subattribs = ptrlist_new();
	util_list_iterate(all, p) {
		t = p->ptr;
		if (t->st == st)
			ptrlist_add(subattribs, t);
	}

	return subattribs;
}

void print_type(struct devtype *dt, struct subtype *st, bool multiple)
{
	int i;

	if (!multiple)
		return;

	if (st)
		printf("TYPE %s\n", st->name);
	else {
		printf("TYPE ");
		for (i = 0; dt->subtypes[i]; i++) {
			printf("%s%s", i == 0 ? "" : ", ",
			       dt->subtypes[i]->name);
		}
		printf("\n");
	}
}

/* Display table of attributes. */
void table_attribs_show(struct util_list *attribs, int headings, int pairs,
			struct devtype *dt)
{
	struct util_list *subtypes, *subattribs;
	struct ptrlist_node *p;
	struct subtype *st;
	bool multiple, first;
	int indent;

	subtypes = get_subtypes(attribs);
	if (util_list_len(subtypes) > 1) {
		multiple = true;
		indent = 2;
	} else {
		multiple = false;
		indent = 0;
	}

	first = true;
	util_list_iterate(subtypes, p) {
		st = p->ptr;
		subattribs = get_subtype_attribs(attribs, st);

		if (first)
			first = false;
		else
			printf("\n");

		print_type(dt, st, multiple);

		table_print(table_attribs, table_attribs_get_value, st,
			    subattribs, NULL, headings, pairs, indent, 0);

		ptrlist_free(subattribs, 0);
	}

	ptrlist_free(subtypes, 0);
}

static void table_attribs_show_details_one(struct table_attrib *t,
					   struct devtype *dt, bool multiple)
{
	struct subtype *st = t->st;
	struct attrib *a = t->attrib;
	const int i = 2, j = 4;
	int k;

	printf("ATTRIBUTE %s\n\n", a->name);

	if (multiple) {
		indent(i, "APPLICABLE TYPES\n");
		printf("%*s", j, "");
		if (st)
			printf("%s", st->name);
		else {
			for (k = 0; dt->subtypes[k]; k++) {
				printf("%s%s", k == 0 ? "" : ", ",
				       dt->subtypes[k]->name);
			}
		}
		printf("\n\n");
	}

	indent(i, "DESCRIPTION\n");
	indent(j, "%s", a->desc);

	if (a->defval) {
		printf("\n");
		indent(i, "DEFAULT VALUE\n");
		indent(j, "The default value is '%s'.\n", a->defval);
	}

	if (!a->readonly) {
		printf("\n");
		indent(i, "ACCEPTED VALUES\n");
		attrib_print_acceptable(a, j);
	}

	if (!(a->multi || a->activeonly || a->unstable || a->writeonly ||
	      a->rewrite || a->mandatory || a->newline || a->activerem ||
	      a->nounload || a->check || a->readonly))
		return;

	printf("\n");
	indent(i, "NOTES\n");
	if (a->multi) {
		indent(j, "- This attribute maintains a list of values "
		       "written to it\n");
	}
	if (a->activeonly) {
		indent(j, "- Only specify this attribute in the active "
		       "configuration\n");
	}
	if (a->unstable) {
		indent(j, "- The value read from this attribute is different "
		       "from the last value\n  written to it\n");
	}
	if (a->writeonly)
		indent(j, "- You cannot read this attribute\n");
	if (a->readonly)
		indent(j, "- You cannot write to this attribute\n");
	if (a->rewrite) {
		indent(j, "- Setting the same value multiple times may have "
		       "additional effects\n");
	}
	if (a->mandatory)
		indent(j, "- Settings for this attribute cannot be removed\n");
	if (a->newline) {
		indent(j, "- A value written to this attribute must be "
		       "followed by a newline character\n");
	}
	if (a->activerem) {
		indent(j, "- Settings for this attribute can be removed in "
			  "the active configuration\n");
	}
	if (a->check == ccw_offline_only_check) {
		indent(j, "- This attribute cannot be changed while the device "
		       "is online\n");
	}
	if (a->check == ccw_online_only_check) {
		indent(j, "- This attribute cannot be changed while the device "
		       "is offline\n");
	}
	if (a->nounload) {
		indent(j, "- Settings for this attribute can be changed "
			  "without reloading the\n  associated kernel "
			  "module\n");
	}
}

static bool check_multiple_types(struct util_list *list)
{
	struct ptrlist_node *p;
	struct table_attrib *t;
	struct subtype *st = NULL;
	bool first;

	first = true;
	util_list_iterate(list, p) {
		t = p->ptr;
		if (first) {
			first = false;
			st = t->st;
		} else if (t->st != st)
			return true;
	}

	return false;
}

/* Display detailed attribute information*/
void table_attribs_show_details(struct util_list *attribs, struct devtype *dt)
{
	struct ptrlist_node *p;
	bool first, multiple;

	first = true;
	multiple = check_multiple_types(attribs);
	util_list_iterate(attribs, p) {
		if (first)
			first = false;
		else
			printf("\n");

		table_attribs_show_details_one(p->ptr, dt, multiple);
	}
}
