/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "table.h"

/* Search for a column in @columns which matches the specified @name. Return
 * corresponding struct column on success, NULL otherwise. */
struct column *table_get_column(struct column *columns, const char *name)
{
	struct column *c;
	int i;

	for (i = 0; columns[i].name; i++) {
		c = &columns[i];
		if (strcasecmp(c->name, name) == 0)
			return c;
		if (strchr(c->name, ':') && starts_with_nocase(name, c->name))
			return c;
	}

	return NULL;
}

/**
 * cell - Representation of a single table cell
 * @id: Column ID of the cell
 * @heading: Actual column heading
 * @value: Cell contents
 * @width: Total width of cell
 * @align: Alignment of cell text
 *
 */
struct cell {
	char *value;
	char *heading;
	int id;
	int width;
	align_t align;
};

/* Used for debugging. */
void cells_print(struct cell *cells, int indent)
{
	int i;

	printf("%*scells at %p\n", indent, "", (void *) cells);
	if (!cells)
		return;
	indent += 2;
	for (i = 0; cells[i].heading; i++) {
		printf("%*scells[%d]:\n", indent, "", i);
		printf("%*svalue=%s\n", indent + 2, "", cells[i].value);
		printf("%*sheading=%s\n", indent + 2, "", cells[i].heading);
		printf("%*sid=%d\n", indent + 2, "", cells[i].id);
		printf("%*swidth=%d\n", indent + 2, "", cells[i].width);
		printf("%*salign=%d\n", indent + 2, "", cells[i].align);
	}
}

static void cells_free(struct cell *cells)
{
	int i;
	struct cell *c;

	if (!cells)
		return;
	for (i = 0; cells[i].heading; i++) {
		c = &cells[i];
		free(c->value);
		free(c->heading);
	}
	free(cells);
}

/* Return a newly allocated array of struct cells containing a struct cell for
 * each default column in the specified table. */
static struct cell *cells_get_default(struct column *columns)
{
	int i, num;
	struct cell *cells;

	/* Determine number of default columns. */
	num = 0;
	for (i = 0; columns[i].name; i++) {
		if (!columns[i].def)
			continue;
		num++;
	}

	/* Allocated cells array. */
	cells = misc_malloc((num + 1) * sizeof(struct cell));

	/* Initialize cells for default columns. */
	num = 0;
	for (i = 0; columns[i].name; i++) {
		if (!columns[i].def)
			continue;
		cells[num].heading = misc_strdup(columns[i].name);
		cells[num].id = columns[i].id;
		cells[num].align = columns[i].align;
		num++;
	}

	return cells;
}

bool is_shell_char(const char c)
{
	/* check whether character is alphabetic */
	if (tolower(c) >= 'a' && tolower(c) <= 'z')
		return true;
	if (isdigit(c) || c == '_')
		return true;
	return false;
}

/* replaces bad characters that won't work if using them
 * as part of variable names in a shell environment
 */
char *replace_bad_chars(const char *value)
{
	int i;
	char *copy, c;

	/* remove bad characters and replace them by an underscore */
	copy = misc_strdup(value);
	for (i = 0; (c = value[i]); i++) {
		/*
		 * check whether character is alphabetic,
		 * first character of an env var can't be a digit
		 */
		if (!is_shell_char(c) || (i == 0 && isdigit(c)))
			c = '_';
		/* copy character into string copy */
		copy[i] = c;
	}

	return copy;
}

/* Return a newly allocated array of struct cells containing a struct cell for
 * each column definition whose name was specified in strlist @names. */
static struct cell *cells_get(struct column *columns, struct util_list *names)
{
	unsigned long num;
	struct cell *cells;
	int i;
	const struct column *column;
	struct strlist_node *s;

	num = util_list_len(names);
	cells = misc_malloc((num + 1) * sizeof(struct cell));

	i = 0;
	util_list_iterate(names, s) {
		column = table_get_column(columns, s->str);
		if (!column)
			goto err_unknown;
		cells[i].heading = misc_strdup(s->str);
		cells[i].id = column->id;
		cells[i].align = column->align;
		i++;
	}

	return cells;

err_unknown:
	cells_free(cells);
	error("Unknown column name specified: %s\n", s->str);

	return NULL;
}

/* Determine maximum width for values and headings in table. */
static void cells_get_width(struct cell *cells, struct util_list *items,
			    table_value_cb_t value_cb, void *data)
{
	int i, len;
	struct cell *c;
	struct ptrlist_node *p;
	char *val;

	/* Initialize widths. */
	for (i = 0; cells[i].heading; i++)
		cells[i].width = strlen(cells[i].heading);

	/* Determine largest width from items. */
	util_list_iterate(items, p) {
		for (i = 0; cells[i].heading; i++) {
			c = &cells[i];
			val = value_cb(p->ptr, c->id, c->heading, data);
			if (!val)
				continue;
			len = strlen(val);
			free(val);
			if (c->width < len)
				c->width = len;
		}
	}
}

/* Return the optimal space delimiter for the specified cells. */
static const char *cells_get_space(struct cell *cells, struct util_list *items,
				   table_value_cb_t value_cb, void *data,
				   int indent)
{
	char *val;
	int columns, i, off_one, off_two, last, wrap_one, wrap_two, len;
	struct ptrlist_node *p;
	struct cell *c;

	/* Quick exit on special case to make processing simpler. */
	if (!cells[0].heading)
		return " ";

	/* Determine column offset of last column. */
	off_one = indent;
	off_two = indent;
	for (i = 0; cells[i + 1].heading; i++) {
		off_one += cells[i].width + 1;
		off_two += cells[i].width + 2;
	}
	last = i;

	/* Determine how many rows would wrap with either one or two spaces. */
	columns = get_columns();
	wrap_one = 0;
	wrap_two = 0;
	c = &cells[last];
	util_list_iterate(items, p) {
		val = value_cb(p->ptr, c->id, c->heading, data);
		if (val) {
			len = strlen(val);
			free(val);
		} else
			len = 0;
		if (off_one + len >= columns)
			wrap_one++;
		if (off_two + len >= columns)
			wrap_two++;
	}

	/* Use two spaces if the number of lines that would wrap is the same
	 * for one and two spaces. */
	if (wrap_two <= wrap_one)
		return "  ";

	return " ";
}

/* Get all values for an item. */
static void cells_get_values(struct cell *cells, void *item,
			     table_value_cb_t value_cb, void *data)
{
	int i;
	struct cell *c;

	for (i = 0; cells[i].heading; i++) {
		c = &cells[i];
		free(c->value);
		c->value = value_cb(item, c->id, c->heading, data);
	}

}

/* Print all headings. */
static void print_heading(struct cell *cells, const char *space, int indent)
{
	int i, width;
	struct cell *c;

	if (indent > 0)
		printf("%*s", indent, "");
	for (i = 0; cells[i].heading; i++) {
		c = &cells[i];

		/* Don't print spaces in last cell. */
		if (!cells[i + 1].heading)
			width = 0;
		else if (c->align == align_left)
			width = -c->width;
		else
			width = c->width;

		printf("%s%*s", i > 0 ? space : "", width, c->heading);

	}
	printf("\n");
}

/* Print all cells in a row in list format. */
static void print_row(struct cell *cells, const char *space, int indent,
		      int wrap)
{
	int i, width, columns, offset, slen;
	struct cell *c;

	columns = get_columns();
	slen = strlen(space);
	offset = indent;

	if (indent > 0)
		printf("%*s", indent, "");

	for (i = 0; cells[i].heading; i++) {
		c = &cells[i];

		/* Don't print spaces in last cell. */
		if (!cells[i + 1].heading)
			width = 0;
		else if (c->align == align_left)
			width = -c->width;
		else
			width = c->width;

		if (!wrap)
			goto do_print;

		offset += (i > 0 ? slen : 0);
		if (c->value)
			offset += MAX((size_t) abs(width), strlen(c->value));
		else
			offset += abs(width);

		if (offset >= columns && i > 0) {
			/* Printing this cell would wrap the line - start on
			 * the next line, indented to the second column. */
			offset = indent + cells[0].width;
			printf("\n%*s", offset, "");
			if (c->value) {
				offset += MAX((size_t) abs(width),
					      strlen(c->value));
			} else
				offset += abs(width);
		}

do_print:
		printf("%s%*s", i > 0 ? space : "", width,
		       c->value ? c->value : "");
	}
	printf("\n");
}

/* Print all cells in a row in pairs format. */
static void print_row_pairs(struct cell *cells, int shell)
{
	int i;
	struct cell *c;
	char *val;
	char *heading;

	for (i = 0; cells[i].heading; i++) {
		c = &cells[i];
		val = quote_str(c->value ? c->value : "", 1);
		if (shell)
			heading = replace_bad_chars(c->heading);
		else
			heading = misc_strdup(c->heading);
		printf("%s%s=%s", i > 0 ? " " : "", heading, val);
		free(val);
		free(heading);
	}
	printf("\n");
}

/* Print a table. Either in list form or in pairs form (if @pairs is set).
 * In list form, print a heading if @heading is set. Show data from items
 * in ptrlist @items. Specify column names of columns to be printed in
 * @names. If @wrap is set, wrap overlong lines. , */
exit_code_t table_print(struct column *columns, table_value_cb_t get_value_cb,
			void *data, struct util_list *items,
			struct util_list *names, int heading, int pairs,
			int indent, int wrap, int shell)
{
	struct cell *cells;
	struct ptrlist_node *p;
	const char *space = " ";

	/* Initialize cells array. */
	if (!names || util_list_is_empty(names))
		cells = cells_get_default(columns);
	else {
		cells = cells_get(columns, names);
		if (!cells)
			return EXIT_UNKNOWN_COLUMN;
	}

	if (!pairs) {
		cells_get_width(cells, items, get_value_cb, data);
		if (wrap) {
			space = cells_get_space(cells, items, get_value_cb,
						data, indent);
		} else
			space = "  ";
		if (heading)
			print_heading(cells, space, indent);
	}

	/* Print rows. */
	util_list_iterate(items, p) {
		cells_get_values(cells, p->ptr, get_value_cb, data);
		if (pairs)
			print_row_pairs(cells, shell);
		else
			print_row(cells, space, indent, wrap);
	}

	cells_free(cells);

	return EXIT_OK;
}

exit_code_t table_check_columns(struct column *columns, struct util_list *names)
{
	struct cell *cells;

	if (!names || util_list_is_empty(names))
		return EXIT_OK;

	cells = cells_get(columns, names);
	if (!cells)
		return EXIT_UNKNOWN_COLUMN;

	cells_free(cells);

	return EXIT_OK;
}

enum {
	column_name,
	column_desc,
};

static struct column *columns_table = COLUMN_ARRAY(
	COLUMN("COLUMN",	align_left, column_name, 1, ""),
	COLUMN("DESCRIPTION",	align_left, column_desc, 1, "")
);

static char *columns_table_get_value(void *item, int id, const char *heading,
				     void *data)
{
	struct column *c = item;

	switch (id) {
	case column_name:
		return misc_strdup(c->name);
	case column_desc:
		return misc_strdup(c->desc);
	}

	return NULL;
}

/* Print a table listing available columns and their description. */
void table_print_columns(struct column *columns, struct util_list *names,
			 int heading, int pairs)
{
	int i;
	struct util_list *items;

	items = ptrlist_new();
	for (i = 0; columns[i].name; i++)
		ptrlist_add(items, &columns[i]);
	table_print(columns_table, columns_table_get_value, NULL, items, names,
		    heading, pairs, 0, 0, 0);
	ptrlist_free(items, 0);
}

/* Change the default state of column with @id in table @columns to @def. */
void table_set_default(struct column *columns, int id, int def)
{
	int i;

	for (i = 0; columns[i].name; i++) {
		if (columns[i].id == id) {
			columns[i].def = def;
			break;
		}
	}
}
