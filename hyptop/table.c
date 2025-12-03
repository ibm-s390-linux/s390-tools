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

#include <ctype.h>
#include <errno.h>
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_fmt.h"
#include "lib/util_libc.h"

#include "helper.h"
#include "hyptop.h"
#include "table.h"

#define L_ROWS_EXTRA			2 /* head + last */

#define table_col_iterate(t, col, i) \
	for (i = 0, col = t->col_vec[0]; col != NULL;  col = t->col_vec[++i])

/*
 * Is row marked?
 */
static int l_row_is_marked(struct table *t, struct table_row *row)
{
	struct table_mark_key *key;

	util_list_iterate(&t->mark_key_list, key) {
		if (strcmp(row->entries[0].str, key->str) == 0)
			return 1;
	}
	return 0;
}

/*
 * Add mark key to table
 */
static void l_mark_key_add(struct table *t, char *str)
{
	struct table_mark_key *key;

	key = ht_zalloc(sizeof(*key));
	util_strlcpy(key->str, str, sizeof(key->str));
	util_list_add_tail(&t->mark_key_list, key);
}

/*
 * Remove mark key from table
 */
static void l_mark_key_remove(struct table *t, char *str)
{
	struct table_mark_key *key, *tmp;

	util_list_iterate_safe(&t->mark_key_list, key, tmp) {
		if (strcmp(str, key->str) == 0) {
			util_list_remove(&t->mark_key_list, key);
			ht_free(key);
			return;
		}
	}
}

/*
 * Delete all mark keys from table
 */
void table_row_mark_del_all(struct table *t)
{
	struct table_mark_key *key, *tmp;
	struct table_row *row;

	util_list_iterate(&t->row_list, row)
		row->marked = 0;
	util_list_iterate_safe(&t->mark_key_list, key, tmp) {
		util_list_remove(&t->mark_key_list, key);
		ht_free(key);
	}
}

/*
 * Toggle mark for "row"
 */
void table_row_mark_toggle(struct table *t, struct table_row *row)
{
	if (row->marked) {
		l_mark_key_remove(t, row->entries[0].str);
		row->marked = 0;
		t->row_cnt_marked--;
		if (t->row_cnt_marked == 0)
			t->mode_hide_unmarked = 0;
	} else {
		l_mark_key_add(t, row->entries[0].str);
		row->marked = 1;
		t->row_cnt_marked++;
	}
}

/*
 * Toggle mark by key
 */
void table_row_mark_toggle_by_key(struct table *t, const char *str)
{
	struct table_row *row;

	util_list_iterate(&t->row_list, row) {
		if (strcmp(str, row->entries[0].str) == 0)
			table_row_mark_toggle(t, row);
	}
}

/*
 * Is column selected?
 */
static int l_col_selected(struct table *t, struct table_col *col)
{
	return t->col_selected == col;
}

/*
 * Get number of rows for table
 */
static int l_row_cnt(struct table *t)
{
	return t->mode_hide_unmarked ? t->row_cnt_marked : t->row_cnt;
}

/*
 * Get number of data rows that we can display on screen
 */
static int l_row_cnt_displ(struct table *t)
{
	return g.c.row_cnt - t->row_cnt_extra;
}

/*
 * Alloc a new row for table
 */
struct table_row *table_row_alloc(struct table *t)
{
	struct table_row *table_row;

	table_row = ht_zalloc(sizeof(*table_row));
	table_row->entries = ht_zalloc(sizeof(*table_row->entries) *
					  t->col_cnt);
	return table_row;
}

/*
 * Free table row
 */
static void table_row_free(struct table_row *table_row)
{
	ht_free(table_row->entries);
	ht_free(table_row);
}

/*
 * Allocate and initialize a new table
 */
struct table *table_new(int extra_rows, int sorted, int first_bold,
			int with_units)
{
	struct table *t = ht_zalloc(sizeof(*t));

	util_list_init(&t->row_list, struct table_row, list);
	util_list_init(&t->mark_key_list, struct table_mark_key, list);
	t->row_cnt_marked = 0;
	if (with_units)
		t->row_cnt_extra = extra_rows + L_ROWS_EXTRA + 1;
	else
		t->row_cnt_extra = extra_rows + L_ROWS_EXTRA;
	t->attr_with_units = with_units;
	t->attr_sorted_table = sorted;
	t->attr_first_bold = first_bold;

	return t;
}

/*
 * Initialize headline for one column
 */
static void l_col_headline_init(struct table *t, struct table_col *col)
{
	char *ptr;

	strcpy(col->p->head_first, col->head);
	ptr = strchr(col->p->head_first, tolower(col->hotkey));
	assert(ptr != NULL);
	*ptr = 0;
	col->p->head_char[0] = col->hotkey;
	strcpy(col->p->head_last, ++ptr);
	if (!t->attr_sorted_table) {
		util_str_toupper(col->p->head_first);
		util_str_toupper(col->p->head_last);
		col->p->head_char[0] = toupper(col->p->head_char[0]);
	}
}

/*
 * Initialize the max width values for a column
 */
static void l_col_max_width_init(struct table *t, struct table_col *col)
{
	/* Units are displayed with brackets, therefore (+2) */
	if (t->attr_with_units)
		col->p->max_width = MAX(strlen(col->head),
					strlen(col->unit->str) + 2);
	else
		col->p->max_width = strlen(col->head);
}

/*
 * Add a new column to table
 */
void table_col_add(struct table *t, struct table_col *col)
{
	col->p = ht_zalloc(sizeof(*col->p));
	col->p->col_nr = t->col_cnt;
	col->p->enabled = 1;
	t->col_cnt++;
	t->col_vec = ht_realloc(t->col_vec, sizeof(void *) *
				   (t->col_cnt + 1));
	t->col_vec[t->col_cnt - 1] = col;
	t->col_vec[t->col_cnt] = NULL;
	if (!t->col_selected && t->attr_sorted_table)
		t->col_selected = col;
	if (t->row_last)
		table_row_free(t->row_last);
	t->row_last = table_row_alloc(t);
	l_col_headline_init(t, col);
	l_col_max_width_init(t, col);
}

/*
 * Initialize last row
 */
static void l_row_last_init(struct table *t)
{
	memset(t->row_last->entries, 0,
	       t->col_cnt * sizeof(struct table_entry));
}

/*
 * Delete all rows of a table
 */
void table_row_del_all(struct table *t)
{
	struct table_row *row, *tmp;

	util_list_iterate_safe(&t->row_list, row, tmp) {
		util_list_remove(&t->row_list, row);
		table_row_free(row);
	}
	if (t->row_physical) {
		table_row_free(t->row_physical);
		t->row_physical = NULL;
	}
	l_row_last_init(t);
	t->row_cnt_marked = 0;
	t->ready = 0;
	t->row_cnt = 0;
}

/*
 * Reset table
 */
void table_reset(struct table *t)
{
	table_row_mark_del_all(t);
	table_row_del_all(t);
	t->mode_sort_inverse = 0;
	t->mode_select = 0;
}

/*
 * Return true, if "e1" is less than "e2"
 */
static int l_entry_less_than(enum table_col_type type, struct table_entry *e1,
			     struct table_entry *e2)
{
	switch (type) {
	case TABLE_COL_TYPE_U64:
		return (e1->d.u64.v1 < e2->d.u64.v1);
	case TABLE_COL_TYPE_S64:
		return (e1->d.s64.v1 < e2->d.s64.v1);
	case TABLE_COL_TYPE_STR:
		return (strcmp(e1->str, e2->str) > 0);
	}
	return 0; /* Keep gcc quite */
}

/*
 * Return true, if "row1" is less than "row2"
 */
static int l_row_less_than(struct table *t, struct table_row *row1,
			   struct table_row *row2)
{
	struct table_col *col = t->col_selected;
	struct table_entry *e1 = &row1->entries[col->p->col_nr];
	struct table_entry *e2 = &row2->entries[col->p->col_nr];

	if ((t->mode_sort_inverse && !col->p->rsort) ||
	    (!t->mode_sort_inverse && col->p->rsort))
		return !l_entry_less_than(col->type, e1, e2);
	else
		return l_entry_less_than(col->type, e1, e2);
}

/*
 * Calculate: e1 = e1 + e2
 */
static void l_entry_sum(enum table_col_type type, struct table_entry *e1,
			struct table_entry *e2)
{
	switch (type) {
	case TABLE_COL_TYPE_U64:
		e1->d.u64.v1 += e2->d.u64.v1;
		return;
	case TABLE_COL_TYPE_S64:
		e1->d.s64.v1 += e2->d.s64.v1;
		return;
	default:
		assert(0);
		return;
	}
}

/*
 * Calculate: e1 = MAX(e1, e2)
 */
static void l_entry_max(enum table_col_type type, struct table_entry *e1,
			struct table_entry *e2)
{
	switch (type) {
	case TABLE_COL_TYPE_U64:
		e1->d.u64.v1 = MAX(e1->d.u64.v1, e2->d.u64.v1);
		return;
	case TABLE_COL_TYPE_S64:
		e1->d.s64.v1 = MAX(e1->d.s64.v1, e2->d.s64.v1);
		return;
	default:
		assert(0);
		return;
	}
}

/*
 * Aggregate "row" to "last row"
 */
static void l_row_last_agg(struct table *t, struct table_row *table_row)
{
	struct table_col *col;
	int col_nr;

	table_col_iterate(t, col, col_nr) {
		struct table_entry *e_last = &t->row_last->entries[col_nr];
		struct table_entry *e_new = &table_row->entries[col_nr];

		if (!e_new->set)
			continue;
		switch (col->agg) {
		case TABLE_COL_AGG_SUM:
			l_entry_sum(col->type, e_last, e_new);
			break;
		case TABLE_COL_AGG_MAX:
			l_entry_max(col->type, e_last, e_new);
			break;
		case TABLE_COL_AGG_NONE:
			break;
		}
		e_last->set = 1;
	}
}

/*
 * Format row: Invoke unit callback and adjust max width of column
 */
static void l_row_format(struct table *t, struct table_row *row)
{
	unsigned int len, col_nr;
	struct table_col *col;

	table_col_iterate(t, col, col_nr) {
		struct table_entry *e = &row->entries[col_nr];
		if (col->agg == TABLE_COL_AGG_NONE && row == t->row_last)
			len = 0;
		else
			len = col->unit->fn(col, e);
		assert(len < TABLE_STR_MAX);
		if (len > col->p->max_width)
			col->p->max_width = len;
	}
}

/*
 * Calculate last row
 */
static void l_row_last_calc(struct table *t)
{
	struct table_row *row;

	l_row_last_init(t);
	util_list_iterate(&t->row_list, row) {
		if (t->mode_hide_unmarked && !row->marked)
			continue;
		l_row_last_agg(t, row);
	}
	l_row_format(t, t->row_last);
}

/*
 * Finish table after all rows have been added
 */
void table_finish(struct table *t)
{
	if (t->row_physical)
		l_row_format(t, t->row_physical);
	l_row_last_calc(t);
	t->ready = 1;
}

/*
 * Add new row to table
 */
void table_row_add(struct table *t, struct table_row *row)
{
	struct table_row *tmp;

	l_row_format(t, row);

	if (util_list_is_empty(&t->row_list) || !t->attr_sorted_table) {
		util_list_add_tail(&t->row_list, row);
	} else {
		util_list_iterate(&t->row_list, tmp) {
			if (l_row_less_than(t, tmp, row))
				break;
		}
		if (tmp)
			util_list_add_prev(&t->row_list, row, tmp);
		else
			util_list_add_tail(&t->row_list, row);
	}
	if (l_row_is_marked(t, row)) {
		row->marked = 1;
		t->row_cnt_marked++;
	}
	t->row_cnt++;
}

/*
 * Rebuild table: Reformat all rows and adjust max width values
 */
void table_rebuild(struct table *t)
{
	struct table_col *col;
	struct table_row *row;
	unsigned int i;

	table_col_iterate(t, col, i)
		l_col_max_width_init(t, col);
	util_list_iterate(&t->row_list, row)
		l_row_format(t, row);
	if (t->row_physical)
		l_row_format(t, t->row_physical);
	l_row_format(t, t->row_last);
}

/*
 * Compare callback for linked list sorting (ordering: large to small)
 */
static int l_row_cmp_fn(void *a, void *b, void *data)
{
	return l_row_less_than(data, a, b) ? 1 : -1;
}

/*
 * Sort table (ordering: large to small)
 */
static void l_table_sort(struct table *t)
{
	util_list_sort(&t->row_list, l_row_cmp_fn, t);
}

/*
 * Adjust table values for select mode (e.g. for window resize or scrolling)
 */
static void l_adjust_values_select_mode(struct table *t)
{
	int row_cnt_displ = l_row_cnt_displ(t);
	int row_cnt = l_row_cnt(t);

	/* We went out of range with row selection */
	if (t->row_nr_select >= row_cnt)
		t->row_nr_select = row_cnt - 1;

	/* Is selected row within visible area? */
	if (t->row_nr_select < t->row_nr_begin) {
		/* Selected row is above area: Scroll up */
		t->row_nr_begin = t->row_nr_select;
	} else if (t->row_nr_select - t->row_nr_begin >= row_cnt_displ) {
		/* Selected row is below area: Scroll down */
		t->row_nr_begin = MAX(t->row_nr_select - row_cnt_displ + 1, 0);
	}
}

/*
 * Adjust table values (e.g. for window resize or scrolling)
 */
static void l_adjust_values(struct table *t)
{
	int row_cnt_displ = l_row_cnt_displ(t);
	int row_cnt = l_row_cnt(t);

	if (t->mode_select)
		l_adjust_values_select_mode(t);
	/* If we do not use the whole screen, scroll up */
	if (row_cnt - t->row_nr_begin < row_cnt_displ)
		t->row_nr_begin = MAX(row_cnt - row_cnt_displ, 0);
}

/*
 * Number of rows to be scrolled for page scroll
 */
static int l_scroll_page_row_cnt(struct table *t)
{
	/* We have two rows overlap for scrolling pages */
	return l_row_cnt_displ(t) - 2;
}

/*
 * Scroll table down
 */
void table_scroll_down(struct table *t, enum table_scroll_unit scroll_unit)
{
	switch (scroll_unit) {
	case TABLE_SCROLL_LINE:
		t->row_nr_begin++;
		break;
	case TABLE_SCROLL_PAGE:
		t->row_nr_begin += l_scroll_page_row_cnt(t);
		break;
	case TABLE_SCROLL_LAST:
		t->row_nr_begin = t->row_cnt;
		break;
	}
}

/*
 * Scroll table up
 */
void table_scroll_up(struct table *t, enum table_scroll_unit scroll_unit)
{
	switch (scroll_unit) {
	case TABLE_SCROLL_LINE:
		t->row_nr_begin = MAX(t->row_nr_begin - 1, 0);
		break;
	case TABLE_SCROLL_PAGE:
		t->row_nr_begin =
			MAX(t->row_nr_begin - l_scroll_page_row_cnt(t), 0);
		break;
	case TABLE_SCROLL_LAST:
		t->row_nr_begin = 0;
		break;
	}
}

/*
 * Return selected row
 */
static struct table_row *l_selected_row(struct table *t)
{
	struct table_row *row;
	int row_nr = 0;

	util_list_iterate(&t->row_list, row) {
		if (t->mode_hide_unmarked && !row->marked)
			continue;
		if (row_nr == t->row_nr_select)
			return row;
		row_nr++;
	}
	return NULL;
}

/*
 * Toggle mark for selected row
 */
static void l_row_select_mark_toggle(struct table *t)
{
	struct table_row *row;

	row = l_selected_row(t);
	table_row_mark_toggle(t, row);
	l_row_last_calc(t);
}

/*
 * Switch select mode off
 */
static void l_select_mode_off(struct table *t)
{
	t->mode_select = 0;
}

/*
 * Switch select mode on
 */
static void l_select_mode_on(struct table *t)
{
	t->mode_select = 1;
	t->row_nr_select = t->row_nr_begin;
}

/*
 * Get key for selected row
 */
void table_row_select_key_get(struct table *t, char str[TABLE_STR_MAX])
{
	struct table_row *row;

	row = l_selected_row(t);
	util_strlcpy(str, row->entries[0].str, TABLE_STR_MAX);
}

/*
 * Select row one page down
 */
void table_row_select_down(struct table *t, enum table_scroll_unit scroll_unit)
{
	switch (scroll_unit) {
	case TABLE_SCROLL_LINE:
		t->row_nr_select++;
		break;
	case TABLE_SCROLL_PAGE:
		t->row_nr_select += g.c.row_cnt - t->row_cnt_extra;
		break;
	case TABLE_SCROLL_LAST:
		t->row_nr_select = t->row_cnt;
		break;
	}
}

/*
 * Select row one page up
 */
void table_row_select_up(struct table *t, enum table_scroll_unit scroll_unit)
{
	switch (scroll_unit) {
	case TABLE_SCROLL_LINE:
		t->row_nr_select = MAX(t->row_nr_select - 1, 0);
		break;
	case TABLE_SCROLL_PAGE:
		t->row_nr_select = MAX(t->row_nr_begin -
				       (g.c.row_cnt - t->row_cnt_extra), 0);
		break;
	case TABLE_SCROLL_LAST:
		t->row_nr_select = 0;
		break;
	}
}

/*
 * Toggle "hide unmarked" mode
 */
static int l_mode_hide_unmarked_toggle(struct table *t)
{
	if (t->row_cnt_marked == 0)
		return -ENODEV;
	t->mode_hide_unmarked = t->mode_hide_unmarked ? 0 : 1;
	t->row_nr_select = 0;
	l_row_last_calc(t);
	return 0;
}

/*
 * Is it possible to scroll down the table?
 */
static int l_can_scroll_down(struct table *t)
{
	int row_cnt = t->mode_hide_unmarked ? t->row_cnt_marked : t->row_cnt;
	int row_cnt_real = g.c.row_cnt - t->row_cnt_extra;

	return (row_cnt - t->row_nr_begin > row_cnt_real);
}

/*
 * Is it possible to scroll up the table?
 */
static int l_can_scroll_up(struct table *t)
{
	return (t->row_nr_begin > 0);
}

/*
 * Update the status field
 */
static void l_status_update(struct table *t)
{
	struct table_entry *e_status = &t->row_last->entries[0];

	if (g.o.batch_mode_specified)
		return;

	if (l_can_scroll_down(t) && l_can_scroll_up(t))
		strcpy(e_status->str, "|");
	else if (l_can_scroll_up(t))
		strcpy(e_status->str, "^");
	else if (l_can_scroll_down(t))
		strcpy(e_status->str, "V");
	else
		strcpy(e_status->str, "=");

	if (t->attr_sorted_table) {
		strcat(e_status->str, ":");
		if (t->mode_sort_inverse)
			strcat(e_status->str, "^");
		else
			strcat(e_status->str, "V");
	}
	strcat(e_status->str, ":");
	if (t->mode_select)
		strcat(e_status->str, "S");
	else
		strcat(e_status->str, "N");
}

/*
 * Print string with alignment
 */
static void l_str_print(struct table_col *col, const char *str)
{
	char unit[10];

	if (col->align == TABLE_COL_ALIGN_LEFT)
		sprintf(unit, "%%-%ds", col->p->max_width);
	else
		sprintf(unit, "%%%ds", col->p->max_width);
	hyptop_printf(unit, str);
}

/*
 * Print string for "col"
 */
static void l_col_print(struct table *t, struct table_col *col, const char *str)
{
	if (l_col_selected(t, col))
		ht_underline_on();
	if (col->p->col_nr == 0 && t->attr_first_bold)
		ht_bold_on();

	l_str_print(col, str);

	if (l_col_selected(t, col))
		ht_underline_off();
	if (col->p->col_nr == 0 && t->attr_first_bold)
		ht_bold_off();
}

/*
 * Print status field
 */
static void l_status_print(struct table *t, const char *str)
{
	ht_bold_on();
	l_str_print(t->col_vec[0], str);
	ht_bold_off();
}

/*
 * Print headline of column
 */
static void l_col_headline_print(struct table *t, struct table_col *col)
{
	unsigned int len = strlen(col->head);
	char blank_str[TABLE_STR_MAX];
	(void) t;

	memset(blank_str, ' ', col->p->max_width - len);
	blank_str[col->p->max_width - len] = 0;

	if (l_col_selected(t, col))
		ht_bold_on();
	if (col->align == TABLE_COL_ALIGN_RIGHT)
		hyptop_printf("%s", blank_str);
	hyptop_printf("%s", col->p->head_first);
	if (t->attr_sorted_table)
		ht_underline_on();
	hyptop_printf("%s", col->p->head_char);
	if (t->attr_sorted_table)
		ht_underline_off();
	hyptop_printf("%s", col->p->head_last);
	if (col->align == TABLE_COL_ALIGN_LEFT)
		hyptop_printf("%s", blank_str);
	if (l_col_selected(t, col))
		ht_bold_off();

}

/*
 * Print headline for table
 */
static void l_headline_print(struct table *t)
{
	struct table_col *col;
	int col_nr, first = 1;

	ht_reverse_on();
	/* Print all column headlines */
	table_col_iterate(t, col, col_nr) {
		if (!col->p->enabled)
			continue;
		if (first)
			first = 0;
		else
			hyptop_printf(" ");
		l_col_headline_print(t, col);
	}
	/* This creates a black bar to the end of the line */
	hyptop_print_seek_back(0);
	ht_reverse_off();
	hyptop_print_nl();
}

/*
 * Print unit line for table
 */
static void l_unitline_print(struct table *t)
{
	struct table_col *col;
	int col_nr, first = 1;
	char unit_str[20];

	if (!t->attr_with_units)
		return;
	ht_reverse_on();
	/* Print all column units */
	table_col_iterate(t, col, col_nr) {
		if (!col->p->enabled)
			continue;
		if (first)
			first = 0;
		else
			hyptop_printf(" ");
		if (l_col_selected(t, col))
			ht_bold_on();
		snprintf(unit_str, sizeof(unit_str), "(%s)", col->unit->str);
		l_str_print(col, unit_str);
		if (l_col_selected(t, col))
			ht_bold_off();
	}
	/* This creates a black bar to the end of the line */
	hyptop_print_seek_back(0);
	ht_reverse_off();
	hyptop_print_nl();
}

/*
 * Print one table row
 */
static void l_row_print(struct table *t, struct table_row *row)
{
	struct table_col *col;
	int first = 1, col_nr;

	table_col_iterate(t, col, col_nr) {
		struct table_entry *e = &row->entries[col_nr];
		if (!col->p->enabled)
			continue;
		if (!first)
			hyptop_printf(" ");
		else
			first = 0;
		if (row == t->row_last && col_nr == 0)
			l_status_print(t, e->str);
		else
			l_col_print(t, col, e->str);
	}
}

/*
 * Print table under curses
 */
static void l_table_print_curses(struct table *t)
{
	struct table_row *row;
	int row_nr = 0;

	if (!t->ready)
		return;
	l_adjust_values(t);
	l_status_update(t);
	l_headline_print(t);
	l_unitline_print(t);
	util_list_iterate(&t->row_list, row) {
		if (t->mode_hide_unmarked && !row->marked)
			continue;
		if (row_nr < t->row_nr_begin) {
			row_nr++;
			continue;
		}
		if (row_nr - t->row_nr_begin >= g.c.row_cnt - t->row_cnt_extra)
			break;
		if (t->mode_select && row_nr == t->row_nr_select)
			ht_reverse_on();
		if (row->marked)
			ht_bold_on();
		l_row_print(t, row);
		if (t->mode_select && row_nr == t->row_nr_select) {
#ifdef WITH_SCROLL_BAR
			hyptop_print_seek_back(1);
#else
			hyptop_print_seek_back(0);
#endif
			ht_reverse_off();
		}
		if (row->marked)
			ht_bold_off();
		hyptop_print_nl();
		row_nr++;
	}
	ht_reverse_on();
	l_row_print(t, t->row_last);
	if (t->row_physical) {
		hyptop_print_nl();
		l_row_print(t, t->row_physical);
	}
	hyptop_print_seek_back(0);
	ht_reverse_off();
#ifdef WITH_SCROLL_BAR
	if (t->mode_hide_unmarked)
		ht_print_scroll_bar(t->row_cnt_marked, t->row_nr_begin,
					t->row_cnt_extra - 1, 1,
					l_can_scroll_up(t),
					l_can_scroll_down(t), 1);
	else
		ht_print_scroll_bar(t->row_cnt, t->row_nr_begin,
					t->row_cnt_extra - 1, 1,
					l_can_scroll_up(t),
					l_can_scroll_down(t), 1);
#endif
}

/*
 * Print table under batch mode
 */
static void l_table_print_all(struct table *t)
{
	struct table_row *row;

	l_headline_print(t);
	l_unitline_print(t);
	util_list_iterate(&t->row_list, row) {
		l_row_print(t, row);
		hyptop_print_nl();
	}
	l_row_print(t, t->row_last);
	hyptop_print_nl();
	if (t->row_physical) {
		l_row_print(t, t->row_physical);
		hyptop_print_nl();
	}
	hyptop_printf("------------------------------------------------------"
		      "-------------------------\n");
}

/*
 * Print one table row as structured output
 *
 * Note: column filtering and sorting is explicitly ignored because the
 * assumption is that these operations can be trivially performed by the
 * consumer.
 */
static void l_row_print_formatted(struct table *t, struct table_row *row)
{
	struct table_col *col;
	int col_nr;

	table_col_iterate(t, col, col_nr) {
		unsigned int flags = 0;
		struct table_entry *e = &row->entries[col_nr];

		if (row == t->row_last && col_nr == 0)
			continue;
		if (table_col_needs_quotes(col))
			flags = FMT_QUOTE;
		util_fmt_pair(flags, col->head, "%s", e->str);
	}
}

/*
 * Print table as structured output
 */
static void l_table_print_all_formatted(struct table *t)
{
	struct table_row *row;

	util_fmt_obj_start(FMT_ROW, "iteration");
	util_fmt_pair(FMT_PERSIST, "iteration", "%u", g.o.iterations_act);
	ht_fmt_time();
	ht_fmt_cpu_types();
	if (t->row_physical) {
		util_fmt_obj_start(FMT_ROW, "physical_information");
		l_row_print_formatted(t, t->row_physical);
		util_fmt_obj_end(); /* physical_information{} */
	}
	if (strcmp(g.o.cur_win->id, "sys_list") == 0)
		util_fmt_obj_start(FMT_LIST, "systems");
	else
		util_fmt_obj_start(FMT_LIST, "cpus");
	util_list_iterate(&t->row_list, row) {
		util_fmt_obj_start(FMT_ROW, "entry");
		l_row_print_formatted(t, row);
		util_fmt_obj_end(); /* entry */
	}
	util_fmt_obj_end(); /* systems[] */
	util_fmt_obj_start(FMT_DEFAULT, "summary");
	l_row_print_formatted(t, t->row_last);
	util_fmt_obj_end(); /* summary{} */
	util_fmt_obj_end(); /* iteration */
}

void table_fmt_start(void)
{
	if (!g.o.format_specified)
		return;
	if (g.o.format != FMT_JSONSEQ)
		util_fmt_obj_start(FMT_LIST, "hyptop");
}

void table_fmt_end(void)
{
	if (!g.o.format_specified)
		return;
	if (g.o.format != FMT_JSONSEQ)
		util_fmt_obj_end(); /* hyptop[] */
}

/*
 * Print table to screen
 */
void table_print(struct table *t)
{
	if (g.o.batch_mode_specified) {
		if (!g.o.format_specified)
			l_table_print_all(t);
		else
			l_table_print_all_formatted(t);
	} else {
		l_table_print_curses(t);
	}
}

/*
 * Return column by hotkey
 */
static struct table_col *l_col_by_hotkey(struct table *t, char hotkey)
{
	struct table_col *col;
	int col_nr;

	table_col_iterate(t, col, col_nr) {
		if (col->hotkey == hotkey)
			return col;
	}
	return NULL;
}

/*
 * Select next unit for column with "hotkey"
 */
void table_col_unit_next(struct table *t, char hotkey)
{
	struct table_col *col;
	int i;

	col = l_col_by_hotkey(t, hotkey);
	if (!col || !col->unit_fam)
		assert(0);

	for (i = 0; col->unit_fam[i] != NULL; i++) {
		if (col->unit != col->unit_fam[i])
			continue;

		if (col->unit_fam[i + 1] == NULL)
			col->unit = col->unit_fam[0];
		else
			col->unit = col->unit_fam[i + 1];
		return;
	}
	assert(0);
}

/*
 * Select previous unit for column with "hotkey"
 */
void table_col_unit_prev(struct table *t, char hotkey)
{
	struct table_col *col;
	int i;

	col = l_col_by_hotkey(t, hotkey);
	if (!col || !col->unit_fam)
		assert(0);

	for (i = 0; col->unit_fam[i] != NULL; i++) {
		if (col->unit != col->unit_fam[i])
			continue;

		if (i == 0) {
			int j;

			for (j = 0; col->unit_fam[j] != NULL; j++) {}
			col->unit = col->unit_fam[j - 1];
		} else {
			col->unit = col->unit_fam[i - 1];
		}
		return;
	}
	assert(0);
}

/*
 * Set unit for column
 */
int table_col_unit_set(struct table *t, char hotkey, const char *str)
{
	struct table_col *col;
	int i;

	col = l_col_by_hotkey(t, hotkey);
	if (!col)
		return -ENODEV;

	for (i = 0; col->unit_fam[i] != NULL; i++) {
		if (strcasecmp(col->unit_fam[i]->str, str) == 0) {
			col->unit = col->unit_fam[i];
			return 0;
		}
	}
	return -EINVAL;
}

/*
 * Select column by hotkey
 */
int table_col_select(struct table *t, char hotkey)
{
	struct table_col *col;

	if (!t->attr_sorted_table)
		assert(0);
	col = l_col_by_hotkey(t, hotkey);
	if (!col || !col->p->enabled)
		return -ENODEV;
	if (t->col_selected == col) {
		t->mode_sort_inverse = t->mode_sort_inverse ? 0 : 1;
	} else  {
		t->mode_sort_inverse = 0;
		t->col_selected = col;
	}
	table_rebuild(t);
	l_table_sort(t);
	return 0;
}

/*
 * Select next column
 */
void table_col_select_next(struct table *t)
{
	int i;

	for (i = t->col_selected->p->col_nr + 1; i < t->col_cnt; i++) {
		if (t->col_vec[i]->p->enabled)
			goto found;
	}
	return;
found:
	t->col_selected = t->col_vec[i];
	l_table_sort(t);
}

/*
 * Select previous column
 */
void table_col_select_prev(struct table *t)
{
	int i;

	for (i = t->col_selected->p->col_nr - 1; i >= 0; i--) {
		if (t->col_vec[i]->p->enabled)
			goto found;
	}
	return;
found:
	t->col_selected = t->col_vec[i];
	l_table_sort(t);
}

/*
 * Toggle enabled status for column
 */
void table_col_enable_toggle(struct table *t, char hotkey)
{
	struct table_col *col;

	col = l_col_by_hotkey(t, hotkey);
	if (!col || col->p->col_nr == 0)
		return;
	col->p->enabled = col->p->enabled ? 0 : 1;
	if (col == t->col_selected)
		t->col_selected = t->col_vec[0];
}

/*
 * Process input for table
 */
void table_process_input(struct table *t, int c)
{
	switch (c) {
	case '<':
		if (t->attr_sorted_table)
			table_col_select_prev(t);
		break;
	case '>':
		if (t->attr_sorted_table)
			table_col_select_next(t);
		break;
	case '.':
		if (l_mode_hide_unmarked_toggle(t) == 0)
			l_select_mode_off(t);
		break;
	case '+':
		if (!t->attr_with_units)
			break;
		table_col_unit_next(t, t->col_selected->hotkey);
		table_rebuild(t);
		break;
	case '-':
		if (!t->attr_with_units)
			break;
		table_col_unit_prev(t, t->col_selected->hotkey);
		table_rebuild(t);
		break;
	case 'G':
		if (t->mode_select)
			table_row_select_down(t, TABLE_SCROLL_LAST);
		else
			table_scroll_down(t, TABLE_SCROLL_LAST);
		break;
	case 'g':
		if (t->mode_select)
			table_row_select_up(t, TABLE_SCROLL_LAST);
		else
			table_scroll_up(t, TABLE_SCROLL_LAST);
		break;
	case KEY_NPAGE:
		if (t->mode_select)
			table_row_select_down(t, TABLE_SCROLL_PAGE);
		else
			table_scroll_down(t, TABLE_SCROLL_PAGE);
		break;
	case KEY_PPAGE:
		if (t->mode_select)
			table_row_select_up(t, TABLE_SCROLL_PAGE);
		else
			table_scroll_up(t, TABLE_SCROLL_PAGE);
		break;
	case 'j':
	case KEY_DOWN:
		if (t->mode_select)
			table_row_select_down(t, TABLE_SCROLL_LINE);
		else
			table_scroll_down(t, TABLE_SCROLL_LINE);
		break;
	case 'k':
	case KEY_UP:
		if (t->mode_select)
			table_row_select_up(t, TABLE_SCROLL_LINE);
		else
			table_scroll_up(t, TABLE_SCROLL_LINE);
		break;
	case ' ':
		if (t->mode_select) {
			l_row_select_mark_toggle(t);
		} else {
			table_row_mark_del_all(t);
			t->mode_hide_unmarked = 0;
		}
		break;
	case 'l':
	case KEY_RIGHT:
		if (!t->mode_select)
			l_select_mode_on(t);
		break;
	case 'h':
	case KEY_LEFT:
		if (t->mode_select)
			l_select_mode_off(t);
		break;
	default:
		if (t->attr_sorted_table)
			table_col_select(t, c);
	}
}
