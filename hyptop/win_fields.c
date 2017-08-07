/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Window "fields": Select fields dialog.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "helper.h"
#include "hyptop.h"
#include "table.h"
#include "win_fields.h"


/*
 * Globals for fields window
 */
static struct table_col l_col_select = TABLE_COL_STR_LEFT('s', "s");
static struct table_col l_col_id = TABLE_COL_STR_LEFT('i', "id");
static struct table_col l_col_key = TABLE_COL_STR_LEFT('k', "k");
static struct table_col l_col_unit = TABLE_COL_STR_LEFT('u', "unit");
static struct table_col l_col_agg = TABLE_COL_STR_LEFT('a', "agg");
static struct table_col l_col_desc = TABLE_COL_STR_LEFT('d', "description");

/*
 * Online help text for fields window
 */
static const char l_help_str[] =
"In the \"fields\" window you can select fields and units. Toggle the selection\n"
"of fields either by pressing the corresponding hotkey or by selecting them\n"
"in select mode using the SPACE bar. The units can be changed by selecting a\n"
"field in select mode and by pressing '+' or '-'.\n"
"\n"
"The table of the \"fields\" window has the following columns:\n"
"  - K   : Hotkey of field\n"
"  - S   : Shows if field is selected\n"
"  - ID  : Name of field\n"
"  - UNIT: Current unit used for field\n"
"  - AGG : Aggregation used for last line of table\n"
"  - DESC: Description of field\n";

/*
 * Description of Navigation Keys (used for help window)
 */
static struct nav_desc *l_nav_desc_normal_vec[] = {
	&nav_desc_select_mode_enter,
	&nav_desc_marks_clear,
	&nav_desc_win_leave_fields,
	NULL,
};

static struct nav_desc *l_nav_desc_select_vec[] = {
	&nav_desc_select_mode_leave,
	&nav_desc_mark_toggle,
	&nav_desc_row_unit_increase,
	&nav_desc_row_unit_decrease,
	&nav_desc_win_leave_fields_fast,
	NULL,
};

static struct nav_desc *l_nav_desc_general_vec[] = {
	&nav_desc_toggle_mark_hotkey,
	&nav_desc_scroll_up_line,
	&nav_desc_scroll_down_line,
	&nav_desc_scroll_up_page,
	&nav_desc_scroll_down_page,
	&nav_desc_scroll_up_head,
	&nav_desc_scroll_down_tail,
	&nav_desc_mark_toggle_view,
	NULL,
};

/*
 * Add a field that is the column of the reference table to the table
 */
static void l_add_field(struct win_fields *win_fields, struct table_col *col,
			const char *desc)
{
	char char_str[2], select_str[2];
	struct table_row *table_row;

	if (table_col_enabled(col))
		sprintf(select_str, "*");
	else
		sprintf(select_str, " ");
	sprintf(char_str, "%c", table_col_hotkey(col));

	table_row = table_row_alloc(win_fields->t);
	table_row_entry_str_add(table_row, &l_col_select, select_str);
	table_row_entry_str_add(table_row, &l_col_key, char_str);
	table_row_entry_str_add(table_row, &l_col_id, table_col_head(col));
	table_row_entry_str_add(table_row, &l_col_unit,
				table_col_unit_str(col));
	table_row_entry_str_add(table_row, &l_col_agg,
				table_col_agg_str(col->agg));
	table_row_entry_str_add(table_row, &l_col_desc, desc);
	table_row_add(win_fields->t, table_row);

	if (table_col_enabled(col))
		table_row_mark_toggle(win_fields->t, table_row);
}

/*
 * Fill all field information into table
 */
static void l_table_create(struct win_fields *win_fields)
{
	unsigned int i;

	table_row_del_all(win_fields->t);
	table_row_mark_del_all(win_fields->t);
	for (i = 0; win_fields->col_vec[i]; i++) {
		l_add_field(win_fields, win_fields->col_vec[i],
			    win_fields->col_desc_vec[i]);
	}
	table_finish(win_fields->t);
}

/*
 * Process input for selection with SPACE key
 */
static void l_process_input_select_space(struct win_fields *win_fields)
{
	char field_key[TABLE_STR_MAX];

	if (table_mode_select(win_fields->t)) {
		table_row_select_key_get(win_fields->t, field_key);
		table_col_enable_toggle(win_fields->table, field_key[0]);
	} else {
		struct table_mark_key *key;
		/* switch off all fields in reference table */
		table_iterate_mark_keys(win_fields->t, key)
			table_col_enable_toggle(win_fields->table,
					 key->str[0]);
	}
}

/*
 * Process input for selection with hotkey
 */
static void l_process_input_select_key(struct win_fields *win_fields, int c)
{
	char field_key[TABLE_STR_MAX];

	sprintf(field_key, "%c", c);
	table_row_mark_toggle_by_key(win_fields->t, field_key);
	table_col_enable_toggle(win_fields->table, field_key[0]);
}

/*
 * Process input for unit selection
 */
static void l_process_input_units(struct win_fields *win_fields, int c)
{
	char field_key[TABLE_STR_MAX];

	if (!table_mode_select(win_fields->t))
		return;
	table_row_select_key_get(win_fields->t, field_key);
	if (c == '+')
		table_col_unit_next(win_fields->table, field_key[0]);
	else
		table_col_unit_prev(win_fields->table, field_key[0]);
}

/*
 * Process input and switch window if necessary
 */
static enum hyptop_win_action l_process_input(struct hyptop_win *win, int c)
{
	struct win_fields *win_fields = (struct win_fields *) win;

	switch (c) {
	case 'f':
	case 'q':
		return win_back();
	case KEY_RETURN:
	case KEY_ENTER:
	case 'h':
	case KEY_LEFT:
		if (!table_mode_select(win_fields->t))
			return win_back();
		break;
	case '?':
		return win_switch(win_fields->win_help);
	case ' ':
		l_process_input_select_space(win_fields);
		break;
	case '+':
	case '-':
		l_process_input_units(win_fields, c);
		break;
	case ERR:
		return WIN_KEEP;
	default:
		l_process_input_select_key(win_fields, c);
		break;
	}
	table_process_input(win_fields->t, c);
	hyptop_update_term();
	return WIN_KEEP;
}

/*
 * Event loop: We stay in hyptop_process_input() until fields menu
 * is left.
 */
static void l_run(struct hyptop_win *win)
{
	struct win_fields *win_fields = (struct win_fields *) win;

	table_reset(win_fields->t);
	while (1) {
		hyptop_update_term();
		if (hyptop_process_input() == WIN_SWITCH)
			return;
	}
}

/*
 * Create table and print it to screen
 */
static void l_update_term(struct hyptop_win *win)
{
	struct win_fields *win_fields = (struct win_fields *) win;

	l_table_create(win_fields);
	hyptop_printf("Select Fields and Units");
	ht_print_help_icon();
	hyptop_print_nl();
	table_print(win_fields->t);
}

/*
 * Create new fields window
 *
 * - t...........: Reference table
 * - col_vec.....: Table column vector for fields
 * - col_desc_vec: Vector with descriptions for fields
 */
struct hyptop_win *win_fields_new(struct table *t, struct table_col **col_vec,
				  char **col_desc_vec)
{
	struct win_fields *win_fields;

	win_fields = ht_zalloc(sizeof(*win_fields));

	win_fields->win.process_input = l_process_input;
	win_fields->win.update_term = l_update_term;
	win_fields->win.run = l_run;
	win_fields->win.desc = l_help_str;
	win_fields->win.desc_normal_vec = l_nav_desc_normal_vec;
	win_fields->win.desc_select_vec = l_nav_desc_select_vec;
	win_fields->win.desc_general_vec = l_nav_desc_general_vec;
	win_fields->win.id = "fields";

	win_fields->t = table_new(1, 0, 0, 0);
	table_col_add(win_fields->t, &l_col_key);
	table_col_add(win_fields->t, &l_col_select);
	table_col_add(win_fields->t, &l_col_id);
	table_col_add(win_fields->t, &l_col_unit);
	table_col_add(win_fields->t, &l_col_agg);
	table_col_add(win_fields->t, &l_col_desc);
	win_fields->col_desc_vec = col_desc_vec;
	win_fields->col_vec = col_vec;
	win_fields->table = t;
	win_fields->win_help = win_help_new((struct hyptop_win *) win_fields);

	l_table_create(win_fields);
	return (struct hyptop_win *) win_fields;
}
