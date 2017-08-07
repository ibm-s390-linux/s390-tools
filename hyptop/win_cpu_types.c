/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Window "cpu_types": Select CPU types used for CPU data calculation.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "helper.h"
#include "hyptop.h"
#include "nav_desc.h"
#include "sd.h"
#include "table.h"
#include "win_cpu_types.h"

/*
 * Globals for cpu_types window
 */
static struct table_col l_col_key = TABLE_COL_STR_LEFT('k', "k");
static struct table_col l_col_select = TABLE_COL_STR_LEFT('s', "s");
static struct table_col l_col_id = TABLE_COL_STR_LEFT('i', "id");
static struct table_col l_col_desc = TABLE_COL_STR_LEFT('d', "description");

/*
 * Online help text for cpu_types window
 */
static const char l_help_str[] =
"In the \"cpu_types\" window you can select the CPU types that are used for\n"
"calculating CPU data. Toggle the selection of types either by pressing the\n"
"corresponding hotkey or by selecting them in select mode using the SPACE bar.\n"
"\n"
"The table of the \"cpu_types\" window has the following columns:\n"
"  - K   : Hotkey of CPU type\n"
"  - S   : Shows if CPU type is selected\n"
"  - ID  : Name of CPU type\n"
"  - DESC: Description of CPU type\n";

/*
 * Description of Navigation Keys (used for help window)
 */
static struct nav_desc *l_nav_desc_normal_vec[] = {
	&nav_desc_select_mode_enter,
	&nav_desc_marks_clear,
	&nav_desc_win_leave_cpu_types,
	NULL,
};

static struct nav_desc *l_nav_desc_select_vec[] = {
	&nav_desc_select_mode_leave,
	&nav_desc_mark_toggle,
	&nav_desc_win_leave_cpu_types_fast,
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
 * Add a CPU type to the table
 */
static void l_add_cpu_type(struct win_cpu_types *win_cpu_types,
			   struct sd_cpu_type *cpu_type)
{
	char char_str[2], select_str[2];
	struct table_row *table_row;

	if (sd_cpu_type_selected(cpu_type))
		sprintf(select_str, "*");
	else
		sprintf(select_str, " ");
	sprintf(char_str, "%c", cpu_type->hotkey);

	table_row = table_row_alloc(win_cpu_types->t);
	table_row_entry_str_add(table_row, &l_col_select, select_str);
	table_row_entry_str_add(table_row, &l_col_key, char_str);
	table_row_entry_str_add(table_row, &l_col_id, cpu_type->id);
	table_row_entry_str_add(table_row, &l_col_desc, cpu_type->desc);
	table_row_add(win_cpu_types->t, table_row);
	if (sd_cpu_type_selected(cpu_type))
		table_row_mark_toggle(win_cpu_types->t, table_row);
}

/*
 * Fill all available CPU types into table
 */
static void l_table_create(struct win_cpu_types *win_cpu_types)
{
	struct sd_cpu_type *cpu_type;
	unsigned int i;

	table_row_del_all(win_cpu_types->t);
	table_row_mark_del_all(win_cpu_types->t);
	sd_cpu_type_iterate(cpu_type, i)
		l_add_cpu_type(win_cpu_types, cpu_type);
	table_finish(win_cpu_types->t);
}

/*
 * Toggle the cpu type specified by "key" in the system data module
 */
static void l_toggle_cpu_type(char key)
{
	struct sd_cpu_type *cpu_type;
	unsigned int i;

	sd_cpu_type_iterate(cpu_type, i) {
		if (key == cpu_type->hotkey) {
			sd_cpu_type_select_toggle(cpu_type);
			return;
		}
	}
}

/*
 * Process input for selection with SPACE key
 */
static void l_process_input_select_space(struct win_cpu_types *win_cpu_types)
{
	char cpu_type_key[TABLE_STR_MAX];

	if (table_mode_select(win_cpu_types->t)) {
		table_row_select_key_get(win_cpu_types->t, cpu_type_key);
		l_toggle_cpu_type(cpu_type_key[0]);
	} else {
		struct table_mark_key *key;

		table_iterate_mark_keys(win_cpu_types->t, key)
			l_toggle_cpu_type(key->str[0]);
	}
}

/*
 * Process input for selection with hotkey
 */
static void l_process_input_select_key(struct win_cpu_types *win_cpu_types,
				       int c)
{
	char cpu_type_key[TABLE_STR_MAX];

	sprintf(cpu_type_key, "%c", c);
	table_row_mark_toggle_by_key(win_cpu_types->t, cpu_type_key);
	l_toggle_cpu_type(cpu_type_key[0]);
}

/*
 * Process input and switch window if necessary
 */
static enum hyptop_win_action l_process_input(struct hyptop_win *win, int c)
{
	struct win_cpu_types *win_cpu_types = (struct win_cpu_types *) win;

	switch (c) {
	case 't':
	case 'q':
		return win_back();
	case KEY_RETURN:
	case KEY_ENTER:
	case 'h':
	case KEY_LEFT:
		if (!table_mode_select(win_cpu_types->t))
			return win_back();
		break;
	case '?':
		return win_switch(win_cpu_types->win_help);
	case ' ':
		l_process_input_select_space(win_cpu_types);
		break;
	case ERR:
		return WIN_KEEP;
	default:
		l_process_input_select_key(win_cpu_types, c);
		break;
	}
	table_process_input(win_cpu_types->t, c);
	hyptop_update_term();
	return WIN_KEEP;
}

/*
 * Event loop: We stay in hyptop_process_input() until fields menu
 * is left.
 */
static void l_run(struct hyptop_win *win)
{
	struct win_cpu_types *win_cpu_types = (struct win_cpu_types *) win;

	table_reset(win_cpu_types->t);
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
	struct win_cpu_types *win_cpu_types = (struct win_cpu_types *) win;

	l_table_create(win_cpu_types);
	hyptop_printf("Select Processor Types");
	ht_print_help_icon();
	hyptop_print_nl();

	table_print(win_cpu_types->t);
}

/*
 * Create new cpu_types window
 */
struct hyptop_win *win_cpu_types_new(void)
{
	struct win_cpu_types *win_cpu_types;

	win_cpu_types = ht_zalloc(sizeof(*win_cpu_types));

	win_cpu_types->win.process_input = l_process_input;
	win_cpu_types->win.update_term = l_update_term;
	win_cpu_types->win.run = l_run;
	win_cpu_types->win.desc = l_help_str;
	win_cpu_types->win.desc_normal_vec = l_nav_desc_normal_vec;
	win_cpu_types->win.desc_select_vec = l_nav_desc_select_vec;
	win_cpu_types->win.desc_general_vec = l_nav_desc_general_vec;
	win_cpu_types->win.id = "cpu_types";

	win_cpu_types->t = table_new(1, 0, 0, 0);
	table_col_add(win_cpu_types->t, &l_col_key);
	table_col_add(win_cpu_types->t, &l_col_select);
	table_col_add(win_cpu_types->t, &l_col_id);
	table_col_add(win_cpu_types->t, &l_col_desc);

	win_cpu_types->win_help =
		win_help_new((struct hyptop_win *) win_cpu_types);
	l_table_create(win_cpu_types);
	return (struct hyptop_win *) win_cpu_types;
}
