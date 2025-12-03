/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Window "sys_list":
 * Shows a list of systems that the hypervisor is currently running.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "helper.h"
#include "hyptop.h"
#include "nav_desc.h"
#include "opts.h"
#include "sd.h"
#include "table.h"
#include "win_fields.h"
#include "win_help.h"

/*
 * Globals for sys_list window
 */
static struct table		*l_t;		/* Table */
static struct hyptop_win	*l_win_fields;	/* Fields Window */
static struct hyptop_win	*l_win_help;	/* Herp Window */

/* System column */
static struct table_col l_col_sys = TABLE_COL_STR_LEFT('y', "system");

/*
 * Online help text for sys_list window
 */
static const char l_help_str[] =
"The following windows can be accessed:\n"
"\n"
" +-----------+        RIGHT             +----------+\n"
" |           | <----------------------> |          |\n"
" |           |         LEFT             |          |\n"
" |           |                          |          |\n"
" | sys_list  |  't'      +-----------+  |          |  't'      +-----------+\n"
" |           | <-------> | cpu_types |  |   sys    | <-------> | cpu_types |\n"
" |  (start)  | 't',LEFT  +-----------+  |          | 't',LEFT  +-----------+\n"
" |           |                          |          |\n"
" |           |  'f'      +--------+     |          |  'f'      +--------+\n"
" |           | <-------> | fields |     |          | <-------> | fields |\n"
" |           | 'f',LEFT  +--------+     |          | 'f',LEFT  +--------+\n"
" +-----------+                          +----------+\n"
"\n"
" * sys_list:  Start window that shows a list of systems that the hypervisor\n"
"              is currently running.\n"
" * sys:       Shows one system in more detail.\n"
" * cpu_types: Select CPU types that are used for calculating CPU data.\n"
" * fields:    Select fields and units for windows sys_list or sys.\n"
"\n"
"\\BNavigation\\B\n"
"\n"
"To navigate between the windows, use the arrow keys or 'hjkl'. The windows\n"
"have two modes, \"normal mode\" and \"select mode\". When you start the "
"program,\n"
"the window is in normal mode where data is updated at regular intervals. Use\n"
"the RIGHT arrow key to enter the select mode. In select mode you can select\n"
"rows with with UP and DOWN arrow keys and mark them with the SPACE bar. From\n"
"the \"sys_list\" window you can access the \"sys\" window in select mode\n"
"with the arrow key RIGHT. Leave the select mode with the arrow key LEFT.\n"
"If you are in normal mode, the arrow key LEFT goes to the previous window.\n"
"You can scroll all windows using the arrow keys UP, DOWN, PAGEUP and\n"
"PAGEDOWN. You can jump to the end of a window with 'G' and to the beginning\n"
"with 'g'.\n"
"\n"
"Select a column by pressing the hotkey of the column. This key is underlined\n"
"in the heading. The table is sorted according to the values in the selected\n"
"column. If you press the hotkey again, the sort order is reversed.\n"
"Alternatively you can select columns with the '<' and '>' keys.\n"
"\n"
"\\BTable layout\\B\n"
"\n"
"At the top left of the table the current time is shown. Then the CPU types\n"
"with the physical CPU numbers that are used for CPU time calculation are\n"
"displayed. The second row shows the units that are currently used for\n"
"formatting the data. The last row shows the status display (see description\n"
"below) and the aggregation of the the data columns. The last row aggregates\n"
"all rows, not only the visible ones. If only the marked rows are shown\n"
"(with '.') then only these rows are aggregated.\n"
"\n"
"\\BStatus display\\B\n"
"\n"
"At the left bottom of the screen a status display is shown.\n"
"Example: \"V:V:N\"\n\n"
"The first character shows, if the window can be scrolled:\n"
" 'V': Window can be scrolled down\n"
" '|': Window can be scrolled up/down\n"
" '^': Window can be scrolled up\n"
" '=': Window cannot be scrolled\n"
"The second character shows the sort order for sorted tables:\n"
" 'V': Higher values first\n"
" '^': Lower values first\n"
"The third character shows the current mode:\n"
" 'N': Normal mode\n"
" 'S': Select mode\n";

/*
 * Description of Navigation Keys (used for help window)
 */
static struct nav_desc *l_nav_desc_normal_vec[] = {
	&nav_desc_select_mode_enter,
	&nav_desc_marks_clear,
	NULL,
};

static struct nav_desc *l_nav_desc_select_vec[] = {
	&nav_desc_select_mode_leave,
	&nav_desc_win_enter_sys,
	&nav_desc_mark_toggle,
	NULL,
};

static struct nav_desc *l_nav_desc_general_vec[] = {
	&nav_desc_win_enter_fields,
	&nav_desc_win_enter_cpu_types,
	&nav_desc_col_unit_increase,
	&nav_desc_col_unit_decrease,
	&nav_desc_select_col_next,
	&nav_desc_select_col_prev,
	&nav_desc_select_col_hotkey,
	&nav_desc_scroll_up_line,
	&nav_desc_scroll_down_line,
	&nav_desc_scroll_up_page,
	&nav_desc_scroll_down_page,
	&nav_desc_scroll_up_head,
	&nav_desc_scroll_down_tail,
	&nav_desc_mark_toggle_view,
	&nav_desc_quit,
	NULL,
};

/*
 * Add system item to table row
 */
static void l_sys_item_add(struct table_row *table_row, struct sd_sys *sys,
			   struct sd_sys_item *item)
{
	switch (sd_sys_item_type(item)) {
	case SD_TYPE_U64:
	case SD_TYPE_U32:
	case SD_TYPE_U16:
		table_row_entry_u64_add(table_row,
					sd_sys_item_table_col(item),
					sd_sys_item_u64(sys, item));
		break;
	case SD_TYPE_S64:
		table_row_entry_s64_add(table_row,
					sd_sys_item_table_col(item),
					sd_sys_item_s64(sys, item));
		break;
	case SD_TYPE_STR:
		table_row_entry_str_add(table_row,
					sd_sys_item_table_col(item),
					sd_sys_item_str(sys, item));
		break;
	}
}

static void l_row_add_physical(struct table *t, struct sd_sys *sys)
{
	struct sd_sys_item *item;
	struct table_row *row;
	unsigned int i;

	row = table_row_alloc(t);
	table_row_entry_str_add(row, &l_col_sys, sd_sys_id(sys));
	sd_sys_item_iterate(item, i) {
		if (!sd_sys_item_set(sys, item))
			continue;
		l_sys_item_add(row, sys, item);
	}
	t->row_physical = row;
}

/*
 * Add system to table
 */
static void l_sys_add(struct sd_sys *sys)
{
	struct table_row *table_row;
	struct sd_sys_item *item;
	unsigned int i;

	table_row = table_row_alloc(l_t);
	table_row_entry_str_add(table_row, &l_col_sys, sd_sys_id(sys));

	sd_sys_item_iterate(item, i) {
		if (!sd_sys_item_set(sys, item))
			continue;
		l_sys_item_add(table_row, sys, item);
	}
	table_row_add(l_t, table_row);
}

/*
 * Fill system data into table
 */
static void l_table_create(void)
{
	struct sd_sys *parent, *guest;

	table_row_del_all(l_t);
	parent = sd_sys_root_get();
	sd_sys_iterate(parent, guest) {
		if (!opts_sys_specified(&win_sys_list, sd_sys_id(guest)))
			continue;
		l_sys_add(guest);
	}
	if (sd_dg_has_phys_data())
		l_row_add_physical(l_t, parent);
	table_finish(l_t);
}

/*
 * Print table to screen
 */
static void l_table_update_term(struct hyptop_win *win)
{
	(void) win;

	if (!g.o.format_specified)
		ht_print_head(NULL);
	table_print(l_t);
}

/*
 * Process input and switch window if necessary
 */
static enum hyptop_win_action l_process_input(struct hyptop_win *win, int c)
{
	char selected_sys[TABLE_STR_MAX];
	(void) win;

	switch (c) {
	case 'f':
		return win_switch(l_win_fields);
	case 't':
		return win_switch(g.win_cpu_types);
	case '?':
		return win_switch(l_win_help);
	case 'q':
		hyptop_exit(0);
	case 'l':
	case KEY_RIGHT:
		if (!table_mode_select(l_t))
			break;
		table_row_select_key_get(l_t, selected_sys);
		win_sys_set(selected_sys);
		return win_switch(&win_sys);
	case ERR:
		break;
	}
	table_process_input(l_t, c);
	hyptop_update_term();
	return WIN_KEEP;
}

/*
 * Enable field and set unit
 */
static void l_field_set(struct table_col_spec *col_spec)
{
	table_col_enable_toggle(l_t, col_spec->hotkey);
	if (!col_spec->unit_str)
		return;
	if (table_col_unit_set(l_t, col_spec->hotkey, col_spec->unit_str))
		ERR_EXIT("Invalid unit \"%s\" for field \"%c\"\n",
			 col_spec->unit_str, col_spec->hotkey);
}

/*
 * Enable field defined in "col_spec"
 */
static void l_field_enable(struct table_col_spec *col_spec)
{
	struct sd_sys_item *item;
	struct table_col *col;
	unsigned int i;

	sd_sys_item_iterate(item, i) {
		col = sd_sys_item_table_col(item);
		if (table_col_hotkey(col) != col_spec->hotkey)
			continue;
		l_field_set(col_spec);
		return;
	}
	ERR_EXIT("Unknown field \"%c\"\n", col_spec->hotkey);
}

/*
 * Enable fields defined on command line
 */
static void l_fields_enable_cmdline(void)
{
	unsigned int i;

	for (i = 0; i < win_sys_list.opts.fields.cnt; i++)
		l_field_enable(win_sys_list.opts.fields.vec[i]);
}

/*
 * Enable fields like defined in data gatherer
 */
static void l_fields_enable_default(void)
{
	struct sd_sys_item *item;
	struct table_col *col;
	unsigned int i;

	sd_sys_item_enable_iterate(item, i) {
		col = sd_sys_item_table_col(item);
		table_col_enable_toggle(l_t, table_col_hotkey(col));
	}
}

/*
 * Event loop: Make regular updates of table
 */
static void l_run(struct hyptop_win *win)
{
	enum hyptop_win_action action;
	(void) win;

	/* Reformat table when entering window */
	table_rebuild(l_t);
	table_fmt_start();
	while (1) {
		l_table_create();
		hyptop_update_term();
		action = hyptop_process_input_timeout();
		if (action == WIN_SWITCH)
			return;
		/* No updates in select mode */
		if (!table_mode_select(l_t))
			sd_update();
	}
}

/*
 * Initialize window
 */
void win_sys_list_init(void)
{
	struct table_col **col_vec;
	struct sd_sys_item *item;
	struct table_col *col;
	char **col_desc_vec;
	unsigned int i;
	int item_cnt;

	/* Alloc table and add columns */
	l_t = table_new(2, 1, 1, 1);
	table_col_add(l_t, &l_col_sys);

	item_cnt = sd_sys_item_cnt() + 1;
	col_vec = ht_zalloc(sizeof(void *) * item_cnt);
	col_desc_vec = ht_zalloc(sizeof(void *) * item_cnt);

	sd_sys_item_iterate(item, i) {
		col = sd_sys_item_table_col(item);
		table_col_add(l_t, col);
		table_col_enable_toggle(l_t, table_col_hotkey(col));
		col_vec[i] = col;
		col_desc_vec[i] = item->desc;
	}
	/* Enable fields */
	if (win_sys_list.opts.fields.specified)
		l_fields_enable_cmdline();
	else
		l_fields_enable_default();

	/* Select sort field */
	if (win_sys_list.opts.sort_field_specified) {
		for (i = 0; i < win_sys_list.opts.sort_field_specified; i++) {
			if (table_col_select(l_t, win_sys_list.opts.sort_field))
				ERR_EXIT("Sort field \"%c\" is not available\n",
					  win_sys_list.opts.sort_field);
		}
	} else {
		table_col_select(l_t, sd_sys_item_cpu_diff.table_col.hotkey);
	}
	/* Initialize help and fields window */
	l_win_help = win_help_new(&win_sys_list);
	l_win_fields = win_fields_new(l_t, col_vec, col_desc_vec);
}

/*
 * hyptop window structure definition
 */
struct hyptop_win win_sys_list = {
	.process_input		= l_process_input,
	.update_term		= l_table_update_term,
	.run			= l_run,
	.id			= "sys_list",
	.desc			= l_help_str,
	.desc_normal_vec	= l_nav_desc_normal_vec,
	.desc_select_vec	= l_nav_desc_select_vec,
	.desc_general_vec	= l_nav_desc_general_vec,
};
