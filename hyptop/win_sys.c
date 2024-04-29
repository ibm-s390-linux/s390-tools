/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Window "sys": Shows one system in more detail.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>

#include "helper.h"
#include "hyptop.h"
#include "opts.h"
#include "sd.h"
#include "table.h"
#include "win_fields.h"
#include "win_help.h"

/*
 * Globals for sys_list window
 */
static char l_sys_id[SD_SYS_ID_SIZE];	/* System to show */
static struct table_col l_cpu_col;	/* CPU column */
static struct table_col l_vis_col;	/* Visual column */
static struct table *l_t;		/* Table */
static int l_initialized;		/* Win initialized ? */
static struct hyptop_win *l_win_fields;	/* Fields window */
static struct hyptop_win *l_win_help;	/* Help window */

/* CPU column */
static struct table_col l_cpu_col = {
	.type		= TABLE_COL_TYPE_U64,
	.unit		= &table_col_unit_cnt,
	.unit_fam	= table_col_unit_fam_cnt,
	.align		= TABLE_COL_ALIGN_LEFT,
	.agg		= TABLE_COL_AGG_NONE,
	.hotkey		= 'i',
	.head		= "cpuid",
};

/* Visual column */
static struct table_col l_vis_col = {
	.type		= TABLE_COL_TYPE_U64,
	.unit		= &table_col_unit_vis,
	.unit_fam	= table_col_unit_fam_vis,
	.align		= TABLE_COL_ALIGN_LEFT,
	.agg		= TABLE_COL_AGG_NONE,
	.hotkey		= 'v',
	.head		= "visual",
};

/*
 * Online help text for sys window
 */
static const char l_help_str[] =
"The \"sys\" window displays CPU information about one selected system.\n"
"Under z/VM you can only see aggregated CPU information and not information\n"
"about single CPUs.\n"
"\n"
"Select a column by pressing the hotkey of the column. This key is underlined\n"
"in the heading. The table is sorted according to the values in the selected\n"
"column. If you press the hotkey again, the sort order is reversed.\n"
"Alternatively you can select columns with the '<' and '>' keys.\n";

/*
 * Description of Navigation Keys (used for help window)
 */
static struct nav_desc *l_nav_desc_normal_vec[] = {
	&nav_desc_select_mode_enter,
	&nav_desc_marks_clear,
	&nav_desc_win_leave_sys,
	NULL,
};

static struct nav_desc *l_nav_desc_select_vec[] = {
	&nav_desc_select_mode_leave,
	&nav_desc_mark_toggle,
	&nav_desc_win_leave_sys_fast,
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
	NULL,
};

/*
 * Add CPU item to table row
 */
static void l_cpu_item_add(struct table_row *table_row, struct sd_cpu *cpu,
			   struct sd_cpu_item *item)
{
	switch (sd_cpu_item_type(item)) {
	case SD_TYPE_U16:
	case SD_TYPE_U32:
		assert(0);
		break;
	case SD_TYPE_U64:
		table_row_entry_u64_add(table_row,
					sd_cpu_item_table_col(item),
					sd_cpu_item_u64(item, cpu));
		break;
	case SD_TYPE_S64:
		table_row_entry_s64_add(table_row,
					sd_cpu_item_table_col(item),
					sd_cpu_item_s64(item, cpu));
		break;
	case SD_TYPE_STR:
		table_row_entry_str_add(table_row,
					sd_cpu_item_table_col(item),
					sd_cpu_item_str(item, cpu));
		break;
	}
}

/*
 * Add visualization of CPU time to table row
 */
static void l_cpu_add_visual(struct table_row *table_row, struct sd_cpu *cpu)
{
	s64 steal_us;
	u64 cpu_us;

	cpu_us = sd_cpu_item_u64(&sd_cpu_item_cpu_diff, cpu);
	steal_us = sd_cpu_item_s64(&sd_cpu_item_steal_diff, cpu);
	steal_us = MAX(steal_us, 0);
	table_row_entry_u64_add_pair(table_row, &l_vis_col, cpu_us, steal_us);
}

/*
 * Add CPU to table
 */
static void l_cpu_add(struct sd_cpu *cpu)
{
	struct table_row *table_row;
	struct sd_cpu_item *item;
	unsigned int cpu_id;
	unsigned int i;

	table_row = table_row_alloc(l_t);
	cpu_id = atoi(sd_cpu_id(cpu));
	table_row_entry_u64_add(table_row, &l_cpu_col, cpu_id);

	sd_cpu_item_iterate(item, i) {
		if (!sd_cpu_item_set(item, cpu))
			continue;
		l_cpu_item_add(table_row, cpu, item);
	}
	l_cpu_add_visual(table_row, cpu);
	table_row_add(l_t, table_row);
}

/*
 * Fill system CPU data into table
 */
static int l_table_create(void)
{
	struct sd_sys *parent;
	struct sd_cpu *cpu;
	int i;

	parent = sd_sys_get(sd_sys_root_get(), l_sys_id);
	if (!parent)
		return -ENODEV;
	table_row_del_all(l_t);
	sd_cpu_iterate(parent, cpu) {
		for (i = 0; i < cpu->cnt; i++)
			l_cpu_add(cpu);
	}
	table_finish(l_t);
	return 0;
}

/*
 * Print table to screen
 */
static void l_table_update_term(struct hyptop_win *win)
{
	(void) win;

	if (!g.o.format_specified)
		ht_print_head(l_sys_id);
	table_print(l_t);
}

/*
 * Process input and switch window if necessary
 */
static enum hyptop_win_action l_process_input(struct hyptop_win *win, int c)
{
	(void) win;

	switch (c) {
	case 't':
		return win_switch(g.win_cpu_types);
	case '?':
		return win_switch(l_win_help);
	case 'f':
		return win_switch(l_win_fields);
	case 'q':
		return win_back();
	case 'h':
	case KEY_LEFT:
		if (!(table_mode_select(l_t)))
			return win_back();
		break;
	case ERR:
		return WIN_KEEP;
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
	struct sd_cpu_item *item;
	struct table_col *col;
	unsigned int i;

	if (table_col_hotkey(&l_vis_col) == col_spec->hotkey) {
		l_field_set(col_spec);
		return;
	}
	sd_cpu_item_iterate(item, i) {
		col = sd_cpu_item_table_col(item);
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

	table_col_enable_toggle(l_t, table_col_hotkey(&l_vis_col));
	for (i = 0; i < win_sys.opts.fields.cnt; i++)
		l_field_enable(win_sys.opts.fields.vec[i]);
}

/*
 * Enable fields like defined in data gatherer
 */
static void l_fields_enable_default(void)
{
	struct sd_cpu_item *item;
	struct table_col *col;
	unsigned int i;

	sd_cpu_item_enable_iterate(item, i) {
		col = sd_cpu_item_table_col(item);
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
		if (l_table_create()) {
			if (g.o.batch_mode_specified)
				ERR_EXIT("System \"%s\" not available.\n",
					 l_sys_id);
			win_back();
			return;
		}
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
 * Define system for window
 */
void win_sys_set(const char *sys_id)
{
	if (l_initialized)
		table_reset(l_t);
	util_strlcpy(l_sys_id, sys_id, sizeof(l_sys_id));
}

/*
 * Initialize window
 */
void win_sys_init(void)
{
	struct table_col **col_vec;
	struct sd_cpu_item *item;
	struct table_col *col;
	char **col_desc_vec, *vis_str;
	unsigned int i, item_cnt;

	if (sd_dg_has_core_data()) {
		strcpy(l_cpu_col.head, "coreid");
		vis_str = "Visualization of core dispatch time per second";
	} else {
		vis_str = "Visualization of CPU time per second";
	}

	/* Alloc table and add columns */
	l_t = table_new(1, 1, 1, 1);
	table_col_add(l_t, &l_cpu_col);
	table_col_rsort(&l_cpu_col);

	item_cnt = sd_cpu_item_cnt() + 2;
	col_vec = ht_zalloc(sizeof(void *) * item_cnt);
	col_desc_vec = ht_zalloc(sizeof(void *) * item_cnt);

	sd_cpu_item_iterate(item, i) {
		col = sd_cpu_item_table_col(item);
		table_col_add(l_t, col);
		table_col_enable_toggle(l_t, table_col_hotkey(col));
		col_vec[i] = col;
		col_desc_vec[i] = item->desc;
	}
	col_vec[i] = &l_vis_col;
	col_desc_vec[i] = vis_str;
	table_col_add(l_t, &l_vis_col);

	/* Enable fields */
	if (win_sys.opts.fields.specified)
		l_fields_enable_cmdline();
	else
		l_fields_enable_default();

	/* Select sort field */
	if (win_sys.opts.sort_field_specified) {
		for (i = 0; i < win_sys.opts.sort_field_specified; i++) {
			if (table_col_select(l_t, win_sys.opts.sort_field))
				ERR_EXIT("Sort field \"%c\" is not available\n",
					 win_sys.opts.sort_field);
		}
	}
	/* Initialize help and fields window */
	l_win_fields = win_fields_new(l_t, col_vec, col_desc_vec);
	l_win_help = win_help_new(&win_sys);

	l_initialized = 1;
}

/*
 * hyptop window structure definition
 */
struct hyptop_win win_sys = {
	.process_input		= l_process_input,
	.update_term		= l_table_update_term,
	.run			= l_run,
	.id			= "sys",
	.desc			= l_help_str,
	.desc_normal_vec	= l_nav_desc_normal_vec,
	.desc_select_vec	= l_nav_desc_select_vec,
	.desc_general_vec	= l_nav_desc_general_vec,
};
