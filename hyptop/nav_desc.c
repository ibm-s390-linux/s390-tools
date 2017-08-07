/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Description of navigation keys
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "nav_desc.h"
#include "tbox.h"

#define L_KEY_LEN	14
#define L_KEY_FMT	"%-14s"

/* Select mode */

struct nav_desc nav_desc_select_mode_enter = {
	.desc	= "Enter select mode",
	.keys	= {"RIGHT", "l", NULL},
};

struct nav_desc nav_desc_select_mode_leave = {
	.desc	= "Leave select mode",
	.keys	= {"LEFT", "h", NULL},
};

/* "sys" Window */

struct nav_desc nav_desc_win_enter_sys = {
	.desc	= "Go to the \"sys\" window for selected system",
	.keys	= {"RIGHT", "l", NULL},
};

struct nav_desc nav_desc_win_leave_sys = {
	.desc	= "Go to the previous window",
	.keys	= {"LEFT", "h", "q", NULL},
};

struct nav_desc nav_desc_win_leave_sys_fast = {
	.desc	= "Go to the previous window",
	.keys	= {"q", NULL},
};

/* "fields" window */

struct nav_desc nav_desc_win_enter_fields = {
	.desc	= "Go to the \"fields\" window",
	.keys	= {"f", NULL},
} ;

struct nav_desc nav_desc_win_leave_fields = {
	.desc	= "Go to the previous window",
	.keys	= {"LEFT", "ENTER", "h", "f", "q", NULL},
};

struct nav_desc nav_desc_win_leave_fields_fast = {
	.desc	= "Go to the previous window",
	.keys	= {"f", "q", NULL},
};

/* "cpu_types" window */

struct nav_desc nav_desc_win_enter_cpu_types = {
	.desc	= "Go to the \"cpu_types\" window",
	.keys	= {"t", NULL},
};

struct nav_desc nav_desc_win_leave_cpu_types = {
	.desc	= "Go to the previous window",
	.keys	= {"LEFT", "ENTER", "h", "t", "q", NULL},
};

struct nav_desc nav_desc_win_leave_cpu_types_fast = {
	.desc	= "Go to the previous window",
	.keys	= {"t", "q", NULL},
};

/* Marks */

struct nav_desc nav_desc_marks_clear = {
	.desc	= "Clear all marked rows",
	.keys	= {"SPACE", NULL},
};

struct nav_desc nav_desc_mark_toggle = {
	.desc	= "Toggle mark for selected row",
	.keys	= {"SPACE", NULL},
};

struct nav_desc nav_desc_mark_toggle_view = {
	.desc	= "Toggle view for marked rows",
	.keys	= {".", NULL},
};

/* Units */

struct nav_desc nav_desc_col_unit_increase = {
	.desc	= "Increase unit type of selected column",
	.keys	= {"+", NULL},
};

struct nav_desc nav_desc_col_unit_decrease = {
	.desc	= "Decrease unit type of selected column",
	.keys	= {"-", NULL},
};

struct nav_desc nav_desc_row_unit_increase = {
	.desc	= "Increase unit type of selected row",
	.keys	= {"+", NULL},
};

struct nav_desc nav_desc_row_unit_decrease = {
	.desc	= "Decrease unit type of selected row",
	.keys	= {"-", NULL},
};

/* Select columns */

struct nav_desc nav_desc_select_col_next = {
	.desc	= "Select next column",
	.keys	= {">", NULL},
};

struct nav_desc nav_desc_select_col_prev = {
	.desc	= "Select previous column",
	.keys	= {"<", NULL},
};

struct nav_desc nav_desc_select_col_hotkey = {
	.desc	= "Select column with hotkey",
	.keys	= {"<key>", NULL},
};

/* Quit */

struct nav_desc nav_desc_quit = {
	.desc	= "Quit program",
	.keys	= {"q", NULL},
};

/* Select rows */

struct nav_desc nav_desc_toggle_mark_hotkey = {
	.desc	= "Toggle mark for row with hotkey",
	.keys	= {"<key>", NULL},
};

/* Navigation */

struct nav_desc nav_desc_scroll_up_line = {
	.desc	= "Scroll up one line",
	.keys	= {"UP", "k", NULL},
};

struct nav_desc nav_desc_scroll_down_line = {
	.desc	= "Scroll down one line",
	.keys	= {"DOWN", "j", NULL},
};

struct nav_desc nav_desc_scroll_up_page = {
	.desc	= "Scroll up one page",
	.keys	= {"PGUP", NULL},
};

struct nav_desc nav_desc_scroll_down_page = {
	.desc	= "Scroll down one page",
	.keys	= {"PGDOWN", NULL},
};

struct nav_desc nav_desc_scroll_up_head = {
	.desc	= "Scroll up to head of window",
	.keys	= {"g", NULL},
};

struct nav_desc nav_desc_scroll_down_tail = {
	.desc	= "Scroll down to tail of window",
	.keys	= {"G", NULL},
};

/*
 * Add navigation descriptons to text box
 */
static void l_nav_desc_add(struct tbox *tb, struct nav_desc *desc)
{
	char keys_str[L_KEY_LEN + 1];
	unsigned int i, first;
	char *key;

	first = 1;
	keys_str[0] = 0;
	for (i = 0; (key = desc->keys[i]); i++) {
		/*
		 * If we have used the whole space for the keys,
		 * we write the line and begin a new one
		 */
		if (strlen(desc->keys[i]) + strlen(keys_str) + 1 > L_KEY_LEN) {
			tbox_printf(tb, "  " L_KEY_FMT ": %s", keys_str,
				    desc->desc);
			keys_str[0] = 0;
			first = 1;
		}
		if (!first)
			strcat(keys_str, ",");
		else
			first = 0;
		strcat(keys_str, "'");
		strcat(keys_str, desc->keys[i]);
		strcat(keys_str, "'");
		assert(strlen(keys_str) <= L_KEY_LEN);
	}
	tbox_printf(tb, "  " L_KEY_FMT ": %s", keys_str, desc->desc);
}

/*
 * Add navigation descriptions for "normal", "select" and "general" to text box
 */
void nav_desc_add(struct tbox *tb,
		  struct nav_desc **desc_normal,
		  struct nav_desc **desc_select,
		  struct nav_desc **desc_general)
{
	unsigned int i;

	tbox_printf(tb, "\\BSupported keys in this window\\B");
	tbox_printf(tb, " ");

	tbox_printf(tb, "NORMAL MODE:");
	for (i = 0; (desc_normal[i]); i++)
		l_nav_desc_add(tb, desc_normal[i]);
	tbox_printf(tb, " ");
	tbox_printf(tb, "SELECT MODE:");
	for (i = 0; (desc_select[i]); i++)
		l_nav_desc_add(tb, desc_select[i]);
	tbox_printf(tb, " ");
	tbox_printf(tb, "GENERAL:");
	for (i = 0; (desc_general[i]); i++)
		l_nav_desc_add(tb, desc_general[i]);
	tbox_printf(tb, " ");
}
