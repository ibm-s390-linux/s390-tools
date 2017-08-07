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

#ifndef NAV_DESC_H
#define NAV_DESC_H

#include "tbox.h"

struct nav_desc {
	char	*desc;
	char	*keys[];
};

void nav_desc_add(struct tbox *tb,
		  struct nav_desc **desc_normal,
		  struct nav_desc **desc_select,
		  struct nav_desc **desc_general);

extern struct nav_desc nav_desc_quit;
extern struct nav_desc nav_desc_select_mode_enter;
extern struct nav_desc nav_desc_select_mode_leave;
extern struct nav_desc nav_desc_win_enter_sys;
extern struct nav_desc nav_desc_win_leave_sys;
extern struct nav_desc nav_desc_win_leave_sys_fast;
extern struct nav_desc nav_desc_win_enter_fields;
extern struct nav_desc nav_desc_win_leave_fields;
extern struct nav_desc nav_desc_win_leave_fields_fast;
extern struct nav_desc nav_desc_win_enter_cpu_types;
extern struct nav_desc nav_desc_win_leave_cpu_types;
extern struct nav_desc nav_desc_win_leave_cpu_types_fast;
extern struct nav_desc nav_desc_marks_clear;
extern struct nav_desc nav_desc_mark_toggle;
extern struct nav_desc nav_desc_mark_toggle_view;
extern struct nav_desc nav_desc_col_unit_increase;
extern struct nav_desc nav_desc_col_unit_decrease;
extern struct nav_desc nav_desc_row_unit_increase;
extern struct nav_desc nav_desc_row_unit_decrease;
extern struct nav_desc nav_desc_select_col_next;
extern struct nav_desc nav_desc_select_col_prev;
extern struct nav_desc nav_desc_select_col_hotkey;
extern struct nav_desc nav_desc_toggle_mark_hotkey;
extern struct nav_desc nav_desc_scroll_up_line;
extern struct nav_desc nav_desc_scroll_down_line;
extern struct nav_desc nav_desc_scroll_up_page;
extern struct nav_desc nav_desc_scroll_down_page;
extern struct nav_desc nav_desc_scroll_up_head;
extern struct nav_desc nav_desc_scroll_down_tail;

#endif /* NAV_DESC_H */
