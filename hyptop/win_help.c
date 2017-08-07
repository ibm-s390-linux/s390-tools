/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Window "help": Show online help text.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "helper.h"
#include "hyptop.h"
#include "sd.h"
#include "table.h"
#include "win_help.h"

/*
 * Print help text to screen
 */
static void l_update_term(struct hyptop_win *win)
{
	struct win_help *win_help = (struct win_help *) win;
	tbox_print(win_help->tb);
}

/*
 * Process input and switch window if necessary
 */
static enum hyptop_win_action l_process_input(struct hyptop_win *win, int c)
{
	struct win_help *win_help = (struct win_help *) win;

	switch (c) {
	case 'h':
	case KEY_RETURN:
	case KEY_ENTER:
	case KEY_LEFT:
	case '?':
	case 'q':
		return win_back();
	case 'G':
		tbox_scroll_down(win_help->tb, TBOX_SCROLL_LAST);
		break;
	case 'g':
		tbox_scroll_up(win_help->tb, TBOX_SCROLL_LAST);
		break;
	case KEY_NPAGE:
		tbox_scroll_down(win_help->tb, TBOX_SCROLL_PAGE);
		break;
	case KEY_PPAGE:
		tbox_scroll_up(win_help->tb, TBOX_SCROLL_PAGE);
		break;
	case 'k':
	case KEY_UP:
		tbox_scroll_up(win_help->tb, TBOX_SCROLL_LINE);
		break;
	case 'j':
	case KEY_DOWN:
		tbox_scroll_down(win_help->tb, TBOX_SCROLL_LINE);
		break;
	case ERR:
		return WIN_KEEP;
	default:
		break;
	}
	hyptop_update_term();
	return WIN_KEEP;
}

/*
 * Event loop: wait for input and print help text
 */
static void l_run(struct hyptop_win *win)
{
	(void) win;

	while (1) {
		hyptop_update_term();
		if (hyptop_process_input() == WIN_SWITCH)
			return;
	}
}

/*
 * Add text to text box
 */
static void l_add_text(struct tbox *tb, const char *str)
{
	char *line, *line_end, *str_cpy;

	str_cpy = line_end = ht_strdup(str);
	for (line = str_cpy; line_end != NULL; line = line_end + 1) {
		line_end = strchr(line, '\n');
		if (line_end)
			*line_end = 0;
		tbox_line_add(tb, line);
	}
	ht_free(str_cpy);
}

/*
 * Create new help window for "win" and init window description
 */
struct hyptop_win *win_help_new(struct hyptop_win *win)
{
	struct win_help *win_help;

	win_help = ht_zalloc(sizeof(*win_help));

	win_help->tb = tbox_new();
	tbox_printf(win_help->tb, "\\BWindow: %s\\B", win->id);
	tbox_printf(win_help->tb, " ");
	l_add_text(win_help->tb, win->desc);
	nav_desc_add(win_help->tb, win->desc_normal_vec, win->desc_select_vec,
		     win->desc_general_vec);
	tbox_finish(win_help->tb);

	win_help->win.process_input = l_process_input;
	win_help->win.update_term = l_update_term;
	win_help->win.run = l_run;

	return (struct hyptop_win *) win_help;
}
