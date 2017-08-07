/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Text box: Provide scrollable text window under curses.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <ncurses.h>

#include "helper.h"
#include "hyptop.h"
#include "tbox.h"

/*
 * Delete one line
 */
static void l_line_free(struct tbox_line *line)
{
	ht_free(line->str);
	ht_free(line);
}

/*
 * Delete all lines
 */
void tbox_line_del_all(struct tbox *tb)
{
	struct tbox_line *line, *tmp;

	util_list_iterate_safe(&tb->line_list, line, tmp) {
		util_list_remove(&tb->line_list, line);
		l_line_free(line);
	}
	tb->tbox_ready = 0;
	tb->line_cnt = 0;
}

/*
 * Finish text box after all lines have been added
 */
void tbox_finish(struct tbox *tb)
{
	tb->tbox_ready = 1;
}

/*
 * Add one line to text box
 */
void tbox_line_add(struct tbox *tb, const char *str)
{
	struct tbox_line *line;

	if (strlen(str) > TBOX_MAX_STR)
		assert(0);
	line = ht_zalloc(sizeof(*line));
	line->str = ht_strdup(str);
	util_list_add_tail(&tb->line_list, line);
	tb->last_line = line;
	tb->line_cnt++;
}

/*
 * Adjust values, if we scrolled out of range
 */
static void l_adjust_values(struct tbox *tb)
{
	if (tb->line_cnt - tb->line_start < g.c.row_cnt)
		tb->line_start = MAX(tb->line_cnt - g.c.row_cnt, 0);
}

/*
 * Scroll text box down
 */
void tbox_scroll_down(struct tbox *tb, enum tbox_scroll_unit unit)
{
	switch (unit) {
	case TBOX_SCROLL_LINE:
		tb->line_start++;
		break;
	case TBOX_SCROLL_PAGE:
		tb->line_start += (g.c.row_cnt - 2);
		break;
	case TBOX_SCROLL_LAST:
		tb->line_start = tb->line_cnt;
		break;
	}
}

/*
 * Scroll text box up
 */
void tbox_scroll_up(struct tbox *tb, enum tbox_scroll_unit unit)
{
	switch (unit) {
	case TBOX_SCROLL_LINE:
		tb->line_start = MAX(tb->line_start - 1, 0);
		break;
	case TBOX_SCROLL_PAGE:
		tb->line_start = MAX(tb->line_start - (g.c.row_cnt - 2), 0);
		break;
	case TBOX_SCROLL_LAST:
		tb->line_start = 0;
		break;
	}
}

/*
 * Resize text box
 */
void tbox_term_resize(struct tbox *tb)
{
	l_adjust_values(tb);
}

/*
 * Toggle bold curses format attribute
 */
static void l_bold_toggle(void)
{
	static int bold_on;

	if (bold_on) {
		ht_bold_off();
		bold_on = 0;
	} else {
		ht_bold_on();
		bold_on = 1;
	}
}

/*
 * Toggle underline curses format attribute
 */
static void l_underline_toggle(void)
{
	static int underline_on;

	if (underline_on) {
		ht_underline_off();
		underline_on = 0;
	} else {
		ht_underline_on();
		underline_on = 1;
	}
}

/*
 * Print one line with attributes (bold and underline)
 */
static void l_print_line(const char *line)
{
	char line_cpy[TBOX_MAX_STR + 1];
	char *ptr_old, *ptr;

	strncpy(line_cpy, line, sizeof(line_cpy));
	ptr_old = ptr = line_cpy;
	do {
		ptr = strchr(ptr, '\\');
		if (ptr) {
			*ptr = 0;
			hyptop_printf("%s", ptr_old);
			switch (ptr[1]) {
			case 'B':
				l_bold_toggle();
				break;
			case 'U':
				l_underline_toggle();
				break;
			}
			ptr += 2;
			ptr_old = ptr;
		} else {
			hyptop_printf("%s", ptr_old);
			return;
		}
	} while (*ptr);
}

#ifdef WITH_SCROLL_BAR
static int l_can_scroll_down(struct tbox *tb)
{
	return (tb->line_cnt - tb->line_start > g.c.row_cnt);
}

static int l_can_scroll_up(struct tbox *tb)
{
	return (tb->line_start > 0);
}
#endif

/*
 * Print text box to screen
 */
void tbox_print(struct tbox *tb)
{
	int line_nr = 0, first = 1;
	struct tbox_line *line;

	if (!tb->tbox_ready)
		return;

	l_adjust_values(tb);
	util_list_iterate(&tb->line_list, line) {
		if (line_nr < tb->line_start) {
			line_nr++;
			continue;
		}
		/* Have we printed the whole visible screen ? */
		if (line_nr - tb->line_start >= g.c.row_cnt)
			break;
		if (first)
			first = 0;
		else
			hyptop_print_nl();
		l_print_line(line->str);
		line_nr++;
	}
#ifdef WITH_SCROLL_BAR
	ht_print_scroll_bar(tb->line_cnt, tb->line_start, 0,
				0, l_can_scroll_up(tb), l_can_scroll_down(tb),
				0);
#endif
}

/*
 * Create new text box
 */
struct tbox *tbox_new(void)
{
	struct tbox *tb;

	tb = ht_zalloc(sizeof(*tb));
	util_list_init(&tb->line_list, struct tbox_line, list);
	return tb;
}
