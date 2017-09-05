/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Main & init functions
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <ncurses.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "dg_debugfs.h"
#include "helper.h"
#include "hyptop.h"
#include "opts.h"
#include "sd.h"
#include "win_cpu_types.h"

#ifdef WITH_HYPFS
#include "dg_hypfs.h"
#endif

/*
 * Globals for the whole program
 */
struct hyptop_globals g;

/*
 * Get current terminal size and tell curses about it
 */
static void l_term_size_get(void)
{
	struct winsize ws;

	g.c.col_cnt = 80;
	g.c.row_cnt = 24;

	if (ioctl(1, TIOCGWINSZ, &ws) != -1) {
		if ((ws.ws_col != 0) && (ws.ws_row != 0)) {
			g.c.col_cnt = ws.ws_col;
			g.c.row_cnt = ws.ws_row;
		}
	}
	resizeterm(g.c.row_cnt, g.c.col_cnt);
}

/*
 * Process input
 */
static enum hyptop_win_action l_process_input(struct hyptop_win *win)
{
	int c;

	/* Skip all resize events */
	while ((c = wgetch(stdscr)) == KEY_RESIZE) {}
	return win->process_input(win, c);
}

/*
 * Process input with timeout
 */
static enum hyptop_win_action l_process_input_timeout(time_t time_s,
						      long time_us)
{
	struct timeval tv;
	fd_set fds;
	int rc;

	while (1) {
		FD_ZERO(&fds);
		FD_SET(0, &fds);
		tv.tv_sec = time_s;
		tv.tv_usec = time_us;
		rc = select(1, &fds, NULL, NULL, &tv);
		switch (rc) {
		case 0:
			/* Timeout */
			return WIN_KEEP;
		case 1:
			/* Input */
			if (l_process_input(g.w.cur) == WIN_SWITCH)
				return WIN_SWITCH;
			continue;
		case -1:
			if (errno != EINTR)
				ERR_EXIT_ERRNO("Select call failed");
			/* Signal: Resize */
			hyptop_update_term();
			continue;
		default:
			assert(0);
		}
	}
}

/*
 * Sleep
 */
static enum hyptop_win_action l_sleep(time_t time_s, long time_us)
{
	struct timespec ts;

	ts.tv_sec = time_s;
	ts.tv_nsec = time_us * 1000;

	nanosleep(&ts, NULL);
	return WIN_KEEP;
}

/*
 * External process input with timeout funciton
 */
enum hyptop_win_action hyptop_process_input_timeout(void)
{
	enum hyptop_win_action rc;

	if (g.o.batch_mode_specified) {
		opts_iterations_next();
		rc = l_sleep(g.o.delay_s, g.o.delay_us);
	} else {
		rc = l_process_input_timeout(g.o.delay_s, g.o.delay_us);
		opts_iterations_next();
	}
	return rc;
}

/*
 * External process input funciton
 */
enum hyptop_win_action hyptop_process_input(void)
{
	return l_process_input_timeout(-1U, 0);
}

/*
 * Signal handler for exiting hyptop
 */
static void l_sig_exit(int sig)
{
	(void) sig;

	hyptop_exit(0);
}

/*
 * Install signal handler
 */
static void l_sig_handler_init(void)
{
	struct sigaction sigact;

	/* Ignore signals SIGUSR1 and SIGUSR2 */
	if (sigemptyset(&sigact.sa_mask) < 0)
		goto fail;
	sigact.sa_flags = 0;
	sigact.sa_handler = SIG_IGN;
	if (sigaction(SIGUSR1, &sigact, NULL) < 0)
		goto fail;
	if (sigaction(SIGUSR2, &sigact, NULL) < 0)
		goto fail;

	/* Exit on SIGINT, SIGTERM, SIGHUP, ... */
	if (sigemptyset(&sigact.sa_mask) < 0)
		goto fail;
	sigact.sa_handler = l_sig_exit;
	if (sigaction(SIGINT, &sigact, NULL) < 0)
		goto fail;
	if (sigaction(SIGTERM, &sigact, NULL) < 0)
		goto fail;
	if (sigaction(SIGHUP, &sigact, NULL) < 0)
		goto fail;
	if (sigaction(SIGQUIT, &sigact, NULL) < 0)
		goto fail;
	if (sigaction(SIGALRM, &sigact, NULL) < 0)
		goto fail;
	if (sigaction(SIGPIPE, &sigact, NULL) < 0)
		goto fail;
	return;
fail:
	ERR_EXIT_ERRNO("Could not initialize signal handler");
}

/*
 * Start curses
 */
static int l_initscr(void)
{
	if (!initscr())
		return ERR;
	g.c.initialized = 1;
	atexit(hyptop_text_mode);
	return 0;
}

/*
 * Check if terminal is able to run hyptop in curses mode
 */
static void l_term_check(void)
{
	char *term_str = getenv("TERM");

	if (!term_str)
		ERR_EXIT("Please set TERM environment variable or "
			 "try \"--batch_mode\"\n");

 	/* S390 line mode terminals normally have TERM=dumb */
	if (strcmp(term_str, "dumb") == 0)
		ERR_EXIT("Terminal of type \"dumb\" is not supported,"
			" try \"--batch_mode\"\n");
}

/*
 * Init curses
 */
static void l_term_init(void)
{
	if (g.o.batch_mode_specified)
		return;

	l_term_check();

	if (l_initscr() == ERR)
		goto fail;
	if (noecho() == ERR)
		goto fail;
	if (nodelay(stdscr, TRUE) == ERR)
		goto fail;
	if (cbreak() == ERR) /* Line buffering disabled. pass on everything */
		goto fail;
	if (keypad(stdscr, TRUE) == ERR)
		goto fail;
	curs_set(0); /* prevent cursor from blinking */
	l_term_size_get();
	l_sig_handler_init();
	return;
fail:
	ERR_EXIT("Could not initialize curses, try \"--batch_mode\"\n");
}

/*
 * Initialize data gatherer
 */
#ifdef WITH_HYPFS
static void l_dg_init(void)
{
	if (dg_debugfs_init(0) == 0)
		return;
	if (dg_hypfs_init() == 0)
		return;
	ERR_EXIT("Could not initialize data gatherer\n");
}
#else
static void l_dg_init(void)
{
	dg_debugfs_init(1);
}
#endif

/*
 * Windows event loop
 */
static void l_event_loop(void)
{
	while (1)
		g.w.cur->run(g.w.cur);
}

/*
 * Clear terminal and write new window content to it
 */
static void l_update_term_curses(void)
{
	/* Init screen */
	l_term_size_get();
	curs_set(0); /* pervent cursor from blinking */
	move(0, 0);
	erase();
	hyptop_printf_init();
	/* Write window to screen */
	g.w.cur->update_term(g.w.cur);
	refresh();
}

/*
 * Write window content in line mode
 */
static void l_update_term_batch(void)
{
	g.w.cur->update_term(g.w.cur);
	printf("\n");
}

/*
 * Update terminal with new window content
 */
void hyptop_update_term(void)
{
	if (g.o.batch_mode_specified)
		l_update_term_batch();
	else
		l_update_term_curses();
}

/*
 * Switch to new window "win"
 */
enum hyptop_win_action win_switch(struct hyptop_win *win)
{
	assert(g.w.prev_cnt < sizeof(g.w.prev) / sizeof(void *));
	g.w.prev[g.w.prev_cnt] = g.w.cur;
	g.w.prev_cnt++;
	g.w.cur = win;
	return WIN_SWITCH;
}

/*
 * Switch back to previous window
 */
enum hyptop_win_action win_back(void)
{
	g.w.prev_cnt--;
	g.w.cur = g.w.prev[g.w.prev_cnt];
	return WIN_SWITCH;
}

/*
 * Switch to text mode
 */
void hyptop_text_mode(void)
{
	if (!g.c.initialized)
		return;
	g.c.initialized = 0;
	clear();
	refresh();
	endwin();
}

/*
 * Exit hyptop
 */
void __noreturn hyptop_exit(int rc)
{
	hyptop_text_mode();
	exit(rc);
}

/*
 * Initialize all modules and start first window
 */
int main(int argc, char *argv[])
{
	opts_parse(argc, argv);
	hyptop_helper_init();
	sd_init();
	l_dg_init();
	opt_verify_systems();
	l_term_init();

	win_sys_list_init();
	win_sys_init();
	g.win_cpu_types = win_cpu_types_new();
	l_event_loop();
	return 0;
}
