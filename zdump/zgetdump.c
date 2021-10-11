/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Main functions
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "zgetdump.h"
#include "dt.h"
#include "dfi.h"
#include "dfo.h"
#include "stdout.h"
#include "zfuse.h"

/*
 * Globals
 */
struct zgetdump_globals g;

/*
 * Signal handler for exiting zgetdump (the atexit handler will do the work)
 */
static void sig_exit(int sig)
{
	(void) sig;

	STDERR("\n"); /* E.g. to get newline after '^C' */
	ERR_EXIT("Got signal %i, exiting...", sig);
}

/*
 * Install signal handler
 */
static void sig_handler_init(void)
{
	struct sigaction sigact = { 0 };

	/* Ignore signals SIGUSR1 and SIGUSR2 */
	if (sigemptyset(&sigact.sa_mask) < 0)
		goto fail;
	sigact.sa_handler = SIG_IGN;
	if (sigaction(SIGUSR1, &sigact, NULL) < 0)
		goto fail;
	if (sigaction(SIGUSR2, &sigact, NULL) < 0)
		goto fail;

	/* Exit on SIGINT, SIGTERM, SIGHUP, ... */
	if (sigemptyset(&sigact.sa_mask) < 0)
		goto fail;
	sigact.sa_handler = sig_exit;
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
 * Check if dump contains kdump dump and production system dump
 */
static void kdump_select_check(void)
{
	static char *msg =
		"The dump contains \"kdump\" and \"production system\"\n"
		"          Access \"production system\" with \"-s prod\"\n"
		"          Access \"kdump\" with \"-s kdump\"\n"
		"          Access the complete dump with \"-s all\"\n"
		"          Send both dumps to your service organization";

	if (g.opts.select_specified)
		return;
	if (!dfi_kdump_base())
		return;
	ERR_EXIT("%s", msg);
}

/*
 * Run "--umount" action
 */
static int do_umount(void)
{
	zfuse_umount();
	return 0;
}

/*
 * Run "--device" action
 */
static int do_device_info(void)
{
	dt_init();
	dt_info_print();
	return 0;
}

/*
 * Run "--info" action
 */
static int do_dump_info(void)
{
	if (dfi_init() != 0) {
		dfi_info_print();
		STDERR("\nERROR: Dump is not complete\n");
		zg_exit(1);
	}
	kdump_select_check();
	dfi_info_print();
	dfi_exit();
	return 0;
}

/*
 * Run "--mount" action
 */
static int do_mount(void)
{
	int rc;

	if (dfi_init() != 0)
		ERR_EXIT("Dump cannot be processed (is not complete)");
	dfo_init();
	kdump_select_check();
	rc = zfuse_mount_dump();
	dfi_exit();
	return rc;
}

/*
 * Run "copy to stdout" action
 */
static int do_stdout(void)
{
	int rc;

	if (dfi_init() != 0)
		ERR_EXIT("Dump cannot be processed (is not complete)");
	dfo_init();
	kdump_select_check();
	rc = stdout_write_dump();
	dfi_exit();
	return rc;
}

/*
 * The zgetdump main function
 */
int main(int argc, char *argv[])
{
	sig_handler_init();
	opts_parse(argc, argv, &g.opts);

	if (dfo_set(g.opts.fmt) != 0)
		ERR_EXIT("Invalid target format \"%s\" specified", g.opts.fmt);

	switch (g.opts.action) {
	case ZG_ACTION_STDOUT:
		return do_stdout();
	case ZG_ACTION_DUMP_INFO:
		return do_dump_info();
	case ZG_ACTION_DEVICE_INFO:
		return do_device_info();
	case ZG_ACTION_MOUNT:
		return do_mount();
	case ZG_ACTION_UMOUNT:
		return do_umount();
	}
	ABORT("Invalid action: %i", g.opts.action);
}
