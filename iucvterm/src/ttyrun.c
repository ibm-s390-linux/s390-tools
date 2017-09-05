/*
 * ttyrun - Start a program if a specified terminal device is available
 *
 *
 * ttyrun is typically used to prevent a respawn through the init(8)
 * program when a terminal is not available.
 * ttyrun runs the specific program if the specified terminal device
 * can be opened successfully.  Otherwise the program enters a sleep or
 * exits with a specified return value.
 *
 * Example: To start /sbin/agetty on terminal device hvc1, use:
 *
 *	 h1:2345:respawn:/sbin/ttyrun hvc1 /sbin/agetty -L 9600 %t linux
 *
 * Note: %t is resolved to the terminal device "hvc1" before /sbin/agetty
 *	 is started.
 *
 * Return values:
 *	   1 - invalid argument or parameter is missing
 *	   2 - terminal does not resolve to a terminal device
 *	   3 - starting the specified program failed
 *    1..255 - terminal is not available and the return code is
 *	       specified with the -e option
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/zt_common.h"


#define TTY_ESCAPE_STR		"%t"

#define EXIT_INVALID_ARG	1
#define EXIT_NO_TERMINAL	2
#define EXIT_EXEC_FAILED	3


static const char usage[] =
"Usage: %s [-e status] <term> <program> [<program_options>]\n"
"       %s [-h|--help] [-v|--version]\n"
"\n"
"Start the program if the specified terminal device is available.\n"
"If the terminal device cannot be opened, sleep until a signal is received\n"
"that causes an exit or exit with the return value specified with status.\n"
"\n"
"-e, --exitstatus     Specifies an exit status in the range 1 to 255.\n"
"-V, --verbose        Displays syslog messages.\n"
"-h, --help           Displays this help, then exits.\n"
"-v, --version        Displays version information, then exits.\n";

static void __noreturn help_exit(const char *prg)
{
	printf(usage, prg, prg);
	exit(EXIT_SUCCESS);
}

static void __noreturn version_exit(const char *prg)
{
	printf("%s: Start a program if a terminal device is available, "
	       "version %s\n", prg, RELEASE_STRING);
	printf("Copyright IBM Corp. 2010, 2017\n");
	exit(EXIT_SUCCESS);
}

static void err_exit(const char *prg, const char *msg)
{
	fprintf(stderr, "%s: %s\n", prg, msg);
	exit(EXIT_INVALID_ARG);
}

static void wait_and_exit(void)
{
	/* sleep until a signal is received, then exit */
	pause();
	exit(EXIT_SUCCESS);
}

static const struct option prog_opts[] = {
	{ "help",	no_argument, NULL, 'h'},
	{ "version",	no_argument, NULL, 'v'},
	{ "exitstatus",	required_argument, NULL, 'e'},
	{ "verbose",	no_argument, NULL, 'V'},
	{ NULL,		no_argument, NULL,  0 },
};

int main(int argc, char *argv[])
{
	int rc, tty, i, c, index, done, term_index, verbose;
	char terminal[PATH_MAX] = "";
	unsigned long exitstatus;


	/* parse command options */
	if (argc == 1)
		err_exit(argv[0], "One or more options are required but missing");

	exitstatus = done = term_index = verbose = 0;
	while (!done) {
		c = getopt_long(argc, argv, "-hve:V", prog_opts, NULL);
		switch (c) {
		case -1:
			done = 1;
			break;
		case 1:
			/* the first non-optional argument must be the
			 * terminal device */
			if (!strncmp(optarg, "/", 1))
				strncpy(terminal, optarg, PATH_MAX - 1);
			else
				snprintf(terminal, PATH_MAX, "/dev/%s", optarg);
			terminal[PATH_MAX - 1] = 0;
			term_index = optind - 1;
			done = 1;
			break;
		case 'e':
			errno = 0;
			exitstatus = strtoul(optarg, (char **) NULL, 10);
			if (errno == ERANGE)
				err_exit(argv[0], "The exit status must be "
					"an integer in the range 1 to 255");

			if (!exitstatus || exitstatus > 255)
				err_exit(argv[0], "The exit status must be "
					 "in the range 1 to 255");
			break;
		case 'V':
			verbose = 1;
			break;
		case 'h':
			help_exit(argv[0]);
		case 'v':
			version_exit(argv[0]);
		case '?':
			fprintf(stderr, "Try %s --help for more information\n",
				argv[0]);
			exit(EXIT_INVALID_ARG);
		}
	}
	index = optind;

	/* check terminal */
	if (!strlen(terminal))
		err_exit(argv[0], "You must specify the name of "
				  "a terminal device");

	/* any program to start? */
	if (index == argc)
		err_exit(argv[0], "You must specify a program to start");

	/* open and check terminal device */
	tty = open(terminal, O_NOCTTY | O_RDONLY | O_NONBLOCK);
	if (tty == -1) {
		if (verbose) {
			openlog(argv[0], LOG_PID, LOG_DAEMON);
			syslog(LOG_INFO, "Could not open tty %s (%s)",
			       terminal, strerror(errno));
			closelog();
		}

		/* enter wait or exit */
		if (exitstatus)
			exit(exitstatus);
		wait_and_exit();
	}
	rc = !isatty(tty);
	close(tty);
	if (rc)
		exit(EXIT_NO_TERMINAL);

	/* start getty program */
	for (i = index; i < argc; i++)
		if (!strcmp(argv[i], TTY_ESCAPE_STR) && term_index)
			argv[i] = argv[term_index];
	if (execv(argv[index], argv + index))
		exit(EXIT_EXEC_FAILED);

	exit(EXIT_SUCCESS);
}
