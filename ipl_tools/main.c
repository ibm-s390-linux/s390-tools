/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * Main functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/zt_common.h"
#include "ipl_tools.h"

struct globals g;

void print_help_hint_exit(void)
{
	fprintf(stderr, "Try '%s' --help' for more information.\n",
		g.prog_name);
	exit(1);
}

void print_version_exit(void)
{
	printf("%s: Linux on System z shutdown actions version %s\n",
		g.prog_name, RELEASE_STRING);
	printf("Copyright IBM Corp. 2008, 2017\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	strncpy(g.prog_name, argv[0], sizeof(g.prog_name));
	if (strstr(argv[0], "chreipl") != NULL) {
		cmd_chreipl(argc, argv);
		return 0;
	}
	if (strstr(argv[0], "chshut") != NULL) {
		cmd_chshut(argc, argv);
		return 0;
	}
	if (strstr(argv[0], "lsreipl") != NULL) {
		cmd_lsreipl(argc, argv);
		return 0;
	}
	if (strstr(argv[0], "lsshut") != NULL) {
		cmd_lsshut(argc, argv);
		return 0;
	}
	ERR_EXIT("Invalid program name \"%s\"", argv[0]);
	return 1;
}
