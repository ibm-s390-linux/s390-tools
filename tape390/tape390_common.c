/*
 * tape_390 - Common functions
 *
 * Copyright IBM Corp. 2006, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "tape390_common.h"

#define PROC_DEVICES_FILE "/proc/devices"
#define PROC_DEVICES_FILE_WIDTH 100

char *prog_name;        /* Name of tool */

/*
 * Set name of tool
 */
void set_prog_name(char *name)
{
	prog_name = name;
}

/*
 * Check whether specified device node is tape device
 */
int is_not_tape(char *device)
{
	FILE* fh;
	char line[PROC_DEVICES_FILE_WIDTH];
	char last_line[PROC_DEVICES_FILE_WIDTH];
	int found = 0;
	struct stat stat_struct;

	if (stat(device, &stat_struct)) {
		ERRMSG("%s: Unable to get device status for "
		       "'%s'. \n", prog_name, device);
		perror("");
		return 1;
	}
	fh = fopen(PROC_DEVICES_FILE,"r");
	if (!fh) {
		ERRMSG("%s: WARNING: Cannot check for tape in file "
		       PROC_DEVICES_FILE ".\n", prog_name);
		perror("");
		return(0); /* check not possible, just continue */
	}
	while (!found && (fscanf(fh, "%s", line) != EOF)) {
		if (strcmp(line, "tape") == 0)
			found = 1;
		else
			strcpy(last_line, line);
	}
	fclose(fh);
	if (found && (major(stat_struct.st_rdev) ==
		      (unsigned int) atoi(last_line)))
		return (0);
	else {
		ERRMSG("%s: '%s' is not a tape device. \n", prog_name, device);
		return 1;
	}
}

/*
 * Open the tape device
 */
int open_tape(char *device)
{
	int fd;
	fd = open(device,O_RDONLY);
	if (fd < 0) {
		ERRMSG("%s: Cannot open device %s.\n",
		        prog_name,device);
		perror("");
		exit(EXIT_MISUSE);
	}
	return fd;
}
