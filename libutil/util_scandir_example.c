/**
 * util_dir_example - Example program for util_dir
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

//! [code]
#include <stdio.h>
#include <stdlib.h>

#include "lib/util_scandir.h"

/*
 * Print real sysfs cpu directory contents
 */
static void show_cpu_dir(const char *sys_cpu_path)
{
	char cmd_ls[256];

	sprintf(cmd_ls, "ls -l %s", sys_cpu_path);
	printf("$ %s\n", cmd_ls);
	fflush(stdout);
	if (system(cmd_ls)) {
		perror("system() failed");
		exit(EXIT_FAILURE);
	}
	printf("\n");
}

/*
 * Show all CPUs on Linux system
 */
int main(void)
{
	struct dirent **de_vec;
	int count, i;
	const char *path = "/sys/devices/system/cpu";
	const char *prefix = "cpu";

	show_cpu_dir(path);

	/*
	 * Process all files that match regular expression "cpu[0-9]+"
	 * and sort them alphabetically. Note that the regular expression
	 * is constructed with a variable argument list.
	 */
	count = util_scandir(&de_vec, alphasort, path, "%s[0-9]+", prefix);
	if (count == -1) {
		perror("util_dir_scan failed");
		return EXIT_FAILURE;
	}

	/* Print all directories */
	printf("Found cpus:\n\n");
	for (i = 0; i < count; i++) {
		if (de_vec[i]->d_type != DT_DIR)
			continue;
		printf(" - %s\n", de_vec[i]->d_name);
	}

	/* Free directory entries */
	util_scandir_free(de_vec, count);

	return EXIT_SUCCESS;
}
//! [code]
