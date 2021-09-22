/*
 * zdev_id - Determine system characteristics required by zdev udev rules
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	SYSINFO		"/proc/sysinfo"
#define	CMDLINE		"/proc/cmdline"
#define	WHITESPACE	" \t\n"

static void array_add(char ***array_p, int *num_p, const char *str)
{
	char **array = *array_p, *copy;
	int num = *num_p + 1;

	array = realloc(array, num * sizeof(char *));
	copy = strdup(str);
	if (!array || !copy)
		err(1, "Could not allocate memory");
	array[num - 1] = copy;
	*array_p = array;
	*num_p = num;
}

static void array_free(char **array, int num)
{
	int i;

	for (i = 0; i < num; i++)
		free(array[i]);
	free(array);
}

static void process_sysinfo(const char *filename)
{
	char *line = NULL, *substr, **cps = NULL;
	int is_dpm = 0, num_cps = 0, level, i;
	FILE *fd;
	size_t n;

	fd = fopen(filename, "r");
	if (!fd)
		err(1, "Could not open sysinfo file '%s'", filename);

	while (getline(&line, &n, fd) != -1) {
		if (sscanf(line, "LPAR %m[^:]", &substr) == 1) {
			if (strcmp(substr, "UUID") == 0) {
				/* Heuristic: only DPM LPARs have UUIDs. */
				is_dpm = 1;
			} else if (strcmp(substr, "Number") == 0) {
				array_add(&cps, &num_cps, "LPAR");
			}
			free(substr);
		} else if (sscanf(line, "VM%*d Control Program: %ms ",
				  &substr) == 1) {
			array_add(&cps, &num_cps, substr);
			free(substr);
		}
	}

	free(line);
	fclose(fd);

	/*
	 * ZDEV_NEST_LEVEL=n
	 *
	 * Virtualization nesting level of running system:
	 *  1: LPAR
	 *  2: first level VM
	 *  3: second level VM
	 */
	printf("ZDEV_NEST_LEVEL=%d\n", num_cps);

	/*
	 * ZDEV_HYPERVISOR_<n>=LPAR|z/VM|KVM/Linux
	 *
	 * Type of hypervisor that provides virtualization at nesting level <n>.
	 */
	for (i = 0; i < num_cps; i++) {
		/* Sysinfo lists VMs in reverse order .*/
		level = (i == 0) ? i : (num_cps - i);
		printf("ZDEV_HYPERVISOR_%d=\"%s\"\n", i, cps[level]);
	}
	array_free(cps, num_cps);

	/*
	 * ZDEV_IS_DPM=0|1
	 *
	 * Indicator if top-level LPAR is managed by Dynamic Partition
	 * Manager (DPM):
	 *  0: Classic mode
	 *  1: DPM mode
	 */
	printf("ZDEV_IS_DPM=%d\n", is_dpm);
}

static void process_cmdline(const char *filename)
{
	char *line = NULL, *substr, *next = NULL, *value;
	int no_auto = 0;
	size_t n;
	FILE *fd;

	fd = fopen(filename, "r");
	if (!fd)
		err(1, "Could not open cmdline file '%s'", filename);

	if (getline(&line, &n, fd) == -1)
		goto out;

	for (substr = strtok_r(line, WHITESPACE, &next); substr;
	     substr = strtok_r(NULL, WHITESPACE, &next)) {
		if (sscanf(substr, "rd.zdev=%ms ", &value) != 1)
			continue;
		if (strstr(value, "no-auto"))
			no_auto = 1;

		free(value);
	}

out:
	free(line);
	fclose(fd);

	/*
	 * ZDEV_NO_AUTO=0|1
	 *
	 * Indicator if auto-configuration is requested.
	 *  0: Perform auto-configuration
	 *  1: Skip auto-configuration
	 */
	printf("ZDEV_NO_AUTO=%d\n", no_auto);
}

int main(int argc, char *argv[])
{
	char *sysinfo, *cmdline;

	sysinfo = argc < 2 ? SYSINFO : argv[1];
	cmdline = argc < 3 ? CMDLINE : argv[2];

	process_sysinfo(sysinfo);
	process_cmdline(cmdline);

	return 0;
}
