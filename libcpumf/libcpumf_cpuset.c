/* Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "lib/libcpumf.h"
#include "lib/util_libc.h"

int libcpumf_cpuset(const char *parm, cpu_set_t *mask)
{
	char *cp, *buffer = util_strdup(parm);
	char *cp2 = buffer;
	int to, from, rc;

	/* Check for invalid characters, such as 11.12 instead 11-12
	 * but allow blanks and newline. Newline is appended
	 * when the string is taken from sysfs files, for example
	 * /sys/devices/system/cpu/online
	 */
	if (strspn(buffer, "0123456789-,\n ") != strlen(buffer)) {
		errno = EINVAL;
		rc = -1;
		goto out;
	}
	CPU_ZERO(mask);
	for (; (cp = strtok(buffer, ",")); buffer = NULL) {
		char *dash = strchr(cp, '-');		/* Range character? */
		bool is_ok;

		if (dash) {
			rc = sscanf(cp, "%d-%d", &from, &to);
			is_ok = rc == 2;
		} else {
			rc = sscanf(cp, "%d", &to);
			from = to;
			is_ok = rc == 1;
		}
		if (!is_ok) {
			errno = ERANGE;
			rc = -1;
			goto out;
		}
		for (; from <= to; ++from)
			CPU_SET(from, mask);
	}
	rc = 0;
out:
	free(cp2);
	return rc;
}

int libcpumf_cpuset_fn(const char *filename, cpu_set_t *mask)
{
	char *txt = NULL;
	ssize_t ret = -1;
	size_t len = 0;
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp)
		return ret;
	/* Read out file, one line expected */
	ret = getline(&txt, &len, fp);
	fclose(fp);
	if (ret > 0)
		ret = libcpumf_cpuset(txt, mask);
	free(txt);
	return ret;
}
