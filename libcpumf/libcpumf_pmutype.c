/* Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "lib/libcpumf.h"

int libcpumf_pmutype(const char *dirname)
{
	FILE *file;
	char *fn;
	int ret;

	ret = asprintf(&fn, "%s/type", dirname);
	if (ret == -1)		/* No memory, errno set */
		return ret;
	file = fopen(fn, "r");
	free(fn);
	ret = -1;		/* Errno set on file open error */
	if (file) {
		/* Read out a single number from that file */
		if (fscanf(file, "%u", &ret) != 1)
			/* Unexpected format error, set errno */
			errno = -ERANGE;
		fclose(file);
	}
	return ret;
}
