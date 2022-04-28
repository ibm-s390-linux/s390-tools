/* Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_path.h"
#include "lib/util_scandir.h"
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

int libcpumf_pmuname(unsigned int wanted_type, char **name)
{
	struct dirent **de_vec;
	unsigned int type;
	char *dirname;
	char *path;
	int count;
	int rc;

	path = util_path_sysfs("devices");
	count = util_scandir(&de_vec, alphasort, path, "(pai|cpum_).*");
	free(path);

	*name = NULL;
	for (int i = 0; i < count; i++) {
		if (de_vec[i]->d_type == DT_DIR) {
			dirname = de_vec[i]->d_name;
			path = util_path_sysfs("devices/%s/type", dirname);
			rc = util_file_read_ui(&type, 10, path);
			if (rc)
				warn("Failed to open %s", path);
			free(path);
			if (!rc && type == wanted_type) {
				*name = util_strdup(dirname);
				goto out;
			}
		}
	}
out:
	util_scandir_free(de_vec, count);
	return *name ? 0 : -1;
}
