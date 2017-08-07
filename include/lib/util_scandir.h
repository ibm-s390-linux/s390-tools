/**
 * @defgroup util_scandir_h util_scandir: Scandir interface
 * @{
 * @brief Scan a directory for matching entries
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_SCANDIR_H
#define LIB_UTIL_SCANDIR_H

#include <dirent.h>

int util_scandir_hexsort(const struct dirent **de1, const struct dirent **de2);
int util_scandir(struct dirent ***namelist,
			int compar_fn(const struct dirent **,
				      const struct dirent **),
			const char *path,
			const char *pattern, ...);
void util_scandir_free(struct dirent **de_vec, int count);

#endif /** LIB_UTIL_SCANDIR_H @} */
