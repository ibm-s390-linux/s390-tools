/*
 * util - Utility function library
 *
 * Scan a directory for matching entries
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

/// @cond
struct util_scandir_filter {
	regex_t reg_buf;
};
/// @endcond

/*
 * Check directory entry
 */
static int filter_regexp(const struct dirent *de, void *data)
{
	struct util_scandir_filter *filter = data;
	regmatch_t pmatch[1];

	if (regexec(&filter->reg_buf, de->d_name, (size_t) 1, pmatch, 0) == 0)
		return 1;
	return 0;
}

typedef int (*__compar_fn_t) (const void *, const void *);

/*
 * Return sorted "struct dirent" array for entries that match "filter_fn"
 */
static int __scandir(struct dirent ***de_vec, const char *path,
		     int (*filter_fn)(const struct dirent *, void *),
		     void *filter_data,
		     int (*compar_fn)(const struct dirent **,
				      const struct dirent **))
{
	struct dirent *de, *de_new, **de_vec_new = NULL;
	int count = 0;
	DIR *dirp;

	*de_vec = NULL;
	dirp = opendir(path);
	if (!dirp)
		return -1;
	while ((de = readdir(dirp))) {
		if (filter_fn(de, filter_data) == 0)
			continue;
		de_new = util_malloc(sizeof(*de_new));
		*de_new = *de;
		de_vec_new = realloc(de_vec_new, sizeof(void *) * (count + 1));
		de_vec_new[count++] = de_new;
	}
	closedir(dirp);
	if (compar_fn)
		qsort(de_vec_new, count, sizeof(void *),
		      (__compar_fn_t) compar_fn);
	*de_vec = de_vec_new;
	return count;
}

/*
 * Return sorted "struct dirent" array for entries that match "pattern"
 */
static int scandir_regexp(struct dirent ***de_vec, const char *path,
			  const char *pattern,
			  int compar_fn(const struct dirent **,
					const struct dirent **))
{
	struct util_scandir_filter filter;
	char err_buf[256];
	int count, rc;

	rc = regcomp(&filter.reg_buf, pattern, REG_EXTENDED);
	if (rc) {
		regerror(rc, &filter.reg_buf, err_buf, sizeof(err_buf));
		util_panic("Function regcomp(%s) failed: %s\n", pattern,
			   err_buf);
	}
	count = __scandir(de_vec, path, filter_regexp, &filter, compar_fn);
	regfree(&filter.reg_buf);
	return count;
}

/**
 * Compare two hexadecimal string dirents numerically
 *
 * @param[in] de1  First directory entry
 * @param[in] de2  Second directory entry
 *
 * @retval -1 de1 < de2
 * @retval  0 de1 = de2
 * @retval  1 de1 > de2
 */
int util_scandir_hexsort(const struct dirent **de1, const struct dirent **de2)
{
	unsigned long val1 = strtoul((*de1)->d_name, NULL, 16);
	unsigned long val2 = strtoul((*de2)->d_name, NULL, 16);

	if (val1 < val2)
		return -1;
	if (val1 == val2)
		return 0;
	return 1;
}

/**
 * Construct a list of direcotry entries using POSIX regular expressions
 *
 * A desired directory in sysfs is scanned for entries of a given name
 * pattern. The name pattern is constructed with sprintf() using a format
 * string and variable argument list. After constructing the pattern it
 * is used with regcomp() and regexec() to find matching entries.
 * The returned list of matches consist of an array of pointers to
 * directory entries. The entries as well as the pointer array itself are
 * allocated by the function and has to be released by the user via free.
 *
 * @param[out] de_vec         Vector of matched directory entries, or NULL
 * @param[in]  compar_fn      Callback function for sorting the entry list
 * @param[in]  path           Path to the directory to scan
 * @param[in]  fmt            Format string, describes the search pattern as POSIX regex
 * @param[in]  ...            Values for format string
 *
 * @returns    Number of returned directory entries, or -1 on error
 */
int util_scandir(struct dirent ***de_vec,
		 int compar_fn(const struct dirent **first,
			       const struct dirent **second),
		 const char *path,
		 const char *fmt, ...)
{
	char *pattern;
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vasprintf(&pattern, fmt, ap);
	va_end(ap);
	if (rc < 0)
		return -1;
	rc = scandir_regexp(de_vec, path, pattern, compar_fn);
	free(pattern);

	return rc;
}

/**
 * Free list of directory entries
 *
 * @param[in] de_vec  Vector of directory entries
 * @param[in] count   Count of directory entries
 */
void util_scandir_free(struct dirent **de_vec, int count)
{
	util_ptr_vec_free((void **) de_vec, count);
}
