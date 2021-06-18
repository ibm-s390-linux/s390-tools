/*
 * util - Utility function library
 *
 * General helper functions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <limits.h>
#include <string.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"

/*
 * Print hexdump for buffer with variable group parameter
 */
void util_hexdump_grp(FILE *fh, const char *tag, const void *data, int grp,
		      int count, int indent)
{
	const char *buf = data;
	int i, first = 1;

	for (i = 0; i < count; i++) {
		if (first) {
			fprintf(fh, "%*s", indent, " ");
			if (tag)
				fprintf(fh, "%s: ", tag);
			fprintf(fh, "%08x: ", i);
			first = 0;
		}
		fprintf(fh, "%02x", buf[i]);
		if (i % 16 == 15 || i + 1 == count) {
			fprintf(fh, "\n");
			first = 1;
		} else if (i % grp == grp - 1) {
			fprintf(fh, " ");
		}
	}
}

/*
 * Print hexdump for buffer with fix grp parameter
 */
void util_hexdump(FILE *fh, const char *tag, const void *data, int count)
{
	util_hexdump_grp(fh, tag, data, sizeof(long), count, 0);
}

#define MAX_CHARS_PER_LINE 80

/*
 * Print string with indentation
 *
 * Print a string while accounting for a given indent value, characters per line
 * limit, and line breaks ('\n') within the string. The first line has to be
 * indented manually.
 *
 * @param[in] str    String that should be printed
 * @param[in] indent Indentation for printing
 */
void util_print_indented(const char *str, int indent)
{
	char *word, *line, *desc, *desc_ptr;
	int word_len, pos = indent;

	desc = desc_ptr = util_strdup(str);
	line = strsep(&desc, "\n");
	while (line) {
		word = strsep(&line, " ");
		pos = indent;
		while (word) {
			word_len = strlen(word);
			if (pos + word_len + 1 > MAX_CHARS_PER_LINE) {
				printf("\n%*s", indent, "");
				pos = indent;
			}
			if (pos == indent)
				printf("%s", word);
			else
				printf(" %s", word);
			pos += word_len + 1;
			word = strsep(&line, " ");
		}
		if (desc)
			printf("\n%*s", indent, "");
		line =  strsep(&desc, "\n");
	}
	printf("\n");
	free(desc_ptr);
}

/**
 * Determines the absolute name of an s390-tools system directory
 * (it could be data, or library directory)
 */
static const char *util_sysdir(const char *env_var, const char *default_dir)
{
	return secure_getenv(env_var) ?: default_dir;
}

/**
 * Determines the absolute name of a file installed in the s390-tools
 * system directory
 */
static const char *util_sysdir_path(const char *filename, const char *dirname)
{
	static char libdir_pathname[PATH_MAX];
	int ret;

	ret = snprintf(libdir_pathname, sizeof(libdir_pathname),
		       "%s/%s", dirname, filename);

	if (ret < 0 || ret >= (int)sizeof(libdir_pathname))
		errx(EXIT_FAILURE,
		     "Could not compose absolute pathname of %s and %s",
                     dirname, filename);
	return libdir_pathname;
}

/**
 * Determines the absolute name of a s390-tools library directory
 *
 * Resources are handled by the library
 *
 * @returns Pointer to a buffer, which contains the null-terminated name
 */
const char *util_libdir(void)
{
	return util_sysdir("S390TOOLS_LIBDIR", TOOLS_LIBDIR);
}

/**
 * Determines the absolute name of a file installed in the s390-tools
 * library directory by its relative name.
 *
 * Resources are handled by the library. A second call of this function
 * overwrites previously returned data. Care must be taken when attempting
 * to do a second call.
 *
 * @param[in] filename Null-terminated file name relative to the s390-tools
 *                     library directory
 * @returns Pointer to a buffer of PATH_MAX size, which contains the
 *          null-terminated absolute name
 */
const char *util_libdir_path(const char *filename)
{
	return util_sysdir_path(filename, util_libdir());
}

/**
 * Determines the absolute name of a s390-tools data directory
 *
 * Resources are handled by the library
 *
 * @returns Pointer to a buffer which contains the null-terminated name
 */
const char *util_datadir(void)
{
	return util_sysdir("S390TOOLS_DATADIR", TOOLS_DATADIR);
}

/**
 * Determines the absolute name of a file installed in the s390-tools
 * data directory by its relative name.
 *
 * Resources are handled by the library. A second call of this function
 * overwrites previously returned data. Care must be taken when attempting
 * to do a second call.
 *
 * @param[in] filename Null-terminated file name relative to the s390-tools
 *            data directory
 * @returns Pointer to a buffer of PATH_MAX size, which contains the
 *          null-terminated absolute name
 */
const char *util_datadir_path(const char *filename)
{
	return util_sysdir_path(filename, util_datadir());
}
