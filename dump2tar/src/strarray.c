/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Dynamically growing string arrays
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "misc.h"
#include "strarray.h"

/* Release resources associated with string array @array */
void free_strarray(struct strarray *array)
{
	unsigned int i;

	for (i = 0; i < array->num; i++)
		free(array->str[i]);
	free(array->str);
	array->str = NULL;
	array->num = 0;
}

/* Add string @str to string array @array */
void add_str_to_strarray(struct strarray *array, const char *str)
{
	array->str = mrealloc(array->str, sizeof(char *) * (array->num + 2));
	array->str[array->num + 1] = NULL;
	array->str[array->num] = mstrdup(str);
	array->num++;
}

/* Add string resulting from @fmt and additional arguments to @array */
void add_vstr_to_strarray(struct strarray *array, const char *fmt, ...)
{
	va_list args;
	char *str;

	va_start(args, fmt);
	util_vasprintf(&str, fmt, args);
	va_end(args);

	array->str = mrealloc(array->str, sizeof(char *) * (array->num + 2));
	array->str[array->num + 1] = NULL;
	array->str[array->num] = str;
	array->num++;
}

/* Add all lines in file at @filename to @array */
int add_file_to_strarray(struct strarray *array, const char *filename)
{
	FILE *fd;
	char *line = NULL;
	size_t line_size;
	int rc = EXIT_OK;

	fd = fopen(filename, "r");
	if (!fd) {
		mwarn("%s: Cannot open file", filename);
		return EXIT_RUNTIME;
	}

	while (!feof(fd) && !ferror(fd)) {
		if (getline(&line, &line_size, fd) == -1)
			continue;
		chomp(line, "\n");
		add_str_to_strarray(array, line);
	}
	if (ferror(fd))
		rc = EXIT_RUNTIME;
	free(line);

	fclose(fd);

	return rc;
}
