/**
 * util_libc_example - Example program for util_libc
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

//! [code]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_libc.h"
#include "lib/util_panic.h"

#define	EXAMPLE_WORD	"   /sys/devices/system/cpu    "

/*
 * Demonstrate that out of memory is automatically handled via panic()
 */
int main(void)
{
	unsigned long ulong_max = (unsigned long)-1;
	void *ptr;
	char *zeroes, *str;
	char buffer[sizeof(EXAMPLE_WORD)];

	strcat(buffer, EXAMPLE_WORD);
	fprintf(stderr, "Try to remove leading and trailing spaces from "
			"\"%s\"\nresult = \"%s\"\n", EXAMPLE_WORD,
			util_strstrip(buffer));

	/* Use util_strcat_realloc() for string concatenation */
	fprintf(stderr, "Try to concatenate \"Hello\",  \", \" and \"world!\": ");
	str = util_strdup("Hello");
	str = util_strcat_realloc(str, ", ");
	str = util_strcat_realloc(str, "world!");
	fprintf(stderr, "result = \"%s\"\n", str);
	free(str);

	/* One byte allocation should work */
	fprintf(stderr, "Try to allocate 1 byte: ");
	ptr = util_malloc(1);
	fprintf(stderr, "done\n");

	/* One byte zeroed-allocation should work */
	fprintf(stderr, "Try to allocate 1 byte initialized with zeroes: ");
	zeroes = util_zalloc(1);
	fprintf(stderr, "done\n");
	util_assert(*zeroes == 0, "Garbage found in zero initialized memory\n");

	/* The next allocation will probably fail */
	fprintf(stderr, "Try to allocate %lu bytes:\n", ulong_max);
	ptr = util_malloc(ulong_max);

	fprintf(stderr, "You should not see me (ptr=%p)!\n", ptr);
	return EXIT_FAILURE;
}
//! [code]
