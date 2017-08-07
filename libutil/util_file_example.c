/**
 * util_file_example - Example program for util_file
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
#include <unistd.h>

#include "lib/util_file.h"

/*
 * Write buffer to file and read it back again
 */
int main(void)
{
	char buf_wr[4096], buf_rd[4096];
	unsigned long long value_ull;
	long value_l;

	/* Generate input */
	sprintf(buf_wr, "Say something interesting!\nSecond line\n");
	printf("Write.....:\n%s", buf_wr);

	/* Write string to file */
	if (util_file_write_s(buf_wr, "/tmp/%s", "testfile")) {
		perror("util_file_write_s failed\n");
		return EXIT_FAILURE;
	}

	/* Read back first line of file */
	if (util_file_read_line(buf_rd, sizeof(buf_rd), "/tmp/%s", "testfile")) {
		perror("util_file_read_line failed\n");
		return EXIT_FAILURE;
	}
	printf("Read......: %s\n", buf_rd);

	/* Write long to file */
	printf("Write.....: %ld\n", 4711L);
	if (util_file_write_l(4711L, 10, "/tmp/%s", "testfile")) {
		perror("util_file_write failed\n");
		return EXIT_FAILURE;
	}
	/* Read back long from file */
	if (util_file_read_l(&value_l, 10, "/tmp/%s", "testfile")) {
		perror("util_file_read_l failed\n");
		return EXIT_FAILURE;
	}
	printf("Read......: %ld\n", value_l);

	/* Write long long hexadecimal to file */
	printf("Write.....: 0x%llx\n", 0x4712ULL);
	if (util_file_write_ull(0x4712ULL, 16, "/tmp/%s", "testfile")) {
		perror("util_file_write failed\n");
		return EXIT_FAILURE;
	}
	/* Read back long long hexadecimal from file */
	if (util_file_read_ull(&value_ull, 16, "/tmp/%s", "testfile")) {
		perror("util_file_read_ull failed\n");
		return EXIT_FAILURE;
	}
	printf("Read......: 0x%llx\n", value_ull);
	/* Remove file */
	unlink("/tmp/testfile");

	return EXIT_SUCCESS;
}
//! [code]
