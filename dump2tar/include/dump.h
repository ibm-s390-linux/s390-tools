/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Main dump logic
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DUMP_H
#define DUMP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

#include "strarray.h"

#define NUM_EXCLUDE_TYPES	7

struct dump_spec {
	char *inname;
	char *outname;
	bool is_cmd;
};

struct dump_opts {
	bool add_cmd_status;
	bool append;
	bool dereference;
	bool exclude_type[NUM_EXCLUDE_TYPES];
	bool gzip;
	bool ignore_failed_read;
	bool no_eof;
	bool quiet;
	bool recursive;
	bool threaded;
	bool verbose;
	const char *output_file;
	int file_timeout;
	int timeout;
	long jobs;
	long jobs_per_cpu;
	size_t file_max_size;
	size_t max_buffer_size;
	size_t max_size;
	size_t read_chunk_size;
	struct strarray exclude;
	struct dump_spec *specs;
	unsigned int num_specs;
};

struct dump_opts *dump_opts_new(void);
int dump_opts_set_type_excluded(struct dump_opts *opts, char c);
void dump_opts_add_spec(struct dump_opts *opts, char *inname, char *outname,
			bool is_cmd);
void dump_opts_free(struct dump_opts *opts);

int dump_to_tar(struct dump_opts *opts);

#endif /* DUMP_H */
