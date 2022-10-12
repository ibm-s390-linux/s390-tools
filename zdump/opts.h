/*
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef OPTS_H
#define OPTS_H

#include "zg.h"

/*
 * zgetdump options
 */
struct options {
	const char 	*prog_name;
	int		action_specified;
	enum zg_action	action;
	char		*device;
	/* If `output_path == NULL` the output is written to `stdout` */
	const char	*output_path;
	const char *key_path;
	char		*mount_point;
	int		fmt_specified;
	const char	*fmt;
	int		debug_specified;
	char		**argv_fuse;
	int		argc_fuse;
	const char	*select;
	int		select_specified;
	int		verbose;
};

extern const char *OPTS_SELECT_KDUMP;
extern const char *OPTS_SELECT_PROD;
extern const char *OPTS_SELECT_ALL;

void opts_parse(int argc, char *argv[], struct options *opts);
void opts_print_usage(const char *prog_name);
void __noreturn print_usage_exit(const char *prog_name);

#endif /* OPTS_H */
