/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef OPTS_H
#define OPTS_H

#include "exit_code.h"

#define OPTS_MAX	255
#define OPTS_CONFLICT(x, ...)    { .op = (x), \
				  .conflicts = ((int []) { __VA_ARGS__, 0 })}

struct opts_conflict {
	int op;
	int *conflicts;
};

struct option;

exit_code_t opts_check_conflict(int, int[OPTS_MAX + 1], struct opts_conflict *,
				const struct option *);

#endif /* OPTS_H */
