/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <getopt.h>

#include "misc.h"
#include "opts.h"

static const char *get_name(const struct option *opt_list, int op)
{
	int i;

	for (i = 0; opt_list[i].name; i++) {
		if (opt_list[i].val == op)
			break;
	}

	return opt_list[i].name;
}

exit_code_t opts_check_conflict(int op, int selected[OPTS_MAX + 1],
				struct opts_conflict *conf_list,
				const struct option *opt_list)
{
	int i, j, b;

	for (i = 0; conf_list[i].op; i++) {
		for (j = 0; conf_list[i].conflicts[j]; j++) {
			if (conf_list[i].op == op &&
			    selected[conf_list[i].conflicts[j]]) {
				b = conf_list[i].conflicts[j];
				goto err;
			}
			if (conf_list[i].conflicts[j] == op &&
			    selected[conf_list[i].op]) {
				b = conf_list[i].op;
				goto err;
			}
		}
	}

	return EXIT_OK;

err:
	error("Cannot specify '--%s' together with '--%s'\n",
	      get_name(opt_list, op), get_name(opt_list, b));

	return EXIT_USAGE_ERROR;
}
