/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Local helper functions
 *
 * Copyright IBM Corp. 2017, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MISC_H
#define MISC_H

#include <err.h>

#include "lib/util_prg.h"

/**
 * Command is missing (for 'git' like tools)
 */
static inline void misc_print_missing_command(void)
{
	warnx("Command is required");
	util_prg_print_parse_error();
}

/**
 * Subcommand is missing
 */
static inline void misc_print_missing_sub_command(void)
{
	warnx("Subcommand is required");
	util_prg_print_parse_error();
}

/**
 * Invalid command specified (for 'git' like tools)
 */
static void misc_print_invalid_command(const char *command)
{
	warnx("Invalid command '%s'", command);
	util_prg_print_parse_error();
}

/**
 * An required parameter has not been specified
 *
 * @param[in] parm_name  Parameter string
 */
static void misc_print_required_parm(const char *parm_name)
{
	warnx("Parameter '%s' is required", parm_name);
	util_prg_print_parse_error();
}

/**
 * An required parameter has not been specified
 *
 * @param[in] parm_name1  Parameter string 1
 * @param[in] parm_name2  Parameter string 2
 */
static void misc_print_required_parms(const char *parm_name1,
				      const char *parm_name2)
{
	warnx("Parameter '%s' or '%s' is required", parm_name1, parm_name2);
	util_prg_print_parse_error();
}

#endif
