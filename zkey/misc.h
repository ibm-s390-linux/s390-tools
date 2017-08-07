/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Local helper functions
 *
 * Copyright 2017 IBM Corp.
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
 * Invalid command specified (for 'git' like tools)
 */
void misc_print_invalid_command(const char *command)
{
	warnx("Invalid command '%s'", command);
	util_prg_print_parse_error();
}

/**
 * An required parameter has not been specified
 *
 * @param[in] option  Parameter string
 */
void misc_print_required_parm(const char *parm_name)
{
	warnx("Parameter '%s' is required", parm_name);
	util_prg_print_parse_error();
}

#endif