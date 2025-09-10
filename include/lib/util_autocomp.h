/* SPDX-License-Identifier: MIT */
/*
 * autocomp - command line autocompletion
 *
 * Generating autocompletion scripts for bash and zsh
 * based on util_opt struct
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef LIB_UTIL_AUTOCOMP_H
#define LIB_UTIL_AUTOCOMP_H

#include "lib/util_opt.h"

void generate_autocomp(struct util_opt *opt_vec, char *tool_name);

#endif
