/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_CMDLINE_OPTIONS_H
#define _HSAVMCORE_CMDLINE_OPTIONS_H

#include "config.h"

/*
 * Parses the given command-line options and adjusts the application's
 * configuration accordingly.
 */
void parse_cmdline_options(int argc, char *argv[], struct config *config);

#endif
