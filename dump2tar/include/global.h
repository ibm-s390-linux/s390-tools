/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Global variables
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef GLOBAL_H
#define GLOBAL_H

#include <stdbool.h>

extern bool global_threaded;
extern bool global_debug;
extern bool global_verbose;
extern bool global_quiet;
extern bool global_timestamps;

#endif /* GLOBAL_H */
