/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef FIRMWARE_H
#define FIRMWARE_H

#include <stdio.h>
#include <stdbool.h>

#include "exit_code.h"
#include "misc.h"

struct util_list;

bool firmware_detect(FILE *fd);
exit_code_t firmware_read(FILE *fd, const char *filename, long skip,
			  config_t config, struct util_list *objects);

#endif /* FIRMWARE_H */
