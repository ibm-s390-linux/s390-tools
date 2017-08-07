/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TABLE_TYPES_H
#define TABLE_TYPES_H

#include "misc.h"

struct util_list;

exit_code_t table_types_show(struct util_list *, int, int);

#endif /* TABLE_TYPES_H */
