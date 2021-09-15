/*
 * @defgroup util_udev_h  util_udev: UDEV interface
 * @{
 * @brief Work with UDEV files
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_UDEV_H
#define LIB_UTIL_UDEV_H

#include <stdbool.h>
#include "lib/util_exit_code.h"
#include "lib/util_list.h"

/* Single key-operator-value entry in a udev rule line.*/
struct util_udev_entry_node {
	struct util_list_node node;
	char *key;
	char *op;
	char *value;
};

/* Single udev line in a udev rule file. */
struct util_udev_line_node {
	struct util_list_node node;
	struct util_list entries;
	char *line;
};

/* Udev rule file. */
struct util_udev_file {
	struct util_list lines;
};

util_exit_code_t util_udev_read_file(const char *path,
				     struct util_udev_file **file_ptr);
void util_udev_free_file(struct util_udev_file *file);
void util_udev_file_print(struct util_udev_file *file);

#endif /** LIB_UTIL_UDEV_H @} */
