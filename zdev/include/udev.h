/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UDEV_H
#define UDEV_H

#include "lib/util_list.h"
#include "exit_code.h"

extern int udev_need_settle;
extern int udev_no_settle;

/* Single key-operator-value entry in a udev rule line.*/
struct udev_entry_node {
	struct util_list_node node;
	char *key;
	char *op;
	char *value;
};

/* Single udev line in a udev rule file. */
struct udev_line_node {
	struct util_list_node node;
	struct util_list entries;
	char *line;
};

/* Udev rule file. */
struct udev_file {
	struct util_list lines;
};

exit_code_t udev_read_file(const char *, struct udev_file **);
void udev_free_file(struct udev_file *);
void udev_file_print(struct udev_file *);

void udev_get_device_ids(const char *type, struct util_list *list,
			 bool autoconf);
exit_code_t udev_remove_rule(const char *type, const char *id, bool autoconf);

void udev_settle(void);

#endif /* UDEV_H */
