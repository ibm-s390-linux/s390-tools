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
#include "lib/util_udev.h"

struct attrib;
struct setting_list;

extern int udev_need_settle;
extern int udev_no_settle;

#define SITE_BLOCK_START	"# site_start"
#define SITE_BLOCK_END		"# site_end"

bool udev_file_is_empty(struct util_udev_file *file);

void udev_get_device_ids(const char *type, struct util_list *list,
			 bool autoconf);
exit_code_t udev_remove_rule(const char *type, const char *id, bool autoconf);

void udev_settle(void);

void udev_add_internal_from_entry(struct setting_list *list,
				  struct util_udev_entry_node *entry,
				  struct attrib **attribs);

exit_code_t udev_write_site_rule(void);
bool is_legacy_rule(struct util_udev_file *file);

#endif /* UDEV_H */
