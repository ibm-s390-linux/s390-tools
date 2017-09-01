/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UDEV_CCWGROUP_H
#define UDEV_CCWGROUP_H

#include "exit_code.h"
#include "misc.h"

struct device;
struct util_list;

bool udev_ccwgroup_exists(const char *type, const char *id, bool autoconf);
exit_code_t udev_ccwgroup_read_device(struct device *dev, bool autoconf);
exit_code_t udev_ccwgroup_write_device(struct device *dev, bool autoconf);
void udev_ccwgroup_add_device_ids(const char *type, struct util_list *list,
				  bool autoconf);
exit_code_t udev_ccwgroup_remove_rule(const char *type, const char *id,
				      bool autoconf);

#endif /* UDEV_CCWGROUP_H */
