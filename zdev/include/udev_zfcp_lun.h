/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UDEV_ZFCP_LUN_H
#define UDEV_ZFCP_LUN_H

#include "exit_code.h"
#include "misc.h"

struct device;

void udev_zfcp_lun_add_device_ids(struct util_list *list, bool autoconf);
bool udev_zfcp_lun_exists(const char *id, bool autoconf);
exit_code_t udev_zfcp_lun_read_device(struct device *dev, bool autoconf);
exit_code_t udev_zfcp_lun_write_device(struct device *dev, bool autoconf);
exit_code_t udev_zfcp_lun_remove_rule(const char *id, bool autoconf);

#endif /* UDEV_ZFCP_LUN_H */
