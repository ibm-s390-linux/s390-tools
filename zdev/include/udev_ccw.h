/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UDEV_CCW_H
#define UDEV_CCW_H

#include "exit_code.h"
#include "misc.h"

struct device;

bool udev_ccw_exists(const char *, const char *);
exit_code_t udev_ccw_read_device(struct device *);
exit_code_t udev_ccw_write_device(struct device *);
exit_code_t udev_ccw_write_cio_ignore(const char *);

#endif /* UDEV_CCW_H */
