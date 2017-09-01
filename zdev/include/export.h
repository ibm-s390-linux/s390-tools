/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef EXPORT_H
#define EXPORT_H

#include <stdio.h>

#include "exit_code.h"
#include "misc.h"

struct device;
struct devtype;

typedef enum {
	export_device,
	export_devtype,
} export_t;

struct export_object {
	export_t type;
	union {
		struct devtype *dt;
		struct device *dev;
	} ptr;
};

struct export_object *object_new(export_t type, void *ptr);
exit_code_t export_write_device(FILE *, struct device *, config_t, int *);
exit_code_t export_write_devtype(FILE *, struct devtype *, config_t, int *);
exit_code_t export_read(FILE *, const char *, struct util_list *);

#endif /* EXPORT_H */
