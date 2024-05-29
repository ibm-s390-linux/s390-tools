/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AP_H
#define AP_H

#include "lib/util_list.h"

#define AP_MOD_NAME		"ap"
#define AP_NAME			"ap"
#define VFIO_AP_MOD_NAME	"vfio_ap"

struct devtype;
struct subtype;
struct namespace;

extern struct devtype ap_devtype;
extern struct subtype ap_subtype;
extern struct namespace ap_namespace;

struct mdev_cb_data {
	struct util_list *adapters;
	struct util_list *domains;
	bool typeap;
	bool autoconf;
	bool found_conflict;
};

#endif /* AP_H */
