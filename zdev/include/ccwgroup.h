/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CCWGROUP_H
#define CCWGROUP_H

#include <stdbool.h>

#include "ccw.h"
#include "exit_code.h"
#include "misc.h"

#define CCWGROUP_BUS		"ccwgroup"
#define CCWGROUP_MAX_DEVIDS	3

struct ns_range_iterator;
struct subtype;
struct attrib;

struct ccwgroup_devid {
	struct ccw_devid devid[CCWGROUP_MAX_DEVIDS];
	unsigned int num;
} __attribute__ ((packed));

/**
 * ccwgroup_subtype_data - CCWGROUP subtype specific information
 * @ccwgroupdrv: The name of the CCWGROUP device driver for this subtype
 * @ccwdrv: The name of the CCW device driver for this subtype
 * @rootdrv: The name used by the driver in root_device_register.
 * @mod: The name of the main kernel module for this subtype
 * @num_devs: Number of CCW devices that are combined to form one device
 */
struct ccwgroup_subtype_data {
	const char *ccwgroupdrv;
	const char *ccwdrv;
	const char *rootdrv;
	const char *mod;
	unsigned int num_devs;
};

extern struct subtype ccwgroup_subtype;

extern struct attrib ccwgroup_attr_online;

/* ID handling. */
exit_code_t ccwgroup_parse_devid(struct ccwgroup_devid *, const char *, err_t);
bool ccwgroup_parse_devid_simple(struct ccwgroup_devid *, const char *);
bool ccwgroup_is_id_similar(const char *);
char *ccwgroup_devid_to_str(struct ccwgroup_devid *);
int ccwgroup_cmp_ids(const char *, const char *);
int ccwgroup_cmp_parsed_ids(const void *, const void *);
int ccwgroup_qsort_cmp(const void *, const void *);
struct ccwgroup_devid *ccwgroup_copy_devid(struct ccwgroup_devid *);
char *ccwgroup_get_partial_id(const char *);
bool ccwgroup_is_id_in_range(const char *id, const char *range);

/* Namespace helpers. */
void ccwgroup_range_next(struct ns_range_iterator *);
bool ccwgroup_compatible_namespace(struct namespace *);

#endif /* CCWGROUP_H */
