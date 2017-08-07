/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TABLE_ATTRIBS_H
#define TABLE_ATTRIBS_H

#include "misc.h"

struct util_list;
struct devtype;
struct subtype;
struct attrib;

struct table_attrib {
	struct subtype *st;
	struct attrib *attrib;
};

struct table_attrib *table_attrib_new(struct subtype *, struct attrib *);
void table_attribs_show(struct util_list *, int, int, struct devtype *);
void table_attribs_show_details(struct util_list *, struct devtype *);

#endif /* TABLE_ATTRIBS_H */
