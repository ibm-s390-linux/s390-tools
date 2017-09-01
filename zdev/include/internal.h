/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef INTERNAL_H
#define INTERNAL_H

#include <stdbool.h>

#include "attrib.h"

#define INTERNAL_ATTR_PREFIX	"zdev:"
#define	INTERNAL_ATTR_EARLY	INTERNAL_ATTR_PREFIX "early"

extern struct attrib internal_attr_early;

const char *internal_get_name(const char *name);
bool internal_by_name(const char *name);

#endif /* INTERNAL_H */
