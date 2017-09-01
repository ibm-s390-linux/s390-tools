/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "attrib.h"
#include "internal.h"
#include "misc.h"

struct attrib internal_attr_early = {
	.name = INTERNAL_ATTR_EARLY,
	.title = "Activate device early during boot",
	.desc = "Control the time of activation of a device:\n"
		"  0: Device is activated normally during boot\n"
		"  1: Device is activated early in the boot process, by the\n"
		"     initial RAM-disk\n",
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.internal = 1,
};

/* Return identifier of internal attribute with specified @name. */
const char *internal_get_name(const char *name)
{
	return name + sizeof(INTERNAL_ATTR_PREFIX) - 1;
}

/* Check if attribute is internal by name. */
bool internal_by_name(const char *name)
{
	return starts_with(name, INTERNAL_ATTR_PREFIX);
}
