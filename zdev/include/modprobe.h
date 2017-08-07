/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MODPROBE_H
#define MODPROBE_H

#include "exit_code.h"
#include "misc.h"

struct attrib;
struct setting_list;

exit_code_t modprobe_read_settings(const char *, const char *,
				   struct attrib **, struct setting_list **);
exit_code_t modprobe_write_settings(const char *, const char *,
				    struct setting_list *);

#endif /* MODPROBE_H */
