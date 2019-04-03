/*
 * dasd - Library for DASD related functions
 *
 * DASD related helper functions for accessing device information via sysfs
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_DASD_SYS_H
#define LIB_DASD_SYS_H

#include <stdio.h>

int dasd_sys_raw_track_access(char *);
int dasd_reset_chpid(char *, char *);
int dasd_get_host_access_count(char *device);

#endif /* LIB_DASD_SYS_H */
