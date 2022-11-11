/*
 * tunedasd - Adjust tunable parameters on DASD devices
 *
 * Functions to handle dasd specific operations
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DISK_H
#define DISK_H

#include <linux/hdreg.h>
#include <stdint.h>
#include <sys/types.h>


int check_cache (char* cache);
int check_no_cyl (char* no_cyl);
int check_add (char* device);
int check_prof_item (char* prof_item);
int disk_prof_sum (void);
int disk_get_cache (char* device);
int disk_set_cache (char* device, char* cache, char* no_cyl);
int disk_reserve (char* device);
int disk_release (char* device);
int disk_slock (char* device);
int disk_query_reserve_status(char* device);
int disk_profile (char* device, char* prof_item);
int disk_reset_prof(char *device);
int disk_reset_chpid(char *device, char *chpid);
int disk_copy_swap(char *device, char *copy_pair);

#endif /* not DISK_H */

