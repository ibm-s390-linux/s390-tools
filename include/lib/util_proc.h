/*
 *   Scanner for the /proc files
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef LIB_UTIL_PROC_H
#define LIB_UTIL_PROC_H

#include <ctype.h>
#include <sys/types.h>

struct util_proc_part_entry {
	dev_t device;
	size_t blockcount;
	char *name;
};

struct util_proc_dev_entry {
	int blockdev;
	dev_t device;
	char *name;
};

#define UTIL_PROC_DEV_ENTRY_DASD     "dasd"
#define UTIL_PROC_DEV_ENTRY_VIRTBLK  "virtblk"
#define UTIL_PROC_DEV_ENTRY_SD       "sd"
#define UTIL_PROC_DEV_ENTRY_BLKEXT   "blkext"
#define UTIL_PROC_DEV_ENTRY_MD       "md"
#define UTIL_PROC_DEV_ENTRY_DM       "device-mapper"

int util_proc_part_get_entry(dev_t device, struct util_proc_part_entry *entry);
void util_proc_part_free_entry(struct util_proc_part_entry *entry);
int util_proc_dev_get_entry(dev_t dev, int blockdev,
			    struct util_proc_dev_entry *entry);
void util_proc_dev_free_entry(struct util_proc_dev_entry *entry);

#endif /* LIB_UTIL_PROC_H */
