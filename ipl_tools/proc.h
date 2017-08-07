/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * Scanner for /proc files
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PROC_H
#define PROC_H

#include <ctype.h>
#include <sys/types.h>

struct proc_part_entry {
	dev_t device;
	size_t blockcount;
	char* name;
};

struct proc_dev_entry {
	int blockdev;
	dev_t device;
	char *name;
};

int proc_part_get_entry(dev_t device, struct proc_part_entry* entry);
void proc_part_free_entry(struct proc_part_entry* entry);
int proc_dev_get_entry(dev_t dev, int blockdev, struct proc_dev_entry* entry);
void proc_dev_free_entry(struct proc_dev_entry* entry);

#endif /* not PROC_H */
