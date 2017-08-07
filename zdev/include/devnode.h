/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DEVNODE_H
#define DEVNODE_H

#include "misc.h"

struct util_list;

typedef enum {
	BLOCKDEV,
	CHARDEV,
	NETDEV,
} devnode_t;

struct devnode {
	devnode_t type;

	unsigned int major;
	unsigned int minor;

	char name[];
};

struct devnode *devnode_new(devnode_t, unsigned int, unsigned int,
			    const char *);
struct devnode *devnode_copy(struct devnode *);
void devnode_print(struct devnode *, int);

struct devnode *devnode_from_node(const char *, err_t);
struct devnode *devnode_from_devfile(const char *, const char *, devnode_t);
struct devnode *devnode_from_path(const char *path);

int devnode_cmp(struct devnode *, struct devnode *);
int devnode_add_block_from_sysfs(struct util_list *, const char *);
int devnode_add_net_from_sysfs(struct util_list *, const char *);
char *devnode_readlink(struct devnode *);

#endif /* DEVNODE_H */
