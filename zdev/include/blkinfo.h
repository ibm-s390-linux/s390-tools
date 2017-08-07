/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef BLKINFO_H
#define BLKINFO_H

struct util_list;
struct devnode;

void blkinfo_exit(void);

struct util_list *blkinfo_get_ancestor_devnodes(struct devnode *);
struct util_list *blkinfo_get_same_uuid_devnodes(struct devnode *);
struct devnode *blkinfo_get_devnode_by_path(const char *);
void blkinfo_add_mountpoints(struct util_list *);
void blkinfo_add_swap_devnodes(struct util_list *);

#endif /* BLKINFO_H */
