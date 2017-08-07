/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef NET_H
#define NET_H

#include <stdbool.h>

struct util_list;
struct devnode;

bool net_add_linked_devnodes(struct util_list *, struct devnode *);
bool net_add_vlan_base(struct util_list *, struct devnode *);
bool net_add_bonding_base(struct util_list *, struct devnode *);

#endif /* NET_H */
