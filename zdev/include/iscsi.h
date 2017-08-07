/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ISCSI_H
#define ISCSI_H

struct devnode;

struct devnode *iscsi_get_net_devnode(struct devnode *);

#endif /* ISCSI_H */
