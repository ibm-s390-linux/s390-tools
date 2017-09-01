/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef QETH_H
#define QETH_H

#define	QETH_MOD_NAME		"qeth"
#define QETH_CCWGROUPDRV_NAME	"qeth"
#define QETH_CCWDRV_NAME	"qeth"
#define QETH_ROOTDRV_NAME	"qeth"
#define	QETH_NUM_DEVS		3

struct devtype;
struct subtype;
struct namespace;

extern struct devtype qeth_devtype;
extern struct subtype qeth_subtype_qeth;
extern struct namespace qeth_namespace;

#endif /* QETH_H */
