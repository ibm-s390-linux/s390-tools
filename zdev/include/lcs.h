/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LCS_H
#define LCS_H

#define	LCS_MOD_NAME		"lcs"
#define LCS_CCWGROUPDRV_NAME	"lcs"
#define LCS_CCWDRV_NAME		"lcs"
#define LCS_ROOTDRV_NAME	"lcs"
#define	LCS_NUM_DEVS		2

struct devtype;
struct namespace;

extern struct devtype lcs_devtype;
extern struct namespace lcs_namespace;

#endif /* LCS_H */
