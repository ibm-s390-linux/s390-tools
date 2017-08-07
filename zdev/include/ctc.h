/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CTC_H
#define CTC_H

#include <stdbool.h>

#define	CTC_MOD_NAME		"ctcm"
#define CTC_CCWGROUPDRV_NAME	"ctcm"
#define CTC_CCWDRV_NAME		"ctcm"
#define CTC_ROOTDRV_NAME	"ctcm"
#define	CTC_NUM_DEVS		2

struct devtype;
struct namespace;
struct ccw_devid;

extern struct devtype ctc_devtype;
extern struct namespace ctc_namespace;

void ctc_exit(void);
bool ctc_confirm(struct ccw_devid *);

#endif /* CTC_H */
