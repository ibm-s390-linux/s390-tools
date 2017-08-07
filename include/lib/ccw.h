/*
 * ccw - Channel Command Word library (traditional I/O)
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef LIB_CCW_H
#define LIB_CCW_H

#include <stdbool.h>

#include "lib/zt_common.h"

/**
 * ccw_devid - CCW device ID
 */
struct ccw_devid {
	/** Channel Subsystem ID */
	unsigned int cssid:8;
	/** Subchannel set ID */
	unsigned int ssid:8;
	/** Device number */
	unsigned int devno:16;
} __packed;

/**
 * Initialize ccw_devid structure
 *
 * @param[in,out] devid   Pointer to ccw_devid structure to be initialized
 * @param[in]     cssid   Channel Subsystem ID
 * @param[in]     ssid    Subchannel set ID
 * @param[in]     devno   Device number
 */
static inline void ccw_devid_init(struct ccw_devid *devid,
				  unsigned int cssid, unsigned int ssid,
				  unsigned int devno)
{
	devid->cssid = cssid;
	devid->ssid = ssid;
	devid->devno = devno;
}

bool ccw_parse_str(struct ccw_devid *devid, const char *id);

#endif
