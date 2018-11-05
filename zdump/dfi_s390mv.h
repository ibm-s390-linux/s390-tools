/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 multi-volume dump input format common structures
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef DFI_S390MV_H
#define DFI_S390MV_H

#include "lib/zt_common.h"

#define SYSFS_BUSDIR	"bus/ccw/devices"
#define MAX_VOLUMES	32

/*
 * Parameter for DASD multi-volume dump
 */
struct vol_parm {
	u16	devno;
	u32	start_blk;
	u32	end_blk;
	u8	blk_size;
	u8	end_sec;
	u8	num_heads;
} __attribute__ ((packed));

struct vol_parm_table {
	u64		timestamp;
	u16		vol_cnt;
	struct vol_parm	vol_parm[MAX_VOLUMES];
	u8		ssid[MAX_VOLUMES];
} __attribute__ ((packed));

/*
 * Device signature
 */
enum dev_sign {
	SIGN_INVALID	= 0,	/* No dumper installed */
	SIGN_VALID	= 1,	/* dumper installed, but volume not used */
	SIGN_ACTIVE	= 2,	/* dumper installed and volume userd */
};

static char *dev_sign_str[] = {"invalid", "valid", "active"};
#define dev_sign_str(x) (dev_sign_str[x])

/*
 * Device status
 */
enum dev_status {
	DEV_ONLINE	= 0,
	DEV_OFFLINE	= 1,
	DEV_UNDEFINED	= 2,
};

static char *dev_status_str[] = {"online", "offline", "undefined"};
#define dev_status_str(x) (dev_status_str[x])

#endif /* DFI_S390MV_H */
