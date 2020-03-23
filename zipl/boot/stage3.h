/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Main program for stage3 bootloader.
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STAGE3_H
#define STAGE3_H

#include "lib/zt_common.h"
#include "boot/s390.h"
#include "boot/ipl.h"
#include "boot/linux_layout.h"


#define STAGE3_FLAG_SCSI	 0x0001000000000000ULL
#define STAGE3_FLAG_KDUMP	 0x0002000000000000ULL

#define DEFAULT_PSW_LOAD	 0x0008000080010000UL

#define UNSPECIFIED_ADDRESS		-1UL

/* Stage 3 bootloader parameter structure */
/* Structure must not have any padding */
struct stage3_parms {
	unsigned long long parm_addr;   /* address of parmline */
	unsigned long long initrd_addr; /* address of initrd */
	unsigned long long initrd_len;  /* length of initrd */
	unsigned long long load_psw;    /*  load psw of kernel */
	unsigned long long extra_parm;  /* use extra parm line mechanism? */
	unsigned long long flags;       /* flags (e.g. STAGE3_FLAG_KDUMP) */
	unsigned long long image_len;   /* length of kernel */
	unsigned long long image_addr;  /* target address of kernel */
};
STATIC_ASSERT(sizeof(struct stage3_parms) == 8 * 8)

extern struct stage3_parms _stage3_parms;
extern void kdump_stage3();

#endif /* STAGE3_H */
