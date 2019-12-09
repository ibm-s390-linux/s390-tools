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

#include "libc.h"

#include "boot/s390.h"
#include "boot/ipl.h"
#include "boot/linux_layout.h"


#define COMMAND_LINE_EXTRA       0xE000

#define STAGE3_FLAG_SCSI	 0x0001000000000000ULL
#define STAGE3_FLAG_KDUMP	 0x0002000000000000ULL

#define DEFAULT_PSW_LOAD	 0x0008000080010000UL
#define PSW_ADDR_MASK		 0x000000007FFFFFFFUL

#define UNSPECIFIED_ADDRESS		-1UL


extern unsigned long long _parm_addr;   /* address of parmline */
extern unsigned long long _initrd_addr; /* address of initrd */
extern unsigned long long _initrd_len;  /* length of initrd */
extern unsigned long long _load_psw;    /*  load psw of kernel */
extern unsigned long long _extra_parm;  /* use extra parm line mechanism? */
extern unsigned long long stage3_flags; /*  flags (e.g. STAGE3_FLAG_KDUMP) */
extern unsigned long long _image_len;   /* length of kernel */
extern unsigned long long _image_addr;  /* target address of kernel */
extern void kdump_stage3();

#endif /* STAGE3_H */
