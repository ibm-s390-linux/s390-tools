/*
 * s390-tools/zipl/include/zipl.h
 *   zSeries Initial Program Loader tool.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef ZIPL_H
#define ZIPL_H

#include <stdint.h>
#include "lib/zt_common.h"

#define ZIPL_MAGIC			"zIPL"
#define ZIPL_MAGIC_SIZE			4
#define DISK_LAYOUT_ID			0x00000001

#define ZIPL_STAGE2_LOAD_ADDRESS        0x2000
#define ZIPL_STAGE3_ENTRY_ADDRESS	0xa050LL
#define DEFAULT_IMAGE_ADDRESS		0x10000LL
#define KDUMP_IMAGE_ADDRESS		0x10010LL
#define DEFAULT_STAGE3_ADDRESS          0xa000LL
#define MINIMUM_ADDRESS 		0x10000LL
#define ADDRESS_LIMIT 			0x80000000LL
#define ADDRESS_LIMIT_KDUMP		0x2000000UL /* HSA size: 32 MiB */
#define UNSPECIFIED_ADDRESS		-1ULL
#define MAXIMUM_PARMLINE_SIZE 		0x380
#define MAXIMUM_PHYSICAL_BLOCKSIZE 	0x1000

#define PSW_ADDRESS_MASK		0x000000007fffffffLL
#define PSW_LOAD                        0x0008000080000000LL
#define PSW_DISABLED_WAIT               0x000a000000000000LL

#define KERNEL_HEADER_SIZE		65536
#define BOOTMAP_FILENAME		"bootmap"
#define BOOTMAP_TEMPLATE_FILENAME	"bootmap_temp.XXXXXX"

#define DEFAULTBOOT_SECTION		"defaultboot"

#define ZIPL_CONF_VAR			"ZIPLCONF"
#define ZIPL_DEFAULT_CONF		"/etc/zipl.conf"
#define ZIPL_DEFAULT_BLSDIR		"/boot/loader/entries"

#define MENU_DEFAULT_PROMPT		0
#define MENU_DEFAULT_TIMEOUT		0

#define FSDUMP_IMAGE	STRINGIFY(ZFCPDUMP_DIR) "/" STRINGIFY(ZFCPDUMP_FS_IMAGE)
#define FSDUMP_RAMDISK	STRINGIFY(ZFCPDUMP_DIR) "/" STRINGIFY(ZFCPDUMP_FS_RD)
#define FSDUMP_PART_IMAGE	STRINGIFY(ZFCPDUMP_DIR) "/" \
					STRINGIFY(ZFCPDUMP_PART_IMAGE)
#define FSDUMP_PART_RAMDISK	STRINGIFY(ZFCPDUMP_DIR) "/" \
					STRINGIFY(ZFCPDUMP_PART_RD)

#define MAX_DUMP_VOLUMES		32

/* Internal component load address type */
typedef uint64_t address_t;

/* Type for address calculations */
#define VOID_ADD(ptr, offset)	((void *) (((unsigned long) ptr) + \
				((unsigned long) offset)))

/* Call a function depending on the value of dry_run and return either the
 * resulting return code or 0. */
#define	DRY_RUN_FUNC(x)	(dry_run ? 0 : (x))

#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof(x[0]))

extern int verbose;
extern int interactive;
extern int dry_run;

#endif /* not ZIPL_H */
