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
#include "boot/loaders_layout.h"

#define ZIPL_MAGIC			"zIPL"
#define ZIPL_MAGIC_SIZE			4
#define DISK_LAYOUT_ID			0x00000001

#define ADDRESS_LIMIT			0x80000000UL
#define ADDRESS_LIMIT_KDUMP		0x2000000UL /* HSA size: 32 MiB */
#define UNSPECIFIED_ADDRESS		-1UL
#define MAXIMUM_PARMLINE_SIZE		0x380UL
#define MAXIMUM_PHYSICAL_BLOCKSIZE	0x1000UL

#define BOOTMAP_FILENAME		"bootmap"
#define BOOTMAP_TEMPLATE_FILENAME	"bootmap_temp.XXXXXX"

#define DEFAULTBOOT_SECTION		"defaultboot"

#define ZIPL_CONF_VAR			"ZIPLCONF"
#define ZIPL_RUNTIME_CONF		"/run/zipl/zipl.conf"
#define ZIPL_DEFAULT_CONF		TOOLS_SYSCONFDIR "/zipl.conf"
#define ZIPL_MINIMAL_CONF		TOOLS_LIBDIR "/zipl.conf"
#define ZIPL_DEFAULT_BLSDIR		"/boot/loader/entries"
#define ZIPL_STAGE3_PATH		TOOLS_LIBDIR "/stage3.bin"
#define ZIPL_SIPL_PATH			"/sys/firmware/ipl/has_secure"

#define MENU_DEFAULT_PROMPT		0
#define MENU_DEFAULT_TIMEOUT		0

#define MAX_DUMP_VOLUMES		32

#define SECURE_BOOT_UNDEFINED	       -1
#define SECURE_BOOT_DISABLED		0
#define SECURE_BOOT_ENABLED		1
#define SECURE_BOOT_AUTO		2

/* Internal component load address type */
typedef uint64_t address_t;

/* Type for address calculations */
#define VOID_ADD(ptr, offset)	((void *) (((unsigned long) ptr) + \
				((unsigned long) offset)))

/* Call a function depending on the value of dry_run and return either the
 * resulting return code or 0. */
#define	DRY_RUN_FUNC(x)	(dry_run ? 0 : (x))

extern int verbose;
extern int interactive;
extern int dry_run;

#endif /* not ZIPL_H */
