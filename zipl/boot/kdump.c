/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Stand-alone kdump support
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "error.h"
#include "kdump.h"
#include "libc.h"
#include "menu.h"
#include "boot/s390.h"

void kdump_failed(unsigned long reason)
{
	panic(reason, "Dump failed: Check disabled wait code");
}

void os_info_check(struct os_info *os_info)
{
	if (os_info == NULL)
		kdump_failed(EOS_INFO_MISSING);
	if (((unsigned long) os_info) % PAGE_SIZE)
		kdump_failed(EOS_INFO_MISSING);
	if (!page_is_valid((unsigned long) os_info))
		kdump_failed(EOS_INFO_MISSING);
	if (os_info->magic != OS_INFO_MAGIC)
		kdump_failed(EOS_INFO_MISSING);
	if (csum_partial(&os_info->version_major, OS_INF0_CSUM_SIZE, 0) !=
	    os_info->csum)
		kdump_failed(EOS_INFO_CSUM_FAILED);
	if (os_info->version_major > OS_INFO_VERSION_MAJOR_SUPPORTED)
		kdump_failed(EOS_INFO_VERSION);
	if (os_info->crashkernel_addr == 0)
		kdump_failed(EOS_INFO_NOCRASHKERNEL);
}
