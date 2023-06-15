/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Stand-alone kdump support
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "kdump.h"
#include "libc.h"
#include "menu.h"
#include "boot/error.h"
#include "boot/s390.h"
#include "boot/os_info.h"

void kdump_failed(unsigned long reason)
{
	panic(reason, "Dump failed: Check disabled wait code");
}

void kdump_os_info_check(const struct os_info *os_info)
{
	int rc;

	rc = os_info_check(os_info);
	if (rc < 0)
		kdump_failed(-rc);
	if (os_info->version_major > OS_INFO_VERSION_MAJOR_SUPPORTED)
		kdump_failed(EOS_INFO_VERSION);
	if (os_info->crashkernel_addr == 0)
		kdump_failed(EOS_INFO_NOCRASHKERNEL);
}
