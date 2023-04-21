/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Stand-alone kdump support (stage 2)
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "error.h"
#include "kdump.h"
#include "libc.h"
#include "menu.h"
#include "stage2.h"
#include "boot/os_info.h"

/*
 * Copy crashkernel memory from [0, crash size] to
 * [crash base, crash base + crash size] if config_nr specifies a
 * kdump boot menu entry.
 *
 * Parameter:
 *   Config number (starts with 1)
 */
void kdump_stage2(unsigned long config_nr)
{
	struct os_info *os_info = (struct os_info *)S390_lowcore.os_info;
	unsigned long crash_size;
	void *crash_base;

	if (!(__stage2_params.config_kdump & (0x1 << config_nr)))
		return;
	kdump_os_info_check(os_info);

	/* Copy crashkernel memory */
	crash_base = (void *) os_info->crashkernel_addr;
	crash_size = os_info->crashkernel_size;
	memcpy(crash_base, NULL, crash_size);
	/*
	 * Relocate OS info pointer if necessary (needed for stage 3)
	 * If OS info is smaller than crash size then add crash base
	 */
	if (__pa(os_info) >= crash_size)
		return;
	S390_lowcore.os_info = __pa(os_info) + __pa(crash_base);
}
