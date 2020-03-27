/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Stand-alone kdump support (stage 3)
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "error.h"
#include "kdump.h"
#include "libc.h"
#include "sclp_stage3.h"
#include "stage3.h"

static struct os_info **lc_os_info = (struct os_info **)&S390_lowcore.os_info;

/*
 * Copy memory from HSA and exit in case of an error
 */
static void copy_from_hsa(unsigned long dst, unsigned long src, int cnt)
{
	if (cnt == 0)
		return;
	if (sclp_hsa_copy((void *) dst, 2 + src / PAGE_SIZE, cnt / PAGE_SIZE)) {
		sclp_hsa_copy_exit();
		kdump_failed(EHSA_COPY_FAILED);
	}
}

/*
 * Save lower memory to crash kernel memory and get crash base and size
 */
static void kdump_stage3_scsi(unsigned long *base, unsigned long *size)
{
	unsigned long os_info_addr, crash_base, crash_size, crash_end, hsa_page;
	struct os_info *os_info;
	unsigned long hsa_size;

	hsa_page = get_zeroed_page();
	sclp_hsa_copy_init((void *) hsa_page);
	if (sclp_hsa_get_size(&hsa_size)) {
		sclp_hsa_copy_exit();
		kdump_failed(EHSA_COPY_FAILED);
	}
	/* Get OS info pointer from HSA lowcore */
	copy_from_hsa(hsa_page, 0, PAGE_SIZE);
	os_info_addr = *((unsigned long *) (hsa_page + __LC_OS_INFO));
	/* If OS info is inside HSA, get it from there */
	if (os_info_addr < hsa_size) {
		copy_from_hsa(hsa_page, os_info_addr, PAGE_SIZE);
		os_info = (void *) hsa_page;
	} else {
		os_info = (void *) os_info_addr;
	}
	os_info_check(os_info);
	crash_base = os_info->crashkernel_addr;
	crash_size = os_info->crashkernel_size;
	crash_end = crash_base + crash_size;
	/*
	 * Copy [0, crash_size] to [crash_base, crash_base + crash_size] and
	 * restore 1:1 memory from HSA
	 */

	/* copy [0, MIN(crash_size, hsa_size)] to [crash base, ...] from HSA */
	copy_from_hsa(crash_base, 0, MIN(crash_size, hsa_size));
	if (crash_size > hsa_size) {
		/* Copy rest of crashkernel from real memory */
		memcpy((void *) crash_base + hsa_size, (void *) hsa_size,
		       crash_size - hsa_size);
	} else {
		/* Restore real memory above crash_size 1:1 from HSA */
		copy_from_hsa(crash_size, crash_size,
			      MIN(hsa_size, crash_base) - crash_size);
	}
	if (crash_end < hsa_size) {
		/* Restore memory above crash end 1:1 from HSA */
		copy_from_hsa(crash_end, crash_end, hsa_size -  crash_end);
	}
	sclp_hsa_copy_exit();
	*base = __pa(crash_base);
	*size = crash_size;
}

/*
 * Get crash base and size from (stage 2 relocated) OS info lowcore pointer
 */
static void kdump_stage3_dasd(unsigned long *base, unsigned long *size)
{
	*base = (*lc_os_info)->crashkernel_addr;
	*size = (*lc_os_info)->crashkernel_size;
}

/*
 * Stage 3 kdump code
 */
void kdump_stage3(void)
{
	unsigned long crash_base, crash_size;

	if (!(_stage3_parms.flags & STAGE3_FLAG_KDUMP))
		return;
	if (!(_stage3_parms.flags & STAGE3_FLAG_SCSI))
		kdump_stage3_dasd(&crash_base, &crash_size);
	else
		kdump_stage3_scsi(&crash_base, &crash_size);

	/* Register oldmem in kernel parameter area */
	*((unsigned long *) OLDMEM_BASE) = crash_base;
	*((unsigned long *) OLDMEM_SIZE) = crash_size;
}
