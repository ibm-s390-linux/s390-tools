/*
 * Main program for stage3a bootloader
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "stage3a.h"

#include "lib/zt_common.h"
#include "boot/s390.h"
#include "boot/ipl.h"
#include "sclp.h"
#include "error.h"


static volatile struct stage3a_args __section(".loader_parms") loader_parms;

void __noreturn start(void)
{
	int rc;
	volatile struct stage3a_args *args = &loader_parms;
	/* calculate the IPIB memory address */
	struct ipl_parameter_block *ipib = (void *)((uint64_t)args + args->ipib_offs);

	/* Calculate the PV header memory address and set it and its
	 * size in the IPIB. This allows the PV header to be position
	 * independent.
	 */
	ipib->pv.pv_hdr_addr = (uint64_t)args + args->hdr_offs;
	ipib->pv.pv_hdr_size = args->hdr_size;

	/* set up ASCII and line-mode */
	sclp_setup(SCLP_LINE_ASCII_INIT);

	/* test if Secure Execution Unpack facility is available */
	stfle(S390_lowcore.stfle_fac_list,
	      ARRAY_SIZE(S390_lowcore.stfle_fac_list));
	rc = test_facility(UNPACK_FACILITY);
	if (rc == 0)
		panic(ENOPV, "Secure unpack facility is not available\n");

	rc = diag308(DIAG308_SET_PV, ipib);
	if (rc != DIAG308_RC_OK)
		panic(EPV, "Protected boot setup has failed: 0x%x\n", rc);

	rc = diag308(DIAG308_UNPACK_PV, 0x0);
	if (rc != DIAG308_RC_OK) {
		sclp_setup(SCLP_LINE_ASCII_INIT);
		panic(EPV, "Protected boot has failed: 0x%x\n", rc);
	}

	while (1)
		;
}

void panic_notify(unsigned long UNUSED(rc))
{
}
