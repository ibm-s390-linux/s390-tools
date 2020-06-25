/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Main program for stage3 bootloader
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "boot/sigp.h"
#include "boot/s390.h"
#include "boot/sigp.h"
#include "boot/linux_layout.h"
#include "boot/loaders_layout.h"

#include "stage3.h"
#include "error.h"
#include "ebcdic.h"
#include "ebcdic_conv.h"

#define for_each_rb_entry(entry, rb) \
	for (entry = rb->entries; \
	     (void *) entry + sizeof(*entry) <= (void *) rb + rb->len; \
	     entry++)

static const char *msg_sipl_inval = "Secure boot failure: invalid load address";
static const char *msg_sipl_unverified = "Secure boot failure: unverified load address";
static const char *msg_sipl_noparm = "Secure boot failure: unable to load ipl parameter";

static inline void __noreturn start_kernel(void)
{
	struct psw_t *psw = &S390_lowcore.program_new_psw;
	unsigned long addr, code;

	/* Setup program check handler */
	psw->mask = 0x000000180000000ULL;
	code = 1;

	asm volatile(
		/* Setup program check handler */
		"       larl    %[addr],.no_diag308\n"
		"       stg     %[addr],8(%[psw])\n"
		"       diag    %[code],%[code],0x308\n"
		".no_diag308:\n"
		"       sam31\n"
		"       sr      %r1,%r1\n"
		"       sr      %r2,%r2\n"
		"       sigp    %r1,%r2,%[order]\n"
		"       lpsw    0\n"
		: [addr] "=&d" (addr),
		  [code] "+&d" (code)
		: [psw] "a" (psw),
		  [order] "L" (SIGP_SET_ARCHITECTURE));
	while (1);
}

unsigned int
is_verified_address(unsigned long image_addr)
{
	struct ipl_rb_component_entry *comp;
	struct ipl_rb_components *comps;
	struct ipl_pl_hdr *pl_hdr;
	struct ipl_rl_hdr *rl_hdr;
	struct ipl_rb_hdr *rb_hdr;
	unsigned long tmp;
	void *rl_end;

	/*
	 * There is an IPL report, to find it load the pointer to the
	 * IPL parameter information block from lowcore and skip past
	 * the IPL parameter list, then align the address to a double
	 * word boundary.
	 */
	tmp = (unsigned long) S390_lowcore.ipl_parmblock_ptr;
	pl_hdr = (struct ipl_pl_hdr *) tmp;
	tmp = (tmp + pl_hdr->len + 7) & -8UL;
	rl_hdr = (struct ipl_rl_hdr *) tmp;
	/* Walk through the IPL report blocks in the IPL Report list */
	comps = NULL;
	rl_end = (void *) rl_hdr + rl_hdr->len;
	rb_hdr = (void *) rl_hdr + sizeof(*rl_hdr);
	while ((void *) rb_hdr + sizeof(*rb_hdr) < rl_end &&
	       (void *) rb_hdr + rb_hdr->len <= rl_end) {
		switch (rb_hdr->rbt) {
		case IPL_RBT_COMPONENTS:
			comps = (struct ipl_rb_components *) rb_hdr;
			break;
		default:
			break;
		}

		rb_hdr = (void *) rb_hdr + rb_hdr->len;
	}

	if (!comps)
		return 0;

	for_each_rb_entry(comp, comps) {
		if (image_addr == comp->addr &&
		    comp->flags & IPL_RB_COMPONENT_FLAG_SIGNED &&
		    comp->flags & IPL_RB_COMPONENT_FLAG_VERIFIED)
			return 1;
	}
	return 0;
}

unsigned int
secure_boot_enabled()
{
	struct ipl_pl_hdr *pl_hdr;
	unsigned int rc;

	pl_hdr = (void *)get_zeroed_page();
	switch (diag308(DIAG308_STORE, pl_hdr)) {
	case DIAG308_RC_OK:
		rc = pl_hdr->version <= IPL_MAX_SUPPORTED_VERSION &&
			!!(pl_hdr->flags & IPL_FLAG_SECURE);
		break;
	case DIAG308_RC_NO_CONF:
		rc = 0;
		break;
	default:
		panic(ESECUREBOOT, "%s", msg_sipl_noparm);
		break;
	}
	free_page((unsigned long) pl_hdr);

	return rc;
}

void start(void)
{
	unsigned int subchannel_id;
	unsigned char *cextra = (unsigned char *)COMMAND_LINE_EXTRA;
	unsigned char *cmdline =  (unsigned char *)COMMAND_LINE;
	unsigned int cmdline_len = 0, cextra_len = 0;

	/*
	 * IPL process is secure we have to use default IPL values and
	 * check if the psw jump address is within at the start of a
	 * verified component. If it is not IPL is aborted.
	 */
	if (secure_boot_enabled()) {
		if (_stage3_parms.image_addr != IMAGE_LOAD_ADDRESS ||
		    _stage3_parms.load_psw != DEFAULT_PSW_LOAD)
			panic(ESECUREBOOT, "%s", msg_sipl_inval);

		if (!is_verified_address(_stage3_parms.load_psw & PSW32_ADDR_MASK))
			panic(ESECUREBOOT, "%s", msg_sipl_unverified);
	}
	/*
	 * cut the kernel header
	 */
	memmove((void *)_stage3_parms.image_addr,
		(void *)_stage3_parms.image_addr + IMAGE_LOAD_ADDRESS,
		_stage3_parms.image_len - IMAGE_LOAD_ADDRESS);

	/* store subchannel ID into low core and into new kernel space */
	subchannel_id = S390_lowcore.subchannel_id;
	*(unsigned int *)__LC_IPLDEV = subchannel_id;
	*(unsigned long long *)IPL_DEVICE = subchannel_id;

	/* if valid command line is given, copy it into new kernel space */
	if (_stage3_parms.parm_addr != UNSPECIFIED_ADDRESS) {
		memcpy(cmdline,
		       (void *)(unsigned long *)_stage3_parms.parm_addr,
		       COMMAND_LINE_SIZE);
		/* terminate \0 */
		cmdline[COMMAND_LINE_SIZE - 1] = 0;
	}

	/* convert extra parameter to ascii */
	if (!_stage3_parms.extra_parm || !*cextra)
		goto noextra;

	/* Handle extra kernel parameters specified in DASD boot menu. */
	ebcdic_to_ascii(cextra, cextra, COMMAND_LINE_SIZE);

	/* determine length of extra parameter */
	cextra_len = MIN(strlen((const char *)cextra), COMMAND_LINE_SIZE - 1);

	/* remove leading whitespace of extra parameter */
	while (cextra_len > 0 && *cextra == 0x20) {
		cextra++;
		cextra_len--;
	}

	/* determine length of original parm line */
	cmdline_len = MIN(strlen((const char *)cmdline),
			  COMMAND_LINE_SIZE - 1);

	/*
	 * if extra parm string starts with '=' replace original string,
	 * else append
	 */
	if (*cextra == 0x3d && cextra_len >= 1) {
		/* skip '=' */
		cextra++;
		cextra_len--;
		memcpy(cmdline, cextra, cextra_len);
		cmdline[cextra_len] = 0;
	} else if (cmdline_len + 1 <= COMMAND_LINE_SIZE - 1) {
		/* add blank */
		cmdline[cmdline_len] = 0x20;
		cmdline_len++;
		/* check if length is within max value */
		cextra_len = (cmdline_len + cextra_len <= COMMAND_LINE_SIZE - 1) ?
			cextra_len : (COMMAND_LINE_SIZE - 1 - cmdline_len);
		/* append string */
		memcpy(cmdline + cmdline_len, cextra, cextra_len);
		/* terminate 0 */
		cmdline[cmdline_len + cextra_len] = 0;
	}

noextra:
	/* copy initrd start address and size intop new kernle space */
	*(unsigned long long *)INITRD_START = _stage3_parms.initrd_addr;
	*(unsigned long long *)INITRD_SIZE = _stage3_parms.initrd_len;

	/* store address of new kernel to 0 to be able to start it */
	*(unsigned long long *)0 = _stage3_parms.load_psw;

	kdump_stage3();

	/* start new kernel */
	start_kernel();
}

void panic_notify(unsigned long UNUSED(rc))
{
}
