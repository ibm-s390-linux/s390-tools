/*
 * Main program for stage3b bootloader
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "stage3b.h"

#include "lib/zt_common.h"
#include "boot/s390.h"
#include "boot/linux_layout.h"
#include "boot/loaders_layout.h"
#include "sclp.h"
#include "error.h"


static volatile struct stage3b_args __section(".loader_parms") loader_parms;

static inline void __noreturn load_psw(struct psw_t psw)
{
	asm volatile("lpswe %0" : : "Q"(psw) : "cc");

	while (1)
		;
}

void __noreturn start(void)
{
	volatile struct stage3b_args *args = &loader_parms;
	volatile struct memblob *kernel = &args->kernel;
	volatile struct memblob *cmdline = &args->cmdline;
	volatile struct memblob *initrd = &args->initrd;
	volatile struct psw_t psw = args->psw;

	/* set up ASCII and line-mode */
	sclp_setup(SCLP_LINE_ASCII_INIT);

	if (kernel->size < IMAGE_LOAD_ADDRESS)
		panic(EINTERNAL, "Invalid kernel\n");

	if (cmdline->size > COMMAND_LINE_SIZE)
		panic(EINTERNAL, "Command line is too large\n");

	/* move the kernel and cut the kernel header */
	memmove((void *)IMAGE_LOAD_ADDRESS,
		(void *)(kernel->src + IMAGE_LOAD_ADDRESS),
		kernel->size - IMAGE_LOAD_ADDRESS);

	/* move the kernel cmdline */
	memmove((void *)COMMAND_LINE,
		(void *)cmdline->src,
		cmdline->size);
	/* the initrd does not need to be moved */

	if (initrd->size != 0) {
		/* copy initrd start address and size into new kernel space */
		*(unsigned long long *)INITRD_START = initrd->src;
		*(unsigned long long *)INITRD_SIZE = initrd->size;
	}

	/* disable ASCII and line-mode */
	sclp_setup(SCLP_DISABLE);

	/* use lpswe instead of diag308 as a I/O subsystem reset is not
	 * needed as this was already done by the diag308 subcode 10 call
	 * in stage3a
	 */
	load_psw(psw);
}

void panic_notify(unsigned long UNUSED(rc))
{
}
