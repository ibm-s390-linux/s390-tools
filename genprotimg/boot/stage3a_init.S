/*
 * Entry code for stage 3a boot loader
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "stage3a.h"
#include "boot/sigp.h"

.section .text.init
.globl _init
_init:
	/* set architecture and switch to 64bit  */
	lhi	%r1, 1
	sigp	%r1, %r0, SIGP_SET_ARCHITECTURE
	sam64
	/* The original stage3 boot loader will try to store the
	 * kernel command line and the address and size of the
	 * ramdisk. Simply ignore this by starting at 0x11000.
	 */
	basr	%r13, 0
.Lbase:	llgf	%r1, .Lstage3a_entry - .Lbase(%r13)
	br	%r1
.Lstage3a_entry: .long STAGE3A_ENTRY
.previous
