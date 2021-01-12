/*
 * Entry code for stage 3a and stage 3b boot loader
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


#include "common_memory_layout.h"

#include "boot/s390.h"
#include "boot/sigp.h"

.section .text.start
.globl _start
_start:
	/* Might be called after a diag308 so better set
	 * architecture and addressing mode
	 */
	lhi	%r1, 1
	sigp	%r1, %r0, SIGP_SET_ARCHITECTURE
	sam64

	/* Initialize stack */
	basr	%r13, 0
.Lbase:	llgf	%r15, .Lstack - .Lbase(%r13)
	brasl	%r14, initialize
.Lstack: .long STACK_ADDRESS + STACK_SIZE - STACK_FRAME_OVERHEAD
.previous
