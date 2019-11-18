/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Entry code for stage 2 and stage 3 boot loader
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "boot/sigp.h"

.section .text.start
.globl _start
_start:
	basr	%r13,0
0:	la	%r7,2				/* First try code 2: */
	la	%r6,0				/* 64 bit psws are restored */
	sigp	%r7,%r6,SIGP_SET_ARCHITECTURE	/* Switch to 64 bit */
	bc	8,.Lswitched_64-0b(%r13)	/* Accepted ? */
	la	%r7,1				/* Failed - try code 1 */
	sigp	%r7,%r6,SIGP_SET_ARCHITECTURE	/* Switch to 64 bit */
.Lswitched_64:
	sam64					/* Switch to 64 bit addr mode */
	basr	%r13,0
1:	llgf	%r15,.Lstack-1b(%r13)		/* End of stack */
	brasl	%r14,initialize
.Lstack: .long  0x10000-160
.previous
