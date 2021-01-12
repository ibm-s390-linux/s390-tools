/*
 * Relocator code for stage 3b boot loader
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "stage3b.h"
#include "boot/sigp.h"

.macro MEMCPY dst,src,len
	lgr	%r0, \dst
	lgr	%r1, \len
	lgr	%r2, \src
	lgr	%r3, \len

20:	mvcle	%r0, %r2, 0
	jo	20b
.endm

.org 0x0
.section .text.start
.globl stage3b_reloc_start
stage3b_reloc_start:
	/* Might be called after a diag308 so better set
	 * architecture and addressing mode
	 */
	lhi	%r1, 1
	sigp	%r1, %r0, SIGP_SET_ARCHITECTURE
	sam64

	/* Location of stage3b in memory */
	larl	%r8, stage3b_start

	/* Destination for stage3b */
	basr	%r13, 0
.Lbase:	llgf	%r9, .Lstage3b_load_address - .Lbase(%r13)

	/* Size of stage3b */
	lghi	%r11, stage3b_end - stage3b_start

	/* Copy the stage3b loader to address STAGE3B_LOAD_ADDRESS */
	MEMCPY	%r9, %r8, %r11

	/* Branch to STAGE3B_ENTRY */
	llgf	%r9, .Lstage3b_entry - .Lbase(%r13)
	br	%r9
.Lstage3b_load_address:	.long STAGE3B_LOAD_ADDRESS
.Lstage3b_entry:	.long STAGE3B_ENTRY
stage3b_start:
	.incbin	"stage3b.bin"
stage3b_end:
.previous
