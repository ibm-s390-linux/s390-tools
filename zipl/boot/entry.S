/*
 * Entry module for stage 2 stand-alone dump tools
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#define __LC_SAVE_AREA_SYNC	0x200	/* Save area for interrupts */
#define __LC_PGM_OLD_PSW	0x0150	/* Program check old PSW */

.globl pgm_check_handler
pgm_check_handler:
	stmg	%r0,%r15,__LC_SAVE_AREA_SYNC
	aghi	%r15,-200
	larl	%r14,pgm_check_handler_fn
	basr	%r14,%r14
	lmg	%r0,%r15,__LC_SAVE_AREA_SYNC
	lpswe	__LC_PGM_OLD_PSW(%r0)

/* The code doesn't require an executable stack */
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
