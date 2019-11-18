/*
 * SIGP related definitions and functions.
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef S390_SIGP_H
#define S390_SIGP_H

/* Signal Processor Order Codes */
#define SIGP_STOP_AND_STORE_STATUS	9
#define SIGP_SET_ARCHITECTURE		18
#define SIGP_SET_MULTI_THREADING	22
#define SIGP_STORE_ASTATUS_AT_ADDRESS	23

/* Signal Processor Condition Codes */
#define SIGP_CC_ORDER_CODE_ACCEPTED	0
#define SIGP_CC_BUSY			2


#ifndef __ASSEMBLER__

#include <stdint.h>

static inline int sigp(uint16_t addr, uint8_t order, uint32_t parm,
		       uint32_t *status)
{
	register unsigned int reg1 asm ("1") = parm;
	int cc;

	asm volatile(
		"	sigp	%1,%2,0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		: "=d" (cc), "+d" (reg1) : "d" (addr), "a" (order) : "cc");
	if (status && cc == 1)
		*status = reg1;
	return cc;
}

static inline int sigp_busy(uint16_t addr, uint8_t order, uint32_t parm,
			    uint32_t *status)
{
	int cc;

	do {
		cc = sigp(addr, order, parm, status);
	} while (cc == SIGP_CC_BUSY);
	return cc;
}

#endif /* __ASSEMBLER__ */
#endif /* S390_SIGP_H */
