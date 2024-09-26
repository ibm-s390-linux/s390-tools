// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

#include <stdint.h>

uint32_t stfle(uint64_t *stfle_fac_list, uint32_t size)
{
	uint32_t reg0 = size - 1;

	asm volatile("	lgr	%%r0,%[reg0]\n"
		     "	.insn	s,0xb2b00000,%[list]\n" /* stfle */
		     "	lgr	%[reg0],%%r0\n"
		     : [reg0] "+&d"(reg0), [list] "+Q"(*stfle_fac_list)
		     :
		     : "memory", "cc", "r0");
	return reg0;
}
