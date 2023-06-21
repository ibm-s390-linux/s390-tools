/*
 * Program Status Word related definitions and functions.
 *
 * Copyright IBM Corp. 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef BOOT_PSW_H
#define BOOT_PSW_H

#include "lib/zt_common.h"

#define PSW32_ADDR_MASK   _AC(0x000000007fffffff, UL)
#define PSW_MASK_BA	  _AC(0x0000000080000000, UL)
#define PSW_MASK_EA	  _AC(0x0000000100000000, UL)
#define PSW_MASK_BIT_12	  _AC(0x0008000000000000, UL)
#define PSW_LOAD	  _AC(0x0008000080000000, UL)
#define PSW_DISABLED_WAIT _AC(0x000a000000000000, UL)

#ifndef __ASSEMBLER__
#include <stdint.h>

struct psw_t {
	uint64_t mask;
	uint64_t addr;
} __aligned(8);

#endif
#endif
