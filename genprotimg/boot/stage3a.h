/*
 * Main program for stage3a bootloader.
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STAGE3A_H
#define STAGE3A_H

#include "lib/zt_common.h"
#include "boot/loaders_layout.h"

#define STAGE3A_INIT_ENTRY		IMAGE_ENTRY
#define STAGE3A_ENTRY			(STAGE3A_INIT_ENTRY + _AC(0x1000, UL))
#define STAGE3A_LOAD_ADDRESS		IMAGE_LOAD_ADDRESS


#ifndef __ASSEMBLER__

#include <stdint.h>

/* Must not have any padding */
struct stage3a_args {
	uint64_t hdr_offs;
	uint64_t hdr_size;
	uint64_t ipib_offs;
};
STATIC_ASSERT(sizeof(struct stage3a_args) == 3 * 8)

#endif /* __ASSEMBLER__ */
#endif /* STAGE3A_H */
