/*
 * Main program for stage3b bootloader
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STAGE3B_H
#define STAGE3B_H

#include "lib/zt_common.h"
#include "boot/loaders_layout.h"

#define STAGE3B_ENTRY			STAGE3_ENTRY
#define STAGE3B_LOAD_ADDRESS		STAGE3B_ENTRY


#ifndef __ASSEMBLER__

#include <stdint.h>

#include "boot/s390.h"

/* Must not have any padding included */
struct memblob {
	uint64_t src;
	uint64_t size;
};
STATIC_ASSERT(sizeof(struct memblob) == 2 * 8)

/* Must not have any padding included */
struct stage3b_args {
	struct memblob kernel;
	struct memblob cmdline;
	struct memblob initrd;
	struct psw_t psw;
};
STATIC_ASSERT(sizeof(struct stage3b_args) == 3 * sizeof(struct memblob) + 16)
#endif /* __ASSEMBLER__ */
#endif /* STAGE3B_H */
