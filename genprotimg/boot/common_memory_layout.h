/*
 * Common memory layout for stage3a and stage3b bootloader.
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef COMMON_MEMORY_LAYOUT_H
#define COMMON_MEMORY_LAYOUT_H

#include "boot/loaders_layout.h"

#define STACK_ADDRESS		STAGE3_STACK_ADDRESS
#define STACK_SIZE		STAGE3_STACK_SIZE

#define HEAP_ADDRESS		STAGE3_HEAP_ADDRESS
#define HEAP_SIZE		STAGE3_HEAP_SIZE


#ifndef __ASSEMBLER__

#endif /* __ASSEMBLER__ */
#endif /* COMMON_MEMORY_LAYOUT_H */
