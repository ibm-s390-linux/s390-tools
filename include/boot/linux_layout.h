/*
 * s390 Linux layout definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LINUX_LAYOUT_H
#define LINUX_LAYOUT_H

#include "lib/zt_common.h"

/* Entry address offsets */
#define IMAGE_ENTRY		_AC(0x10000, UL)
#define IMAGE_ENTRY_KDUMP	_AC(0x10010, UL)

/* Parameter address offsets */
#define PARMAREA		_AC(0x10400, UL)
#define IPL_DEVICE		_AC(0x10400, UL)
#define INITRD_START		_AC(0x10408, UL)
#define INITRD_SIZE		_AC(0x10410, UL)
#define OLDMEM_BASE		_AC(0x10418, UL)
#define OLDMEM_SIZE		_AC(0x10420, UL)
#define COMMAND_LINE		_AC(0x10480, UL)

/* Parameter sizes */
#define COMMAND_LINE_SIZE	896


#ifndef __ASSEMBLER__
#endif /* __ASSEMBLER__ */
#endif /* LINUX_LAYOUT_H */
