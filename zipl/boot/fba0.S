#
# IPL stage 0 and 1 loader for FBA
#
# Copyright IBM Corp. 2001, 2017
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
# Startup for IPL at address 0
# Second stage boot loader is loaded to 0x2000 and starts at 0x2018
#
# The first 24 bytes are loaded by IPL to addresses 0-23 (PSW and two CCWs).
# The CCWs on 8-23 are used as a continuation of the implicit IPL channel
# program.
# The 1st CCW reads block 0 again with READ IPL
# The 2nd CCW tics to the re-loaded stage 1 IPL record.
#

#include "boot/loaders_layout.h"
#include "boot/s390.h"

	.org   0x0
	.globl _start
_start:
	.quad  PSW_LOAD+STAGE2_ENTRY		# The first 24 byte are loaded
	.long  0x02000000,0x60000000+.Lend	# by ipl to addresses 0-23.
	.long  0x08000000+.Ltic,0x40000000	# Tic to continuation
#
# Here starts stage 1
#
.Ltic:	.long  0x43000000+.Llo0,0x40000008	# locate record 0
	.long  0x42000000,0x60000200		# bytes 0-512 of stage 1 ext
	.long  0x43000000+.Llo1,0x40000008	# locate record 1
	.long  0x42000000,0x60000200		# bytes 512-1024 of stage 1 ext
	.long  0x08000000,0x00000000		# tic to stage 1b
# offset 2 in .Llo[0-15]: block count (unsigned short) = 1
# offset 4 in .Llo[0-15]: block number (unsigned long)
.Llo0:	.long  0x06000001,0x00000000
.Llo1:	.long  0x06000001,0x00000000

	.long  0x00000000,0x00000000		# reserved
	.long  0x00000000,0x00000000		# reserved
	.long  0x00000000,0x00000000		# reserved
	.long  0x00000000,0x00000000		# reserved

	.long  0x00000000,0x02000000		# boot_info
	.long  0x00000000,0x00000000
	.long  0x00000000,0x00000000
	.long  0x00000000,0x00000000
	.long  0x00000000,0x00000000
.Lend:
