#
# IPL stage 0 loader for ECKD Compatible Disk Layout (CDL)
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
# The 1st CCW reads stage 1 IPL record.
# The 2nd CCW tics to the loaded stage 1 IPL record.
#

#include "boot/loaders_layout.h"
#include "boot/s390.h"

	.org   0x0
	.globl _start
_start:
	.quad  PSW_LOAD+STAGE2_ENTRY # PSW :the first 24 byte are loaded by IPL
	.long  0x06000018,0x60000068 # read IPL record 2
	.long  0x08000018,0x00000000 # TIC to stage 1
