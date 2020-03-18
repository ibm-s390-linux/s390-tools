#
# IPL stage 0 loader for ECKD Linux Disk Layout (LDL)
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
# The 1st CCW rewinds to record zero (read record zero)
# The 2nd CCW reads stage 1 IPL record (re-read record 1) and continues with
# command chaining at address 0x18
#

#include "boot/loaders_layout.h"
#include "boot/s390.h"

	.org   0x0
	.globl _start
_start:
	.quad  PSW_LOAD+STAGE2_ENTRY # PSW :the first 24 byte are loaded by IPL
	.long  0x16002000,0x60000016 # Read record zero
	.long  0x06000000,0x60000080 # Read IPL record 1 again
