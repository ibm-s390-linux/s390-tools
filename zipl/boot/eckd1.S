#
# IPL stage 1 loader for ECKD
#
# Copyright IBM Corp. 2001, 2017
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
# Stage 1 is loaded to 0x18-0x80 and is used to load stage 1b (two blocks) with
# seek/search/tic/read CCWs. After stage 1b is loaded we tic to it.

	.globl _start
_start:
	.long  0x07000000+.Lseek1,0x60000006    # seek 1
.Lsearch1:
	.long  0x31000000+.Lseek1+2,0x60000005  # search
	.long  0x08000000+.Lsearch1,0x00000000  # tic back to search until found
	.long  0x06000000,0x40000000            # read

	.long  0x07000000+.Lseek2,0x60000006    # seek 2
.Lsearch2:
	.long  0x31000000+.Lseek2+2,0x60000005  # search
	.long  0x08000000+.Lsearch2,0x00000000  # tic back to search until found
	.long  0x06000000,0x40000000            # read
.Ltick:
	.long  0x08000000,0x00000000            # tic to stage 1b
.Lseek1:
	.long  0x00000000,0x00000000            # seekarg 1
.Lseek2:
	.long  0x00000000,0x00000000            # seekarg 2

	.long  0x00000000,0x00000000            # bootinfo
	.long  0x00000000,0x00000000
	.long  0x00000000,0x00000000
	.long  0x00000000,0x00000000
	.long  0x00000000,0x00000000
.Lend:
