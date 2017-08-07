#
# IPL stage 1b loader for FBA
#
# Copyright IBM Corp. 2001, 2017
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
#
# Stage 1b is loaded to 0xe000-0xe400 and is used to load stage 2 with
# locate record/read CCWs. Currently stage 1b can load up to 24
# blocks and therefore 12 KiB stage 2 code with 512 byte block size.
#
	.org   0x0
	.globl _start
_start:
	.long  0x43000000+.Llo0,0x40000008  # locate record 0
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo1,0x40000008  # locate record 1
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo2,0x40000008  # locate record 2
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo3,0x40000008  # locate record 3
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo4,0x40000008  # locate record 4
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo5,0x40000008  # locate record 5
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo6,0x40000008  # locate record 6
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo7,0x40000008  # locate record 7
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo8,0x40000008  # locate record 8
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo9,0x40000008  # locate record 9
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo10,0x40000008 # locate record 10
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo11,0x40000008 # locate record 11
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo12,0x40000008 # locate record 12
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo13,0x40000008 # locate record 13
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo14,0x40000008 # locate record 14
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo15,0x40000008 # locate record 15
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo16,0x40000008 # locate record 16
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo17,0x40000008 # locate record 17
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo18,0x40000008 # locate record 18
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo19,0x40000008 # locate record 19
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo20,0x40000008 # locate record 20
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo21,0x40000008 # locate record 21
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo22,0x40000008 # locate record 22
	.long  0x42000000,0x60000200        # read
	.long  0x43000000+.Llo23,0x40000008 # locate record 23
	.long  0x42000000,0x20000200        # read
# offset 2 in .Llo[0-15]: block count (unsigned short) = 1
# offset 4 in .Llo[0-15]: block number (unsigned long)
.Llo0:	.long  0x06000001,0x00000000
.Llo1:	.long  0x06000001,0x00000000
.Llo2:	.long  0x06000001,0x00000000
.Llo3:	.long  0x06000001,0x00000000
.Llo4:	.long  0x06000001,0x00000000
.Llo5:	.long  0x06000001,0x00000000
.Llo6:	.long  0x06000001,0x00000000
.Llo7:	.long  0x06000001,0x00000000
.Llo8:	.long  0x06000001,0x00000000
.Llo9:	.long  0x06000001,0x00000000
.Llo10:	.long  0x06000001,0x00000000
.Llo11:	.long  0x06000001,0x00000000
.Llo12:	.long  0x06000001,0x00000000
.Llo13:	.long  0x06000001,0x00000000
.Llo14:	.long  0x06000001,0x00000000
.Llo15:	.long  0x06000001,0x00000000
.Llo16:	.long  0x06000001,0x00000000
.Llo17:	.long  0x06000001,0x00000000
.Llo18:	.long  0x06000001,0x00000000
.Llo19:	.long  0x06000001,0x00000000
.Llo20:	.long  0x06000001,0x00000000
.Llo21:	.long  0x06000001,0x00000000
.Llo22:	.long  0x06000001,0x00000000
.Llo23:	.long  0x06000001,0x00000000
.org 1024 # Stage 1b should have 1024 byte
.Lend:
