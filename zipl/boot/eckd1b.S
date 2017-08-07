#
# IPL stage 1b loader for ECKD
#
# Copyright IBM Corp. 2012, 2017
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
#
# Stage 1b is loaded to 0xe000-0xe400 and is used to load stage 2 with
# seek/search/tic/read CCWs. Currently stage 1b can load up to 16
# blocks and therefore 8 KiB stage 2 code with 512 byte block size.
#

	.globl _start
_start:
	.long  0x07000000+.Lseek1,0x60000006     # seek
.Lsearch1:
	.long  0x31000000+.Lseek1+2,0x60000005   # search
	.long  0x08000000+.Lsearch1,0x00000000   # tic back until found
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek2,0x60000006     # seek
.Lsearch2:
	.long  0x31000000+.Lseek2+2,0x60000005   # search
	.long  0x08000000+.Lsearch2,0x00000000   # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek3,0x60000006     # seek
.Lsearch3:
	.long  0x31000000+.Lseek3+2,0x60000005   # search
	.long  0x08000000+.Lsearch3,0x00000000   # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek4,0x60000006     # seek
.Lsearch4:
	.long  0x31000000+.Lseek4+2,0x60000005   # search
	.long  0x08000000+.Lsearch4,0x00000000   # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek5,0x60000006     # seek
.Lsearch5:
	.long  0x31000000+.Lseek5+2,0x60000005   # search
	.long  0x08000000+.Lsearch5,0x00000000   # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek6,0x60000006     # seek
.Lsearch6:
	.long  0x31000000+.Lseek6+2,0x60000005   # search
	.long  0x08000000+.Lsearch6,0x00000000   # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek7,0x60000006     # seek
.Lsearch7:
	.long  0x31000000+.Lseek7+2,0x60000005   # search
	.long  0x08000000+.Lsearch7,0x00000000   # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek8,0x60000006     # seek
.Lsearch8:
	.long  0x31000000+.Lseek8+2,0x60000005   # search
	.long  0x08000000+.Lsearch8,0x00000000   # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek9,0x60000006     # seek
.Lsearch9:
	.long  0x31000000+.Lseek9+2,0x60000005   # search
	.long  0x08000000+.Lsearch9,0x00000000   # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek10,0x60000006    # seek
.Lsearch10:
	.long  0x31000000+.Lseek10+2,0x60000005  # search
	.long  0x08000000+.Lsearch10,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek11,0x60000006    # seek
.Lsearch11:
	.long  0x31000000+.Lseek11+2,0x60000005  # search
	.long  0x08000000+.Lsearch11,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek12,0x60000006    # seek
.Lsearch12:
	.long  0x31000000+.Lseek12+2,0x60000005  # search
	.long  0x08000000+.Lsearch12,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek13,0x60000006    # seek
.Lsearch13:
	.long  0x31000000+.Lseek13+2,0x60000005  # search
	.long  0x08000000+.Lsearch13,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek14,0x60000006    # seek
.Lsearch14:
	.long  0x31000000+.Lseek14+2,0x60000005  # search
	.long  0x08000000+.Lsearch14,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek15,0x60000006    # seek
.Lsearch15:
	.long  0x31000000+.Lseek15+2,0x60000005  # search
	.long  0x08000000+.Lsearch15,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek16,0x60000006    # seek
.Lsearch16:
	.long  0x31000000+.Lseek16+2,0x60000005  # search
	.long  0x08000000+.Lsearch16,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek17,0x60000006    # seek
.Lsearch17:
	.long  0x31000000+.Lseek17+2,0x60000005  # search
	.long  0x08000000+.Lsearch17,0x00000000  # tic back until found
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek18,0x60000006    # seek
.Lsearch18:
	.long  0x31000000+.Lseek18+2,0x60000005  # search
	.long  0x08000000+.Lsearch18,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek19,0x60000006    # seek
.Lsearch19:
	.long  0x31000000+.Lseek19+2,0x60000005  # search
	.long  0x08000000+.Lsearch19,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek20,0x60000006    # seek
.Lsearch20:
	.long  0x31000000+.Lseek20+2,0x60000005  # search
	.long  0x08000000+.Lsearch20,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek21,0x60000006    # seek
.Lsearch21:
	.long  0x31000000+.Lseek21+2,0x60000005  # search
	.long  0x08000000+.Lsearch21,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek22,0x60000006    # seek
.Lsearch22:
	.long  0x31000000+.Lseek22+2,0x60000005  # search
	.long  0x08000000+.Lsearch22,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek23,0x60000006    # seek
.Lsearch23:
	.long  0x31000000+.Lseek23+2,0x60000005  # search
	.long  0x08000000+.Lsearch23,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
	.long  0x07000000+.Lseek24,0x60000006    # seek
.Lsearch24:
	.long  0x31000000+.Lseek24+2,0x60000005  # search
	.long  0x08000000+.Lsearch24,0x00000000  # tic back
	.long  0x06000000,0x40000000             # read
.Lseek1:
	.long  0,0
.Lseek2:
	.long  0,0
.Lseek3:
	.long  0,0
.Lseek4:
	.long  0,0
.Lseek5:
	.long  0,0
.Lseek6:
	.long  0,0
.Lseek7:
	.long  0,0
.Lseek8:
	.long  0,0
.Lseek9:
	.long  0,0
.Lseek10:
	.long  0,0
.Lseek11:
	.long  0,0
.Lseek12:
	.long  0,0
.Lseek13:
	.long  0,0
.Lseek14:
	.long  0,0
.Lseek15:
	.long  0,0
.Lseek16:
	.long  0,0
.Lseek17:
	.long  0,0
.Lseek18:
	.long  0,0
.Lseek19:
	.long  0,0
.Lseek20:
	.long  0,0
.Lseek21:
	.long  0,0
.Lseek22:
	.long  0,0
.Lseek23:
	.long  0,0
.Lseek24:
	.long  0,0
.org 1024 # Stage 1b should have 1024 byte
.Lend:
