#
# Tape IPL loader
#
# Copyright IBM Corp. 2004, 2017
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

#include "boot/sigp.h"
#include "boot/linux_layout.h"
#include "boot/s390.h"

IPL_BS			= 1024			# block size for tape access
IPL_OFF			= 0x4000		# temporary kernel load addr
KERNEL_OFF		= IMAGE_ENTRY		# kernel start code offset
						# relative to image start
__LC_IO_NEW_PSW         = 0x1f0			# IO New PSW addr


# Default IPL parameter - will be overwritten by zIPL

RAMDISK_ORIGIN		= 0x800000		# default ramdisk load addr
RAMDISK_SIZE		= 0x800000		# default ramdisk size
PARMFILE_ADDR		= 0x1000		# default parmfile load addr
KERNEL_ADDR		= IMAGE_ENTRY		# default kernel load addr


	.org 0x0
	.globl _start
_start:

# Stage 0 loader - loads first block of this loader

	.quad PSW_LOAD+iplstart			# PSW to start execution
	.long 0x27000000,0x60000001		# backward Space Block
	.long 0x02000000,0x20000000+IPL_BS	# read IPL_BS bytes to addr 0

	.long 0x00000000,0x00000000		# external old psw
	.long 0x00000000,0x00000000		# svc old psw
	.long 0x00000000,0x00000000		# program check old psw
	.long 0x00000000,0x00000000		# machine check old psw
	.long 0x00000000,0x00000000		# io old psw
	.long 0x00000000,0x00000000
	.long 0x00000000,0x00000000
	.long 0x00000000,0x00000000
	.long 0x000a0000,0x00000058		# external new psw
	.long 0x000a0000,0x00000060		# svc new psw
	.long 0x000a0000,0x00000068		# program check new psw
	.long 0x000a0000,0x00000070		# machine check new psw


# IPL parameter area

	.org 0x200
_parm_addr:
	.quad PARMFILE_ADDR			# parmfile load address
_initrd_addr:
	.quad RAMDISK_ORIGIN			# ramdisk load address
_load_psw:
	.quad PSW_LOAD+KERNEL_ADDR		# kernel start PSW

#
# Subroutine to load from tape until tape mark
#
# Parameters:
#  R1 = device number
#  R2 = load address
#
# Returns:
#  R2 = number of bytes read
#

.Lloader:
	st    %r14,.Lldret			# save return address
	la    %r3,.Lorbread			# r3 = address of orb
	la    %r5,.Lirb				# r5 = address of irb
	st    %r2,.Lccwread+4			# initialize CCW data addresses
	lctl  %c6,%c6,.Lcr6
	slr   %r2,%r2				# set return code to 0
.Lldlp:
	la    %r6,3				# 3 retries
.Lssch:
	ssch  0(%r3)				# load chunk of IPL_BS bytes
	bnz   .Llderr
.Lw4end:
	bas   %r14,.Lwait4io
	tm    8(%r5),0x82			# do we have a problem ?
	bnz   .Lrecov
	slr   %r7,%r7
	icm   %r7,3,10(%r5)			# get residual count
	lcr   %r7,%r7
	la    %r7,IPL_BS(%r7)			# IPL_BS-residual=#bytes read
	ar    %r2,%r7				# add to total size
	tm    8(%r5),0x01			# found a tape mark ?
	bnz   .Ldone
	l     %r0,.Lccwread+4			# update CCW data addresses
	ar    %r0,%r7
	st    %r0,.Lccwread+4
	b     .Lldlp
.Ldone:
	l     %r14,.Lldret
	br    %r14				# r2 contains the total size
.Lrecov:
	bas   %r14,.Lsense			# do the sensing
	bct   %r6,.Lssch			# dec. retry count & branch
	b     .Llderr

#
# Sense subroutine
#

.Lsense:
	st    %r14,.Lsnsret
	la    %r7,.Lorbsense
	ssch  0(%r7)				# start sense command
	bnz   .Llderr
	bas   %r14,.Lwait4io
	l     %r14,.Lsnsret
	tm    8(%r5),0x82			# do we have a problem ?
	bnz   .Llderr
	br    %r14

#
# Wait for interrupt subroutine
#

.Lwait4io:
	lpsw  .Lwaitpsw
.Lioint:
	c     %r1,0xb8				# compare subchannel number
	bne   .Lwait4io
	tsch  0(%r5)
	slr   %r0,%r0
	tm    8(%r5),0x82			# do we have a problem ?
	bnz   .Lwtexit
	tm    8(%r5),0x04			# got device end ?
	bz    .Lwait4io
.Lwtexit:
	br    %r14
.Llderr:
	lpsw  .Lcrash

	.align 8
.Lorbread:
	.long 0x00000000,0x0080ff00,.Lccwread
	.align 8
.Lorbsense:
	.long 0x00000000,0x0080ff00,.Lccwsense
	.align 8
.Lccwread:
	.long 0x02200000+IPL_BS,0x00000000
.Lccwsense:
	.long 0x04200001,0x00000000
.Lwaitpsw:
	.long 0x020a0000,0x80000000+.Lioint

.Lirb:
	.long 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
.Lcr6:
	.long 0xff000000
	.align 8
.Lcrash:
	.long 0x000a0000,0x00000000
.Lldret:
	.long 0
.Lsnsret:
	.long 0
.Lvmparamtemp:
	.long 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0	# vm parameter space

#
# Load and initialize kernel image
#

iplstart:
	stm   %r0,%r15,.Lvmparamtemp		# store vm params for later use
	basr    %r13,0
0:
	la      %r7,2                           #/* First try code 2: */
	la      %r6,0                           #/* 64 bit psws are restored */
	sigp    %r7,%r6,SIGP_SET_ARCHITECTURE   #/* Switch to 64 bit */
	bc      8,.Lswitched_64-0b(%r13)        #/* Accepted ? */
	la      %r7,1                           #/* Failed - try code 1 */
	sigp    %r7,%r6,SIGP_SET_ARCHITECTURE   #/* Switch to 64 bit */
.Lswitched_64:
	sam64                                   #/* Switch to 64 bit addr mode */
	basr    %r13,0
1:
	mvc    __LC_IO_NEW_PSW(16),4f-1b(%r13)    # set i/o new ps
	b      .Lafterpsw
4:
	.long  0x00000001,0x80000000,0x00000000,0x00000000+.Lioint    # io new psw
.Lafterpsw:
	l     %r1,0xb8			 	# load rest of loader/TM
	la    %r2,IPL_BS
	bas   %r14,.Lloader

	la    %r3,.Lvmparamtemp			# move params
	la    %r4,.Lvmparam
	mvc   0(64,%r4),0(%r3)

	l     %r12,.Loffset
.Lagain0:
	lr    %r2,%r12				# load kernel image
	bas   %r14,.Lloader

	clc   0(3,%r12),.L_hdr			# if it is HDRx
	bz    .Lagain0				# skip dataset header
	clc   0(3,%r12),.L_eof			# if it is EOFx
	bz    .Lagain0				# skip dateset trailer

	st    %r2,.Lkernsize			# store size for later use

	a     %r12,.Lparmarea			# r12 points to parameter area
	st    %r1,IPL_DEVICE-PARMAREA+4(%r12)	# store ipl device number

	la    %r2,_initrd_addr			# store ramdisk address
	mvc   INITRD_START-PARMAREA(8,%r12),0(%r2)


#
# Load parameter file
#

	l     %r4,_parm_addr+4
.Lagain1:
	lr    %r2,%r4				# load parmfile
	bas   %r14,.Lloader

	ltr   %r2,%r2				# empty parmfile?
	bz    .Lnopf				# skip parmfile processing

	clc   0(3,%r4),.L_hdr			# if it is HDRx
	bz    .Lagain1				# skip dataset header
	clc   0(3,%r4),.L_eof			# if it is EOFx
	bz    .Lagain1				# skip dateset trailer

	chi   %r2,COMMAND_LINE_SIZE-1		# truncate if line too long
	bnh   .Lnotrunc
	la    %r2,COMMAND_LINE_SIZE-1
.Lnotrunc:

	la    %r5,0(%r4,%r2)			# search for EBCDIC chars
	lr    %r3,%r2
.Lidebc:
	tm    0(%r5),0x80			# high order bit set ?
	bo    .Ldocv				#  yes -> convert from EBCDIC
	ahi   %r5,-1
	bct   %r3,.Lidebc
	b     .Lnocv
.Ldocv:
	la    %r3,_ebcasc
	tr    0(256,%r4),0(%r3)			# convert parameters to ascii
	tr    256(256,%r4),0(%r3)
	tr    512(256,%r4),0(%r3)
	tr    768(127,%r4),0(%r3)
.Lnocv:
	la    %r3,COMMAND_LINE-PARMAREA(%r12)	# load adr. of command line
	mvc   0(256,%r3),0(%r4)
	mvc   256(256,%r3),256(%r4)
	mvc   512(256,%r3),512(%r4)
	mvc   768(127,%r3),768(%r4)
	slr   %r0,%r0
	b     .Lcntlp
.Ldelspc:
	ic    %r0,0(%r2,%r3)			# remove trailing spaces
	chi   %r0,0x20
	be    .Lcntlp
	chi   %r0,0x0a				# remove trailing new line
	be    .Lcntlp
	ahi   %r2,1
	b     .Leolp
.Lcntlp:
	brct  %r2,.Ldelspc
.Leolp:
	slr   %r0,%r0				# nul-terminate buffer
	stc   %r0,0(%r2,%r3)
.Lnopf:

#
# Load initial ramdisk
#

.Lagain2:
 	l     %r2,INITRD_START-PARMAREA+4(%r12)	# load ramdisk
	bas   %r14,.Lloader

 	st    %r2,INITRD_SIZE-PARMAREA+4(%r12)	# store ramdisk size
	ltr   %r2,%r2				# check for empty file
	bnz   .Lrdcont
	st    %r2,INITRD_START-PARMAREA+4(%r12)	# remove address if empty
.Lrdcont:
	l     %r2,INITRD_START-PARMAREA+4(%r12)

	clc   0(3,%r2),.L_hdr			# skip header and trailer
	bz    .Lagain2
	clc   0(3,%r2),.L_eof
	bz    .Lagain2

#
# Copy kernel image to final position
#

	la    %r2,_load_psw			# prepare copy code
	la    %r3,.Lcopypsw
	mvc   0(8,%r3),0(%r2)			# copy load psw

	l     %r4,_initrd_addr+4
	ahi   %r4,-0x100

	la    %r2,.Lcopystart			# get copy code addr (from)
	mvc   0(.Lcopyend-.Lcopystart,%r4),0(%r2)	# copy code

	l     %r1,.Loffset			# temp kernel address (from)

	l     %r2,4(%r3)			# get kernel addr from psw (to)
	n     %r2,.Lpswmask
	s     %r2,.Lkernoff

	l     %r3,.Lkernsize			# (length)
	br    %r4				# branch to copy routine

#
# Copy kernel, then load PSW
#
# R1 = from
# R2 = to
# R3 = length
#

	.align 8
.Lcopystart:
	clr   %r1,%r2
	je    .Lcopyfinish			# kernel is already at dest
	jh    .Lcopytolower			# need move to lower address

# Copy last to first

	ar    %r1,%r3				# start from last long
	ar    %r2,%r3
	lhi   %r4,-4				# set addr increment to -4
	j     .Lcopygo

# Copy first to last

.Lcopytolower:
	lhi   %r4,4				# set addr increment to 4

.Lcopygo:
	ahi   %r3,3				# get size in longs
	srl   %r3,2

.Lcopyloop:
	l     %r0,0(%r1)			# copy longs
	st    %r0,0(%r2)
	ar    %r1,%r4
	ar    %r2,%r4
	brct  %r3,.Lcopyloop

.Lcopyfinish:
	bras  %r13,.Lcopyload			# set up base register
.Lcopyload:
	sr    %r0,%r0
	la    %r1,.Lcopypsw-.Lcopyload(%r13)
	mvc   0(8,%r0),0(%r1)			# copy load psw to 0

	lm    %r0,%r15,.Lvmparam-.Lcopyload(%r13) # load saved registers
	lpsw  0					# start kernel

	.align  8
.Lcopypsw:
	.quad 0
.Lvmparam:
	.long 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0	# vm parameter space

.Lcopyend:

.Lpswmask:
	.long 0x7fffffff
.Lkernsize:
	.long 0
.Lkernoff:
	.long KERNEL_OFF
.Lparmarea:
	.long PARMAREA
.Loffset:
	.long IPL_OFF
.L_eof:
	.long 0xc5d6c600			# C'EOF'
.L_hdr:
	.long 0xc8c4d900			# C'HDR'


#
# EBCDIC 037 -> ASCII (IBM PC 437)
#

_ebcasc:
	.byte 0x00, 0x01, 0x02, 0x03, 0x07, 0x09, 0x07, 0x7F
	.byte 0x07, 0x07, 0x07, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	.byte 0x10, 0x11, 0x12, 0x13, 0x07, 0x0A, 0x08, 0x07
	.byte 0x18, 0x19, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
	.byte 0x07, 0x07, 0x1C, 0x07, 0x07, 0x0A, 0x17, 0x1B
	.byte 0x07, 0x07, 0x07, 0x07, 0x07, 0x05, 0x06, 0x07
	.byte 0x07, 0x07, 0x16, 0x07, 0x07, 0x07, 0x07, 0x04
	.byte 0x07, 0x07, 0x07, 0x07, 0x14, 0x15, 0x07, 0x1A
	.byte 0x20, 0xFF, 0x83, 0x84, 0x85, 0xA0, 0x07, 0x86
	.byte 0x87, 0xA4, 0x9B, 0x2E, 0x3C, 0x28, 0x2B, 0x7C
	.byte 0x26, 0x82, 0x88, 0x89, 0x8A, 0xA1, 0x8C, 0x07
	.byte 0x8D, 0xE1, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0xAA
	.byte 0x2D, 0x2F, 0x07, 0x8E, 0x07, 0x07, 0x07, 0x8F
	.byte 0x80, 0xA5, 0x07, 0x2C, 0x25, 0x5F, 0x3E, 0x3F
	.byte 0x07, 0x90, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
	.byte 0x70, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22
	.byte 0x07, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67
	.byte 0x68, 0x69, 0xAE, 0xAF, 0x07, 0x07, 0x07, 0xF1
	.byte 0xF8, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70
	.byte 0x71, 0x72, 0xA6, 0xA7, 0x91, 0x07, 0x92, 0x07
	.byte 0xE6, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78
	.byte 0x79, 0x7A, 0xAD, 0xAB, 0x07, 0x07, 0x07, 0x07
	.byte 0x5E, 0x9C, 0x9D, 0xFA, 0x07, 0x07, 0x07, 0xAC
	.byte 0xAB, 0x07, 0x5B, 0x5D, 0x07, 0x07, 0x07, 0x07
	.byte 0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
	.byte 0x48, 0x49, 0x07, 0x93, 0x94, 0x95, 0xA2, 0x07
	.byte 0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50
	.byte 0x51, 0x52, 0x07, 0x96, 0x81, 0x97, 0xA3, 0x98
	.byte 0x5C, 0xF6, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58
	.byte 0x59, 0x5A, 0xFD, 0x07, 0x99, 0x07, 0x07, 0x07
	.byte 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
	.byte 0x38, 0x39, 0x07, 0x07, 0x9A, 0x07, 0x07, 0x07
