/*
 * zipl - zSeries Initial Program Loader tool
 *
 * DASD FBA specific functions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef FBA_H
#define FBA_H

#include "error.h"
#include "libc.h"
#include "stage2.h"

/* CCW COMMANDS */
#define DASD_FBA_CCW_LOCATE	0x43
#define DASD_FBA_CCW_LR	        0x06
#define DASD_FBA_CCW_DE	        0x63
#define DASD_FBA_CCW_WRITE	0x41
#define DASD_FBA_CCW_READ	0x42

#define MAX_BLOCKCT             128

struct DE_fba_data {
	struct {
		unsigned char perm:2;   /* Permissions on this extent */
		unsigned char zero:2;   /* Must be zero */
		unsigned char da:1;     /* usually zero */
		unsigned char diag:1;   /* allow diagnose */
		unsigned char zero2:2;  /* zero */
	} __packed mask;
	uint8_t zero;              /* Must be zero */
	uint16_t blk_size;         /* Blocksize */
	uint32_t ext_loc;          /* Extent locator */
	uint32_t ext_beg;          /* logical number of block 0 in extent */
	uint32_t ext_end;          /* logical number of last block in extent */
} __packed;

struct LO_fba_data {
	struct {
		unsigned char zero:4;
		unsigned char cmd:4;
	} __packed operation;
	uint8_t auxiliary;
	uint16_t blk_ct;
	uint32_t blk_nr;
} __packed;

struct indirect_block {
	uint64_t *block;
} __packed;

#endif /* FBA_H */
