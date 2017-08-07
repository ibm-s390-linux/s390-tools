/*
 * zipl - zSeries Initial Program Loader tool
 *
 * DASD ECKD specific functions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef ECKD_H
#define ECKD_H

#include "stage2.h"

/* CCW COMMANDS */
#define DASD_ECKD_CCW_SEEK		0x07
#define DASD_ECKD_CCW_TIC		0x08
#define DASD_ECKD_CCW_SEARCH		0x31
#define DASD_ECKD_CCW_READ_MT		0x86

struct ch_t {
	uint16_t cyl;
	uint16_t head;
} __packed;

struct chr_t {
	uint16_t cyl;
	uint16_t head;
	uint8_t record;
} __packed __aligned(8);

struct seek_arg {
	uint16_t zeroes;
	struct ch_t ch;
} __packed __aligned(8);

struct indirect_block {
	uint64_t *block;
} __packed;

#endif /* ECKD_H */
