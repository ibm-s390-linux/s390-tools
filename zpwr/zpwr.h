/*
 * zpwr - display power readings of s390 computing environment.
 *
 * ioctls for diag324 and structures definitions.
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPWR_H
#define ZPWR_H

#include <linux/types.h>

#define DIAG_MAGIC_STR 'D'

struct pib {
	__u32		: 8;
	__u32 num	: 8;
	__u32 len	: 16;
	__u32		: 24;
	__u32 hlen	: 8;
	__u64		: 64;
	__u64 intv;
	__u8  r[];
} __packed;

struct pib_prologue {
	__u64 format	: 4;
	__u64		: 20;
	__u64 len	: 8;
	__u64		: 32;
};

struct diag324_pib {
	__u64 address;
	__u64 sequence;
};

/* Diag ioctl definitions */
#define DIAG324_GET_PIBBUF	_IOWR(DIAG_MAGIC_STR, 0x77, struct diag324_pib)
#define DIAG324_GET_PIBLEN	_IOR(DIAG_MAGIC_STR, 0x78, size_t)

#endif /* ZPWR_H */
