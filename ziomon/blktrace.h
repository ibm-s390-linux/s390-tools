/*
 * Copyright IBM Corp. 2008, 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef BLKTRACE_H
#define BLKTRACE_H

struct blk_io_trace {
	__u32 magic;
	__u32 sequence;
	__u64 time;
	__u64 sector;
	__u32 bytes;
	__u32 action;
	__u32 pid;
	__u32 device;
	__u32 cpu;
	__u16 error;
	__u16 pdu_len;
};

#endif
