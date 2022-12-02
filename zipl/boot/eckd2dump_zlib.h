/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common ECKD dump I/O functions for zlib compression support
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef ECKD2DUMP_ZLIB_H
#define ECKD2DUMP_ZLIB_H

#include "zlib/zlib.h"
#include "dump/s390_dump.h"

#define ZLIB_WORKSPACE_LIMIT	(1 * MIB)

/* Compression related functions */
int zlib_workarea_init(unsigned long addr, z_stream *strm);
unsigned long write_compressed_dump_segment(unsigned long blk,
					    struct df_s390_dump_segm_hdr *segm,
					    z_stream *strm);

#endif /* ECKD2DUMP_ZLIB_H */
