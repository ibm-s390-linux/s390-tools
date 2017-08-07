/*
 * util - Utility function library
 *
 * Partition detection functions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_PART_H
#define LIB_UTIL_PART_H

int util_part_search(const char *dev, size_t blk_start, size_t blk_cnt,
		     size_t blk_size, int *ext_part);
int util_part_search_fh(int fh, size_t blk_start, size_t blk_cnt,
			size_t blk_size, int *ext_part);

#endif /* LIB_UTIL_PART_H */
