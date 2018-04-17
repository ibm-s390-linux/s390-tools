/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 multi-volume DASD dump tool
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "zgetdump.h"

/*
 * Initialize s390 multi-volume dump tool (for -d option)
 */
static int dt_s390mv_init(void)
{
	return dt_s390mv_init_gen(DUMP_NON_EXTENDED);
}

/*
 * Dump Tool operations
 */
struct dt dt_s390mv = {
	.desc	= "Multi-volume DASD dump tool",
	.init	= dt_s390mv_init,
	.info	= dt_s390mv_info,
};
