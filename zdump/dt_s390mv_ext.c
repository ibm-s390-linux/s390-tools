/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390x multi-volume DASD dump tool
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "zgetdump.h"

/*
 * Initialize s390 multi-volume dump tool (extedend) for -d option
 */
static int dt_s390mv_ext_init(void)
{
	return dt_s390mv_init_gen(DUMP_EXTENDED);
}

/*
 * Dump Tool (extedned) operations
 */
struct dt dt_s390mv_ext = {
	.desc	= "Multi-volume DASD dump tool (extended)",
	.init	= dt_s390mv_ext_init,
	.info	= dt_s390mv_info,
};
