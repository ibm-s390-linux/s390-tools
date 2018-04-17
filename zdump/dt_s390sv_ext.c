/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 single-volume DASD dump tool (extended)
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <linux/fs.h>
#include "zgetdump.h"

/*
 * Initialize s390 single-volume extended dump tool (for -d option)
 */
static int dt_s390sv_ext_init(void)
{
	return dt_s390sv_init_gen(DUMP_EXTENDED);
}

/*
 * s390 single-volume DT (extended) operations
 */
struct dt dt_s390sv_ext = {
	.desc	= "Single-volume DASD dump tool (extended)",
	.init	= dt_s390sv_ext_init,
};
