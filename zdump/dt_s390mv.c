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
 * DT operations
 */
struct dt dt_s390mv = {
	.desc	= "Multi-volume DASD dump tool",
	.init	= dt_s390mv_init,
	.info	= dt_s390mv_info,
};
