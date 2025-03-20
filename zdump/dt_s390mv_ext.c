/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390x multi-volume DASD dump tool
 *
 * Copyright IBM Corp. 2001, 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "dt.h"
#include "df_s390.h"

/*
 * Dump Tool (extedned) operations
 */
struct dt dt_s390mv_ext = {
	.desc	= "Multi-volume DASD dump tool (extended)",
	.init	= dt_s390mv_ext_init,
	.info	= dt_s390mv_info,
};
