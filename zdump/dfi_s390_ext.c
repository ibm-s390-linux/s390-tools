/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 extended dump input format
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "dt.h"
#include "df_s390.h"
#include "dfi.h"

/*
 * Initialize s390 input dump format (extended)
 */
static int dfi_s390_ext_init(void)
{
	return dfi_s390_init_gen(DUMP_EXTENDED);
}

/*
 * s390 nput dump format (extedned) operations
 */
struct dfi dfi_s390_ext = {
	.name		= "s390_ext",
	.init		= dfi_s390_ext_init,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
