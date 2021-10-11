/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390x multi-volume dump input format
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "zgetdump.h"
#include "dt.h"
#include "df_s390.h"
#include "dfi.h"

/*
 * Initialize s390 multi-volume input dump format (extedend)
 */
static int dfi_s390mv_ext_init(void)
{
	return dfi_s390mv_init_gen(DUMP_EXTENDED);
}

/*
 * s390 multi-volume DFI (extedned) operations
 */
struct dfi dfi_s390mv_ext = {
	.name		= "s390mv_ext",
	.init		= dfi_s390mv_ext_init,
	.info_dump	= dfi_s390mv_info,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
