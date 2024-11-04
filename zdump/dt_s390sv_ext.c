/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 single-volume DASD dump tool (extended)
 *
 * Copyright IBM Corp. 2001, 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <linux/fs.h>

#include "zgetdump.h"
#include "zg.h"
#include "dt.h"
#include "df_s390.h"

/*
 * File local static data
 */
static struct {
	struct df_s390_dumper	dumper;
} l;

/*
 * Read dump tool from ECKD DASD device
 */
static int dumper_read_eckd(int blk_size)
{
	if (df_s390_dumper_read(g.fh, blk_size, &l.dumper))
		return -ENODEV;
	if (strncmp(l.dumper.magic, DF_S390_DUMPER_MAGIC_EXT,
		    DF_S390_DUMPER_MAGIC_SIZE) != 0)
		return -ENODEV;
	return 0;
}

/*
 * Read dump tool on FBA disk and check its magic number
 */
static int dumper_read_fba(void)
{
	struct df_s390_dumper *dumper = &l.dumper;
	int bytes_to_read;

	/*
	 * On FBA device the dumper is written at the end of the volume because
	 * there is not enough space to place it at the beginning due to the
	 * linux disk layout.
	 * First read 2 fields at the start of the dumper. The magic number
	 * and the version.
	 */
	zg_seek_end(g.fh, -STAGE2_DUMPER_SIZE_SV, ZG_CHECK);
	bytes_to_read = offsetof(struct df_s390_dumper, size);
	zg_read(g.fh, dumper, bytes_to_read, ZG_CHECK);
	if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_FBA_EXT,
		    DF_S390_DUMPER_MAGIC_SIZE) != 0)
		return -ENODEV;
	dumper->size = STAGE2_DUMPER_SIZE_SV;
	/* Read force and mem fields in the end of the dumper */
	bytes_to_read = sizeof(dumper->force) + sizeof(dumper->mem);
	zg_seek_end(g.fh, -bytes_to_read, ZG_CHECK);
	zg_read(g.fh, &dumper->force, bytes_to_read, ZG_CHECK);
	return 0;
}

/*
 * Read single volume dumper from disk
 */
static int sv_dumper_read(void)
{
	int blk_size;

	if (zg_type(g.fh) == ZG_TYPE_DASD_PART)
		return -ENODEV;
	zg_ioctl(g.fh, BLKSSZGET, &blk_size, "BLKSSZGET", ZG_CHECK);
	if (dumper_read_eckd(blk_size) == 0) {
		dt_attr_dasd_type_set("ECKD");
		return 0;
	}
	if (dumper_read_fba() == 0) {
		dt_attr_dasd_type_set("FBA");
		return 0;
	}
	return -ENODEV;
}

/*
 * Initialize s390 single-volume extended dump tool (for -d option)
 */
static int dt_s390sv_ext_init(void)
{
	if (sv_dumper_read() != 0)
		return -ENODEV;
	dt_version_set(l.dumper.version);
	dt_attr_mem_limit_set(l.dumper.mem);
	return 0;
}

/*
 * s390 single-volume DT (extended) operations
 */
struct dt dt_s390sv_ext = {
	.desc	= "Single-volume DASD dump tool (extended)",
	.init	= dt_s390sv_ext_init,
};
