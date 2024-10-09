/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 single-volume DASD dump tool
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
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
	enum dfi_arch		dumper_arch;
	bool extended;		/* Extended dump-tool */
} l;

/*
 * Read dump tool from ECKD DASD device
 */
static int dumper_read_eckd(int blk_size)
{
	if (df_s390_dumper_read(g.fh, blk_size, &l.dumper))
		return -ENODEV;
	if (l.extended) {
		if (strncmp(l.dumper.magic, DF_S390_DUMPER_MAGIC_EXT,
			    DF_S390_DUMPER_MAGIC_SIZE) != 0)
			return -ENODEV;
	} else {
		if (strncmp(l.dumper.magic, DF_S390_DUMPER_MAGIC64,
			    DF_S390_DUMPER_MAGIC_SIZE) != 0)
			return -ENODEV;
	}
	l.dumper_arch = DFI_ARCH_64;
	return 0;
}

/*
 * Check FBA dump tool magic number and set architecture attribute
 */
static int dumper_check_fba(struct df_s390_dumper *dumper)
{
	if (l.extended) {
		if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_FBA_EXT,
			    DF_S390_DUMPER_MAGIC_SIZE) != 0)
			return -ENODEV;
	} else {
		if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC64_FBA,
			    DF_S390_DUMPER_MAGIC_SIZE) != 0)
			return -ENODEV;
	}
	l.dumper_arch = DFI_ARCH_64;
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
	if (dumper_check_fba(dumper) != 0)
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
 * Initialize s390 single-volume dump tool (for -d option)
 */
int dt_s390sv_init_gen(bool extended)
{
	l.extended = extended;
	if (sv_dumper_read() != 0)
		return -ENODEV;
	dt_arch_set(l.dumper_arch);
	dt_version_set(l.dumper.version);
	dt_attr_mem_limit_set(l.dumper.mem);
	return 0;
}

static int dt_s390sv_init(void)
{
	return dt_s390sv_init_gen(DUMP_NON_EXTENDED);
}
/*
 * s390 single-volume DT (non-extended) operations
 */
struct dt dt_s390sv = {
	.desc	= "Single-volume DASD dump tool",
	.init	= dt_s390sv_init,
};
