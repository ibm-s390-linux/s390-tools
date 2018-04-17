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

#include <linux/fs.h>
#include "zgetdump.h"

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
	df_s390_dumper_read(g.fh, blk_size, &l.dumper);

	if (l.extended) {
		if (strncmp(l.dumper.magic, DF_S390_DUMPER_MAGIC_EXT, 7) != 0)
			return -ENODEV;
		l.dumper_arch = DFI_ARCH_64;
		return 0;
	}
	if (strncmp(l.dumper.magic, DF_S390_DUMPER_MAGIC64, 7) == 0) {
		l.dumper_arch = DFI_ARCH_64;
	} else if (strncmp(l.dumper.magic, DF_S390_DUMPER_MAGIC32, 7) == 0) {
		l.dumper_arch = DFI_ARCH_32;
	} else if (memcmp(l.dumper.magic, OLD_DUMPER_HEX_INSTR1, 4) == 0 &&
		   l.dumper.version == 0) {
		/* We found the old dumper */
		l.dumper_arch = DFI_ARCH_UNKNOWN;
	} else {
		return -ENODEV;
	}
	return 0;
}

/*
 * Check FBA dump tool magic number and set architecture attribute
 */
static int dumper_check_fba(struct df_s390_dumper *dumper)
{
	if (l.extended) {
		if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_FBA_EXT, 7)
		    != 0)
			return -ENODEV;
		l.dumper_arch = DFI_ARCH_64;
		return 0;
	}
	if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC64_FBA, 7) == 0) {
		l.dumper_arch = DFI_ARCH_64;
	} else if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC32_FBA, 7) == 0) {
		l.dumper_arch = DFI_ARCH_32;
	} else if (memcmp(dumper->magic, OLD_DUMPER_HEX_INSTR1, 4) == 0 &&
		   memcmp(&dumper->size, OLD_DUMPER_HEX_INSTR2, 2) == 0) {
		/* We found basr r13,0 (old dumper) */
		dumper->version = 0;
		l.dumper_arch = DFI_ARCH_UNKNOWN;
	} else {
		return -ENODEV;
	}
	return 0;
}

/*
 * Read dump tool from FBA device
 */
static int dumper_read_validate_fba(int size, struct df_s390_dumper *dumper)
{
	int bytes_to_read;

	/*
	 * On FBA device the dumper is written at the end of the volume because
	 * there is not enough space to place it at the beginning due to the
	 * linux disk layout
	 */
	zg_seek_end(g.fh, -size, ZG_CHECK);
	bytes_to_read = offsetof(struct df_s390_dumper, force);
	zg_read(g.fh, dumper, bytes_to_read, ZG_CHECK);
	if (dumper_check_fba(dumper) != 0)
		return -ENODEV;
	dumper->size = size;
	bytes_to_read = sizeof(dumper->force) + sizeof(dumper->mem);
	zg_seek_end(g.fh, -bytes_to_read, ZG_CHECK);
	zg_read(g.fh, &dumper->force, bytes_to_read, ZG_CHECK);
	return 0;
}

/*
 * Read dump tool on FBA disk and check its magic number
 */
static int dumper_read_fba(void)
{
	if (dumper_read_validate_fba(DF_S390_DUMPER_SIZE_V3, &l.dumper) == 0)
		return 0;
	if (dumper_read_validate_fba(DF_S390_DUMPER_SIZE_V2, &l.dumper) == 0)
		return 0;
	if (dumper_read_validate_fba(DF_S390_DUMPER_SIZE_V1, &l.dumper) == 0)
		return 0;
	return -ENODEV;
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
