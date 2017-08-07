/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 single-volume DASD dump tool
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <linux/fs.h>
#include "zgetdump.h"

#define HEXINSTR "\x0d\x10\x47\xf0" /* BASR + 1st halfword of BC */

/*
 * File local static data
 */
static struct {
	struct df_s390_dumper	dumper;
	enum dfi_arch		dumper_arch;
} l;

/*
 * Read dump tool from ECKD DASD device
 */
static int dumper_read_eckd(int blk_size)
{
	df_s390_dumper_read(g.fh, blk_size, &l.dumper);

	if (strncmp(l.dumper.magic, "ZECKD31", 7) == 0) {
		l.dumper_arch = DFI_ARCH_32;
	} else if (strncmp(l.dumper.magic, "ZECKD64", 7) == 0) {
		l.dumper_arch = DFI_ARCH_64;
	} else if ((memcmp(l.dumper.magic, HEXINSTR, 4) == 0) &&
		   (l.dumper.d.v1.code[0] == '\x0d') &&
		   (l.dumper.d.v1.code[1] == '\xd0')) {
		/* We found basr r13,0 (old dumper) */
		l.dumper.version = 0;
		l.dumper_arch = DFI_ARCH_UNKNOWN;
	} else {
		return -ENODEV;
	}
	return 0;
}

/*
 * Read dump tool from FBA DASD device
 */
static void dumper_read_fba_gen(int size, void *buffer)
{
	zg_seek_end(g.fh, -size, ZG_CHECK);
	zg_read(g.fh, buffer, size, ZG_CHECK);
}

/*
 * Read dump tool on FBA disk and check its magic number
 */
static int dumper_check_fba(void)
{
	if (strncmp(l.dumper.magic, "ZDFBA31", 7) == 0) {
		l.dumper_arch = DFI_ARCH_32;
	} else if (strncmp(l.dumper.magic, "ZDFBA64", 7) == 0) {
		l.dumper_arch = DFI_ARCH_64;
	} else if ((memcmp(l.dumper.magic, HEXINSTR, 4) == 0) &&
		   (l.dumper.d.v1.code[0] == '\x0d') &&
		   (l.dumper.d.v1.code[1] == '\xd0')) {
		/* We found basr r13,0 (old dumper) */
		l.dumper.version = 0;
		l.dumper_arch = DFI_ARCH_UNKNOWN;
	} else {
		return -ENODEV;
	}
	return 0;
}

/*
 * Read dump tool on FBA disk and check its magic number
 */
static int dumper_read_fba(void)
{
	dumper_read_fba_gen(DF_S390_DUMPER_SIZE_V1, &l.dumper);
	if (dumper_check_fba() == 0)
		return 0;
	dumper_read_fba_gen(DF_S390_DUMPER_SIZE_V2, &l.dumper);
	if (dumper_check_fba() == 0)
		return 0;
	dumper_read_fba_gen(DF_S390_DUMPER_SIZE_V3, &l.dumper);
	if (dumper_check_fba() == 0)
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
static int dt_s390sv_init(void)
{
	if (sv_dumper_read() != 0)
		return -ENODEV;
	dt_arch_set(l.dumper_arch);
	dt_version_set(df_s390_dumper_version(l.dumper));
	dt_attr_mem_limit_set(df_s390_dumper_mem(&l.dumper));
	return 0;
}

/*
 * s390 single-volume DT operations
 */
struct dt dt_s390sv = {
	.desc	= "Single-volume DASD dump tool",
	.init	= dt_s390sv_init,
};
