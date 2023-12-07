/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * NGDump dump tool
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "zgetdump.h"
#include "zg.h"
#include "dt.h"
#include "ngdump.h"

/*
 * File local static data
 */
static struct {
	int part_num;
	struct ngdump_meta meta;
} l;

static int dt_ngdump_init(void)
{
	char *part_path = NULL;
	int rc;

	l.part_num = ngdump_get_dump_part(g.fh, &part_path);
	if (l.part_num <= 0)
		return -1;
	rc = ngdump_read_meta_from_device(part_path, &l.meta);
	free(part_path);
	if (rc)
		return -1;

	dt_arch_set(DFI_ARCH_64);
	dt_version_set(l.meta.version);

	return 0;
}

static void dt_ngdump_info(void)
{
	STDERR("Partition info:\n");
	STDERR("  Partition number..: %d\n", l.part_num);
	if (!l.meta.file)
		return;
	STDERR("Meta info:\n");
	STDERR("  File..............: %s\n", l.meta.file);
}

/*
 * NGDump DT operations
 */
struct dt dt_ngdump = {
	.desc	= "Next Generation (NGDump) dump tool",
	.init	= dt_ngdump_init,
	.info	= dt_ngdump_info,
};
