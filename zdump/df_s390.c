/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 dump format common functions
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dump/s390_dump.h"

#include "df_s390.h"

/*
 * Check, if we can access the lowcore information in the dump
 */
static int check_addr_max(struct df_s390_hdr *hdr, u64 addr_max)
{
	unsigned int i;

	for (i = 0; i < hdr->cpu_cnt; i++) {
		if (hdr->lc_vec[i] + LOWCORE_SIZE > addr_max)
			return -1;
	}
	return 0;
}

/*
 * Convert lowcore information into internal CPU representation
 */
int df_s390_cpu_info_add(struct df_s390_hdr *hdr, u64 addr_max)
{
	unsigned int i;
	int rc;

	if (hdr->cpu_cnt == 0) {
		/* No Prefix registers in header */
		dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
		return 0;
	}
	if (check_addr_max(hdr, addr_max) != 0) {
		/* Only lowcore pointers available */
		dfi_cpu_info_init(DFI_CPU_CONTENT_LC);
	} else {
		/* All register info available */
		dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);
	}

	for (i = 0; i < hdr->cpu_cnt; i++) {
		rc = dfi_cpu_add_from_lc(hdr->lc_vec[i]);
		if (rc)
			return rc;
	}

	return 0;
}

/*
 * Convert s390 TOD clock into timeval structure
 */
static void tod2timeval(struct timeval *xtime, u64 todval)
{
    /* adjust todclock to 1970 */
    todval -= 0x8126d60e46000000LL - (0x3c26700LL * 1000000 * 4096);

    todval >>= 12;
    xtime->tv_sec  = todval / 1000000;
    xtime->tv_usec = todval % 1000000;
}

/*
 * Convert s390 header information into internal representation
 */
void df_s390_hdr_add(struct df_s390_hdr *hdr)
{
	struct timeval timeval;

	if (hdr->tod) {
		tod2timeval(&timeval, hdr->tod);
		dfi_attr_time_set(&timeval);
	}
	dfi_attr_version_set(hdr->version);
	if (hdr->cpu_id)
		dfi_attr_cpu_id_set(hdr->cpu_id);
	if (hdr->build_arch)
		dfi_attr_build_arch_set(DFI_ARCH_64);
	if (hdr->mem_size_real)
		dfi_attr_mem_size_real_set(hdr->mem_size_real);
	if (hdr->real_cpu_cnt)
		dfi_attr_real_cpu_cnt_set(hdr->real_cpu_cnt);
	if (!hdr->mvdump && hdr->zlib_version_s390 && hdr->zlib_entry_size)
		dfi_attr_zlib_info_set(hdr->zlib_version_s390, hdr->zlib_entry_size);
}

/*
 * Add end marker information to internal representation
 */
void df_s390_em_add(struct df_s390_em *em)
{
	struct timeval timeval;

	if (em->tod) {
		tod2timeval(&timeval, em->tod);
		dfi_attr_time_end_set(&timeval);
	}
}

/*
 * Verify end marker
 */
int df_s390_em_verify(struct df_s390_em *em, struct df_s390_hdr *hdr)
{
	if (strncmp(em->str, DF_S390_EM_STR, strlen(DF_S390_EM_STR)) != 0)
		return -EINVAL;
	if (hdr->tod > em->tod)
		return -EINVAL;
	return 0;
}

/*
 * Read s390 dump tool from DASD with given block size
 */
int df_s390_dumper_read(struct zg_fh *fh, int blk_size,
			struct df_s390_dumper *dumper)
{
	int bytes_to_read, offset = DF_S390_MAGIC_BLK_ECKD * blk_size;

	/*
	 * First read 2 fields at the start of the dumper. The magic number
	 * and the version.
	 */
	bytes_to_read = offsetof(struct df_s390_dumper, size);
	zg_seek(fh, offset, ZG_CHECK);
	zg_read(fh, dumper, bytes_to_read, ZG_CHECK);
	dumper->size = 0;
	switch (dumper->version) {
	/*
	 * Versions 1 and 2 refer to the newer extended DASD dumpers
	 * while version 5 refers to the old (non-extended) DASD dump-tools
	 * we still support (either single-volume or multi-volume).
	 * Magic numbers for SV and MV dumpers apply as well.
	 * Pick a dumper size based on the Version and Magic combination.
	 */
	case 1:
		if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_EXT,
			    DF_S390_DUMPER_MAGIC_SIZE) == 0 ||
		    strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_MV_EXT,
			    DF_S390_DUMPER_MAGIC_SIZE) == 0)
			dumper->size = STAGE2_DUMPER_SIZE_SV;
		break;
	case 2:
		if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_EXT,
			    DF_S390_DUMPER_MAGIC_SIZE) == 0)
			dumper->size = STAGE2_DUMPER_SIZE_SV_ZLIB;
		else if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_MV_EXT,
				 DF_S390_DUMPER_MAGIC_SIZE) == 0)
			dumper->size = STAGE2_DUMPER_SIZE_MV;
		break;
	}
	if (dumper->size == 0)
		return -1;
	/* Read force and mem fields in the end of the dumper */
	bytes_to_read = sizeof(dumper->force) + sizeof(dumper->mem);
	offset += dumper->size - bytes_to_read;
	zg_seek(fh, offset, ZG_CHECK);
	zg_read(fh, &dumper->force, bytes_to_read, ZG_CHECK);
	return 0;
}
