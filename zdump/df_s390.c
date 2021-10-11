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

#include "df_s390.h"

/*
 * Check, if we can access the lowcore information in the dump
 */
static int check_addr_max(struct df_s390_hdr *hdr, u64 addr_max)
{
	unsigned int i, lc_size;

	lc_size = dfi_lc_size(df_s390_to_dfi_arch(hdr->arch));
	for (i = 0; i < hdr->cpu_cnt; i++) {
		if (hdr->lc_vec[i] + lc_size > addr_max)
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

	if (hdr->version < 5 && hdr->magic == DF_S390_MAGIC) {
		/* No Prefix registers in header */
		hdr->cpu_cnt = 0;
		dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
	} else if (check_addr_max(hdr, addr_max) != 0) {
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
	dfi_arch_set(df_s390_to_dfi_arch(hdr->arch));
	if (hdr->cpu_id)
		dfi_attr_cpu_id_set(hdr->cpu_id);
	if ((hdr->version >= 2 || hdr->magic == DF_S390_MAGIC_EXT) &&
	    hdr->build_arch)
		dfi_attr_build_arch_set(df_s390_to_dfi_arch(hdr->build_arch));
	if ((hdr->version >= 3 || hdr->magic == DF_S390_MAGIC_EXT) &&
	    hdr->mem_size_real)
		dfi_attr_mem_size_real_set(hdr->mem_size_real);
	if ((hdr->version >= 5 || hdr->magic == DF_S390_MAGIC_EXT) &&
	    hdr->real_cpu_cnt)
		dfi_attr_real_cpu_cnt_set(hdr->real_cpu_cnt);
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
void df_s390_dumper_read(struct zg_fh *fh, int blk_size,
			 struct df_s390_dumper *dumper)
{
	int bytes_to_read, offset = DF_S390_MAGIC_BLK_ECKD * blk_size;

	/*
	 * First read 3 fields at the start of the dumper. The magic number,
	 * version and one extra field for the old dumper case (no magic
	 * number, checking for specific assembler instructions).
	 */
	bytes_to_read = offsetof(struct df_s390_dumper, force);
	zg_seek(fh, offset, ZG_CHECK);
	zg_read(fh, dumper, bytes_to_read, ZG_CHECK);
	if (memcmp(dumper->magic, OLD_DUMPER_HEX_INSTR1, 4) == 0 &&
	    memcmp(&dumper->size, OLD_DUMPER_HEX_INSTR2, 2) == 0)
		/* We found basr r13,0 (old dumper) */
		dumper->version = 0;
	switch (dumper->version) {
	case 1:
		if (strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_EXT, 7) == 0 ||
		    strncmp(dumper->magic, DF_S390_DUMPER_MAGIC_MV_EXT, 7) == 0)
			dumper->size = DF_S390_DUMPER_SIZE_V3;
		else
			dumper->size = DF_S390_DUMPER_SIZE_V1;
		break;
	case 2:
		dumper->size = DF_S390_DUMPER_SIZE_V2;
		break;
	case 3:
	default:
		dumper->size = DF_S390_DUMPER_SIZE_V3;
	}
	/* Read force and mem fields in the end of the dumper */
	bytes_to_read = sizeof(dumper->force) + sizeof(dumper->mem);
	offset += dumper->size - bytes_to_read;
	zg_seek(fh, offset, ZG_CHECK);
	zg_read(fh, &dumper->force, bytes_to_read, ZG_CHECK);
}
