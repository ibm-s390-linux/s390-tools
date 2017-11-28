/*
 * dasdview - Display DASD and VTOC information or dump the contents of a DASD
 *
 * Copyright IBM Corp. 2002, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DASDVIEW_H
#define DASDVIEW_H

#include <limits.h>
#include "lib/u2s.h"

/********************************************************************************
 * SECTION: Definitions needed for DASD-API (see dasd.h)
 *******************************************************************************/

/*
 * values to be used for dasd_information2_t.format
 * 0x00: NOT formatted
 * 0x01: Linux disc layout
 * 0x02: Common disc layout
 */
#define DASD_FORMAT_NONE 0
#define DASD_FORMAT_LDL  1
#define DASD_FORMAT_CDL  2

/*
 * values to be used for dasd_information2_t.features
 * 0x00: default features
 * 0x01: readonly (ro)
 * 0x02: use diag discipline (diag)
 */
#define DASD_FEATURE_DEFAULT  0
#define DASD_FEATURE_READONLY 1
#define DASD_FEATURE_USEDIAG  2

/********************************************************************************
 * SECTION: DASDVIEW internal types
 *******************************************************************************/

#define LINE_LENGTH 80
#define DASDVIEW_ERROR "dasdview:"
#define DEFAULT_BEGIN 0
#define DEFAULT_SIZE 128
#define NO_PART_LABELS 8 /* for partition related labels (f1,f8 and f9) */
#define SEEK_STEP 4194304LL
#define DUMP_STRING_SIZE 1024LL

#define ERROR_STRING_SIZE 1024
static char error_str[ERROR_STRING_SIZE];

enum dasdview_failure {
	open_error,
	seek_error,
	read_error,
	ioctl_error,
	usage_error,
	disk_layout,
	vtoc_error
};

typedef struct dasdview_info
{
	char device[PATH_MAX];
	dasd_information2_t dasd_info;
	int dasd_info_version;
	unsigned int blksize;
	struct hd_geometry geo;
	u_int32_t hw_cylinders;

	unsigned long long begin;
	unsigned long long size;
	int format1;
	int format2;

	int action_specified;
	int begin_specified;
	int size_specified;
	int characteristic_specified;
	int device_id;
	int general_info;
	int extended_info;
	int volser;
	int vtoc;
	int vtoc_info;
	int vtoc_f1;
	int vtoc_f3;
	int vtoc_f4;
	int vtoc_f5;
	int vtoc_f7;
	int vtoc_f8;
	int vtoc_f9;
	int vtoc_all;
	int vlabel_info;

	format1_label_t f1[NO_PART_LABELS];
	format4_label_t f4;
	format5_label_t f5;
	format7_label_t f7;
	format1_label_t f8[NO_PART_LABELS];
	format9_label_t f9[NO_PART_LABELS];
	int f1c;
	int f4c;
	int f5c;
	int f7c;
	int f8c;
	int f9c;

	char busid[U2S_BUS_ID_SIZE];
	int busid_valid;
	int raw_track_access;
	struct zdsroot *zdsroot;
	struct raw_vtoc *rawvtoc;
	struct dasd *dasd;

} dasdview_info_t;

#endif /* DASDVIEW_H */
