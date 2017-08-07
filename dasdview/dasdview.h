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

#define DASD_IOCTL_LETTER 'D'

/*
 * struct dasd_information_t
 * represents any data about the device, which is visible to userspace.
 *  including foramt and features.
 */
typedef struct dasd_information_t {
        unsigned int devno;         /* S/390 devno */
        unsigned int real_devno;    /* for aliases */
        unsigned int schid;         /* S/390 subchannel identifier */
        unsigned int cu_type  : 16; /* from SenseID */
        unsigned int cu_model :  8; /* from SenseID */
        unsigned int dev_type : 16; /* from SenseID */
        unsigned int dev_model : 8; /* from SenseID */
        unsigned int open_count;
        unsigned int req_queue_len;
        unsigned int chanq_len;     /* length of chanq */
        char type[4];               /* from discipline.name, 'none' for unknown */
        unsigned int status;        /* current device level */
        unsigned int label_block;   /* where to find the VOLSER */
        unsigned int FBA_layout;    /* fixed block size (like AIXVOL) */
        unsigned int characteristics_size;
        unsigned int confdata_size;
        char characteristics[64];   /* from read_device_characteristics */
        char configuration_data[256]; /* from read_configuration_data */
} dasd_information_t;

typedef struct dasd_information2_t {
        unsigned int devno;         /* S/390 devno */
        unsigned int real_devno;    /* for aliases */
        unsigned int schid;         /* S/390 subchannel identifier */
        unsigned int cu_type  : 16; /* from SenseID */
        unsigned int cu_model :  8; /* from SenseID */
        unsigned int dev_type : 16; /* from SenseID */
        unsigned int dev_model : 8; /* from SenseID */
        unsigned int open_count;
        unsigned int req_queue_len;
        unsigned int chanq_len;     /* length of chanq */
        char type[4];               /* from discipline.name, 'none' for unknown */
        unsigned int status;        /* current device level */
        unsigned int label_block;   /* where to find the VOLSER */
        unsigned int FBA_layout;    /* fixed block size (like AIXVOL) */
        unsigned int characteristics_size;
        unsigned int confdata_size;
	unsigned char characteristics[64];/*from read_device_characteristics */
	unsigned char configuration_data[256];/*from read_configuration_data */
        unsigned int format;          /* format info like formatted/cdl/ldl/... */
        unsigned int features;        /* dasd features like 'ro',...            */
        unsigned int reserved0;       /* reserved for further use ,...          */
        unsigned int reserved1;       /* reserved for further use ,...          */
        unsigned int reserved2;       /* reserved for further use ,...          */
        unsigned int reserved3;       /* reserved for further use ,...          */
        unsigned int reserved4;       /* reserved for further use ,...          */
        unsigned int reserved5;       /* reserved for further use ,...          */
        unsigned int reserved6;       /* reserved for further use ,...          */
        unsigned int reserved7;       /* reserved for further use ,...          */
} dasd_information2_t;

struct dasd_eckd_characteristics {
	unsigned short cu_type;
	struct {
		unsigned char support:2;
		unsigned char async:1;
		unsigned char reserved:1;
		unsigned char cache_info:1;
		unsigned char model:3;
	} __attribute__ ((packed)) cu_model;
	unsigned short dev_type;
	unsigned char dev_model;
	struct {
		unsigned char mult_burst:1;
		unsigned char RT_in_LR:1;
		unsigned char reserved1:1;
		unsigned char RD_IN_LR:1;
		unsigned char reserved2:4;
		unsigned char reserved3:8;
		unsigned char defect_wr:1;
		unsigned char XRC_supported:1;
		unsigned char reserved4:1;
		unsigned char striping:1;
		unsigned char reserved5:4;
		unsigned char cfw:1;
		unsigned char reserved6:2;
		unsigned char cache:1;
		unsigned char dual_copy:1;
		unsigned char dfw:1;
		unsigned char reset_alleg:1;
		unsigned char sense_down:1;
	} __attribute__ ((packed)) facilities;
	unsigned char dev_class;
	unsigned char unit_type;
	unsigned short no_cyl;
	unsigned short trk_per_cyl;
	unsigned char sec_per_trk;
	unsigned char byte_per_track[3];
	unsigned short home_bytes;
	unsigned char formula;
	union {
		struct {
			unsigned char f1;
			unsigned short f2;
			unsigned short f3;
		} __attribute__ ((packed)) f_0x01;
		struct {
			unsigned char f1;
			unsigned char f2;
			unsigned char f3;
			unsigned char f4;
			unsigned char f5;
		} __attribute__ ((packed)) f_0x02;
	} __attribute__ ((packed)) factors;
	unsigned short first_alt_trk;
	unsigned short no_alt_trk;
	unsigned short first_dia_trk;
	unsigned short no_dia_trk;
	unsigned short first_sup_trk;
	unsigned short no_sup_trk;
	unsigned char MDR_ID;
	unsigned char OBR_ID;
	unsigned char director;
	unsigned char rd_trk_set;
	unsigned short max_rec_zero;
	unsigned char reserved1;
	unsigned char RWANY_in_LR;
	unsigned char factor6;
	unsigned char factor7;
	unsigned char factor8;
	unsigned char reserved2[3];
	unsigned char reserved3[6];
	unsigned int long_no_cyl;
} __attribute__ ((packed));

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

/* Get information on a dasd device (enhanced) */
#define BIODASDINFO    _IOR(DASD_IOCTL_LETTER,1,dasd_information_t)
#define BIODASDINFO2   _IOR(DASD_IOCTL_LETTER,3,dasd_information2_t)

/********************************************************************************
 * SECTION: Further IOCTL Definitions  (see fs.h and hdreq.h)
 *******************************************************************************/
/* get block device sector size */
#define BLKSSZGET  _IO(0x12,104)
/* return device size in bytes (u64 *arg) */
#define BLKGETSIZE64 _IOR(0x12,114,size_t)

/* get device geometry */
#define HDIO_GETGEO		0x0301

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
	int blksize;
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
