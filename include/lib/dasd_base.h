/*
 * dasd_base - Library for DASD related functions
 *
 * DASD related helper functions for accessing device information
 *
 * Copyright IBM Corp. 2013, 2017
 * Copyright Red Hat Inc. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_DASD_BASE_H
#define LIB_DASD_BASE_H

#ifdef __linux__
#include <linux/hdreg.h>
#endif
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>

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
 * struct format_data_t
 * represents all data necessary to format a dasd
 */
typedef struct format_data_t {
	unsigned int start_unit; /* from track */
	unsigned int stop_unit;  /* to track */
	unsigned int blksize;    /* sectorsize */
	unsigned int intensity;
} format_data_t;

/*
 * struct format_check_t
 * represents all data necessary to evaluate the format of
 * different tracks of a dasd
 */
typedef struct format_check_t {
	/* Input */
	struct format_data_t expect;

	/* Output */
	unsigned int result;            /* Error indication (DASD_FMT_ERR_*) */
	unsigned int unit;              /* Track that is in error */
	unsigned int rec;               /* Record that is in error */
	unsigned int num_records;       /* Records in the track in error */
	unsigned int blksize;           /* Block-size of first record in error */
	unsigned int key_length;        /* Key length of first record in error */
} format_check_t;

#ifndef __linux__
/* definition from hdreg.h */
struct hd_geometry {
	unsigned char heads;
	unsigned char sectors;
	unsigned short cylinders;
	unsigned long start;
};
#endif

#define DASD_IOCTL_LETTER 'D'

/* Disable the volume (for Linux) */
#define BIODASDDISABLE _IO(DASD_IOCTL_LETTER, 0)
/* Enable the volume (for Linux) */
#define BIODASDENABLE  _IO(DASD_IOCTL_LETTER, 1)
/* Get information on a dasd device (enhanced) */
#define BIODASDINFO2   _IOR(DASD_IOCTL_LETTER, 3, dasd_information2_t)
/* #define BIODASDFORMAT  _IOW(IOCTL_LETTER,0,format_data_t) , deprecated */
#define BIODASDFMT     _IOW(DASD_IOCTL_LETTER, 1, format_data_t)
/* Check device format according to format_data_t */
#define BIODASDCHECKFMT _IOWR(DASD_IOCTL_LETTER, 2, format_check_t)

/********************************************************************************
 * SECTION: Further IOCTL Definitions  (see fs.h and hdreq.h)
 *******************************************************************************/
/* get read-only status (0 = read_write) */
#define BLKROGET   _IO(0x12, 94)
/* re-read partition table */
#define BLKRRPART  _IO(0x12, 95)
/* get block device sector size */
#define BLKSSZGET  _IO(0x12, 104)
/* return device size in bytes (u64 *arg) */
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)

#ifndef __linux__ /* from <linux/hdreg.h> */
#define HDIO_GETGEO	0x0301
#endif

int dasd_check_format(const char *device, format_check_t *p);
int dasd_format_disk(int fd, format_data_t *p);
int dasd_disk_disable(const char *device, int *fd);
int dasd_disk_enable(int fd);
int dasd_get_blocksize(const char *device, unsigned int *blksize);
int dasd_get_blocksize_in_bytes(const char *device, unsigned long long *blksize);
int dasd_get_geo(const char *device, struct hd_geometry *geo);
int dasd_get_info(const char *device, dasd_information2_t *info);
int dasd_is_ro(const char *device, bool *ro);
int dasd_reread_partition_table(const char *device, int ntries);

#endif /* LIB_DASD_BASE_H */
