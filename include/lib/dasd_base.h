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

/* the definition of a BUSID in the DASD driver is 20 */
#define DASD_BUS_ID_SIZE	20

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

/*
 * values to be used for dasd_information2_t.format
 * 0x00: NOT formatted
 * 0x01: Linux disc layout
 * 0x02: Common disc layout
 */
#define DASD_FORMAT_NONE 0
#define DASD_FORMAT_LDL  1
#define DASD_FORMAT_CDL  2

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
 * values to be used for format_data_t.intensity
 */
#define DASD_FMT_INT_FMT_R0	1	/* write record zero */
#define DASD_FMT_INT_FMT_HA	2	/* write home address, also set FMT_R0 ! */
#define DASD_FMT_INT_INVAL	4	/* invalidate tracks */
#define DASD_FMT_INT_COMPAT	8	/* use OS/390 compatible disk layout */
#define DASD_FMT_INT_FMT_NOR0	16	/* remove permission to write record zero */
#define DASD_FMT_INT_ESE_FULL	32	/* release space for entire volume */

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

/*
 * values to be used in format_check_t for indicating
 * possible format errors
 */
#define DASD_FMT_ERR_TOO_FEW_RECORDS	1
#define DASD_FMT_ERR_TOO_MANY_RECORDS	2
#define DASD_FMT_ERR_BLKSIZE		3
#define DASD_FMT_ERR_RECORD_ID		4
#define DASD_FMT_ERR_KEY_LENGTH		5

/*
 * struct profile_info_t
 * holds the profiling information
 */
typedef struct dasd_profile_info_t {
	unsigned int dasd_io_reqs;	  /* # of requests processed at all */
	unsigned int dasd_io_sects;	  /* # of sectors processed at all */
	unsigned int dasd_io_secs[32];	  /* request's sizes */
	unsigned int dasd_io_times[32];	  /* requests's times */
	unsigned int dasd_io_timps[32];	  /* requests's times per sector */
	unsigned int dasd_io_time1[32];	  /* time from build to start */
	unsigned int dasd_io_time2[32];	  /* time from start to irq */
	unsigned int dasd_io_time2ps[32]; /* time from start to irq */
	unsigned int dasd_io_time3[32];	  /* time from irq to end */
	unsigned int dasd_io_nr_req[32];  /* # of requests in chanq */
} dasd_profile_info_t;

/*
 * struct attrib_data_t
 * represents the operation (cache) bits for the device.
 * Used in DE to influence caching of the DASD.
 */
typedef struct attrib_data_t {
	unsigned char operation : 3; /* cache operation mode */
	unsigned char reserved	: 5;
	unsigned short nr_cyl;	     /* no of cyliners for read ahaed */
	unsigned char reserved2[29]; /* for future use */
} __attribute__((packed)) attrib_data_t;

/* definition of operation (cache) bits within attributes of DE */
#define DASD_NORMAL_CACHE 0x0
#define DASD_BYPASS_CACHE 0x1
#define DASD_INHIBIT_LOAD 0x2
#define DASD_SEQ_ACCESS	  0x3
#define DASD_SEQ_PRESTAGE 0x4
#define DASD_REC_ACCESS	  0x5

/*
 * Data returned by Sense Path Group ID (SNID)
 */
struct dasd_snid_data {
	struct {
		__u8 group   : 2;
		__u8 reserve : 2;
		__u8 mode    : 1;
		__u8 res     : 3;
	} __attribute__((packed)) path_state;
	__u8 pgid[11];
} __attribute__((packed));

struct dasd_snid_ioctl_data {
	struct dasd_snid_data data;
	__u8 path_mask;
} __attribute__((packed));

struct dasd_copypair_swap_data {
	char primary[DASD_BUS_ID_SIZE]; /* BUSID of primary */
	char secondary[DASD_BUS_ID_SIZE]; /* BUSID of secondary */
	/* Reserved for future updates. */
	char reserved[64];
};

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
/* Reserve the device for the current LPAR */
#define BIODASDRSRV    _IO(DASD_IOCTL_LETTER, 2)
/* Release the device for the current LPAR */
#define BIODASDRLSE    _IO(DASD_IOCTL_LETTER, 3)
/* Unconditional reserve the device for the current LPAR */
#define BIODASDSLCK	_IO(DASD_IOCTL_LETTER, 4)
/* reset profiling information of a device */
#define BIODASDPRRST	_IO(DASD_IOCTL_LETTER, 5)
/* retrieve profiling information of a device */
#define BIODASDPRRD	_IOR(DASD_IOCTL_LETTER, 2, dasd_profile_info_t)
/* Get information on a dasd device (enhanced) */
#define BIODASDINFO2   _IOR(DASD_IOCTL_LETTER, 3, dasd_information2_t)
/* Get Attributes (cache operations) */
#define BIODASDGATTR	_IOR(DASD_IOCTL_LETTER, 5, attrib_data_t)
/* #define BIODASDFORMAT  _IOW(IOCTL_LETTER,0,format_data_t) , deprecated */
#define BIODASDFMT     _IOW(DASD_IOCTL_LETTER, 1, format_data_t)
/* Set Attributes (cache operations) */
#define BIODASDSATTR	_IOW(DASD_IOCTL_LETTER, 2, attrib_data_t)
/* Release Allocated Space */
#define BIODASDRAS     _IOW(DASD_IOCTL_LETTER, 3, format_data_t)
/* Swap copy pair */
#define BIODASDPPRCSWAP _IOW(DASD_IOCTL_LETTER, 4, struct dasd_copypair_swap_data)
/* Get Sense Path Group ID (SNID) data */
#define BIODASDSNID	_IOWR(DASD_IOCTL_LETTER, 1, struct dasd_snid_ioctl_data)
/* Check device format according to format_data_t */
#define BIODASDCHECKFMT _IOWR(DASD_IOCTL_LETTER, 2, format_check_t)

#ifndef __linux__ /* from <linux/hdreg.h> */
#define HDIO_GETGEO	0x0301
#endif

int dasd_check_format(const char *device, format_check_t *p);
int dasd_format_disk(int fd, format_data_t *p);
int dasd_disk_disable(const char *device, int *fd);
int dasd_disk_enable(int fd);
int dasd_release_space(const char *device, format_data_t *r);
int dasd_get_blocksize(const char *device, unsigned int *blksize);
int dasd_get_blocksize_in_bytes(const char *device, unsigned long long *blksize);
int dasd_get_geo(const char *device, struct hd_geometry *geo);
int dasd_get_info(const char *device, dasd_information2_t *info);
int dasd_is_ro(const char *device, bool *ro);
int dasd_reread_partition_table(const char *device, int ntries);
int dasd_disk_reserve(const char *device);
int dasd_disk_release(const char *device);
int dasd_slock(const char *device);
int dasd_get_cache(const char *device, attrib_data_t *attrib_data);
int dasd_set_cache(const char *device, attrib_data_t *attrib_data);
int dasd_query_reserve(const char *device);
int dasd_profile(const char *device, dasd_profile_info_t *dasd_profile_info);
int dasd_reset_profile(const char *device);
int dasd_copy_swap(const char *device, struct dasd_copypair_swap_data *data);

#endif /* LIB_DASD_BASE_H */
