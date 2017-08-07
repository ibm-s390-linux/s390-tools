/*
 * fdasd - Create or modify partitions on ECKD DASDs
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef FDASD_H
#define FDASD_H

/*****************************************************************************
 * SECTION: Definitions needed for DASD-API (see dasd.h)		     *
 *****************************************************************************/

#define DASD_IOCTL_LETTER 'D'

#define DASD_PARTN_BITS 2

/*
 * struct dasd_information_t
 * represents any data about the device, which is visible to userspace.
 *  including foramt and featueres.
 */
typedef struct dasd_information_t {
	unsigned int devno;	      /* S/390 devno			     */
	unsigned int real_devno;      /* for aliases			     */
	unsigned int schid;	      /* S/390 subchannel identifier	     */
	unsigned int cu_type  : 16;   /* from SenseID			     */
	unsigned int cu_model :  8;   /* from SenseID			     */
	unsigned int dev_type : 16;   /* from SenseID			     */
	unsigned int dev_model : 8;   /* from SenseID			     */
	unsigned int open_count;
	unsigned int req_queue_len;
	unsigned int chanq_len;       /* length of chanq		     */
	char type[4];		      /* from discipline.name, 'none' for    */
				      /* unknown			     */
	unsigned int status;	      /* current device level		     */
	unsigned int label_block;     /* where to find the VOLSER	     */
	unsigned int FBA_layout;      /* fixed block size (like AIXVOL)      */
	unsigned int characteristics_size;
	unsigned int confdata_size;
	char characteristics[64];     /* from read_device_characteristics    */
	char configuration_data[256]; /* from read_configuration_data	     */
} dasd_information_t;

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

/* Get information on a dasd device (enhanced) */
#define BIODASDINFO   _IOR(DASD_IOCTL_LETTER,1,dasd_information_t)

/*****************************************************************************
 * SECTION: Further IOCTL Definitions  (see fs.h and hdreq.h)		     *
 *****************************************************************************/
#define BLKROGET   _IO(0x12,94) /* get read-only status (0 = read_write) */
#define BLKRRPART  _IO(0x12,95) /* re-read partition table */
#define BLKSSZGET  _IO(0x12,104)/* get block device sector size */
#define BLKGETSIZE64 _IOR(0x12,114,size_t) /* device size in bytes (u64 *arg)*/

/* get device geometry */
#define HDIO_GETGEO		0x0301

/*****************************************************************************
 * SECTION: FDASD internal types					     *
 *****************************************************************************/
#define PARTN_MASK ((1 << DASD_PARTN_BITS) - 1)
#define USABLE_PARTITIONS ((1 << DASD_PARTN_BITS) - 1)

#define DEFAULT_FDASD_CONF "/etc/fdasd.conf" /* default config file */
#define CONFIG_FILE_SIZE (USABLE_PARTITIONS * LINE_LENGTH)
#define CONFIG_MAX 3 /* maximum number of parameters per config file entry */

#define FDASD_ERROR "fdasd error: "
#define DEVICE "device"
#define DISC   "disc"
#define PART   "part"

#define ALTERNATE_CYLINDERS_USED 0x10

/* partition types */
#define PARTITION_NEW		0
#define PARTITION_NATIVE	1
#define PARTITION_SWAP		2
#define PARTITION_RAID		3
#define PARTITION_LVM		4
#define PARTITION_GPFS		5

/*
 * PARTITION_NEW is the first item in our partition_types array and technically
 * maps to PARTITION_NATIVE. As PARTITION_NEW isn't a valid partition_type, it
 * can be ignored. Use this offset when iterate over the array.
 */
#define VALID_PARTITION_OFFSET	1

typedef struct partition_type {
	char *name;	/* User-friendly Name */
	char *dsname;	/* Data Set Name */
	int type;	/* Numerical Representation */
} partition_type_t;

struct fdasd_options {
	char *device;
	char *volser;
	char *conffile;
};

static struct fdasd_options options = {
	NULL,		/* device   */
	NULL,		/* volser   */
	NULL,		/* conffile */
};

typedef struct partition_info {
	u_int8_t	   used;
	unsigned long	   start_trk;
	unsigned long	   end_trk;
	unsigned long	   len_trk;
	unsigned long	   fspace_trk;
	format1_label_t    *f1;
	int		   type;
	struct partition_info *next;
	struct partition_info *prev;
} partition_info_t;

typedef struct config_data {
	unsigned long start;
	unsigned long stop;
	int type;
} config_data_t;

typedef struct fdasd_anchor {
	int vlabel_changed;
	int vtoc_changed;
	int auto_partition;
	int print_table;
	int print_volser;
	int keep_volser;
	int force_virtual;
	int force_host;
	int big_disk;
	int silent;
	int verbose;
	int devno;
	int option_reuse;
	int option_recreate;
	int partno[USABLE_PARTITIONS];
	u_int16_t dev_type;
	unsigned int used_partitions;
	unsigned long label_pos;
	unsigned int  blksize;
	unsigned long fspace_trk;
	format4_label_t  *f4;
	format5_label_t  *f5;
	format7_label_t  *f7;
	format9_label_t  *f9; /* template for all f9 labels */
	partition_info_t *first;
	partition_info_t *last;
	volume_label_t	 *vlabel;
	config_data_t confdata[USABLE_PARTITIONS];
	u_int32_t hw_cylinders;
	u_int32_t formatted_cylinders;
} fdasd_anchor_t;

enum offset {lower, upper};

enum fdasd_failure {
	parser_failed,
	unable_to_open_disk,
	unable_to_seek_disk,
	unable_to_read_disk,
	read_only_disk,
	unable_to_ioctl,
	wrong_disk_type,
	wrong_disk_format,
	disk_in_use,
	config_syntax_error,
	vlabel_corrupted,
	dsname_corrupted,
	malloc_failed,
	device_verification_failed,
	volser_not_found
};

#define ERROR_STRING_SIZE 1024
#define INPUT_BUF_SIZE 1024

#endif /* FDASD_H */
