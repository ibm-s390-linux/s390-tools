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

#include <stdint.h>

/*****************************************************************************
 * SECTION: Definitions needed for DASD-API (see dasd.h)		     *
 *****************************************************************************/

#define DASD_PARTN_BITS 2

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
	uint8_t	   used;
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
	uint16_t dev_type;
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
	uint32_t hw_cylinders;
	uint32_t formatted_cylinders;
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
