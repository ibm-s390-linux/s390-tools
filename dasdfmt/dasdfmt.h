/*
 * dasdfmt - Format DASD ECKD devices for use by Linux
 *
 * Copyright IBM Corp. 2002, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DASDFMT_H
#define DASDFMT_H

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <limits.h>
#include <mntent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/****************************************************************************
 * SECTION: Definition needed for DASD-API (see dasd.h)                     *
 ****************************************************************************/

#define DASD_IOCTL_LETTER 'D'

/*
 * struct dasd_information2_t
 * represents any data about the device, which is visible to userspace.
 *  including format and features.
 */
typedef struct dasd_information2_t {
        unsigned int devno;           /* S/390 devno                        */
        unsigned int real_devno;      /* for aliases                        */
        unsigned int schid;           /* S/390 subchannel identifier        */
        unsigned int cu_type  : 16;   /* from SenseID                       */
        unsigned int cu_model :  8;   /* from SenseID                       */
        unsigned int dev_type : 16;   /* from SenseID                       */
        unsigned int dev_model : 8;   /* from SenseID                       */
        unsigned int open_count; 
        unsigned int req_queue_len; 
        unsigned int chanq_len;       /* length of chanq                    */
        char type[4];                 /* from discipline.name,              */
	                              /* 'none' for unknown                 */
        unsigned int status;          /* current device level               */
        unsigned int label_block;     /* where to find the VOLSER           */
        unsigned int FBA_layout;      /* fixed block size (like AIXVOL)     */
        unsigned int characteristics_size;
        unsigned int confdata_size;
        char characteristics[64];     /* from read_device_characteristics   */
        char configuration_data[256]; /* from read_configuration_data       */
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
 * Represents possible format modes that can be specified when formatting
 * a DASD.
 */
typedef enum format_mode_t {
	FULL,		/* default mode */
	QUICK,		/* format only the first 2 tracks */
	EXPAND,		/* search for unformatted area and format only that part*/
} format_mode_t;

static const char mode_str[3][10] = {
	"Full", "Quick", "Expand"
};

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
 * 0/8: normal format
 * 1/9: also write record zero
 * 3/11: also write home address
 * 4/12: invalidate track
 */
#define DASD_FMT_INT_FMT_R0 1 /* write record zero */
#define DASD_FMT_INT_FMT_HA 2 /* write home address, also set FMT_R0 ! */
#define DASD_FMT_INT_INVAL  4 /* invalidate tracks */
#define DASD_FMT_INT_COMPAT 8 /* use OS/390 compatible disk layout */
#define DASD_FMT_INT_FMT_NOR0 16 /* remove permission to write record zero */

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
 * values to be used for dasd_information2_t.format
 * 0x00: NOT formatted
 * 0x01: Linux disc layout
 * 0x02: Common disc layout
 */
#define DASD_FORMAT_NONE 0
#define DASD_FORMAT_LDL  1
#define DASD_FORMAT_CDL  2

/* Disable the volume (for Linux) */
#define BIODASDDISABLE _IO(DASD_IOCTL_LETTER,0) 
/* Enable the volume (for Linux) */
#define BIODASDENABLE  _IO(DASD_IOCTL_LETTER,1)  

/* Get information on a dasd device (enhanced) */
#define BIODASDINFO2   _IOR(DASD_IOCTL_LETTER, 3, dasd_information2_t)

/* #define BIODASDFORMAT  _IOW(IOCTL_LETTER,0,format_data_t) , deprecated */
#define BIODASDFMT     _IOW(DASD_IOCTL_LETTER,1,format_data_t) 

/* Check device format according to format_data_t */
#define BIODASDCHECKFMT _IOWR(DASD_IOCTL_LETTER, 2, format_check_t)

/****************************************************************************
 * SECTION: Further IOCTL Definitions  (see fs.h and hdreq.h )              *
 ****************************************************************************/
/* re-read partition table */
#define BLKRRPART  _IO(0x12,95)	
/* get block device sector size */
#define BLKSSZGET  _IO(0x12,104)
/* get read-only status (0 = read_write) */
#define BLKROGET   _IO(0x12,94)

/* get device geometry */
#define HDIO_GETGEO		0x0301	

/****************************************************************************
 * SECTION: DASDFMT internal types                                          *
 ****************************************************************************/

#define DASD_PARTN_BITS 2
#define PARTN_MASK ((1 << DASD_PARTN_BITS) - 1)

#define EXIT_MISUSE 1
#define EXIT_BUSY   2
#define LABEL_LENGTH 14
#define VLABEL_CHARS 84
#define LINE_LENGTH  80
#define ERR_LENGTH   90

#define DEFAULT_BLOCKSIZE  4096
/* requestsize - number of cylinders in one format step */
#define DEFAULT_REQUESTSIZE 10
#define USABLE_PARTITIONS  ((1 << DASD_PARTN_BITS) - 1)

#define ERRMSG(x...) {fflush(stdout);fprintf(stderr,x);}
#define ERRMSG_EXIT(ec,x...) {fflush(stdout);fprintf(stderr,x);exit(ec);}

#define CHECK_SPEC_MAX_ONCE(i,str)                       \
	{if (i>1) ERRMSG_EXIT(EXIT_MISUSE,"%s: " str " " \
	"can only be specified once\n",prog_name);}

#define PARSE_PARAM_INTO(x,param,base,str)                     \
	{char *endptr=NULL; x=(int)strtol(param,&endptr,base); \
	if (*endptr) ERRMSG_EXIT(EXIT_MISUSE,"%s: " str " "    \
	"is in invalid format\n",prog_name);}

typedef struct bootstrap1 {
        u_int32_t key;
        u_int32_t data[6];
} __attribute__ ((packed)) bootstrap1_t;

typedef struct bootstrap2 {
        u_int32_t key;
        u_int32_t data[36];
} __attribute__ ((packed)) bootstrap2_t;

typedef struct dasdfmt_info {
	dasd_information2_t dasd_info;
        int   verbosity;
        int   testmode;
        int   withoutprompt;
        int   print_progressbar;
        int   print_hashmarks, hashstep;
	int   print_percentage;
        int   force;
        int   writenolabel;
        int   labelspec;
        int   cdl_format;
        int   blksize_specified;
	int   reqsize_specified;
        int   device_id;
        int   keep_volser;
	int   force_host;
	int   layout_specified;
	int   check;
} dasdfmt_info_t;


/*
C9D7D3F1 000A0000 0000000F 03000000  00000001 00000000 00000000
*/
static bootstrap1_t ipl1 = {
        0xC9D7D3F1, {
                0x000A0000, 0x0000000F, 0x03000000,
                0x00000001, 0x00000000, 0x00000000
        }
};

/*
C9D7D3F2 07003AB8 40000006 31003ABE  40000005 08003AA0 00000000 06000000
20000000 00000000 00000000 00000400  00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000  00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000  00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000  00000000
*/
static bootstrap2_t ipl2 = {
        0xC9D7D3F2, {
                0x07003AB8, 0x40000006, 0x31003ABE,
                0x40000005, 0x08003AA0, 0x00000000,
                0x06000000, 0x20000000, 0x00000000,
                0x00000000, 0x00000400, 0x00000000,
                0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000
        }
};

#endif /* DASDFMT_H */

