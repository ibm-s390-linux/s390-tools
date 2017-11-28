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

