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

/* Report error, free memory, and exit */
static void error(const char *format, ...)
	__attribute__((__noreturn__, __format__(__printf__, 1, 2)));

#define DASD_PARTN_BITS 2
#define PARTN_MASK ((1 << DASD_PARTN_BITS) - 1)

#define EXIT_MISUSE 1
#define EXIT_BUSY   2
#define ERR_LENGTH   90

#define DEFAULT_BLOCKSIZE  4096
/* requestsize - number of cylinders in one format step */
#define DEFAULT_REQUESTSIZE 10

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
