/*
 * vmur - Work with z/VM spool file queues (reader, punch, printer)
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _VMUR_H
#define _VMUR_H

#define ERR(x...) \
do { \
	fflush(stdout); \
	fprintf(stderr, "%s: ", prog_name);\
	fprintf(stderr, x); \
} while (0)

#define ERR_EXIT(x...) \
do { \
	fflush(stdout); \
	fprintf(stderr, "%s: ", prog_name); \
	fprintf(stderr, x); \
	exit(1); \
} while (0)

#define CHECK_SPEC_MAX(i, j, str) \
do { \
	if (i > j) \
		ERR_EXIT(str " can only be specified once.\n"); \
} while (0)

#define VMCP_DEVICE_NODE "/dev/vmcp"
#define VMCP_BUFSIZE 0x4000
#define VMCP_GETSIZE _IOR(0x10, 3, int)
#define VMCP_SETBUF  _IOW(0x10, 2, int)
#define VMCP_GETCODE _IOR(0x10, 1, int)

#define CP_PREFIX_LEN 11

#define VMRDR_DEVICE_NODE "/dev/vmrdr-0.0.000c"
#define VMPUN_DEVICE_NODE "/dev/vmpun-0.0.000d"
#define VMPRT_DEVICE_NODE "/dev/vmprt-0.0.000e"

#define VMPUN_RECLEN 80
#define VMPRT_RECLEN 132

#define VMUR_REC_COUNT 511

#define PAGE_SIZE 4096
#define MAXCMDLEN 80

#define NOP               0x3
#define CCW_IMMED_FLAG    0x10
#define IS_CONTROL_RECORD 0x20

#define EBCDIC_LF 0x25
#define ASCII_LF  0x0a
#define RSCS_USERID "RSCS"

#define SYSFS_CLASS_DIR   "/sys/class/vmur"
#define PROC_DEVICES_FILE "/proc/devices"
#define PROC_DEVICES_FILE_WIDTH 100

#define LOCK_FILE "/tmp/.vmur_lock"

#define EBCDIC_CODE_PAGE "IBM037"
#define ASCII_CODE_PAGE  "ISO-8859-1"

#define READ_BLOCKS 80

enum spoolfile_fmt {
	TYPE_NORMAL,
	TYPE_VMDUMP,
	TYPE_NETDATA,
};

enum ur_action {
	RECEIVE = 0,
	PUNCH   = 1,
	PRINT   = 2,
	PURGE   = 3,
	ORDER   = 4,
	LIST    = 5,
	LAST    = 6,
};

const char *ur_action_str[] = {
	"receive",
	"punch",
	"print",
	"purge",
	"order",
	"list",
};

unsigned int ur_action_prefix_len[] = {
	2, /* RECEIVE */
	3, /* PUNCH */
	2, /* PRINT */
	3, /* PURGE */
	2, /* ORDER */
	2, /* LIST */
};

struct ccw {
	__u8 opcode;
	char reserved_1[3];
	__u8 flag;
	char reserved_2[1];
	__u16 data_len; /* data length */
} __attribute__ ((packed));

struct data { /* CMS NETDATA format */
	__u8 length;
	__u8 flag;
	char magic[5];
	char reserved[248];
} __attribute__ ((packed));

struct splink_page {
	__u32 magic;
	char reserved1[8];
	__u32 data_recs; /* number of data records in 4k buf */
	char data[4048];
	__u16 rec_len;
	char reserved2[22];
	__u16 spoolid;
	char reserved3[6];
} __attribute__ ((packed));

struct splink_record {
	struct ccw ccw;
	char reserved[2];
	__u16 record_len; /* record length */
	struct data data;
} __attribute__ ((packed));

#endif
