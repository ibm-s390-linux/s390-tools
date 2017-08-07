/*
 * mon_fsstatd - Write file system utilization data to the z/VM monitor stream
 *
 * Definitions used by mon_fsstatd
 *
 * Copyright IBM Corp. 2006, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __mon_fsstatd_h__
#define __mon_fsstatd_h__

#include <getopt.h>
#include <linux/types.h>
#include <sys/ioctl.h>

#include "lib/zt_common.h"

/* mon_function values */
#define MONWRITE_START_INTERVAL 0x00	/* start interval recording */
#define MONWRITE_STOP_INTERVAL	0x01	/* stop interval or config recording */

#define MAX_REC_LEN 4010
#define MAX_NAMES_LEN 3900
#define MAX_NAME_LEN 1800
#define MAX_DIR_LEN  1800
#define MAX_TYPE_LEN 256
#define FSSTATD_APPLID 0x01
/* Assume usually lengths of name, dir and type <= 512 bytes total */
#define SMALL_MON_RECORD_LEN 602
#define LARGE_MON_RECORD_LEN 4010

struct monwrite_hdr {
	unsigned char	mon_function;
	unsigned short	applid;
	unsigned char	record_num;
	unsigned short	version;
	unsigned short	release;
	unsigned short	mod_level;
	unsigned short	datalen;
	unsigned char	hdrlen;

} __attribute__((packed));

struct fsstatd_hdr {
	__u64	time_stamp;
	__u16	fsstat_data_len;
	__u16	fsstat_data_offset;
} __attribute__((packed));

struct fsstatd_data {
	__u64	fs_bsize;
	__u64	fs_frsize;
	__u64	fs_blocks;
	__u64	fs_bfree;
	__u64	fs_bavail;
	__u64	fs_files;
	__u64	fs_ffree;
	__u64	fs_favail;
	__u64	fs_flag;
};

static struct option options[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"attach", no_argument, NULL, 'a'},
	{"interval", required_argument, NULL, 'i'},
	{NULL, 0, NULL, 0}
};

static const char opt_string[] = "+hvai:";

static const char help_text[] =
	"mon_fsstatd: Daemon that writes file system utilization information\n"
	"to the z/VM monitor stream.\n"
	"\n"
	"Usage: mon_fstatd [OPTIONS]\n"
	"\n"
	"Options:\n"
	"-h, --help               Print this help, then exit\n"
	"-v, --version            Print version information, then exit\n"
	"-a, --attach             Run in foreground\n"
	"-i, --interval=<seconds> Sample interval\n";
#endif

