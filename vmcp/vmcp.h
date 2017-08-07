/*
 * vmcp - Send commands to the z/VM control program
 *
 * Definitions used by vmcp
 *
 * Copyright IBM Corp. 2005, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __vmcp_h__
#define __vmcp_h__

#include <getopt.h>
#include <sys/ioctl.h>

#include "lib/zt_common.h"

#define DEVICE_NODE "/dev/vmcp"

#define VMCP_GETCODE _IOR(0x10, 1, int)
#define VMCP_SETBUF _IOW(0x10, 2, int)
#define VMCP_GETSIZE _IOR(0x10, 3, int)

#define MAXBUFFER 1048576
#define MINBUFFER 4096
#define MAXCMDLEN 240

#define VMCP_OK 0
#define VMCP_CP 1
#define VMCP_BUF 2
#define VMCP_LIN 3
#define VMCP_OPT 4

static struct option options[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"keepcase", no_argument, NULL, 'k'},
	{"buffer", required_argument, NULL, 'b'},
	{NULL, 0, NULL, 0}
};

static const char opt_string[] = "+hvkb:";

static const char help_text[] =
    "Usage:\n"
    "vmcp [-k] [-b <size>] command\n"
    "vmcp [-h|-v]\n\n"
    "Options:\n"
    "-h or --help     :Print usage information, then exit\n"
    "-v or --version  :Print version information, then exit\n"
    "-k or --keepcase :Using this option, vmcp does not convert the command\n"
    "                  to uppercase. The default is to translate the command\n"
    "                  string.\n"
    "-b <size> or     :defines the buffer size for the response\n"
    "--buffer=<size>   valid values are from 4096 to 1048576 bytes\n"
    "                  the k and M suffixes are also supported\n";
#endif
