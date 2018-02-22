/*
 * vmcp - Send commands to the z/VM control program
 *
 * Tool for accessing the control program of z/VM using the
 * kernel module vmcp
 * return codes:
 *	0: everything was fine                      (VMCP_OK)
 *	1: CP returned a nn zero response code      (VMCP_CP)
 *	2: the response buffer was not large enough (VMCP_BUF)
 *	3: an internal Linux error occurred         (VMCP_LIN)
 *	4: invalid options                          (VMCP_OPT)
 *
 * CREDITS: The idea is based on cpint of Neale Fergusson
 *
 * Copyright IBM Corp. 2005, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "lib/vmcp.h"

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

static int keep_case = 0;
static int buffersize = VMCP_DEFAULT_BUFSZ;
static char command[MAXCMDLEN + 1];

static void print_help(const char *name)
{
	printf("%s: z/VM CP command interface.\n%s", name, help_text);
}

static void print_version(const char *name)
{
	printf("%s: z/VM CP command interface version %s\n"
	       "Copyright IBM Corp. 2005, 2017\n",
	       name, RELEASE_STRING);
}

/* Parse STRING for buffer size in bytes, allowing size modifier suffix 'k' and
 * 'm'. Return buffer size in bytes on success, -1 on error. */
static long parse_buffersize(char *string)
{
	char *suffix;
	long bytes;

	bytes = strtol(string, &suffix, 10);
	if (strlen(suffix) > 1)
		return -1;
	switch (*suffix) {
	case 'k':
	case 'K':
		bytes *= 1024;
		break;
	case 'm':
	case 'M':
		bytes *= 1048576;
		break;
	case '\0':
		break;
	default:
		return -1;
	}
	if ((bytes < MINBUFFER) || (bytes > MAXBUFFER))
		return -1;
	return bytes;
}

/* Parse tool parameters. Fill in global variables keep_case, buffersize and
 * command according to parameters. Return VMCP_OK on success, VMCP_OPT
 * in case of parameter errors. In case of --help or --version, print
 * respective text to stdout and exit. */
static int parse_args(int argc, char **argv)
{
	int opt;
	int index;

	do {
		opt = getopt_long(argc, argv, opt_string, options, NULL);
		switch (opt) {
		case -1:
			/* Reached end of parameter list. */
			break;
		case 'h':
			print_help(argv[0]);
			exit(VMCP_OK);
		case 'v':
			print_version(argv[0]);
			exit(VMCP_OK);
		case 'k':
			keep_case = 1;
			break;
		case 'b':
			buffersize = (int) parse_buffersize(optarg);
			if (buffersize == -1) {
				fprintf(stderr, "Error: Invalid buffersize "
					"(needs to be between %d and %d)\n",
					MINBUFFER, MAXBUFFER);
				return VMCP_OPT;
			}
			break;
		default:
			fprintf(stderr, "Try 'vmcp --help' for more"
					" information.\n");
			return VMCP_OPT;
		}
	} while (opt != -1);
	/* Merge remaining argv contents into command string. */
	for (index = optind; index < argc; index++) {
		if (strlen(command) + (strlen(command) == 0 ? 0 : 1) +
		    strlen(argv[index]) > MAXCMDLEN) {
			fprintf(stderr,	"Error: Command too long (cannot be "
				"longer than %d characters)\n", MAXCMDLEN);
			return VMCP_OPT;
		}
		if (strlen(command) > 0)
			strcat(command, " ");
		strcat(command, argv[index]);
	}
	if (strlen(command) == 0) {
		print_help(argv[0]);
		return VMCP_OPT;
	}
	return VMCP_OK;
}

static inline void linux_error(const char *message)
{
	fprintf(stderr, "Error: %s: %s\n", message, strerror(errno));
}

/* Write COUNT bytes to FD from memory at location BUF. Return number of bytes
 * written on success, -1 otherwise. */
static ssize_t write_buffer(int fd, const char *buf, size_t count)
{
	ssize_t ret;
	ssize_t done;

	for (done = 0; done < (ssize_t) count; done += ret) {
		ret = write(fd, &buf[done], count - done);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1)
			return -1;
		if (ret == 0)
			break;
	}
	return done;
}

int main(int argc, char **argv)
{
	struct vmcp_parm cp;
	int ret;

	ret = parse_args(argc, argv);
	if (ret != VMCP_OK)
		return ret;

	cp.buffer_size = buffersize;
	cp.cpcmd = command;
	cp.do_upper = !keep_case;

	ret = vmcp(&cp);

	switch (ret) {
	case VMCP_ERR_OPEN:
		linux_error("Could not open device " VMCP_DEVICE_NODE);
		return VMCP_LIN;
	case VMCP_ERR_SETBUF:
		linux_error("Could not set buffer size");
		return VMCP_LIN;
	case VMCP_ERR_WRITE:
		linux_error("Could not issue CP command");
		return VMCP_LIN;
	case VMCP_ERR_GETCODE:
		linux_error("Could not query return code");
		return VMCP_LIN;
	case VMCP_ERR_GETSIZE:
		linux_error("Could not query response size");
		return VMCP_LIN;
	case VMCP_ERR_READ:
		linux_error("Could not read CP response");
		return VMCP_LIN;
	}
	write_buffer(STDOUT_FILENO, cp.response,
		     MIN(cp.response_size, cp.buffer_size));
	free(cp.response);
	if (ret == VMCP_ERR_TOOSMALL) {
		fprintf(stderr, "Error: output (%d bytes) was truncated, try "
			"--buffer to increase size\n", cp.response_size);
		return VMCP_BUF;
	}
	if (cp.cprc > 0) {
		fprintf(stderr, "Error: non-zero CP response for command '%s': "
			"#%d\n", command, cp.cprc);
		return VMCP_CP;
	}
	return VMCP_OK;
}
