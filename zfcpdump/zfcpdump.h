/*
 * zfcpdump - Write /proc/vmcore to SCSI partition
 *
 * Copyright IBM Corp. 2003, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZFCPDUMP_H
#define ZFCPDUMP_H

#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#define ZFCPDUMP_VERSION "3.0"

#define PRINT_TRACE(x...) \
	do { \
		if (g.parm_debug >= 3) { \
			fprintf(stderr, "TRACE: "); \
			fprintf(stderr, ##x); \
		} \
	} while (0)

#define PRINT_ERR(x...) \
	do { \
		fprintf(stderr, "ERROR: "); \
		fprintf(stderr, ##x); \
	} while (0)

#define PRINT_WARN(x...) \
	do { \
		fprintf(stderr, "WARNING: "); \
		fprintf(stderr, ##x); \
	} while (0)

#define PRINT_PERR(x...) \
	do { \
		fprintf(stderr, "ERROR: "); \
		fprintf(stderr, ##x); \
		perror(""); \
	} while (0)

#define PRINT(x...) fprintf(stdout, ##x)
#define CMDLINE_MAX_LEN 1024
#define KERN_PARM_MAX 100

#define DUMP_FLAGS (O_CREAT | O_RDWR | O_TRUNC | O_DIRECT)
#define DUMP_MODE (S_IRUSR | S_IWUSR | S_IRGRP)

#define MIB (1024ULL * 1024)
#define TO_MIB(x) ((x + (MIB / 2)) / MIB)

struct globals {
	int	parm_debug;
	char	parmline[CMDLINE_MAX_LEN];
	struct	sigaction sigact;
	char	dump_devno[16];
	char	dump_wwpn[32];
	char	dump_lun[32];
	char	dump_bootprog[32];
	char	start_time_str[128];
	struct timeval start_time;
	unsigned long vmcore_size;
};

extern struct globals g;

#define PROC_CMDLINE	"/proc/cmdline"
#define DEV_ZCORE_REIPL	"/sys/kernel/debug/zcore/reipl"
#define DEV_ZCORE_HSA	"/sys/kernel/debug/zcore/hsa"
#define REIPL		"1"
#define DEV_SCSI	"/dev/sda"

#define IPL_WWPN	"/sys/firmware/ipl/wwpn"
#define IPL_DEVNO	"/sys/firmware/ipl/device"
#define IPL_LUN		"/sys/firmware/ipl/lun"

#define PARM_DEBUG	"dump_debug"
#define PARM_DEBUG_DFLT	2
#define PARM_DEBUG_MIN	1
#define PARM_DEBUG_MAX	6

#define WAIT_TIME_END		3 /* seconds */
#define WAIT_TIME_ONLINE	2 /* seconds */

#define PAGE_SIZE		4096

#define CHUNK_INFO_SIZE		34  /* 2 16-byte char, each followed by blank */

struct mem_chunk {
	__u64 addr;		/* Start address of this memory chunk */
	__u64 size;		/* Length of this memory chunk */
	struct mem_chunk *next;	/* Pointer to next memory chunk */
};

/*
 * Function prototypes
 */
void release_hsa(void);
__u64 get_hsa_size(void);
int zfcpdump_init(void);
void print_newline(void);
void show_progress(unsigned long done);
int terminate(int rc);

#endif /* ZFCPDUMP_H */
