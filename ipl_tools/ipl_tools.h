/*
 * ipl_tools - Linux for System z reipl tools (shutdown actions)
 *
 * Common macro definitions and declarations
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef IPL_TOOLS_H
#define IPL_TOOLS_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/zt_common.h"

#define IPL_TYPE_LEN_MAX	100
#define NSS_NAME_LEN_MAX	8

extern struct globals {
	char			prog_name[256];	/* Program name */
} g;

/*
 * Commands
 */
extern void cmd_lsshut(int argc, char *argv[]);
extern void cmd_chshut(int argc, char *argv[]);
extern void cmd_lsreipl(int argc, char *argv[]);
extern void cmd_chreipl(int argc, char *argv[]);

extern void print_ccw(int show_ipl);
extern void print_fcp(int show_ipl, int dump);
extern void print_nvme(int show_ipl, int dump);
extern void print_nss(int show_ipl);

/*
 * Helper
 */
extern int is_lpar(void);
extern int is_root(void);

extern void strlow(char *s);

extern void write_str(char *string, char *file);
extern int write_str_errno(char *string, char *file);
extern void read_str(char *string, const char *file, size_t len);
extern void read_fw_str(char *string, const char *file, size_t len);
extern void print_fw_str(const char *fmt, const char *dir, const char *file);

extern void __noreturn print_version_exit(void);
extern void __noreturn print_help_hint_exit(void);

/*
 * FCP
 */
extern int fcp_is_device(const char *devno);
extern void fcp_lun_get(const char *device, char *lun);
extern void fcp_wwpn_get(const char *device, char *wwpn);
extern void fcp_busid_get(const char *device, char *devno);

/*
 * NVME
 */
#define FID_MAX_LEN	11	/* 8 characters + 0x + null */
#define NVME_PATH_MAX	(PATH_MAX + NAME_MAX + 1)

extern void nvme_fid_get(const char *device, char *fid);
extern void nvme_nsid_get(const char *device, char *nsid);
int nvme_is_device(char *fid_str, char *nsid_str);

/*
 * CCW
 */
extern int ccw_is_device(const char *devno);
extern void ccw_busid_get(const char *device, char *devno);

/*
 * Shutdown trigger
 */
struct shutdown_trigger {
	const char	*name;
	const char	*name_print;
	const char	*name_sysfs;
	int		available;
};

extern struct shutdown_trigger shutdown_trigger_panic;
extern struct shutdown_trigger shutdown_trigger_restart;
extern struct shutdown_trigger *shutdown_trigger_vec[];
extern void shutdown_init(void);

/*
 * Shutdown actions
 */
struct shutdown_action {
	const char	*name;
};

extern struct shutdown_action shutdown_action_vmcmd;
extern struct shutdown_action *shutdown_action_vec[];

/*
 * Error and print functions
 */
#define ERR(x...) \
do { \
	fprintf(stderr, "%s: ", g.prog_name); \
	fprintf(stderr, x); \
	fprintf(stderr, "\n"); \
} while (0)

#define ERR_EXIT(x...) \
do { \
	ERR(x); \
	exit(1); \
} while (0)

#define ERR_EXIT_ERRNO(x...) \
	do { \
		fflush(stdout); \
		fprintf(stderr, "%s: ", g.prog_name); \
		fprintf(stderr, x); \
		fprintf(stderr, " (%s)", strerror(errno)); \
		fprintf(stderr, "\n"); \
		exit(1); \
	} while (0)

#endif /* IPL_TOOLS_H */
