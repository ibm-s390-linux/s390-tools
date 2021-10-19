/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Main include file - Should be included by all source files
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZGETDUMP_H
#define ZGETDUMP_H

#include "df_elf.h"
#include "df_lkcd.h"
#include "df_s390.h"
#include "dfi.h"
#include "dfo.h"
#include "dt.h"
#include "zg.h"

/*
 * zgetdump options
 */
struct options {
	int		action_specified;
	enum zg_action	action;
	char		*device;
	char		*mount_point;
	int		fmt_specified;
	const char	*fmt;
	int		debug_specified;
	char		**argv_fuse;
	int		argc_fuse;
	const char	*select;
	int		select_specified;
	int		verbose;
};

extern const char *OPTS_SELECT_KDUMP;
extern const char *OPTS_SELECT_PROD;
extern const char *OPTS_SELECT_ALL;

/*
 * zgetdump globals
 */
extern struct zgetdump_globals {
	struct zg_fh	*fh;
	const char 	*prog_name;
	struct options	opts;
} g;

/*
 * Misc fuctions
 */
extern void opts_parse(int argc, char *argv[]);
extern int stdout_write_dump(void);

#if HAVE_FUSE == 0
static inline int zfuse_mount_dump(void)
{
	ERR_EXIT("Program compiled without fuse support");
}
static inline void zfuse_umount(void)
{
	ERR_EXIT("Program compiled without fuse support");
}
#else
int zfuse_mount_dump(void);
void zfuse_umount(void);
#endif

/*
 * Supported DFI dump formats
 */
extern struct dfi dfi_s390tape;
extern struct dfi dfi_s390mv;
extern struct dfi dfi_s390mv_ext;
extern struct dfi dfi_s390;
extern struct dfi dfi_s390_ext;
extern struct dfi dfi_lkcd;
extern struct dfi dfi_elf;
extern struct dfi dfi_kdump;
extern struct dfi dfi_kdump_flat;
extern struct dfi dfi_devmem;

/*
 * Supported DFO dump formats
 */
extern struct dfo dfo_s390;
extern struct dfo dfo_elf;

/*
 * Supported s390 dumpers
 */
extern struct dt dt_s390mv;
extern struct dt dt_s390mv_ext;
extern struct dt dt_s390sv;
extern struct dt dt_s390sv_ext;
extern struct dt dt_scsi;

#endif /* ZGETDUMP_H */
