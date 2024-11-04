/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Dump tool info generic functions
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DT_H
#define DT_H

#include <stdbool.h>

#include "dfi.h"

#define DUMP_EXTENDED		true
#define DUMP_NON_EXTENDED	false

struct dt {
	const char	*desc;
	int		(*init)(void);
	void		(*info)(void);
};

void dt_init(void);
void dt_info_print(void);
void dt_version_set(int version);
void dt_attr_mem_limit_set(u64 mem_limit);
void dt_attr_force_set(int value);
void dt_attr_dasd_type_set(const char *dasd_type);

/*
 * Supported s390 dumpers
 */
extern struct dt dt_s390mv_ext;
extern struct dt dt_s390sv_ext;
extern struct dt dt_scsi;
extern struct dt dt_ngdump;

#endif
