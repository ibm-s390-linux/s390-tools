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

#include "dfi.h"

struct dt {
	const char	*desc;
	int		(*init)(void);
	void		(*info)(void);
};

extern void dt_init(void);
extern void dt_info_print(void);
extern void dt_arch_set(enum dfi_arch arch);
extern void dt_version_set(int version);
extern void dt_attr_mem_limit_set(u64 mem_limit);
extern void dt_attr_force_set(int value);
extern void dt_attr_dasd_type_set(const char *dasd_type);

#endif
