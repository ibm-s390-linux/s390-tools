/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Common functions for debugfs data gatherer
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DG_DEBUGFS_H
#define DG_DEBUGFS_H

#include "sd.h"

#define DBFS_WAIT_TIME_US 10000

extern int dg_debugfs_init(int exit_on_err);
extern int dg_debugfs_vm_init(void);
extern int dg_debugfs_lpar_init(void);
extern int dg_debugfs_open(const char *file);

/*
 * z/VM diag 0C prototypes
 */
int dg_debugfs_vmd0c_init(void);
void dg_debugfs_vmd0c_sys_cpu_fill(struct sd_sys *sys, u64 online_time,
				   unsigned int cpu_cnt);

#endif /* DG_DEBUGFS_H */
