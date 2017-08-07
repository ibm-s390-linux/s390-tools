/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Window "cpu_types": Select CPU types used for CPU data calculation.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WIN_CPU_TYPES_H
#define WIN_CPU_TYPES_H

#include "hyptop.h"
#include "table.h"
#include "win_help.h"

struct win_cpu_types {
	struct hyptop_win	win;
	struct table		*t;
	int			in_select;
	struct hyptop_win	*win_help;
};

extern struct hyptop_win *win_cpu_types_new(void);

#endif /* WIN_CPU_TYPES_H */
