/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Window "help": Show online help text.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WIN_HELP_H
#define WIN_HELP_H

#include "hyptop.h"
#include "tbox.h"

struct win_help {
	struct hyptop_win	win;
	struct tbox		*tb;
};

struct hyptop_win *win_help_new(struct hyptop_win *win);

#endif /* WIN_HELP_H */
