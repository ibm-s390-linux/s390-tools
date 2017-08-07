/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Window "fields": Select fields dialog.
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WIN_FIELDS_H
#define WIN_FIELDS_H

#include "hyptop.h"
#include "table.h"
#include "win_help.h"

struct win_fields {
	struct hyptop_win	win;
	struct table		*t;
	struct table		*table;
	struct table_col	**col_vec;
	char			**col_desc_vec;
	int			mode_unit_change;
	int			in_select;
	struct hyptop_win	*win_help;
};

struct hyptop_win *win_fields_new(struct table *t, struct table_col **col_vec,
				  char **col_desc_vec);

#endif /* WIN_FIELDS_H */
