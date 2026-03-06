/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef LSSCM_CLI_H
#define LSSCM_CLI_H

#include "lib/util_opt.h"

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
