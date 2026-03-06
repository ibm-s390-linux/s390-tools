/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "chpstat_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "chpstat");

	return 0;
}
