/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "dasdfmt_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "dasdfmt");

	return 0;
}
