/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "vmcp_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "vmcp");

	return 0;
}
