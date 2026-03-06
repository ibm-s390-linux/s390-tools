/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "zpwr_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "zpwr");

	return 0;
}
