/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "lsqeth_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "lsqeth");

	return 0;
}
