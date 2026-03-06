/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "zmemtopo_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "zmemtopo");

	return 0;
}
