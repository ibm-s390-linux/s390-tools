/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "lscss_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "lscss");

	return 0;
}
