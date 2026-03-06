/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "fdasd_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "fdasd");

	return 0;
}
