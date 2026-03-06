/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "dasdinfo_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "dasdinfo");

	return 0;
}
