/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "opticsmon_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "opticsmon");

	return 0;
}
