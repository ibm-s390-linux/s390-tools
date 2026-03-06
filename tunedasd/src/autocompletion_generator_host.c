/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "../include/tunedasd_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "tunedasd");

	return 0;
}
