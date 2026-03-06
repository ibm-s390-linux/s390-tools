/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "lsstp_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "lsstp");

	return 0;
}
