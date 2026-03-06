/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "zpcictl_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "zpcictl");

	return 0;
}
