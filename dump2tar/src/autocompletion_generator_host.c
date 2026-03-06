/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "../include/dump2tar_cli.h"

int main(void)
{
	generate_autocomp(dump2tar_opts, "dump2tar");

	return 0;
}
