/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "dasdview_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "dasdview");

	return 0;
}
