/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "lsscm_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "lsscm");

	return 0;
}
