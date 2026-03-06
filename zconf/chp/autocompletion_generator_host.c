/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "chchp_cli.h"
#include "lschp_cli.h"

int main(void)
{
	generate_autocomp(chchp_opt_vec, "chchp");
	generate_autocomp(lschp_opt_vec, "lschp");

	return 0;
}
