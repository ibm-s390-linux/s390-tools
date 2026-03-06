/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "zipl_editenv_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "zipl-editenv");

	return 0;
}
