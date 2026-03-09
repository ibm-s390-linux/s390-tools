/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "chzcrypt_cli.h"
#include "lszcrypt_cli.h"
#include "zcryptstats_cli.h"

int main(void)
{
	generate_autocomp(chzcrypt_opt_vec, "chzcrypt");
	generate_autocomp(lszcrypt_opt_vec, "lszcrypt");
	generate_autocomp(zcryptstats_opt_vec, "zcryptstats");

	return 0;
}
