// SPDX-License-Identifier: MIT
/*
 * Autocompletion generation - for cpumf family of tools
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/util_autocomp.h"

#include "chcpumf_cli.h"
#include "lscpumf_cli.h"
#include "lshwc_cli.h"
#include "lspai_cli.h"
#include "pai_cli.h"

int main(void)
{
	generate_autocomp(chcpumf_opt_vec, "chcpumf");
	generate_autocomp(lscpumf_opt_vec, "lscpumf");
	generate_autocomp(lshwc_opt_vec, "lshwc");
	generate_autocomp(lspai_opt_vec, "lspai");
	generate_autocomp(pai_opt_vec, "pai");

	return 0;
}
