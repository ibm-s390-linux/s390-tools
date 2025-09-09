// SPDX-License-Identifier: MIT
/*
 * Autocompletion generation - for dasdfmt tool
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/util_autocomp.h"

#include "dasdfmt_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "dasdfmt");

	return 0;
}
