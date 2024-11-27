/* Copyright IBM Corp. 2022, 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "lib/libcpumf.h"

int libcpumf_ctrset(int ctr, int cfvn, int csvn)
{
	/* Governs basic and problem state counters */
	switch (cfvn) {
	case 1:
		if (ctr >= 0 && ctr < 32)
			return CPUMF_CTRSET_BASIC;
		if (ctr >= 32 && ctr < 38)
			return CPUMF_CTRSET_PROBLEM_STATE;
		break;
	case 3:
		if (ctr >= 0 && ctr < 32)
			return CPUMF_CTRSET_BASIC;
		if (ctr >= 32 && ctr < 34)
			return CPUMF_CTRSET_PROBLEM_STATE;
		break;
	}

	/* Governs crypto, extended and MT-Diagnositc counters */
	switch (csvn) {
	case 1 ... 5:
		if (ctr >= 64 && ctr < 80)
			return CPUMF_CTRSET_CRYPTO;
		if ((csvn == 1 && ctr >= 128 && ctr < 160) ||
		    (csvn == 2 && ctr >= 128 && ctr < 176) ||
		    (ctr >= 128 && ctr < 256))
			return CPUMF_CTRSET_EXTENDED;
		break;
	case 6 ... 8:
		if (ctr >= 64 && ctr < 84)
			return CPUMF_CTRSET_CRYPTO;
		if (ctr >= 128 && ctr < 288)
			return CPUMF_CTRSET_EXTENDED;
		break;
	}
	if (csvn >= 3 && ctr >= 448 && ctr < 496)
		return CPUMF_CTRSET_MT_DIAG;
	return CPUMF_CTRSET_NONE;
}
