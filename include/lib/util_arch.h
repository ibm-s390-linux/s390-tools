/**
 * @defgroup util_arch_h util_arch: General architecture helpers
 * @{
 * @brief General architecture helpers
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_ARCH_H
#define LIB_UTIL_ARCH_H

enum util_arch_machine_type {
	UTIL_ARCH_MACHINE_TYPE_UNKNOWN	= 0,
	UTIL_ARCH_MACHINE_TYPE_Z10_EC	= 2097,
	UTIL_ARCH_MACHINE_TYPE_Z10_BC	= 2098,
	UTIL_ARCH_MACHINE_TYPE_ZE_196	= 2817,
	UTIL_ARCH_MACHINE_TYPE_ZE_114	= 2818,
	UTIL_ARCH_MACHINE_TYPE_ZE_EC12	= 2827,
	UTIL_ARCH_MACHINE_TYPE_ZE_BC12	= 2828,
	UTIL_ARCH_MACHINE_TYPE_Z13	= 2964,
	UTIL_ARCH_MACHINE_TYPE_Z13_S	= 2965,
	UTIL_ARCH_MACHINE_TYPE_Z14	= 3906,
	UTIL_ARCH_MACHINE_TYPE_Z14_ZR1	= 3907,
	UTIL_ARCH_MACHINE_TYPE_Z15	= 8561,
	UTIL_ARCH_MACHINE_TYPE_Z15_T02	= 8562,
};

int util_arch_machine_type(void);

const char *util_arch_machine_type_str(void);

const char *util_arch_machine_type_to_str(int type);

unsigned long util_arch_hsa_maxsize(void);

#endif /** LIB_UTIL_ARCH_H @} */
