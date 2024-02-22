/*
 * util - Utility function library
 *
 * General architecture helpers
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_arch.h"

#define	PROC_SYSINFO		"/proc/sysinfo"
#define	PROC_SYSINFO_TYPE	"Type:"

#define HSA_SIZE_32M	(32 * 1024 * 1024)
#define HSA_SIZE_512M	(512 * 1024 * 1024)

/**
 * Get the type of the underlying architecture.
 *
 * @returns  Type of the underlying architecture
 */
int util_arch_machine_type(void)
{
	int type = UTIL_ARCH_MACHINE_TYPE_UNKNOWN;
	char *line = NULL;
	FILE *fp;

	fp = fopen(PROC_SYSINFO, "r");
	if (!fp)
		return type;

	while (fscanf(fp, "%m[^\n]\n", &line) == 1) {
		int n = sscanf(line, PROC_SYSINFO_TYPE "%d", &type);
		free(line);
		if (n == 1)
			break;
	}

	fclose(fp);
	return type;
}

/**
 * Returns a human-readable string of the current machine type.
 *
 * @returns  Pointer to a read-only string corresponding to the current machine
 *           type
 */
const char *util_arch_machine_type_str(void)
{
	return util_arch_machine_type_to_str(util_arch_machine_type());
}

/**
 * Convert a machine type to a human-readable string.
 *
 * @param[in] type Type of the underlying architecture
 *
 * @returns  Pointer to a read-only string corresponding to the given machine
 *           type
 */
const char *util_arch_machine_type_to_str(int type)
{
	switch (type) {
	case UTIL_ARCH_MACHINE_TYPE_Z10_EC:
		return "IBM System z10 EC";
	case UTIL_ARCH_MACHINE_TYPE_Z10_BC:
		return "IBM System z10 BC";
	case UTIL_ARCH_MACHINE_TYPE_ZE_196:
		return "IBM zEnterprise 196";
	case UTIL_ARCH_MACHINE_TYPE_ZE_114:
		return "IBM zEnterprise 114";
	case UTIL_ARCH_MACHINE_TYPE_ZE_EC12:
		return "IBM zEnterprise EC12";
	case UTIL_ARCH_MACHINE_TYPE_ZE_BC12:
		return "IBM zEnterprise BC12";
	case UTIL_ARCH_MACHINE_TYPE_Z13:
		return "IBM z13";
	case UTIL_ARCH_MACHINE_TYPE_Z13_S:
		return "IBM z13s";
	case UTIL_ARCH_MACHINE_TYPE_Z14:
		return "IBM z14";
	case UTIL_ARCH_MACHINE_TYPE_Z14_ZR1:
		return "IBM z14 ZR1";
	case UTIL_ARCH_MACHINE_TYPE_Z15:
	case UTIL_ARCH_MACHINE_TYPE_Z15_T02:
		return "IBM z15";
	case UTIL_ARCH_MACHINE_TYPE_Z16:
	case UTIL_ARCH_MACHINE_TYPE_Z16_A02:
		return "IBM z16";
	default:
		return "Unknown machine type";
	}
}

/**
 * Returns the maximum size of HSA memory in bytes on this architecture.
 *
 * @returns  Maximum HSA size in bytes
 */
unsigned long util_arch_hsa_maxsize(void)
{
	switch (util_arch_machine_type()) {
	case UTIL_ARCH_MACHINE_TYPE_Z15:
	case UTIL_ARCH_MACHINE_TYPE_Z15_T02:
	case UTIL_ARCH_MACHINE_TYPE_Z16:
	case UTIL_ARCH_MACHINE_TYPE_Z16_A02:
		return HSA_SIZE_512M;
	default:
		return HSA_SIZE_32M;
	}
}
