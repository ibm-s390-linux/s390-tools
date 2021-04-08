/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/swap.h>

#include "lib/util_log.h"

#include "common.h"
#include "swap.h"

int swap_on(const char *path)
{
	int ret;

	util_log_print(UTIL_LOG_INFO, "Swap on %s\n", path);

	ret = swapon(path, 0);
	if (ret) {
		util_log_print(UTIL_LOG_ERROR, "swapon syscall failed (%s)\n",
			       strerror(errno));
		return ret;
	}

	return 0;
}

int swap_off(const char *path)
{
	int ret;

	util_log_print(UTIL_LOG_INFO, "Swap off %s\n", path);

	ret = swapoff(path);
	if (ret) {
		util_log_print(UTIL_LOG_ERROR, "swapoff syscall failed (%s)\n",
			       strerror(errno));
		return ret;
	}

	return 0;
}
