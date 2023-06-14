/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Stand-alone kdump definitions
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


#ifndef KDUMP_H
#define KDUMP_H

#include "boot/os_info.h"

#define OS_INFO_VERSION_MAJOR_SUPPORTED	1

void kdump_os_info_check(const struct os_info *os_info);
void kdump_failed(unsigned long reason);

#endif /* KDUMP_H */
