/*
 * @defgroup util_sys_h  util_sys: SysFS interface
 * @{
 * @brief Work with SysFS
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_SYS_H
#define LIB_UTIL_SYS_H

#include <stdbool.h>

int util_sys_get_dev_addr(const char *dev, char *addr);
bool util_sys_dev_is_partition(dev_t dev);
int util_sys_get_partnum(dev_t dev);
int util_sys_get_base_dev(dev_t dev, dev_t *base_dev);

#endif /** LIB_UTIL_SYS_H @} */
