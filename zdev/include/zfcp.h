/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZFCP_H
#define ZFCP_H

#include "exit_code.h"
#include "misc.h"

#define	ZFCP_MOD_NAME		"zfcp"
#define ZFCP_CCWDRV_NAME	"zfcp"

struct devtype;

extern struct devtype zfcp_devtype;

exit_code_t zfcp_check_allow_lun_scan(int *, config_t);

#endif /* ZFCP_H */
