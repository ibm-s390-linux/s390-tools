/*
 * zkey-ekmfweb - EKMFWeb zkey KMS plugin
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZKEY_EKMFWEB_H
#define ZKEY_EKMFWEB_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "ekmfweb/ekmfweb.h"

struct plugin_handle {
	const char *config_path;
	mode_t config_path_mode;
	gid_t config_path_owner;
	struct properties *properties;
	bool apqns_configured;
	bool config_complete;
	char error_msg[1024];
	bool verbose;
};

#define EKMFWEB_CONFIG_FILE			"ekmfweb.conf"

#define EKMFWEB_CONFIG_APQNS			"apqns"

#endif
