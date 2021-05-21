/*
 * zkey-kmip - KMIP zkey KMS plugin
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZKEY_KMIP_H
#define ZKEY_KMIP_H

#include <stddef.h>
#include <stdbool.h>

#include "kmipclient/kmipclient.h"

#include "../plugin-utils.h"

struct plugin_handle {
	struct plugin_data pd;
};

#define KMIP_CONFIG_FILE			"kmip.conf"

#endif
