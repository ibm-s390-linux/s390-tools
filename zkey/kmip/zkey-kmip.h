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
#include "../pkey.h"

struct plugin_handle {
	struct plugin_data pd;
	bool apqns_configured;
	enum card_type card_type;
	bool config_complete;
};

#define KMIP_CONFIG_FILE			"kmip.conf"
#define KMIP_CONFIG_APQNS			"apqns"
#define KMIP_CONFIG_APQN_TYPE			"apqn-type"

#define KMIP_APQN_TYPE_CCA			"CCA"
#define KMIP_APQN_TYPE_EP11			"EP11"

#endif
