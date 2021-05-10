/*
 * libkmipclient - KMIP client library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef NAMES_H
#define NAMES_H

#include <stdint.h>

#include "kmip.h"

struct kmip_enum {
	uint32_t val;
	const char *name;
};


const struct kmip_enum *kmip_enum_info_by_tag(enum kmip_tag tag);
bool kmip_is_tag_mask(enum kmip_tag tag);
int kmip_enum_value_by_name_or_hex(const struct kmip_enum *info,
				   const char *name, uint32_t *value);

const char *kmip_enum_name_by_tag_value(enum kmip_tag tag, uint32_t val);
int kmip_enum_value_by_tag_name_or_hex(enum kmip_tag tag, const char *name,
				       uint32_t *value);

const char *kmip_tag_name_by_tag(enum kmip_tag tag);
const char *kmip_tag_name_or_hex_by_tag(enum kmip_tag tag, char tmp_buff[20]);
enum kmip_tag kmip_tag_by_name_or_hex(const char *name);

const char *kmip_type_name_by_type(enum kmip_type type);
enum kmip_type kmip_type_by_name_or_hex(const char *name);

const char *kmip_v1_attr_name_by_tag(enum kmip_tag attr_tag);
enum kmip_tag kmip_attr_tag_by_v1_attr_name(const char *name);

#endif
