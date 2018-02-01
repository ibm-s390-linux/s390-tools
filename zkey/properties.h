/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Properties file handling functions
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PROPFILE_H
#define PROPFILE_H

#include <stdbool.h>

struct properties;

struct properties *properties_new(void);

void properties_free(struct properties *properties);

int properties_set(struct properties *properties,
		   const char *name, const char *value);

char *properties_get(struct properties *properties, const char *name);

int properties_remove(struct properties *properties, const char *name);

int properties_save(struct properties *properties, const char *filename,
		    bool check_integrity);

int properties_load(struct properties *properties, const char *filename,
		    bool check_integrity);

#endif
