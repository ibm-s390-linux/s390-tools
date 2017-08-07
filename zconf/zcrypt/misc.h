/*
 * misc - Local helper functions
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MISC_H
#define MISC_H

#include <stdbool.h>

bool misc_regex_match(const char *str, const char *regex);

#endif /* MISC_H */
