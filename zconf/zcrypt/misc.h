/*
 * misc - Local helper functions
 *
 * Copyright IBM Corp. 2016, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MISC_H
#define MISC_H

#include <stdbool.h>

bool misc_regex_match(const char *str, const char *regex);
bool ap_bus_has_SB_support(void);

#endif /* MISC_H */
