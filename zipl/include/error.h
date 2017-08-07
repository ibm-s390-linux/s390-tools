/*
 * s390-tools/zipl/include/error.h
 *   Functions to handle error messages.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef ERROR_H
#define ERROR_H

#include "zipl.h"


void error_reason(const char* fmt, ...);
void error_text(const char* fmt, ...);
void error_clear_reason(void);
void error_clear_text(void);
void error_print(void);

#endif /* not ERROR_H */
