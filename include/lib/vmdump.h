/*
 * vmdump - VMDUMP conversion library
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_VMDUMP_H
#define LIB_VMDUMP_H

int vmdump_convert(const char* inputFileName, const char* outputFileName,
		   const char* progName);

#endif /* LIB_VMDUMP_H */
