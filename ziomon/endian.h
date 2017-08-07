/*
 * FCP adapter trace utility
 *
 * Endianness conversion functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <byteswap.h>
#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_be64(x) (x = __bswap_64(x))
#define cpu_to_be32(x) (x = __bswap_32(x))
#define cpu_to_be16(x) (x = __bswap_16(x))
#else
#define cpu_to_be64(x) (x = x)
#define cpu_to_be32(x) (x = x)
#define cpu_to_be16(x) (x = x)
#endif

