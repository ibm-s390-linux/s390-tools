/*
 * EBCDIC conversion functions
 *
 * Copyright IBM Corp. 2013, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef EBCDIC_CONV_H
#define EBCDIC_CONV_H


#ifndef __ASSEMBLER__

void ebcdic_to_ascii(unsigned char *target, const unsigned char *source,
		     unsigned int l);

#endif /* __ASSEMBLER__ */
#endif /* EBCDIC_CONV_H */
