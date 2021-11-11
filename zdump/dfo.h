/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Generic output dump format functions (DFO - Dump Format Output)
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DFO_H
#define DFO_H

u64 dfo_read(void *buf, u64 cnt);
void dfo_seek(u64 addr);
u64 dfo_size(void);
const char *dfo_name(void);
void dfo_init(void);
int dfo_set(const char *dfo_name);

/*
 * DFO operations
 */
struct dfo {
	const char	*name;
	void		(*init)(void);
};

/*
 * Supported DFO dump formats
 */
extern struct dfo dfo_s390;
extern struct dfo dfo_elf;

#endif /* DFO_H */
