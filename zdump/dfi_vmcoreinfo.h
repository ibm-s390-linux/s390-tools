/*
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DFI_VMCOREINFO_H
#define DFI_VMCOREINFO_H

void dfi_vmcoreinfo_init(void);
char *dfi_vmcoreinfo_get(void);
int dfi_vmcoreinfo_tag(char *str, int len, const char *sym);
int dfi_vmcoreinfo_symbol(unsigned long *val, const char *sym);
int dfi_vmcoreinfo_offset(unsigned long *offs, const char *sym);
int dfi_vmcoreinfo_size(unsigned long *size, const char *sym);
int dfi_vmcoreinfo_length(unsigned long *len, const char *sym);
int dfi_vmcoreinfo_val(unsigned long *val, const char *sym);

#endif /* DFI_VMCOREINFO_H */
