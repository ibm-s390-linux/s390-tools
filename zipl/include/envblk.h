/*
 * s390-tools/zipl/include/bootmap.h
 *   Functions to handle environment block.
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */
#include "boot/page.h"

#define ZIPL_ENVBLK_SIGNATURE  "# zIPL Environment Block\n"
#define ENVBLK_DEFAULT_IMPORT_SOURCE   "/etc/ziplenv"
/*
 * The following limit can be increased. It requires modifications
 * of the code, which is responsible for handling environment in
 * stage3, which will increase its memory footprint.
 */
#define ENVBLK_MAX_LINES (PAGE_SIZE / 8 /* sizeof(struct env_hash_entry */)

#define ENVBLK_MAX_IMPORT_SIZE(envblk_size)		\
(envblk_size - sizeof(ZIPL_ENVBLK_SIGNATURE) + 1)

/* get name by prefixed name PNAME and by logical prefix P */
static inline const char *get_name(const char *p, const char *pname)
{
	return p ? pname + strlen(p) : pname;
}

/* get name length by prefixed name PNAME and by logical prefix P */
static inline size_t get_name_len(const char *p, const char *pname)
{
	return p ? strlen(pname) - strlen(p) : strlen(pname);
}

int envblk_offset_get(int fd, off_t *off);
int envblk_offset_set(int fd, off_t off);
int envblk_size_get(int fd, int *size);
int envblk_check_name(const char *name, int len);
int envblk_import(char *from, char *to, int size);
char *envblk_next_line(char *s, const char *end);
int envblk_scan(char *envblk, unsigned int envblk_size,
		int (*actor)(char *name, void *data), void *data);
void envblk_print(char *envblk, unsigned int envblk_size);
void envblk_create_blank(char *envblk, int envblk_len);
void envblk_blank(char *envblk, int envblk_len);
int envblk_list_site(char *envblk, unsigned int envblk_size, int site_id);
int envblk_list_effective_site(char *envblk, unsigned int envblk_size,
			       int site_id);
int envblk_list_all(char *envblk, unsigned int envblk_size, int indent);
int envblk_set(char *envblk, unsigned int envblk_size, const char *name,
	       const char *new_val);
int envblk_unset(char *envblk, int envblk_len, const char *pname,
		 const char *site_id);
int envblk_remove_namespace(char *envblk, unsigned int envblk_size,
			    const char *site_id);
