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
#include "boot/s390.h" /* for PAGE_SIZE */

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

int envblk_offset_get(int fd, off_t *off);
int envblk_offset_set(int fd, off_t off);
int envblk_size_get(int fd, int *size);
int envblk_check_name(char *name, int len);
int envblk_import(char *from, char *to, int size);
char *envblk_next_line(char *s, const char *end);
int envblk_scan(char *envblk, unsigned int envblk_size,
		void (*actor)(char *name));
void envblk_print(char *envblk, unsigned int envblk_size);
void envblk_create_blank(char *envblk, int envblk_len);
