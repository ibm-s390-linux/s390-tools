/*
 * s390-tools/zipl/include/misc.h
 *   Miscellaneous helper functions.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef MISC_H
#define MISC_H

#include <sys/types.h>
#include <unistd.h>

#include "zipl.h"


struct misc_file_buffer {
	char* buffer;
	off_t pos;
	size_t length;
};


void* misc_malloc(size_t size);
int misc_asprintf(char **out, const char *fmt, ...);
void* misc_calloc(size_t n, size_t size);
char* misc_strdup(const char* s);
int misc_open_exclusive(const char* filename);
int misc_read(int fd, void* buffer, size_t count);
int misc_read_file(const char* filename, char** buffer, size_t* size,
		   int nil_terminate);
int misc_read_special_file(const char* filename, char** buffer, size_t* size,
			   int nil_terminate);
int misc_write(int fd, const void* data, size_t count);
int misc_pwrite(int fd, void *buf, size_t size, off_t off);
int misc_seek(int fd, off_t off);
int misc_get_file_buffer(const char* filename,
			 struct misc_file_buffer* buffer);
void misc_free_file_buffer(struct misc_file_buffer* file);
int misc_get_char(struct misc_file_buffer* file, off_t readahead);
char* misc_make_path(char* dirname, char* filename);
int misc_temp_dev(dev_t dev, int blockdev, char** devno);
int misc_temp_dev_from_file(char* file, char** devno);
void misc_free_temp_dev(char* device);
void misc_free_temp_file(char *filename);
int misc_check_writable_directory(const char* directory);
int misc_check_readable_file(const char* filename);
int misc_check_writable_device(const char* devno, int blockdev, int chardev);
void misc_ebcdic_to_ascii(unsigned char *from, unsigned char *to);
void misc_ascii_to_ebcdic(unsigned char *from, unsigned char *to);
unsigned int misc_check_secure_boot(void);

#define ROUNDUP(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif /* not MISC_H */
