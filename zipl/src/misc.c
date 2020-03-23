/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Miscellaneous helper functions
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "error.h"
#include "misc.h"

/* Allocate SIZE bytes of memory. Upon success, return pointer to memory.
 * Return NULL otherwise. */
void *
misc_malloc(size_t size)
{
	void* result;

	result = malloc(size);
	if (result == NULL) {
		error_reason("Could not allocate %lld bytes of memory",
			     (unsigned long long) size);
	}
	return result;
}


/* asprintf with misc error checking */
int misc_asprintf(char** out, const char* fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vasprintf(out, fmt, ap);
	va_end(ap);
	if (rc == -1)
		error_reason("Could not allocate space for new string");
	return rc;
}


/* Allocate N * SIZE bytes of memory. Upon success, return pointer to memory.
 * Return NULL otherwise. */
void *
misc_calloc(size_t n, size_t size)
{
	void* result;

	result = calloc(n, size);
	if (result == NULL) {
		error_reason("Could not allocate %lld bytes of memory",
			     (unsigned long long) n *
			     (unsigned long long) size);
	}
	return result;
}


/* Duplicate the given string S. Upon success, return pointer to new string.
 * Return NULL otherwise. */
char *
misc_strdup(const char* s)
{
	char* result;

	result = strdup(s);
	if (result == NULL) {
		error_reason("Could not allocate %lld bytes of memory",
			     (unsigned long long) strlen(s) + 1);
	}
	return result;
}


/* Open file exclusive */
int
misc_open_exclusive(const char* filename)
{
	int fd;

	fd = open(filename, O_RDWR | O_EXCL);
	if (fd == -1 && errno == EBUSY)
		error_reason("Device is in use (probably mounted)");
	else if (fd == -1)
		error_reason(strerror(errno));
	return fd;
}


/* Read COUNT bytes of data from file identified by file descriptor FD to
 * memory at location BUFFER. Return 0 when all bytes were successfully read,
 * non-zero otherwise. */
int
misc_read(int fd, void* buffer, size_t count)
{
	size_t done;
	ssize_t rc;

	for (done=0; done < count; done += rc) {
		rc = read(fd, VOID_ADD(buffer, done), count - done);
		if (rc == -1) {
			error_reason(strerror(errno));
			return -1;
		}
		if(rc == 0) {
			error_reason("Reached unexpected end of file");
			return -1;
		}
	}
	return 0;
}


/* Read all of file FILENAME to memory. Upon success, return 0 and set BUFFER
 * to point to the data and SIZE (if non-NULL) to contain the file size.
 * If NIL_TERMINATE is non-zero, a nil-char will be added to the buffer string
 * Return non-zero otherwise. */
int
misc_read_file(const char* filename, char** buffer, size_t* size,
	       int nil_terminate)
{
	struct stat stats;
	void* data;
	int fd;
	int rc;

	if (stat(filename, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	if (!S_ISREG(stats.st_mode)) {
		error_reason("Not a regular file");
		return -1;
	}
	data = misc_malloc(stats.st_size + (nil_terminate ? 1 : 0));
	if (data == NULL)
		return -1;
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		error_reason(strerror(errno));
		free(data);
		return -1;
	}
	rc = misc_read(fd, data, stats.st_size);
	close(fd);
	if (rc) {
		free(data);
		return rc;
	}
	*buffer = data;
	if (size != NULL)
		*size = stats.st_size;
	if (nil_terminate) {
		if (size != NULL)
			(*size)++;
		(*buffer)[stats.st_size] = 0;
	}
	return 0;
}


#define INITIAL_FILE_BUFFER_SIZE	1024

/* Read file into buffer without querying its size (necessary for reading files
 * from /proc or /sys). Upon success, return zero and set BUFFER to point to
 * the file buffer and SIZE (if non-null) to contain the file size. Return
 * non-zero otherwise. Add a null-byte at the end of the buffer if
 * NIL_TERMINATE is non-zero.  */
int
misc_read_special_file(const char* filename, char** buffer, size_t* size,
		       int nil_terminate)
{
	FILE* file;
	char* data;
	char* new_data;
	size_t count;
	size_t current_size;
	int current;

	file = fopen(filename, "r");
	if (file == NULL) {
		error_reason(strerror(errno));
		return -1;
	}
	current_size = INITIAL_FILE_BUFFER_SIZE;
	count = 0;
	data = (char *) misc_malloc(current_size);
	if (data == NULL) {
		fclose(file);
		return -1;
	}
	current = fgetc(file);
	while (current != EOF || nil_terminate) {
		if (current == EOF) {
			current = 0;
			nil_terminate = 0;
		}
		data[count++] = (char) current;
		if (count >= current_size) {
			new_data = (char *) misc_malloc(current_size * 2);
			if (new_data == NULL) {
				free(data);
				fclose(file);
				return -1;
			}
			memcpy(new_data, data, current_size);
			free(data);
			data = new_data;
			current_size *= 2;
		}
		current = fgetc(file);
	}
	fclose(file);
	*buffer = data;
	if (size)
		*size = count;
	return 0;
}


/* Get contents of file identified by FILENAME and fill in the respective
 * fields of FILE. Return 0 on success, non-zero otherwise. */
int
misc_get_file_buffer(const char* filename, struct misc_file_buffer* file)
{
	int rc;

	rc = misc_read_file(filename, &file->buffer, &file->length, 0);
	file->pos = 0;
	return rc;
}


/* Free resources allocated for file buffer FILE. */
void
misc_free_file_buffer(struct misc_file_buffer* file)
{
	if (file->buffer != NULL) {
		free(file->buffer);
		file->buffer = NULL;
		file->pos = 0;
		file->length = 0;
	}
}


/* Return character at current FILE buffer position plus READAHEAD or EOF if
 * at end of file. */
int
misc_get_char(struct misc_file_buffer* file, off_t readahead)
{
	if (file->buffer != NULL)
		if ((size_t) (file->pos + readahead) < file->length)
			return file->buffer[file->pos + readahead];
	return EOF;
}


char*
misc_make_path(char* dirname, char* filename)
{
	char* result;
	size_t len;

	len = strlen(dirname) + strlen(filename) + 2;
	result = (char *) misc_malloc(len);
	if (result == NULL)
		return NULL;
	sprintf(result, "%s/%s", dirname, filename);
	return result;
}


#define TEMP_DEV_MAX_RETRIES	1000

int
misc_temp_dev(dev_t dev, int blockdev, char** devno)
{
	char* result;
	char* pathname[] = { "/dev", getenv("TMPDIR"), "/tmp",
			     getenv("HOME"), "." , "/"};
	char filename[] = "zipl0000";
	mode_t mode;
	unsigned int path;
	unsigned int retry;
	int rc;
	int fd;

	if (blockdev)
		mode = S_IFBLK | S_IRWXU;
	else
		mode = S_IFCHR | S_IRWXU;
	/* Try several locations as directory for the temporary device
	 * node. */
	for (path=0; path < ARRAY_SIZE(pathname); path++) {
		if (pathname[path] == NULL)
			continue;
		for (retry=0; retry < TEMP_DEV_MAX_RETRIES; retry++) {
			assert(retry < 10000);
			sprintf(filename, "zipl%04u", retry);
			result = misc_make_path(pathname[path], filename);
			if (result == NULL)
				return -1;
			rc = mknod(result, mode, dev);
			if (rc == 0) {
				/* Need this test to cover 'nodev'-mounted
				 * filesystems. */
				fd = open(result, O_RDWR);
				if (fd != -1) {
					close(fd);
					*devno = result;
					return 0;
				}
				remove(result);
				retry = TEMP_DEV_MAX_RETRIES;
			} else if (errno != EEXIST)
				retry = TEMP_DEV_MAX_RETRIES;
			free(result);
		}
	}
	error_text("Unable to create temporary device node");
	error_reason(strerror(errno));
	return -1;
}


/* Create a temporary device node for the device containing FILE. Upon
 * success, return zero and store a pointer to the name of the device node
 * file into DEVNO. Return non-zero otherwise. */
int
misc_temp_dev_from_file(char* file, char** devno)
{
	struct stat stats;

	if (stat(file, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	return misc_temp_dev(stats.st_dev, 1, devno);
}


/* Delete temporary device node DEVICE and free memory allocated for device
 * name. */
void
misc_free_temp_dev(char* device)
{
	if (remove(device)) {
		fprintf(stderr, "Warning: Could not remove "
				"temporary file %s: %s",
				device, strerror(errno));
	}
	free(device);
}

/* Delete temporary bootmap file */
void
misc_free_temp_file(char *filename)
{
	if (remove(filename)) {
		fprintf(stderr,
			"Warning: Could not remove temporary file %s: %s",
			filename, strerror(errno));
	}
}

/* Write COUNT bytes from memory at location DATA to the file identified by
 * file descriptor FD. Return 0 when all bytes were successfully written,
 * non-zero otherwise. */
int
misc_write(int fd, const void* data, size_t count)
{
	size_t written;
	ssize_t rc;

	for (written=0; written < count; written += rc) {
		rc = write(fd, VOID_ADD(data, written), count - written);
		if (rc == -1) {
			error_reason(strerror(errno));
			error_text("Could not write to device");
			return -1;
		}
		if (rc == 0) {
			error_reason("Write failed");
			error_text("Could not write to device");
			return -1;
		}
	}
	return 0;
}

int misc_seek(int fd, off_t off)
{
	if (lseek(fd, off, SEEK_SET) == off)
		return 0;
	error_reason(strerror(errno));
	error_text("Could not seek on device");
	return -1;
}

int misc_pwrite(int fd, void *buf, size_t size, off_t off)
{
	if (misc_seek(fd, off))
		return -1;
	return misc_write(fd, buf, size);
}

int
misc_check_writable_directory(const char* directory)
{
	struct stat stats;

	if (stat(directory, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	if (!S_ISDIR(stats.st_mode)) {
		error_reason("Not a directory");
		return -1;
	}
	if (access(directory, W_OK)) {
		error_reason(strerror(errno));
		return -1;
	}
	return 0;
}


int
misc_check_readable_file(const char* filename)
{
	struct stat stats;

	if (stat(filename, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	if (!S_ISREG(stats.st_mode)) {
		error_reason("Not a regular file");
		return -1;
	}
	if (access(filename, R_OK)) {
		error_reason(strerror(errno));
		return -1;
	}
	return 0;
}


int
misc_check_writable_device(const char* devno, int blockdev, int chardev)
{
	struct stat stats;

	if (stat(devno, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	if (blockdev && chardev) {
		if (!(S_ISCHR(stats.st_mode) || S_ISBLK(stats.st_mode))) {
			error_reason("Not a device");
			return -1;
		}
	} else if (blockdev) {
		if (!S_ISBLK(stats.st_mode)) {
			error_reason("Not a block device");
			return -1;
		}
	} else if (chardev) {
		if (!S_ISCHR(stats.st_mode)) {
			error_reason("Not a character device");
			return -1;
		}
	}
	if (access(devno, W_OK)) {
		error_reason(strerror(errno));
		return -1;
	}
	return 0;
}



/* ASCII to EBCDIC conversion table. */
unsigned char ascebc[256] =
{
	0x00, 0x01, 0x02, 0x03, 0x37, 0x2D, 0x2E, 0x2F,
	0x16, 0x05, 0x15, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x3C, 0x3D, 0x32, 0x26,
	0x18, 0x19, 0x3F, 0x27, 0x22, 0x1D, 0x1E, 0x1F,
	0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D,
	0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
	0xF8, 0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
	0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
	0xC8, 0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
	0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
	0xE7, 0xE8, 0xE9, 0xBA, 0xE0, 0xBB, 0xB0, 0x6D,
	0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
	0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
	0xA7, 0xA8, 0xA9, 0xC0, 0x4F, 0xD0, 0xA1, 0x07,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x59, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
	0x90, 0x3F, 0x3F, 0x3F, 0x3F, 0xEA, 0x3F, 0xFF
};

/* EBCDIC to ASCII conversion table. */
unsigned char ebcasc[256] =
{
/* 0x00  NUL   SOH   STX   ETX  *SEL    HT  *RNL   DEL */
	0x00, 0x01, 0x02, 0x03, 0x07, 0x09, 0x07, 0x7F,
/* 0x08  -GE  -SPS  -RPT    VT    FF    CR    SO    SI */
	0x07, 0x07, 0x07, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
/* 0x10  DLE   DC1   DC2   DC3  -RES   -NL    BS  -POC */
	0x10, 0x11, 0x12, 0x13, 0x07, 0x0A, 0x08, 0x07,
/* 0x18  CAN    EM  -UBS  -CU1  -IFS  -IGS  -IRS  -ITB */
	0x18, 0x19, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
/* 0x20  -DS  -SOS    FS  -WUS  -BYP    LF   ETB   ESC */
	0x07, 0x07, 0x1C, 0x07, 0x07, 0x0A, 0x17, 0x1B,
/* 0x28  -SA  -SFE   -SM  -CSP  -MFA   ENQ   ACK   BEL */
	0x07, 0x07, 0x07, 0x07, 0x07, 0x05, 0x06, 0x07,
/* 0x30 ----  ----   SYN   -IR   -PP  -TRN  -NBS   EOT */
	0x07, 0x07, 0x16, 0x07, 0x07, 0x07, 0x07, 0x04,
/* 0x38 -SBS   -IT  -RFF  -CU3   DC4   NAK  ----   SUB */
	0x07, 0x07, 0x07, 0x07, 0x14, 0x15, 0x07, 0x1A,
/* 0x40   SP   RSP           ?              ----       */
	0x20, 0xFF, 0x83, 0x84, 0x85, 0xA0, 0x07, 0x86,
/* 0x48                      .     <     (     +     | */
	0x87, 0xA4, 0x9B, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
/* 0x50    &                                      ---- */
	0x26, 0x82, 0x88, 0x89, 0x8A, 0xA1, 0x8C, 0x07,
/* 0x58          ?     !     $     *     )     ;       */
	0x8D, 0xE1, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0xAA,
/* 0x60    -     /  ----     ?  ----  ----  ----       */
	0x2D, 0x2F, 0x07, 0x8E, 0x07, 0x07, 0x07, 0x8F,
/* 0x68             ----     ,     %     _     >     ? */
	0x80, 0xA5, 0x07, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
/* 0x70  ---        ----  ----  ----  ----  ----  ---- */
	0x07, 0x90, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
/* 0x78    *     `     :     #     @     '     =     " */
	0x70, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
/* 0x80    *     a     b     c     d     e     f     g */
	0x07, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
/* 0x88    h     i              ----  ----  ----       */
	0x68, 0x69, 0xAE, 0xAF, 0x07, 0x07, 0x07, 0xF1,
/* 0x90    ?     j     k     l     m     n     o     p */
	0xF8, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
/* 0x98    q     r                    ----        ---- */
	0x71, 0x72, 0xA6, 0xA7, 0x91, 0x07, 0x92, 0x07,
/* 0xA0          ~     s     t     u     v     w     x */
	0xE6, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
/* 0xA8    y     z              ----  ----  ----  ---- */
	0x79, 0x7A, 0xAD, 0xAB, 0x07, 0x07, 0x07, 0x07,
/* 0xB0    ^                    ----     ?  ----       */
	0x5E, 0x9C, 0x9D, 0xFA, 0x07, 0x07, 0x07, 0xAC,
/* 0xB8       ----     [     ]  ----  ----  ----  ---- */
	0xAB, 0x07, 0x5B, 0x5D, 0x07, 0x07, 0x07, 0x07,
/* 0xC0    {     A     B     C     D     E     F     G */
	0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
/* 0xC8    H     I  ----           ?              ---- */
	0x48, 0x49, 0x07, 0x93, 0x94, 0x95, 0xA2, 0x07,
/* 0xD0    }     J     K     L     M     N     O     P */
	0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
/* 0xD8    Q     R  ----           ?                   */
	0x51, 0x52, 0x07, 0x96, 0x81, 0x97, 0xA3, 0x98,
/* 0xE0    \           S     T     U     V     W     X */
	0x5C, 0xF6, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
/* 0xE8    Y     Z        ----     ?  ----  ----  ---- */
	0x59, 0x5A, 0xFD, 0x07, 0x99, 0x07, 0x07, 0x07,
/* 0xF0    0     1     2     3     4     5     6     7 */
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
/* 0xF8    8     9  ----  ----     ?  ----  ----  ---- */
	0x38, 0x39, 0x07, 0x07, 0x9A, 0x07, 0x07, 0x07
};

void misc_ebcdic_to_ascii(unsigned char *from, unsigned char *to)
{
	for (; from != to; from++)
		*from = ebcasc[*from];
}

void misc_ascii_to_ebcdic(unsigned char *from, unsigned char *to)
{
	for (; from != to; from++)
		*from = ascebc[*from];
}


