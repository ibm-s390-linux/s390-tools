/*
 * s390-tools/zipl/src/proc.c
 *   Scanner for the /proc/ files
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "lib/util_proc.h"

static const char util_proc_part_filename[] = "/proc/partitions";
static const char util_proc_dev_filename[] = "/proc/devices";

struct file_buffer {
	char *buffer;
	off_t pos;
	size_t length;
};

#define INITIAL_FILE_BUFFER_SIZE	1024

/* Read file into buffer without querying its size (necessary for reading files
 * from /proc). Upon success, return zero and set BUFFER to point to
 * the file buffer and SIZE (if non-null) to contain the file size. Return
 * non-zero otherwise. Add a null-byte at the end of the buffer if
 * NIL_TERMINATE is non-zero.  */
static int
util_proc_read_special_file(const char *filename, char **buffer, size_t *size,
		       int nil_terminate)
{
	FILE *file;
	char *data;
	char *new_data;
	size_t count;
	size_t current_size;
	int current;

	file = fopen(filename, "r");
	if (file == NULL) {
		printf("Could not open %s\n",
		       filename);
		return -1;
	}
	current_size = INITIAL_FILE_BUFFER_SIZE;
	count = 0;
	data = (char *) malloc(current_size);
	if (data == NULL) {
		printf("Could not allocate %zu bytes of memory", current_size);
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
			new_data = (char *) malloc(current_size * 2);
			if (new_data == NULL) {
				printf("Could not allocate %zu bytes of memory",
				       current_size * 2);
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

/* Get the contents of a file and fill in the respective fields of
 * FILE. Return 0 on success, non-zero otherwise. */
static int
get_file_buffer(struct file_buffer *file, const char *filename)
{
	int rc;

	rc = util_proc_read_special_file(filename, &file->buffer,
					 &file->length, 0);
	file->pos = 0;
	return rc;
}


/* Free resources allocated for file buffer identified by
 * FILE. */
static void
free_file_buffer(struct file_buffer *file)
{
	if (file->buffer != NULL) {
		free(file->buffer);
		file->buffer = NULL;
		file->pos = 0;
		file->length = 0;
	}
}


/* Return character at current FILE buffer position or EOF if at end of
 * file. */
static int
current_char(struct file_buffer *file)
{
	if (file->buffer != NULL)
		if (file->pos < (off_t) file->length)
			return file->buffer[file->pos];
	return EOF;
}


/* Advance the current file pointer of file buffer FILE until the current
 * character is no longer a whitespace or until the end of line or file is
 * reached. Return 0 if at least one whitespace character was encountered,
 * non-zero otherwise. */
static int
skip_whitespaces(struct file_buffer *file)
{
	int rc;

	rc = -1;
	while ((current_char(file) != '\n') && isspace(current_char(file))) {
		rc = 0;
		file->pos++;
	}
	return rc;
}


/* Scan a positive integer number at the current position of file buffer FILE
 * and advance the position respectively. Upon success, return zero and set
 * NUMBER to contain the scanned number. Return non-zero otherwise. */
static int
scan_number(struct file_buffer *file, size_t *number)
{
	int rc;
	size_t old_number;

	*number = 0;
	rc = -1;
	while (isdigit(current_char(file))) {
		rc = 0;
		old_number = *number;
		*number = *number * 10 + current_char(file) - '0';
		/* Check for overflow */
		if (old_number > *number) {
			rc = -1;
			break;
		}
		file->pos++;
	}
	return rc;
}


/* Scan a device node name at the current position of file buffer FILE and
 * advance the position respectively. Upon success, return zero and set
 * NAME to contain a copy of the scanned name. Return non-zero otherwise. */
static int
scan_name(struct file_buffer *file, char **name)
{
	off_t start_pos;

	start_pos = file->pos;
	while (!isspace(current_char(file)) &&
	       (current_char(file) != EOF))
			file->pos++;
	if (file->pos > start_pos) {
		*name = (char *) malloc(file->pos - start_pos + 1);
		if (*name == NULL)
			return -1;
		memcpy((void *) *name, (void *) &file->buffer[start_pos],
		       file->pos - start_pos);
		(*name)[file->pos - start_pos] = 0;
		return 0;
	} else
		return -1;
}

/* Scan for the specified STRING at the current position of file buffer FILE
 * and advance the position respectively. Upon success, return zero. Return
 * non-zero otherwise. */
static int
scan_string(struct file_buffer *file, const char *string)
{
	int i;

	i = 0;
	for (i = 0; string[i] && (current_char(file) == string[i]);
	     i++, file->pos++)
		;
	if (string[i] == '\0')
		return 0;
	return -1;
}


/* Advance the current file position to beginning of next line in file buffer
 * FILE or to end of file. */
static void
skip_line(struct file_buffer *file)
{
	while ((current_char(file) != '\n') && (current_char(file) != EOF))
		file->pos++;
	if (current_char(file) == '\n')
		file->pos++;
}


/* Return non-zero if the current file position of file buffer FILE is at the
 * end of file. Return zero otherwise. */
static int
eof(struct file_buffer *file)
{
	return file->pos >= (off_t) file->length;
}


/* Scan a line of the specified /proc/partitions FILE buffer and advance the
 * current file position pointer respectively. If the current line matches
 * the correct pattern, fill in the corresponding data into ENTRY and return 0.
 * Return non-zero otherwise. */
static int
scan_part_entry(struct file_buffer *file, struct util_proc_part_entry *entry)
{
	int rc;
	size_t dev_major;
	size_t dev_minor;
	size_t blockcount;
	char *name;

	/* Scan for: (\s*)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)(\S+)(\.*)$ */
	skip_whitespaces(file);
	rc = scan_number(file, &dev_major);
	if (rc)
		return rc;
	rc = skip_whitespaces(file);
	if (rc)
		return rc;
	rc = scan_number(file, &dev_minor);
	if (rc)
		return rc;
	rc = skip_whitespaces(file);
	if (rc)
		return rc;
	rc = scan_number(file, &blockcount);
	if (rc)
		return rc;
	rc = skip_whitespaces(file);
	if (rc)
		return rc;
	rc = scan_name(file, &name);
	if (rc)
		return rc;
	skip_line(file);
	entry->device = makedev(dev_major, dev_minor);
	entry->blockcount = blockcount;
	entry->name = name;
	return 0;
}


/* Release resources associated with ENTRY. */
void
util_proc_part_free_entry(struct util_proc_part_entry *entry)
{
	if (entry->name != NULL) {
		free(entry->name);
		entry->name = NULL;
	}
}

/* Scan a line of the specified /proc/devices FILE buffer and advance the
 * current file position pointer respectively. If the current line matches
 * the correct pattern, fill in the corresponding data into ENTRY and return 0.
 * Return non-zero otherwise. */
static int
scan_dev_entry(struct file_buffer *file, struct util_proc_dev_entry *entry,
	       int blockdev)
{
	int rc;
	size_t dev_major;
	char *name;

	/* Scan for: (\s*)(\d+)(\s+)(\S+)(\.*)$ */
	skip_whitespaces(file);
	rc = scan_number(file, &dev_major);
	if (rc)
		return rc;
	rc = skip_whitespaces(file);
	if (rc)
		return rc;
	rc = scan_name(file, &name);
	if (rc)
		return rc;
	skip_line(file);
	entry->device = makedev(dev_major, 0);
	entry->name = name;
	entry->blockdev = blockdev;
	return 0;
}


/* Release resources associated with ENTRY. */
void
util_proc_dev_free_entry(struct util_proc_dev_entry *entry)
{
	if (entry->name != NULL) {
		free(entry->name);
		entry->name = NULL;
	}
}

/* Parse one record. */
static int
scan_mnt_entry(struct file_buffer *file, struct util_proc_mnt_entry *entry)
{
	int rc;

	skip_whitespaces(file);
	rc = scan_name(file, &entry->spec);
	if (rc)
		return rc;
	skip_whitespaces(file);
	rc = scan_name(file, &entry->file);
	if (rc)
		return rc;
	skip_whitespaces(file);
	rc = scan_name(file, &entry->vfstype);
	if (rc)
		return rc;
	skip_whitespaces(file);
	rc = scan_name(file, &entry->mntOpts);
	if (rc)
		return rc;
	skip_whitespaces(file);
	rc = scan_name(file, &entry->dump);
	if (rc)
		return rc;
	skip_whitespaces(file);
	rc = scan_name(file, &entry->passno);
	if (rc)
		return rc;
	skip_line(file);
	return 0;
}

/* Free the memory allocated for one record. */
void
util_proc_mnt_free_entry(struct util_proc_mnt_entry *entry)
{
	free(entry->spec);
	free(entry->file);
	free(entry->vfstype);
	free(entry->mntOpts);
	free(entry->dump);
	free(entry->passno);
	memset(entry, 0, sizeof(*entry));
}

/* Scan /proc/partitions for an entry matching DEVICE. When there is a match,
 * store entry data in ENTRY and return 0. Return non-zero otherwise. */
int
util_proc_part_get_entry(dev_t device, struct util_proc_part_entry *entry)
{
	struct file_buffer file;
	int rc;

	rc = get_file_buffer(&file, util_proc_part_filename);
	if (rc)
		return rc;
	rc = -1;
	while (!eof(&file)) {
		if (scan_part_entry(&file, entry) == 0) {
			if (entry->device == device) {
				rc = 0;
				break;
			}
			util_proc_part_free_entry(entry);
		} else
			skip_line(&file);
	}
	free_file_buffer(&file);
	return rc;
}

/* Scan /proc/devices for a blockdevice (BLOCKDEV is 1) or a character
 * device (BLOCKDEV is 0) with a major number matching the major number of DEV.
 * When there is a match, store entry data in ENTRY and return 0. Return
 * non-zero otherwise. */
int
util_proc_dev_get_entry(dev_t device, int blockdev,
			struct util_proc_dev_entry *entry)
{
	struct file_buffer file;
	int rc;
	int scan_blockdev = 0;

	rc = get_file_buffer(&file, util_proc_dev_filename);
	if (rc)
		return rc;
	rc = -1;
	while (!eof(&file)) {
		if (scan_string(&file, "Block") == 0) {
			skip_line(&file);
			scan_blockdev = 1;
			continue;
		} else if (scan_dev_entry(&file, entry, scan_blockdev) == 0) {
			if ((major(entry->device) == major(device)) &&
			    blockdev == scan_blockdev) {
				rc = 0;
				break;
			}
			util_proc_dev_free_entry(entry);
		} else
			skip_line(&file);
	}
	free_file_buffer(&file);
	return rc;
}


/*
 * Provide one record from a /proc/mounts like file
 *
 * The parameter file_name distinguishes the file from procfs which
 * is read, the parameter spec is the selector for the record.
 */
int util_proc_mnt_get_entry(const char *file_name, const char *spec,
			    struct util_proc_mnt_entry *entry)
{
	struct file_buffer file;
	int rc;

	rc = get_file_buffer(&file, file_name);
	if (rc)
		return rc;
	while (!eof(&file)) {
		rc = scan_mnt_entry(&file, entry);
		if (rc)
			goto out_free;
		if (!strcmp(entry->vfstype, spec)) {
			rc = 0;
			goto out_free;
		}
		util_proc_mnt_free_entry(entry);
	}
	rc = -1;
out_free:
	free_file_buffer(&file);
	return rc;
}
