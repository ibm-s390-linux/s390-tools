/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions to manipulate with environment block
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bootmap.h"
#include "envblk.h"
#include "error.h"
#include "misc.h"
#include <assert.h>

/* from linux/fs.h */
#define FIGETBSZ	_IO(0x00, 2)
#define KEYWORD_SIZE    strlen("[site X]\n")
#define MAX_NR_SITES    10
#define PARAM_SIZE      8

void envblk_create_blank(char *envblk, int envblk_len)
{
	memcpy(envblk, ZIPL_ENVBLK_SIGNATURE,
	       sizeof(ZIPL_ENVBLK_SIGNATURE) - 1);
	memset(envblk + sizeof(ZIPL_ENVBLK_SIGNATURE) - 1, '\0',
	       envblk_len - sizeof(ZIPL_ENVBLK_SIGNATURE) + 1);
}

/**
 * Find out environment block location.
 * FD: bootmap file descriptor.
 * On success the searched location is saved in variable pointed out by OFF
 */
int envblk_offset_get(int fd, off_t *off)
{
	struct bootmap_header bh;

	if (bootmap_header_read(fd, &bh)) {
		error_reason("Could not read bootmap_header");
		return -1;
	}
	*off = bh.envblk_offset;
	return 0;
}

/**
 * Save environment block location specified by OFF
 * FD: bootmap file descriptor.
 * On success the location is saved in the bootmap header.
 */
int envblk_offset_set(int fd, off_t off)
{
	struct bootmap_header bh;

	if (bootmap_header_read(fd, &bh)) {
		error_reason("Could not read bootmap header");
		return -1;
	}
	bh.envblk_offset = off;

	if (bootmap_header_write(fd, &bh)) {
		error_reason("Could not write bootmap header");
		return -1;
	}
	return 0;
}

/**
 * Find out environment block size.
 * FD: bootmap file descriptor.
 * On success the searched size is stored in RESULT
 */
int envblk_size_get(int fd, int *result)
{
	if (ioctl(fd, FIGETBSZ, result) == -1) {
		error_reason(strerror(errno));
		return -1;
	}
	return 0;
}

#define LINE_HASH_SIZE (16)

/*
 * This defines "extended string", an object consisting of
 * an optional prefix and a substring
 */
struct estr {
	char *prefix; /* pointer to the prefix */
	char *str;    /* pointer to the substring */
	int len;      /* length of the substring */
};

/**
 * Hash function on "extended strings"
 */
static unsigned int hash_fn(struct estr *estr)
{
	char *str = estr->str;
	int len = estr->len;
	unsigned int sum;

	sum = 0;
	if (estr->prefix)
		sum += 5 * *estr->prefix;
	while (len) {
		sum += 5 * *(str++);
		len--;
	}
	return sum % LINE_HASH_SIZE;
}

/**
 * Compare a string STR with an "extended string" ESTR
 */
static int cmp_fn(char *str, struct estr *estr)
{
	if (!estr->prefix)
		return strncmp(str, estr->str, estr->len);
	if (str[0] != *estr->prefix)
		return -1;
	return strncmp(str + 1, estr->str, estr->len);
}

struct line_hash_entry {
	struct line_hash_entry *next;
	char *line; /* pointer to an "environment line",
		     * a string containing NAME=VALUE with
		     * optional trailing end-of-line symbol
		     */
};

/**
 * Populate a hash TABLE with an item built by an "extended string" ESTR
 */
static int hash_table_add(struct line_hash_entry **table, struct estr *estr)
{
	struct line_hash_entry *new;
	unsigned int hash;
	int len;

	new = malloc(sizeof(*new));
	if (!new)
		return -ENOMEM;
	memset(new, 0, sizeof(*new));

	len = strlen(estr->str);
	if (estr->prefix) {
		new->line = misc_malloc(len + 2);
		if (!new->line) {
			free(new);
			return -ENOMEM;
		}
		new->line[0] = *estr->prefix;
		memcpy(new->line + 1, estr->str, len);
		new->line[len + 1] = '\0';
	} else {
		new->line = misc_strdup(estr->str);
		if (!new->line) {
			free(new);
			return -ENOMEM;
		}
	}
	hash = hash_fn(estr);
	new->next = table[hash];
	table[hash] = new;
	return 0;
}

/**
 * Search an item in the hash table by an "extended string" ESTR
 */
static struct line_hash_entry *hash_table_find(struct line_hash_entry **table,
					       struct estr *estr)
{
	struct line_hash_entry *item;

	item = table[hash_fn(estr)];
	while (item) {
		if (!cmp_fn(item->line, estr))
			return item;
		item = item->next;
	}
	return NULL;
}

/**
 * Replace an ITEM with another one built by an "extended string" ESTR
 */
static int hash_entry_replace(struct line_hash_entry *item, struct estr *estr,
			      int *offset)
{
	int len;
	char *new;

	len = strlen(estr->str);
	if (estr->prefix) {
		len++;
		new = misc_malloc(len + 1);
		if (!new)
			return -ENOMEM;
		new[0] = *estr->prefix;
		memcpy(new + 1, estr->str, len - 1);
		new[len] = '\0';
	} else {
		new = misc_strdup(estr->str);
		if (!new)
			return -ENOMEM;
	}
	*offset -= strlen(item->line);
	free(item->line);
	item->line = new;
	*offset += len;
	return 1;
}

/**
 * Scan hash table TABLE, and call ACTOR for each its entry.
 * The ACTOR is allowed even to release the entry.
 */
static void hash_table_scan(struct line_hash_entry **table,
			    void (*actor)(struct line_hash_entry *entry))
{
	int i;

	for (i = 0; i < LINE_HASH_SIZE; i++) {
		struct line_hash_entry *item = table[i];

		while (item) {
			struct line_hash_entry *next = item->next;

			actor(item);
			item = next;
		}
	}
}

static void hash_entry_free(struct line_hash_entry *this)
{
	free(this->line);
	free(this);
}

static void hash_table_free(struct line_hash_entry **table)
{
	hash_table_scan(table, hash_entry_free);
}

/**
 * Scan hash table TABLE, and for each its entry copy its line to the
 * in-memory environment block specified by DST at the offset OFF.
 * Insert end-of-line symbol, if needed. The caller should guarantee
 * enough space in the buffer DST
 */
static void hash_table_flush(struct line_hash_entry **table, char *dst,
			     int off)
{
	int i;

	for (i = 0; i < LINE_HASH_SIZE; i++) {
		struct line_hash_entry *item = table[i];

		while (item) {
			int str_len;

			str_len = strlen(item->line);
			memcpy(dst + off, item->line, str_len);
			off += str_len;
			if (dst[off - 1] != '\n') {
				dst[off] = '\n';
				off += 1;
			}
			item = item->next;
		}
	}
}

enum keyword_status {
	KW_UNKNOWN,
	KW_VALID,
	KW_MALFORMED,
	KW_UNSUPP_ID
};

/**
 * Return 1, if the line's TAIL is empty, or is a whitespace
 * (may be empty) followed by a comment. Otherwise, return 0.
 */
static int ignore_tail(const char *tail)
{
	if (*tail == '\n')
		return 1;
	do {
		if (*tail == '#')
			return 1;
		if (*tail == '\t' || *tail == ' ') {
			tail++;
			continue;
		}
		return 0;
	} while (*tail != '\n');
	return 0;
}

/**
 * Check if LINE represents a keyword to identify a section in the
 * environment file. Return the result of the check. If the LINE
 * represents a valid keyword (KW_VALID is returned), then SITE_ID
 * contains ID of the namespace represented by that section.
 *
 * LINE: a null-terminated string with optional end-of-line symbol
 * LEN: number of characters in the LINE excluding NULL-termination
 */
static enum keyword_status check_keyword(char *line, size_t len,
					 char *site_id, long *val)
{
	char *endptr;

	if (len < KEYWORD_SIZE || line[len - 1] != '\n')
		return KW_UNKNOWN;

	if ((line[0] == '[') &&
	    (line[1] == 's' || line[1] == 'S') &&
	    (line[2] == 'i' || line[2] == 'I') &&
	    (line[3] == 't' || line[3] == 'T') &&
	    (line[4] == 'e' || line[4] == 'E') &&
	    (line[5] == ' ') && isdigit(line[6])) {
		*site_id = line[6];
		*val = strtol(&line[6], &endptr, 10);
		if (*endptr == ']') {
			if (endptr - &line[6] > PARAM_SIZE ||
			    !ignore_tail(endptr + 1))
				return KW_MALFORMED;
			return *val < MAX_NR_SITES ? KW_VALID : KW_UNSUPP_ID;
		}
		return KW_MALFORMED;
	}
	return KW_UNKNOWN;
}

/**
 * Check if @name meets the requirements for shell environment variables
 * (IEEE Std 1003.1-2001), mitigated with lowercase letter allowance
 *
 * Return 0, if it meets, and 1 otherwise
 */
int envblk_check_name(char *name, int len)
{
	int i;

	if (len == 0)
		return 1;
	if (!isalpha(name[0]) && name[0] != '_')
		return 1;
	for (i = 1; i < len; i++)
		if (!isalpha(name[i]) && !isdigit(name[i]) && name[i] != '_')
			return 1;
	return 0;
}

/**
 * Put a zIPL environment line 'NAME=VALUE' to a namespace referenced by NS_ID
 *
 * If the line was successfully imported without replacement a line with
 * the same NAME, that was added before, then return 0.
 * If the line should be ignored, or it replaced previously added line with
 * the same NAME, then return > 0. On errors return < 0.
 *
 * THIS: pointer to a NULL-terminated string, which contains the line to
 * be imported.
 * NS_ID: Pointer to a numerical character, indicating namespace ID
 */
static int import_one_line(char *this, struct line_hash_entry **table,
			   int *offset, char *ns_id)
{
	struct line_hash_entry *item;
	struct estr estr;
	char *p;

	if (*this == '#')
		/* Ignore "commented" line */
		return 1;

	p = strchr(this, '=');
	if (p == NULL || p == this)
		/* Could not identify NAME in the line. Ignore */
		return 1;
	if (envblk_check_name(this, p - this)) {
		error_reason("Unacceptable name '%.*s'", p - this, this);
		return -EINVAL;
	}
	estr.prefix = ns_id;
	estr.str = this;
	estr.len = p - this + 1;

	item = hash_table_find(table, &estr);
	return item != NULL ? hash_entry_replace(item, &estr, offset) :
		hash_table_add(table, &estr);
}

/**
 * Import environment line-by-line from a regular file specified
 * by its name FROM_FILE to a pre-allocated buffer TO_BUF. Ignore
 * malformed, or "commented" lines. If the file doesn't end with
 * end-of-line symbol, then append that symbol in the destination
 * buffer. Return 0 on success.
 *
 * ENVBLK_SIZE: size of the destination buffer TO_BUF.
 */
int envblk_import(char *from_file, char *to_buf, int envblk_size)
{
	const char *err_prefix = "Failed to import environment file";
	struct line_hash_entry *table[LINE_HASH_SIZE];
	unsigned int lines_imported = 0;
	char *line = NULL;
	char site_id = 0;
	long site_id_val;
	size_t len = 0;
	FILE *stream;
	ssize_t read;
	int ret = 0;
	int offset;

	stream = fopen(from_file, "r");
	if (stream == NULL)
		return 0;

	memset(table, 0, LINE_HASH_SIZE*sizeof(void *));
	offset = sizeof(ZIPL_ENVBLK_SIGNATURE) - 1;

	while ((read = getline(&line, &len, stream)) != -1) {
		if (read > envblk_size - offset) {
			error_reason("%s %s: maximal size (%d) exceeded",
				     err_prefix, from_file,
				     ENVBLK_MAX_IMPORT_SIZE(envblk_size));
			ret = -EINVAL;
			break;
		}
		if (read < 2)
			/* malformed line. Ignored */
			continue;

		switch (check_keyword(line, read, &site_id, &site_id_val)) {
		case KW_VALID:
			continue;
		case KW_MALFORMED:
			/*
			 * any line not ended with line feed character
			 * has to be evaluated as KW_UNKNOWN
			 */
			assert(line[read - 1] == '\n');
			line[read - 1] = '\0';
			error_reason("%s %s: bad section title '%s'",
				     err_prefix, from_file, line);
			ret = -EINVAL;
			goto error;
		case KW_UNSUPP_ID:
			error_reason("%s %s: unsupported site ID '%li'",
				     err_prefix, from_file, site_id_val);
			ret = -EINVAL;
			goto error;
		case KW_UNKNOWN:
			break;
		}
		/* LINE is not a secton title */

		if (line[read - 1] != '\n' && read == envblk_size - offset) {
			/*
			 * file's tail doesn't contain end-of-line symbol at
			 * the end, whereas there is no enough space in the
			 * destination buffer to insert that symbol, which is
			 * mandatory according to the environment block format
			 */
			error_reason("%s %s: maximal size (%d) exceeded",
				     err_prefix, from_file,
				     ENVBLK_MAX_IMPORT_SIZE(envblk_size));
			ret = -EINVAL;
			break;
		}
		ret = import_one_line(line, table, &offset,
				      site_id ? &site_id : NULL);
		if (ret < 0) {
			/* error */
			error_text("%s %s", err_prefix, from_file);
			break;
		} else if (ret > 0) {
			/*
			 * either this line was ignored, or previously
			 * imported line was overwritten by it
			 */
			ret = 0;
			continue;
		}
		if (lines_imported >= ENVBLK_MAX_LINES) {
			error_reason("%s %s: maximum number of lines (%d) exceeded",
				     err_prefix, from_file, ENVBLK_MAX_LINES);
			ret = -EINVAL;
			break;
		}
		offset += read;
		lines_imported++;
	}
	hash_table_flush(table, to_buf, sizeof(ZIPL_ENVBLK_SIGNATURE) - 1);
error:
	hash_table_free(table);
	free(line);
	fclose(stream);
	return ret;
}

char *envblk_next_line(char *s, const char *end)
{
	while (s < end) {
		if (*s == '\n')
			break;
		s++;
	}
	return s + 1;
}

/**
 * Scan installed environment block and call ACTOR for each found NAME.
 * Return -1 on corrupted environment blocks. Otherwise, return 0
 */
int envblk_scan(char *envblk, unsigned int envblk_size,
		void (*actor)(char *name))
{
	unsigned int lines_scanned = 0;
	const char *reason;
	char *s, *end;
	char *name;

	s = envblk + sizeof(ZIPL_ENVBLK_SIGNATURE) - 1;
	end = envblk + envblk_size;

	while (s < end && *s != 0) {
		if (lines_scanned > ENVBLK_MAX_LINES) {
			reason = "maximum number of lines exceeded";
			goto corrupted;
		}
		name = s;
		while (s < end && *s != '=')
			s++;
		if (s == end) {
			/* delimiter "=" not found */
			reason = "missed delimiter";
			goto corrupted;
		}
		/* here @s points to "=" */
		s++;

		while (s < end && *s != '\n')
			s++;
		if (s == end) {
			/* end of line not found */
			reason = "missed EOL";
			goto corrupted;
		}
		*s = '\0';
		actor(name);
		*s = '\n';
		lines_scanned++;
		s = envblk_next_line(s, end);
	}
	return 0;
corrupted:
	error_reason("Found corrupted environment block (%s) - please run zipl",
		     reason);
	return -1;
}

static void print_name_value(char *this)
{
	printf("  %s\n", this);
}

void envblk_print(char *envblk, unsigned int envblk_size)
{
	printf("Environment block content:\n");
	envblk_scan(envblk, envblk_size, print_name_value);
}
