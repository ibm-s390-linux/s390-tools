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

#include "lib/util_libc.h"
#include "bootmap.h"
#include "envblk.h"
#include "error.h"
#include "misc.h"
#include <assert.h>

/* from linux/fs.h */
#define FIGETBSZ	_IO(0x00, 2)
#define KEYWORD_SIZE    strlen("[site X]\n")
#define MAX_NR_SITES    10
#define LINE_HASH_SIZE  16
#define PARAM_SIZE      8

struct iter_info {
	struct line_hash_entry **table;
	const char *site_id;
	char *envblk;
	int envblk_len;
	int indent;
};

void envblk_blank(char *envblk, int envblk_len)
{
	memset(envblk + sizeof(ZIPL_ENVBLK_SIGNATURE) - 1, '\0',
	       envblk_len - sizeof(ZIPL_ENVBLK_SIGNATURE) + 1);
}

void envblk_create_blank(char *envblk, int envblk_len)
{
	memcpy(envblk, ZIPL_ENVBLK_SIGNATURE,
	       sizeof(ZIPL_ENVBLK_SIGNATURE) - 1);
	envblk_blank(envblk, envblk_len);
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

/*
 * This defines "extended string", an object consisting of
 * an optional logical prefix and a substring
 */
struct estr {
	char *prefix;    /* pointer to the logical prefix */
	char *str;       /* pointer to the substring */
	int hashed_len;  /* number of bytes in the substring,
			  * participating in hash calculation
			  */
};

/**
 * Hash function on "extended strings"
 */
static unsigned int hash_fn(struct estr *estr)
{
	int len = estr->hashed_len;
	char *str = estr->str;
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
		return strncmp(str, estr->str, estr->hashed_len);
	if (str[0] != *estr->prefix)
		return -1;
	return strncmp(str + 1, estr->str, estr->hashed_len);
}

struct line_hash_entry {
	struct line_hash_entry *next;
	char *line; /* pointer to a string containing a pair 'KEY=VALUE'
		     * with an optional prefix and an optional trailing
		     * new line character
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

	if (!table)
		return NULL;
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
static int hash_table_scan(struct line_hash_entry **table,
			   int (*actor)(struct line_hash_entry *entry,
					void *data), void *data)
{
	int ret;
	int i;

	if (!table)
		return 0;
	for (i = 0; i < LINE_HASH_SIZE; i++) {
		struct line_hash_entry *item = table[i];

		while (item) {
			struct line_hash_entry *next = item->next;

			ret = actor(item, data);
			if (ret)
				return ret;
			item = next;
		}
	}
	return 0;
}

static int hash_entry_free(struct line_hash_entry *this,
			   __attribute__ ((unused))void *data)
{
	free(this->line);
	free(this);
	return 0;
}

static void hash_table_free(struct line_hash_entry **table)
{
	hash_table_scan(table, hash_entry_free, NULL);
}

/**
 * Scan hash table TABLE, and for each its entry copy its line to the
 * in-memory environment block specified by DST at the offset OFF.
 * Insert a new line character, if needed. The caller should guarantee
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
 * LINE: a null-terminated string with optional new line character
 * LEN: number of characters in the LINE excluding NULL-termination
 */
static enum keyword_status check_keyword(char *line, size_t len, char **site_id)
{
	char *endptr;
	long val;

	if (len < KEYWORD_SIZE - 1 || line[len - 1] != '\n')
		return KW_UNKNOWN;

	if ((line[0] == '[') &&
	    (line[1] == 's' || line[1] == 'S') &&
	    (line[2] == 'i' || line[2] == 'I') &&
	    (line[3] == 't' || line[3] == 'T') &&
	    (line[4] == 'e' || line[4] == 'E')) {
		if (line[5] != ' ')
			return KW_MALFORMED;

		*site_id = &line[6];
		val = strtol(&line[6], &endptr, 10);
		if (endptr == &line[6])
			/* not a number */
			return KW_MALFORMED;
		if (val < 0) {
			/* negative number */
			*endptr = '\0';
			return KW_UNSUPP_ID;
		}
		if (*endptr == ']') {
			if (line[6] == '0' && endptr - &line[6] > 1) {
				/* leading zeros are not allowed */
				*endptr = '\0';
				return KW_UNSUPP_ID;
			}
			if (!ignore_tail(endptr + 1))
				/* unacceptable trailing characters */
				return KW_MALFORMED;
			*endptr = '\0';
			return val < MAX_NR_SITES ? KW_VALID : KW_UNSUPP_ID;
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
int envblk_check_name(const char *name, int len)
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
 * Acceps a string STR, containing a pair 'KEY=VALUE'.
 * Returns length of the KEY.
 */
static int get_key_len(const char *str)
{
	return strchr(str, '=') - str;
}

/**
 * Acceps a string STR, containing a pair 'KEY=VALUE'.
 * Returns number of characters in the string, participating in hash
 * calculation.
 */
static int get_hashed_len(const char *str)
{
	/* hash is calculated by the key with a trailing '=' */
	return get_key_len(str) + 1;
}

/**
 * Put a line containing a pair 'NAME=VALUE' to a namespace referenced
 * by NS_ID
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
	estr.hashed_len = get_hashed_len(this);

	item = hash_table_find(table, &estr);
	return item != NULL ? hash_entry_replace(item, &estr, offset) :
		hash_table_add(table, &estr);
}

/**
 * Import environment line-by-line from a regular file specified
 * by its name FROM_FILE to a pre-allocated buffer TO_BUF. Ignore
 * malformed, or "commented" lines. If the file doesn't end with
 * new line character, then append that character in the destination
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
	char *site_idp;
	size_t len = 0;
	FILE *stream;
	ssize_t read;
	int ret = 0;
	int offset;

	stream = fopen(from_file, "r");
	if (stream == NULL)
		return 0;

	memset(table, 0, sizeof(table));
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

		switch (check_keyword(line, read, &site_idp)) {
		case KW_VALID:
			site_id = *site_idp;
			continue;
		case KW_MALFORMED:
			/*
			 * any line not ended with a new line character
			 * has to be evaluated as KW_UNKNOWN
			 */
			assert(line[read - 1] == '\n');
			line[read - 1] = '\0';
			error_reason("%s %s: bad section title '%s'",
				     err_prefix, from_file, line);
			ret = -EINVAL;
			goto error;
		case KW_UNSUPP_ID:
			error_reason("%s %s: unsupported site ID '%s'",
				     err_prefix, from_file, site_idp);
			ret = -EINVAL;
			goto error;
		case KW_UNKNOWN:
			break;
		}
		/* LINE is not a secton title */

		if (line[read - 1] != '\n' && read == envblk_size - offset) {
			/*
			 * file's tail doesn't contain a new line charactere at
			 * the end, whereas there is no enough space in the
			 * destination buffer to insert that character, which is
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
		int (*actor)(char *name, void *data), void *data)
{
	unsigned int lines_scanned = 0;
	const char *reason;
	char *s, *end;
	char *name;
	int ret;

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
		ret = actor(name, data);
		*s = '\n';
		if (ret)
			return ret;
		lines_scanned++;
		s = envblk_next_line(s, end);
	}
	return 0;
corrupted:
	error_reason("Found corrupted environment block (%s) - please run zipl",
		     reason);
	return -1;
}

static const char *indent_by_size(int size)
{
	switch (size) {
	case 1:
		return "  ";
	case 2:
		return "    ";
	default:
		return "";
	}
}

/**
 * Put a line containing a pair 'NAME=VALUE' to a respective namespace.
 *
 * THIS: line containing a pair 'NAME=VALUE', optionally prefixed
 * with one numerical character indicating namespace ID
 */
static int add_line_namespace(char *this, void *data)
{
	struct line_hash_entry ***tables = data;
	struct estr estr;
	char *endptr;
	int val;

	val = strtol(this, &endptr, 10);
	if (endptr == this)
		val = MAX_NR_SITES;
	if (!tables[val]) {
		tables[val] =
			util_zalloc(LINE_HASH_SIZE * sizeof(*tables));
		if (!tables[val])
			return -ENOMEM;
	}
	estr.prefix = NULL;
	estr.str = endptr;
	estr.hashed_len = get_hashed_len(endptr);

	return hash_table_add(tables[val], &estr);
}

static int hash_table_print_line(struct line_hash_entry *item, void *data)
{
	struct iter_info *ii = data;

	printf("%s%s\n", indent_by_size(ii->indent), item->line);
	return 0;
}

static int hash_table_print_line_cond(struct line_hash_entry *item, void *data)
{
	struct iter_info *ii = data;
	struct estr estr;

	estr.prefix = NULL;
	estr.str = item->line;
	estr.hashed_len = get_hashed_len(item->line);

	if (!hash_table_find(ii->table, &estr))
		hash_table_print_line(item, data);
	return 0;
}

static int print_namespace(struct line_hash_entry **table, const char *title,
			   int indent)
{
	struct iter_info ii;

	if (!table)
		return 0;
	printf("%s%s", indent_by_size(indent), title);
	ii.table = table;
	ii.indent = indent + 1;
	hash_table_scan(table, hash_table_print_line, &ii);
	return 0;
}

/**
 * Dump content of the environment block in human-readable form,
 * sorting it by "sections"
 */
int envblk_list_all(char *envblk, unsigned int envblk_size, int indent)
{
	struct line_hash_entry **tables[MAX_NR_SITES + 1];
	int nr_sites = 0;
	int ret = 0;
	int i;

	memset(tables, 0, sizeof(tables));
	/*
	 * Scan environment block and sort the pairs 'NAME=VALUE'
	 * by namespaces
	 */
	ret = envblk_scan(envblk, envblk_size, add_line_namespace, tables);
	if (ret)
		goto out;
	for (i = 0; i < MAX_NR_SITES; i++) {
		if (tables[i])
			nr_sites++;
	}
	/* print common namespace */
	print_namespace(tables[MAX_NR_SITES],
			nr_sites ? "Common variables:\n" : "",
			nr_sites ? indent : indent - 1);
	/* print site-specific namespaces */
	for (i = 0; i < MAX_NR_SITES; i++) {
		char title[10];

		sprintf(title, "Site %d:\n", i);
		print_namespace(tables[i], title, indent);
	}
out:
	for (i = 0; i <= MAX_NR_SITES; i++) {
		hash_table_free(tables[i]);
		free(tables[i]);
	}
	return ret;
}

/**
 * Print environment determined by effective SITE_ID
 */
int envblk_list_effective_site(char *envblk, unsigned int envblk_size, int site_id)
{
	struct line_hash_entry **tables[MAX_NR_SITES + 1];
	struct iter_info ii;
	int ret = 0;
	int i;

	memset(tables, 0, sizeof(tables));
	/*
	 * Scan environment block and sort out the pairs 'NAME=VALUE'
	 * by namespaces
	 */
	ret = envblk_scan(envblk, envblk_size, add_line_namespace, tables);
	if (ret)
		goto out;
	/*
	 * print all variables of the common namespace, which are not
	 * defined in the SITE_ID namespace
	 */
	ii.table = tables[site_id];
	ii.indent = 0;
	hash_table_scan(tables[MAX_NR_SITES], hash_table_print_line_cond,
			&ii);
	/*
	 * print all variables of the SITE_ID namespace
	 */
	ii.table = NULL;
	ii.indent = 0;
	hash_table_scan(tables[site_id], hash_table_print_line, &ii);
out:
	for (i = 0; i <= MAX_NR_SITES; i++) {
		hash_table_free(tables[i]);
		free(tables[i]);
	}
	return ret;
}

/**
 * List all variables defined by the namespace with SITE_ID
 */
int envblk_list_site(char *envblk, unsigned int envblk_size, int site_id)
{
	struct line_hash_entry **tables[MAX_NR_SITES + 1];
	struct iter_info ii;
	int ret = 0;
	int i;

	memset(tables, 0, sizeof(tables));
	/*
	 * Scan environment block and sort out the pairs 'NAME=VALUE'
	 * by namespaces
	 */
	ret = envblk_scan(envblk, envblk_size, add_line_namespace, tables);
	if (ret)
		goto out;
	ii.table = NULL;
	ii.indent = 0;
	hash_table_scan(tables[site_id], hash_table_print_line, &ii);
out:
	for (i = 0; i <= MAX_NR_SITES; i++) {
		hash_table_free(tables[i]);
		free(tables[i]);
	}
	return ret;
}

void envblk_print(char *envblk, unsigned int envblk_size)
{
	printf("zIPL environment block content:\n");
	envblk_list_all(envblk, envblk_size, 1 /* indent */);
}

int envblk_set(char *envblk, unsigned int envblk_size, const char *name,
	       const char *new_val)
{
	unsigned int name_len, new_val_len;
	char *fss; /* free space start */
	unsigned int lines_scanned = 0;
	int name_found = 0;
	char *s, *end;

	name_len = strlen(name);
	new_val_len = strlen(new_val);

	s = envblk + sizeof(ZIPL_ENVBLK_SIGNATURE) - 1;
	end = envblk + envblk_size;

	/*
	 * find the start of free space
	 */
	for (fss = end - 1; *fss == '\0'; fss--)
		;
	if (*fss != '\n') {
		error_reason("Found corrupted environment block - please run zipl");
		return -1;
	}
	fss++;

	while (fss - s > name_len) {
		if (lines_scanned >= ENVBLK_MAX_LINES) {
			error_reason("Found corrupted environment block - please run zipl");
			return -1;
		}
		if (memcmp(s, name, name_len) == 0 && s[name_len] == '=') {
			unsigned int cur_val_len;
			/*
			 * such name exists, replace its current value
			 */
			s += (name_len + 1);

			cur_val_len = 0;
			while (s + cur_val_len < end && s[cur_val_len] != '\n')
				cur_val_len++;
			if (s + cur_val_len >= end) {
				error_reason("Found corrupted environment block - please run zipl");
				return -1;
			}
			if (new_val_len > cur_val_len &&
			    end - fss < new_val_len - cur_val_len) {
				error_reason("Not enough space for new value");
				return -1;
			}
			/*
			 * make a precise-sized room for the new value
			 */
			if (new_val_len < cur_val_len) {
				memmove(s + new_val_len, s + cur_val_len,
					end - (s + cur_val_len));

				memset(fss + cur_val_len - new_val_len, '\0',
				       cur_val_len - new_val_len);
			} else {
				memmove(s + new_val_len, s + cur_val_len,
					end - (s + new_val_len));
			}
			name_found = 1;
			break;
		}
		lines_scanned++;
		s = envblk_next_line(s, end);
	}
	assert(lines_scanned <= ENVBLK_MAX_LINES);

	if (!name_found) {
		if (lines_scanned == ENVBLK_MAX_LINES) {
			error_reason("Maximum number of lines reached");
			return -1;
		}
		/*
		 * append a new variable
		 */
		if (end - fss < name_len + new_val_len + 2) {
			error_reason("Not enough space in environment block");
			return -1;
		}
		memcpy(fss, name, name_len);
		s = fss + name_len;
		*s++ = '=';
	}
	/*
	 * copy the new value and terminate it with a new line character
	 */
	memcpy(s, new_val, new_val_len);
	s[new_val_len] = '\n';
	return 0;
}

int envblk_unset(char *envblk, int envblk_len,
		 const char *pname, const char *site_id)
{
	unsigned int pname_len;
	char *s, *end;

	pname_len = strlen(pname);
	s = envblk + sizeof(ZIPL_ENVBLK_SIGNATURE) - 1;
	end = envblk + envblk_len;

	while (end - s >= pname_len + 2 /* minimal length of
					 * pattern "name=foo"
					 */) {
		if (memcmp(s, pname, pname_len) == 0 && s[pname_len] == '=') {
			/*
			 * prefixed name was found. Locate the whole
			 * "named" line and cut it including
			 * the trailing "\n"
			 */
			unsigned int cut_len = pname_len + 1;

			while (s + cut_len < end) {
				if (s[cut_len] == '\n')
					break;
				cut_len++;
			}
			if (s + cut_len >= end) {
				/*
				 * trailing "\n" not found
				 */
				error_reason("Found corrupted environment block - please run zipl");
				return -1;
			}
			cut_len++;
			memmove(s, s + cut_len, end - (s + cut_len));
			memset(end - cut_len, '\0', cut_len);
			return 0;
		}
		s = envblk_next_line(s, end);
	}
	error_reason("Name '%s' not found in %s%s namespace",
		     get_name(site_id, pname),
		     site_id ? "site " : "common",
		     site_id ?: "");
	return -1;
}

static int remove_name_value(struct line_hash_entry *item, void *data)
{
	struct iter_info *ii = data;
	char *pname;
	int len;
	int ret;

	/*
	 * construct a prefixed null-terminated name by a line 'KEY=VALUE'
	 */
	len = get_key_len(item->line);
	pname = misc_malloc(len + 2);
	if (!pname) {
		error_reason(strerror(errno));
		return -ENOMEM;
	}
	pname[0] = *ii->site_id;
	memcpy(pname + 1, item->line, len);
	pname[len + 1] = '\0';

	ret = envblk_unset(ii->envblk,
			   strnlen(ii->envblk, ii->envblk_len),
			   pname, ii->site_id);
	free(pname);
	return ret;
}

/**
 * Remove all lines prefixed with SITE_ID from environment block
 */
int envblk_remove_namespace(char *envblk, unsigned int envblk_size,
			    const char *site_id)
{
	struct line_hash_entry **tables[MAX_NR_SITES + 1];
	struct iter_info ii;
	int ret = 0;
	int i;

	memset(tables, 0, sizeof(tables));
	/*
	 * Scan environment block and populate hash tables
	 * with the pairs 'NAME=VALUE'
	 */
	ret = envblk_scan(envblk, envblk_size, add_line_namespace, tables);
	if (ret)
		goto out;

	ii.table = tables[atoi(site_id)];
	ii.envblk_len = envblk_size;
	ii.envblk = envblk;
	ii.site_id = site_id;
	ii.indent = 0;

	ret = hash_table_scan(tables[atoi(site_id)], remove_name_value, &ii);
out:
	for (i = 0; i <= MAX_NR_SITES; i++) {
		hash_table_free(tables[i]);
		free(tables[i]);
	}
	return ret;
}
