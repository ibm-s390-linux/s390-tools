/*
 * util - Utility function library
 *
 * UDEV helper functions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_exit_code.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_path.h"
#include "lib/util_udev.h"

/* Create a newly allocated udev entry. */
static struct util_udev_entry_node *util_udev_entry_node_new(const char *key,
							     const char *op,
							     const char *value)
{
	struct util_udev_entry_node *entry;

	entry = util_zalloc(sizeof(struct util_udev_entry_node));
	entry->key = util_strdup(key);
	entry->op = util_strdup(op);
	entry->value = util_strdup(value);

	return entry;
}

/* Release resources associated with udev entry. */
static void util_udev_entry_node_free(struct util_udev_entry_node *entry)
{
	if (!entry)
		return;
	free(entry->key);
	free(entry->op);
	free(entry->value);
	free(entry);
}

/* Create a newly allocated udev line. */
static struct util_udev_line_node *util_udev_line_node_new(void)
{
	struct util_udev_line_node *line;

	line = util_zalloc(sizeof(struct util_udev_line_node));
	util_list_init(&line->entries, struct util_udev_entry_node, node);

	return line;
}

/* Release resources associated with udev line. */
static void util_udev_line_node_free(struct util_udev_line_node *line)
{
	struct util_udev_entry_node *e, *n;

	if (!line)
		return;
	util_list_iterate_safe(&line->entries, e, n) {
		util_list_remove(&line->entries, e);
		util_udev_entry_node_free(e);
	}
	free(line->line);
	free(line);
}

/* Create a newly allocated udev file. */
static struct util_udev_file *util_udev_file_new(void)
{
	struct util_udev_file *file;

	file = util_zalloc(sizeof(struct util_udev_file));
	util_list_init(&file->lines, struct util_udev_line_node, node);

	return file;
}

/**
 * Release resources associated with udev file.
 *
 * @param[in, out] file       Udev file structure to be freed
 */
void util_udev_free_file(struct util_udev_file *file)
{
	struct util_udev_line_node *l, *n;

	if (!file)
		return;
	util_list_iterate_safe(&file->lines, l, n) {
		util_list_remove(&file->lines, l);
		util_udev_line_node_free(l);
	}
	free(file);
}

/**
 * Print the contents of a udev file to stdout. Used for debugging.
 *
 * @param[in]      file       Udev file structure to print
 */
void util_udev_file_print(struct util_udev_file *file)
{
	struct util_udev_line_node *l;
	struct util_udev_entry_node *e;

	printf("util_udev_file at %p\n", (void *) file);
	if (!file)
		return;
	util_list_iterate(&file->lines, l) {
		printf("  util_udev_line_node at %p\n", (void *) l);
		printf("    line='%s'\n", l->line);
		util_list_iterate(&l->entries, e) {
			printf("    util_udev_entry at %p\n", (void *) e);
			printf("      '%s' '%s' '%s'\n", e->key, e->op,
			       e->value);
		}
	}
}

static void skip_whitespace(const char **s_ptr)
{
	const char *s = *s_ptr;

	while (*s && isspace(*s))
		s++;

	*s_ptr = s;
}

static char *parse_key(const char **s_ptr)
{
	const char *s, *e;
	char *key;

	s = *s_ptr;
	/* Parse \w+(\{[^\}]*\})? */
	e = s;
	while (*e && (isalnum(*e) || *e == '_'))
		e++;
	if (*e == '{') {
		while (*e && *e != '}')
			e++;
		if (*e == '}')
			e++;
	}

	if (e == s)
		return NULL;

	/* s points to key start, e to character after key end. */
	key = util_zalloc(e - s + 1);
	memcpy(key, s, e - s);

	*s_ptr = e;

	return key;
}

static char *parse_op(const char **s_ptr)
{
	const char *ops[] = { "==", "!=", "=", "+=", ":=", NULL };
	const char *entry;
	size_t len;
	int i;

	entry = *s_ptr;
	for (i = 0; ops[i]; i++) {
		len = strlen(ops[i]);
		if (strncmp(entry, ops[i], len) == 0) {
			*s_ptr += len;
			return util_strdup(ops[i]);
		}
	}

	return NULL;
}

static char *parse_value(const char **s_ptr)
{
	const char *s, *e;
	char *value;

	/* Parse: ^\s*(.*)\s*$ */
	s = *s_ptr;
	skip_whitespace(&s);
	e = s;
	while (*e)
		e++;
	e--;
	while (e > s && isspace(*e))
		e--;
	e++;

	*s_ptr = e;

	/* Remove quotes. */
	if ((*s == '"' && *(e - 1) == '"') ||
	    (*s == '\'' && *(e - 1) == '\'')) {
		s++;
		e--;
	}

	/* s points to value start, e to character after value end. */
	value = util_zalloc(e - s + 1);
	memcpy(value, s, e - s);

	return value;
}

static bool parse_util_udev_entry(struct util_udev_line_node *line,
				  const char *entry)
{
	char *key = NULL, *op = NULL, *value = NULL;
	struct util_udev_entry_node *e;
	bool rc = false;

	/* Parse: ^\s*(\w+)\s*(==|!=|=|\+=|:=)\s*"?([^"]*)"\s*$ */

	/* Parse key. */
	skip_whitespace(&entry);
	key = parse_key(&entry);
	if (!key)
		goto out;

	/* Parse operator. */
	skip_whitespace(&entry);
	op = parse_op(&entry);
	if (!op)
		goto out;

	/* Parse value. */
	skip_whitespace(&entry);
	value = parse_value(&entry);
	if (!value)
		goto out;
	skip_whitespace(&entry);

	/* Check for unrecognized characters at end of entry. */
	if (*entry != 0)
		goto out;

	/* Add entry to list. */
	e = util_udev_entry_node_new(key, op, value);
	util_list_add_tail(&line->entries, e);
	rc = true;

out:
	free(key);
	free(op);
	free(value);

	return rc;
}

static void replace_unquoted(char *s, char from, char to)
{
	char quoted = 0;

	for (; *s; s++) {
		if (quoted) {
			/* Skip until quote end is found. */
			if (*s == quoted)
				quoted = 0;
			continue;
		}
		if (*s == '"' || *s == '\'') {
			quoted = *s;
			continue;
		}
		if (*s == from)
			*s = to;
	}
}

static bool parse_util_udev_line(struct util_udev_file *file, const char *line)
{
	char *copy, *curr, *next;
	struct util_udev_line_node *l;
	int i;
	bool result = true;

	l = util_udev_line_node_new();
	l->line = util_strdup(line);

	/* Check for empty lines and comment lines. */
	for (i = 0; line[i] && isspace(line[i]); i++);
	if (line[i] == 0 || line[i] == '#')
		goto ok;

	/* Parse each comma-separated entry. */
	copy = util_strdup(line);

	/* A hack to differentiate between quoted and unquoted commas. */
	replace_unquoted(copy, ',', 1);

	next = copy;
	while ((curr = strsep(&next, "\1"))) {
		if (!parse_util_udev_entry(l, curr)) {
			result = false;
			break;
		}
	}
	free(copy);

ok:
	if (result)
		util_list_add_tail(&file->lines, l);
	else
		util_udev_line_node_free(l);

	return result;
}

/**
 * Create a new util_udev_file structure and read the contents of a specified
 * udev file into that structure.
 *
 * @param[in]      path       Path to the udev file that will be read in
 * @param[in, out] file_ptr   A buffer to store resulting udev file structure
 *
 * @retval         0                       Udev file read successfully
 * @retval         UTIL_EXIT_RUNTIME_ERROR Error reading the udev file
 */
util_exit_code_t util_udev_read_file(const char *path,
				     struct util_udev_file **file_ptr)
{
	char *text, *curr, *next;
	struct util_udev_file *file;
	int once = 0;

	text = util_file_read_text_file(path, 0);
	if (!text)
		return UTIL_EXIT_RUNTIME_ERROR;
	file = util_udev_file_new();

	/* Iterate over each line. */
	next = text;
	while ((curr = strsep(&next, "\n"))) {
		if (parse_util_udev_line(file, curr))
			continue;
		if (!once) {
			once = 1;
			fprintf(stderr, "Unrecognized udev rule in %s:\n",
				path);
		}
		fprintf(stderr, "%s\n", curr);
	}

	free(text);
	*file_ptr = file;

	return UTIL_EXIT_OK;
}
