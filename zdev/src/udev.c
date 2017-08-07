/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attrib.h"
#include "ccw.h"
#include "device.h"
#include "misc.h"
#include "path.h"
#include "setting.h"
#include "udev.h"

int udev_need_settle = 0;

/* Create a newly allocated udev entry. */
static struct udev_entry_node *udev_entry_node_new(const char *key,
						   const char *op,
						   const char *value)
{
	struct udev_entry_node *entry;

	entry = misc_malloc(sizeof(struct udev_entry_node));
	entry->key = misc_strdup(key);
	entry->op = misc_strdup(op);
	entry->value = misc_strdup(value);

	return entry;
}

/* Release resources associated with udev entry. */
static void udev_entry_node_free(struct udev_entry_node *entry)
{
	if (!entry)
		return;
	free(entry->key);
	free(entry->op);
	free(entry->value);
	free(entry);
}

/* Create a newly allocated udev line. */
static struct udev_line_node *udev_line_node_new(void)
{
	struct udev_line_node *line;

	line = misc_malloc(sizeof(struct udev_line_node));
	util_list_init(&line->entries, struct udev_entry_node, node);

	return line;
}

/* Release resources associated with udev line. */
static void udev_line_node_free(struct udev_line_node *line)
{
	struct udev_entry_node *e, *n;

	if (!line)
		return;
	util_list_iterate_safe(&line->entries, e, n) {
		util_list_remove(&line->entries, e);
		udev_entry_node_free(e);
	}
	free(line->line);
	free(line);
}

/* Create a newly allocated udev file. */
static struct udev_file *udev_file_new(void)
{
	struct udev_file *file;

	file = misc_malloc(sizeof(struct udev_file));
	util_list_init(&file->lines, struct udev_line_node, node);

	return file;
}

/* Release resources associated with udev file. */
void udev_free_file(struct udev_file *file)
{
	struct udev_line_node *l, *n;

	if (!file)
		return;
	util_list_iterate_safe(&file->lines, l, n) {
		util_list_remove(&file->lines, l);
		udev_line_node_free(l);
	}
	free(file);
}

/* Used for debugging. */
void udev_file_print(struct udev_file *file)
{
	struct udev_line_node *l;
	struct udev_entry_node *e;

	printf("udev_file at %p\n", (void *) file);
	if (!file)
		return;
	util_list_iterate(&file->lines, l) {
		printf("  udev_line_node at %p\n", (void *) l);
		printf("    line='%s'\n", l->line);
		util_list_iterate(&l->entries, e) {
			printf("    udev_entry at %p\n", (void *) e);
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
	key = misc_malloc(e - s + 1);
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
			return misc_strdup(ops[i]);
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
	value = misc_malloc(e - s + 1);
	memcpy(value, s, e - s);

	return value;
}

static bool parse_udev_entry(struct udev_line_node *line, const char *entry)
{
	char *key = NULL, *op = NULL, *value = NULL;
	struct udev_entry_node *e;
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
	e = udev_entry_node_new(key, op, value);
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

static bool parse_udev_line(struct udev_file *file, const char *line)
{
	char *copy, *curr, *next;
	struct udev_line_node *l;
	int i;
	bool result = true;

	l = udev_line_node_new();
	l->line = misc_strdup(line);

	/* Check for empty lines and comment lines. */
	for (i = 0; line[i] && isspace(line[i]); i++);
	if (line[i] == 0 || line[i] == '#')
		goto ok;

	/* Parse each comma-separated entry. */
	copy = misc_strdup(line);

	/* A hack to differentiate between quoted and unquoted commas. */
	replace_unquoted(copy, ',', 1);

	next = copy;
	while ((curr = strsep(&next, "\1"))) {
		if (!parse_udev_entry(l, curr)) {
			result = false;
			break;
		}
	}
	free(copy);

ok:
	if (result)
		util_list_add_tail(&file->lines, l);
	else
		udev_line_node_free(l);

	return result;
}

/* Read the contents of a udev rule file. */
exit_code_t udev_read_file(const char *path, struct udev_file **file_ptr)
{
	char *text, *curr, *next;
	struct udev_file *file;
	int once = 0;

	text = misc_read_text_file(path, 0, err_print);
	if (!text)
		return EXIT_RUNTIME_ERROR;
	file = udev_file_new();

	/* Iterate over each line. */
	next = text;
	while ((curr = strsep(&next, "\n"))) {
		if (parse_udev_line(file, curr))
			continue;
		if (!once) {
			once = 1;
			verb("Unrecognized udev rule format in %s:\n", path);
		}
		verb("%s\n", curr);
	}

	free(text);
	*file_ptr = file;

	return EXIT_OK;
}

static bool get_ids_cb(const char *filename, void *data)
{
	char *prefix = data;

	if (strncmp(filename, prefix, strlen(prefix)) != 0)
		return false;
	if (!ends_with(filename, UDEV_SUFFIX))
		return false;

	return true;
}

/* Add the IDs for all devices of the specified subtype name for which a
 * udev rule exists to strlist LIST. */
void udev_get_device_ids(const char *type, struct util_list *list)
{
	char *path, *prefix;
	struct util_list *files;
	struct strlist_node *s;
	size_t plen, len;

	prefix = misc_asprintf("%s-%s-", UDEV_PREFIX, type);
	plen = strlen(prefix);
	path = path_get_udev_rules();
	files = strlist_new();
	if (!misc_read_dir(path, files, get_ids_cb, prefix))
		goto out;

	util_list_iterate(files, s) {
		/* 41-dasd-eckd-0.0.1234.rules */
		len = strlen(s->str);
		s->str[len - sizeof(UDEV_SUFFIX) + 1] = 0;
		strlist_add(list, &s->str[plen]);
	}

out:
	strlist_free(files);
	free(path);
	free(prefix);
}

/* Remove UDEV rule for device. */
exit_code_t udev_remove_rule(const char *type, const char *id)
{
	char *path;
	exit_code_t rc = EXIT_OK;

	path = path_get_udev_rule(type, id);
	if (file_exists(path))
		rc = remove_file(path);
	free(path);

	return rc;
}

/* Wait for all current udev events to finish. */
void udev_settle(void)
{
	misc_system(err_ignore, "%s settle", PATH_UDEVADM);
}
