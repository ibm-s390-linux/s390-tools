/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_path.h"

#include "attrib.h"
#include "misc.h"
#include "modprobe.h"
#include "path.h"
#include "setting.h"

/**
 * struct modprobe_line - Representation of a line in a modprobe.conf file
 * @node: List node for adding to list
 * @line: Original line contents or NULL if unavailable
 * @argv: Array of command arguments
 * @argc: Count of command arguments
 */
struct modprobe_line {
	struct util_list_node node;
	char *line;
	char **argv;
	int argc;
};

/**
 * struct modprobe_file - Representation of a modprobe.conf file
 * @path: Full path and filename of modprobe.conf file
 * @list: List of lines in file
 */
struct modprobe_file {
	char *path;
	struct util_list lines;
};

/* Used for debugging. */
void modprobe_file_print(struct modprobe_file *mf)
{
	struct modprobe_line *l;
	int i;

	printf("modprobe_file(%p)\n", (void *) mf);
	printf("  path='%s'\n", mf->path);
	util_list_iterate(&mf->lines, l) {
		printf("  line(%p)\n", (void *) l);
		printf("    line='%s'\n", l->line);
		printf("    argc=%d\n", l->argc);
		for (i = 0; i < l->argc; i++)
			printf("    argv[%d]='%s'\n", i, l->argv[i]);
	}
}

/* Remove the line continuation character \\ at end of line. */
static void remove_linecont(char *line)
{
	int i;

	for (i = 0; line[i]; i++) {
		if (line[i] == '\\' && line[i + 1] == '\n')
			line[i++] = ' ';
	}
}

/* Allocate and initialize a struct modprobe_line from a line of text. */
static void set_line_content(struct modprobe_line *m, char *line)
{
	char c, *copy;

	m->line = misc_strdup(line);
	if (sscanf(line, " %c", &c) != 1) {
		/* Empty line. */
		m->argv = misc_malloc(sizeof(char *));
		m->argv[0] = misc_strdup("");
		m->argc = 1;
	} else if (c == '#') {
		/* Comment line. */
		m->argv = misc_malloc(sizeof(char *));
		m->argv[0] = misc_strdup("#");
		m->argc = 1;
	} else {
		/* Line containing a command. */
		copy = misc_strdup(line);
		remove_linecont(copy);
		line_split(copy, &m->argc, &m->argv);
		free(copy);
	}
}

/* Allocate and initialize a struct modprobe_line from a line of text. */
static struct modprobe_line *modprobe_line_new(char *line)
{
	struct modprobe_line *m;

	m = misc_malloc(sizeof(struct modprobe_line));
	set_line_content(m, line);

	return m;
}

/* Release all resources associated with a modprobe_line. */
static void modprobe_line_free(struct modprobe_line *m)
{
	int i;

	if (!m)
		return;
	free(m->line);
	for (i = 0; i < m->argc; i++)
		free(m->argv[i]);
	free(m->argv);
	free(m);
}

/* Create and initialize a new modprobe_file. */
static struct modprobe_file *modprobe_file_new(const char *path)
{
	struct modprobe_file *file;

	file = misc_malloc(sizeof(struct modprobe_file));
	file->path = misc_strdup(path);
	util_list_init(&file->lines, struct modprobe_line, node);

	return file;
}

/* Release resources used by file. */
static void modprobe_file_free(struct modprobe_file *file)
{
	struct modprobe_line *l, *n;

	if (!file)
		return;
	free(file->path);
	util_list_iterate_safe(&file->lines, l, n) {
		util_list_remove(&file->lines, l);
		modprobe_line_free(l);
	}

	free(file);
}

/* Add a new line to the file. */
static void modprobe_file_add(struct modprobe_file *file,
			      struct modprobe_line *line)
{
	util_list_add_tail(&file->lines, line);
}

#define MODPROBE_MAX_LINE	2048

/* Read a modprobe.conf file and return a modprobe_file. */
static exit_code_t modprobe_read(const char *path, struct modprobe_file **mf)
{
	char line[MODPROBE_MAX_LINE];
	char *l, *last;
	int len;
	FILE *fd;
	struct modprobe_file *mfile;

	debug("Reading udev file %s\n", path);
	mfile = modprobe_file_new(path);
	fd = misc_fopen(path, "r");
	if (!fd) {
		error("Could not read file %s: %s\n", path, strerror(errno));
		modprobe_file_free(mfile);
		return EXIT_RUNTIME_ERROR;
	}
	last = NULL;
	while (fgets(line, sizeof(line), fd)) {
		if (last) {
			/* The previous line had a continuation mark. */
			l = misc_asprintf("%s%s", last, line);
			free(last);
			last = NULL;
		} else
			l = misc_strdup(line);
		len = strlen(l);
		if (len > 2 && line[len - 1] == '\n' && line[len - 2] == '\\') {
			/* This line is continued on the next one. */
			last = l;
			continue;
		}
		modprobe_file_add(mfile, modprobe_line_new(l));
		free(l);
	}
	if (last) {
		/* Handle last line with a broken continuation mark
		 * gracefully. */
		modprobe_file_add(mfile, modprobe_line_new(last));
		free(last);
	}
	if (misc_fclose(fd))
		warn("Could not close file %s: %s\n", path, strerror(errno));
	*mf = mfile;

	return EXIT_OK;
}

/* Check modprobe file for a leading chzdev comment. */
static bool find_chzdev_comment(struct modprobe_file *mf)
{
	struct modprobe_line *l;

	util_list_iterate(&mf->lines, l) {
		/* Newly created line at start. */
		if (!l->line)
			return false;
		/* Skip empty line. */
		if (strlen(l->argv[0]) == 0)
			continue;
		/* Non-comment line. */
		if (strcmp(l->argv[0], "#") != 0)
			return false;
		/* Check for chzdev comment. */
		if (strstr(l->line, "chzdev"))
			return true;
	}

	return false;
}

/* Write a modprobe.conf file. */
static exit_code_t modprobe_write(struct modprobe_file *mf)
{
	FILE *fd;
	struct modprobe_line *l;
	int i;

	debug("Writing udev file %s\n", mf->path);
	fd = misc_fopen(mf->path, "w");
	if (!fd) {
		error("Could not write to file %s: %s\n", mf->path,
		      strerror(errno));
		return EXIT_RUNTIME_ERROR;
	}

	/* Add leading comment. */
	if (!find_chzdev_comment(mf))
		fprintf(fd, "# Generated by chzdev\n");
	util_list_iterate(&mf->lines, l) {
		if (l->line) {
			/* Use existing line. */
			fprintf(fd, "%s", l->line);
		} else {
			/* Create line by concatenating arguments. */
			for (i = 0; i < l->argc; i++) {
				fprintf(fd, "%s%s", i == 0 ? "" : " ",
					l->argv[i]);
			}
			fprintf(fd, "\n");
		}
	}
	if (misc_fclose(fd)) {
		warn("Could not close file %s: %s\n", mf->path,
		     strerror(errno));
	}

	return EXIT_OK;
}

/* Convert a single modprobe.conf option argument into a newly allocated
 * struct setting. */
static struct setting *arg_to_setting(struct attrib **attribs, char *arg)
{
	struct setting *s;
	struct attrib *a;
	char *key;
	char *val;

	key = misc_strdup(arg);
	val = strchr(key, '=');
	if (val) {
		*val = 0;
		val++;
	} else {
		/* Assume boolean parameter. */
		val = "1";
	}

	/* Get attribute pointer for known attributes. */
	a = attrib_find(attribs, key);
	s = setting_new(a, key, val);
	free(key);

	return s;
}

/* Return a newly allocated struct setting_list for module options found
 * in modprobe.conf file for specified module name. */
static struct setting_list *modprobe_get_settings(struct modprobe_file *mf,
						  const char *mod,
						  struct attrib **attribs)
{
	struct setting_list *sl;
	struct modprobe_line *l;
	struct setting *s;
	int i;

	sl = setting_list_new();
	util_list_iterate(&mf->lines, l) {
		/* argv[]="option", "<mod>", "<key>=<value>", ... */
		if (l->argc < 3)
			continue;
		if (strcmp(l->argv[0], "options") != 0)
			continue;
		if (strcmp(l->argv[1], mod) != 0)
			continue;
		for (i = 2; i < l->argc; i++) {
			s = arg_to_setting(attribs, l->argv[i]);
			setting_list_add(sl, s);
		}
	}

	return sl;
}

/* Apply settings list as module parameters to modprobe file. */
static void modprobe_apply_settings(struct modprobe_file *mf, const char *mod,
				    struct setting_list *sl)
{
	struct modprobe_line *l, *n;
	struct setting *s;
	unsigned long num;

	/* Remove all lines containing parameters for this module. */
	util_list_iterate_safe(&mf->lines, l, n) {
		if (l->argc < 2)
			continue;
		if (strcmp(l->argv[0], "options") != 0)
			continue;
		if (strcmp(l->argv[1], mod) != 0)
			continue;
		util_list_remove(&mf->lines, l);
		modprobe_line_free(l);
	}

	/* Add new line with specified settings. */
	num = 0;
	util_list_iterate(&sl->list, s) {
		if (setting_is_set(s))
			num++;
	}
	if (num == 0)
		return;
	l = misc_malloc(sizeof(struct modprobe_line));
	l->argv = misc_malloc(sizeof(char *) * (num + 2));
	l->argv[0] = misc_strdup("options");
	l->argv[1] = misc_strdup(mod);
	l->argc = 2;
	util_list_iterate(&sl->list, s) {
		if (!setting_is_set(s))
			continue;
		l->argv[(l->argc)++] = misc_asprintf("%s=%s", s->name,
						     s->value);
	}
	modprobe_file_add(mf, l);
}

/* Read attribute settings from a modprobe.conf file into a newly
 * allocated struct setting_list. */
exit_code_t modprobe_read_settings(const char *path, const char *mod,
				   struct attrib **attribs,
				   struct setting_list **settings)
{
	struct modprobe_file *mf;
	exit_code_t rc;

	if (!util_path_is_reg_file(path)) {
		*settings = NULL;
		return EXIT_OK;
	}
	rc = modprobe_read(path, &mf);
	if (rc)
		return rc;

	*settings = modprobe_get_settings(mf, mod, attribs);
	modprobe_file_free(mf);

	return EXIT_OK;
}

/* Write attribute settings to a modprobe.conf file.*/
exit_code_t modprobe_write_settings(const char *path, const char *mod,
				    struct setting_list *settings)
{
	struct modprobe_file *mf;
	exit_code_t rc;
	unsigned long lines;

	if (util_path_is_reg_file(path)) {
		rc = modprobe_read(path, &mf);
		if (rc)
			return rc;
	} else {
		rc = path_create(path);
		if (rc)
			return rc;
		mf = modprobe_file_new(path);
	}

	modprobe_apply_settings(mf, mod, settings);

	lines = util_list_len(&mf->lines);
	if (lines == 0 || (lines == 1 && find_chzdev_comment(mf))) {
		/* Do not write empty files. */
		if (util_path_is_reg_file(path))
			rc = remove_file(path);
	} else
		rc = modprobe_write(mf);
	modprobe_file_free(mf);

	return rc;
}
