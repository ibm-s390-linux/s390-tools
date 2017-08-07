/*
 * cmsfs-fuse - CMS EDF filesystem support for Linux
 *
 * Config option parsing
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/zt_common.h"

#include "cmsfs-fuse.h"
#include "helper.h"

#define MAX_LINE_LEN 80

static char *conf_file;

static int open_conf_file(FILE **fh)
{
	const char *home_env;

	conf_file = malloc(4096);
	if (conf_file == NULL)
		DIE_PERROR("malloc failed");

	home_env = getenv("HOME");
	if (home_env == NULL)
		goto no_home;

	sprintf(conf_file, "%s/.cmsfs-fuse/filetypes.conf", home_env);
	*fh = fopen(conf_file, "r");
	if (*fh != NULL)
		goto out;

no_home:
	sprintf(conf_file, "%s/%s", TOOLS_SYSCONFDIR,
		"/cmsfs-fuse/filetypes.conf");
	*fh = fopen(conf_file, "r");
	if (*fh == NULL) {
		free(conf_file);
		return -ENOENT;
	}
out:
	DEBUG("using config file: %s\n", conf_file);
	return 0;
}

static void add_filetype(char *name, struct util_list *list)
{
	struct filetype *entry;

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		DIE_PERROR("malloc failed");
	strncpy(entry->name, name, MAX_TYPE_LEN);
	util_list_add_head(list, entry);
}

static int filetype_valid(const char *type, int line)
{
	unsigned int i;

	if (strlen(type) > 8) {
		WARN("entry too long in line: %d in config file: %s\n",
		     line, conf_file);
		return 0;
	}

	for (i = 0; i < strlen(type); i++)
		if (!is_edf_char(*(type + i))) {
			WARN("invalid character in line: %d in config file: %s\n",
			     line, conf_file);
			return 0;
		}

	return 1;
}

int scan_conf_file(struct util_list *list)
{
	char buf[MAX_LINE_LEN], *tmp;
	int line = 0;
	FILE *fh;

	if (open_conf_file(&fh) < 0)
		return -ENOENT;

	while (fgets(buf, MAX_LINE_LEN, fh) != NULL) {
		line++;
		tmp = buf;
		while (isblank(*tmp))
			tmp++;

		if (*tmp == '\n')
			continue;

		/*
		 * Skip comments, comment must be "# " because # is a valid
		 * EDF character.
		 */
		if (strlen(tmp) > 1 && *tmp == '#' && *(tmp + 1) == ' ')
			continue;

		/* remove trailing \n */
		if (strlen(tmp) && *(tmp + strlen(tmp) - 1) == '\n')
			*(tmp + strlen(tmp) - 1) = '\0';

		if (filetype_valid(tmp, line))
			add_filetype(tmp, list);
	}
	fclose(fh);
	free(conf_file);
	return 0;
}
