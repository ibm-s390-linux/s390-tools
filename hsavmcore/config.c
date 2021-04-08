/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "lib/util_libc.h"
#include "lib/util_log.h"

#include "config.h"

#define CONFIG_LINE_MAX_SIZE 1024

/*
 * Supported configuration parameters
 */
#define CONFIG_VERBOSE "verbose"
#define CONFIG_WORKDIR "workdir"
#define CONFIG_HSA_SIZE "hsa_size"
#define CONFIG_MOUNT_DEBUGFS "mount_debugfs"
#define CONFIG_USE_HSA_MEM "use_hsa_mem"
#define CONFIG_RELEASE_HSA "release_hsa"
#define CONFIG_BIND_MOUNT_VMCORE "bind_mount_vmcore"
#define CONFIG_FUSE_DEBUG "fuse_debug"
#define CONFIG_SWAP "swap"

static char *get_value_str(char *line)
{
	char *ptr = strchr(line, '=');

	if (!ptr)
		return NULL;

	return util_strstrip(ptr + 1);
}

static int parse_bool(char *line, int linenum, const char *name, bool *value)
{
	const char *value_str;
	unsigned long value_num;
	char *endptr;

	value_str = get_value_str(line);
	if (!value_str) {
		util_log_print(UTIL_LOG_ERROR,
			       "config line %d: value expected for %s\n",
			       linenum, name);
		return -1;
	}

	util_log_print(UTIL_LOG_DEBUG, "config parse bool: %s\n", value_str);

	value_num = strtoul(value_str, &endptr, 0);
	if (*endptr != '\0' || (value_num != 0 && value_num != 1)) {
		util_log_print(UTIL_LOG_ERROR,
			       "config line %d: invalid value for %s\n",
			       linenum, name);
		return -1;
	}

	*value = value_num;

	return 0;
}

static int parse_int(char *line, int linenum, const char *name, int min_value,
		     int max_value, int *value)
{
	const char *value_str;
	long value_num;
	char *endptr;

	value_str = get_value_str(line);
	if (!value_str) {
		util_log_print(UTIL_LOG_ERROR,
			       "config line %d: value expected for %s\n",
			       linenum, name);
		return -1;
	}

	util_log_print(UTIL_LOG_DEBUG, "config parse int: %s\n", value_str);

	value_num = strtol(value_str, &endptr, 0);
	if (*endptr != '\0' || value_num < min_value || value_num > max_value) {
		util_log_print(UTIL_LOG_ERROR,
			       "config line %d: invalid value for %s\n",
			       linenum, name);
		return -1;
	}

	*value = value_num;

	return 0;
}

static int parse_str(char *line, int linenum, const char *name, int min_size,
		     int max_size, char *value)
{
	const char *value_str;
	int size;

	value_str = get_value_str(line);
	if (!value_str) {
		util_log_print(UTIL_LOG_ERROR,
			       "config line %d: value expected for %s\n",
			       linenum, name);
		return -1;
	}

	util_log_print(UTIL_LOG_DEBUG, "config parse string: %s\n", value_str);

	size = strlen(value_str);
	if ((min_size >= 0 && size < min_size) || size > max_size) {
		util_log_print(UTIL_LOG_ERROR,
			       "config line %d: invalid value for %s\n",
			       linenum, name);
		return -1;
	}

	strncpy(value, value_str, max_size);
	/* Ensure null termination */
	value[max_size] = '\0';

	return 0;
}

static int parse_line(char *line, int linenum, struct config *config)
{
	if (strncmp(line, CONFIG_VERBOSE, strlen(CONFIG_VERBOSE)) == 0) {
		if (parse_int(line, linenum, CONFIG_VERBOSE, UTIL_LOG_ERROR,
			      UTIL_LOG_TRACE, &config->verbose))
			return -1;
	} else if (strncmp(line, CONFIG_WORKDIR, strlen(CONFIG_WORKDIR)) == 0) {
		if (parse_str(line, linenum, CONFIG_WORKDIR, 0,
			      sizeof(config->workdir_path) - 1,
			      config->workdir_path))
			return -1;
	} else if (strncmp(line, CONFIG_HSA_SIZE, strlen(CONFIG_HSA_SIZE)) ==
		   0) {
		if (parse_int(line, linenum, CONFIG_HSA_SIZE, -1, INT_MAX,
			      &config->hsa_size))
			return -1;
	} else if (strncmp(line, CONFIG_MOUNT_DEBUGFS,
			   strlen(CONFIG_MOUNT_DEBUGFS)) == 0) {
		if (parse_bool(line, linenum, CONFIG_MOUNT_DEBUGFS,
			       &config->mount_debugfs))
			return -1;
	} else if (strncmp(line, CONFIG_USE_HSA_MEM,
			   strlen(CONFIG_USE_HSA_MEM)) == 0) {
		if (parse_bool(line, linenum, CONFIG_USE_HSA_MEM,
			       &config->use_hsa_mem))
			return -1;
	} else if (strncmp(line, CONFIG_RELEASE_HSA,
			   strlen(CONFIG_RELEASE_HSA)) == 0) {
		if (parse_bool(line, linenum, CONFIG_RELEASE_HSA,
			       &config->release_hsa))
			return -1;
	} else if (strncmp(line, CONFIG_BIND_MOUNT_VMCORE,
			   strlen(CONFIG_BIND_MOUNT_VMCORE)) == 0) {
		if (parse_bool(line, linenum, CONFIG_BIND_MOUNT_VMCORE,
			       &config->bind_mount_vmcore))
			return -1;
	} else if (strncmp(line, CONFIG_FUSE_DEBUG,
			   strlen(CONFIG_FUSE_DEBUG)) == 0) {
		if (parse_bool(line, linenum, CONFIG_FUSE_DEBUG,
			       &config->fuse_debug))
			return -1;
	} else if (strncmp(line, CONFIG_SWAP, strlen(CONFIG_SWAP)) == 0) {
		if (parse_str(line, linenum, CONFIG_SWAP, 0,
			      sizeof(config->swap) - 1, config->swap))
			return -1;
	} else {
		util_log_print(UTIL_LOG_ERROR,
			       "config line %d: unknown configuration '%s'\n",
			       linenum, line);
		return -1;
	}

	return 0;
}

void init_config(struct config *config)
{
	memset(config, 0, sizeof(struct config));
	strncpy(config->vmcore_path, PROC_VMCORE,
		sizeof(config->vmcore_path) - 1);
	strncpy(config->zcore_hsa_path, ZCORE_HSA,
		sizeof(config->zcore_hsa_path) - 1);
	strncpy(config->workdir_path, WORKDIR,
		sizeof(config->workdir_path) - 1);
	strncpy(config->bind_mount_vmcore_path, PROC_VMCORE,
		sizeof(config->bind_mount_vmcore_path) - 1);
	config->hsa_size = -1;
	config->mount_debugfs = false;
	config->use_hsa_mem = false;
	config->release_hsa = true;
	config->bind_mount_vmcore = true;
	config->fuse_debug = false;
}

int update_config_from_file(const char *config_path, struct config *config)
{
	char line[CONFIG_LINE_MAX_SIZE], *ptr;
	int ret = 0, linenum;
	FILE *fp;

	fp = fopen(config_path, "r");
	if (!fp) {
		util_log_print(UTIL_LOG_ERROR, "Couldn't open config file %s\n",
			       config_path);
		return -1;
	}

	/* Read the given configuration file linewise and parse parameters */
	linenum = 0;
	while (fgets(line, sizeof(line), fp)) {
		linenum++;

		ptr = util_strstrip(line);
		/* Skip empty or comment lines */
		if (ptr[0] == '\0' || ptr[0] == '#')
			continue;

		util_log_print(UTIL_LOG_DEBUG, "config line %d: %s\n", linenum,
			       ptr);

		ret = parse_line(ptr, linenum, config);
		if (ret < 0)
			break;
	}

	fclose(fp);

	return ret;
}
