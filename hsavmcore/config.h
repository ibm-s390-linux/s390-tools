/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_CONFIG_H
#define _HSAVMCORE_CONFIG_H

#include <limits.h>
#include <stdbool.h>

#include "common.h"

/*
 * This represents the application's configuration.
 */
struct config {
	/* Log message level */
	int verbose;
	/* Path to the system's vmcore file */
	char vmcore_path[PATH_MAX];
	/* Path to the system's zcore hsa file */
	char zcore_hsa_path[PATH_MAX];
	/*
	 * Path to a directory where the application could create temporary
	 * files.
	 */
	char workdir_path[PATH_MAX];
	/* Path to a bind-mount target for vmcore Overlay */
	char bind_mount_vmcore_path[PATH_MAX];
	/* Path to a swap device/file */
	char swap[PATH_MAX];
	/* HSA memory size */
	int hsa_size;
	/* Indicates whether the debugfs shall be mounted */
	bool mount_debugfs;
	/* Indicates whether the HSA memory file reader shall be used */
	bool use_hsa_mem;
	/* Indicates whether the HSA memory shall be released after caching */
	bool release_hsa;
	/* Indicates whether a bind-mount of vmcore Proxy shall be enabled */
	bool bind_mount_vmcore;
	/* Indicates whether the FUSE debug messages shall be enabled */
	bool fuse_debug;
};

/*
 * Initializes the application's configuration to its default values.
 */
void init_config(struct config *config);

/*
 * Updates the application's configuration from the given configuration file.
 */
int update_config_from_file(const char *config_path, struct config *config);

#endif
