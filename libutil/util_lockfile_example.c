/**
 * util_lockfile_example - Example program for util_lockfile
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

//! [code]
#include <stdio.h>
#include <stdlib.h>
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/util_lockfile.h"

static const struct util_prg prg = {
	.desc = "Example for util_lockfile.",
	.copyright_vec = { {
			.owner = "IBM Corp.",
			.pub_first = 2022,
			.pub_last = 2022,
		},
		UTIL_PRG_COPYRIGHT_END }
};

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "file", required_argument, NULL, 'f' },
		.argument = "PATH",
		.desc = "Use the specified path for a lockfile.",
	},
	{
		.option = { "lock", required_argument, NULL, 'l' },
		.argument = "RETRIES",
		.desc = "Acquire the specified file lock using the parent "
			"process id of this process.  If not immediately "
			"successful, retry for the specified number of times",
	},
	{
		.option = { "release", 0, NULL, 'r' },
		.desc = "Release the specified lock file using the parent "
			"process id",
	},
	{
		.option = { "lock-and-release", required_argument, NULL, 'L' },
		.argument = "RETRIES",
		.desc = "Acquire the specified file lock using this process "
			"id, then release it.  If not immediately successful, "
			"retry for the specified number of times.",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

enum prg_action {
	ACTION_NONE = 0,
	ACTION_LOCK,
	ACTION_RELEASE,
	ACTION_LOCK_AND_RELEASE,
};

static void print_single_action_error(void)
{
	warnx("Only a single action (--lock, --lock-parent, --release, "
	      "--release-parent) is allowed");
}

int main(int argc, char *argv[])
{
	enum prg_action action_id = ACTION_NONE;
	int opt, rc, retries = 0;
	char *endp, *path = NULL;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while (1) {
		opt = util_opt_getopt_long(argc, argv);
		if (opt == -1)
			break;
		switch (opt) {
		case 'f':
			path = optarg;
			break;
		case 'L':
			if (action_id != ACTION_NONE) {
				print_single_action_error();
				return EXIT_FAILURE;
			}
			retries = strtol(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' || retries < 0) {
				warnx("Invalid retry value for "
				      "--lock-and-release: '%s'",
				      optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			action_id = ACTION_LOCK_AND_RELEASE;
			break;
		case 'l':
			if (action_id != ACTION_NONE) {
				print_single_action_error();
				return EXIT_FAILURE;
			}
			retries = strtol(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' || retries < 0) {
				warnx("Invalid retry value for "
				      "--parent-lock: '%s'",
				      optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			action_id = ACTION_LOCK;
			break;
		case 'r':
			if (action_id != ACTION_NONE) {
				print_single_action_error();
				return EXIT_FAILURE;
			}
			action_id = ACTION_RELEASE;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		default:
			util_opt_print_parse_error(opt, argv);
			return EXIT_FAILURE;
		}
	}

	if (!path) {
		warnx("--file is required, see --help for more information");
		return EXIT_FAILURE;
	}

	if (action_id == ACTION_NONE) {
		warnx("One of the following actions must be specified: "
		      "--lock, --release, --lock-and-release");
		return EXIT_FAILURE;
	}

	/* Determine which util_lockfile function to call */
	switch (action_id) {
	case ACTION_LOCK:
		rc = util_lockfile_parent_lock(path, retries);
		switch (rc) {
		case UTIL_LOCKFILE_OK:
			printf("lock acquired successfully\n");
			break;
		case UTIL_LOCKFILE_LOCK_FAIL:
			warnx("lock was not acquired; already held");
			return EXIT_FAILURE;
		case UTIL_LOCKFILE_ERR:
			warnx("lock was not acquired; file error");
			return EXIT_FAILURE;
		default:
			warnx("Unknown util_lockfile rc %d", rc);
			return EXIT_FAILURE;
		}
		break;
	case ACTION_RELEASE:
		rc = util_lockfile_parent_release(path);
		switch (rc) {
		case UTIL_LOCKFILE_OK:
			printf("lock released successfully\n");
			break;
		case UTIL_LOCKFILE_RELEASE_NONE:
			warnx("lock file did not exist");
			return EXIT_FAILURE;
		case UTIL_LOCKFILE_RELEASE_FAIL:
			warnx("lock was not held by the specified pid");
			return EXIT_FAILURE;
		case UTIL_LOCKFILE_ERR:
			warnx("lock was not released; file error");
			return EXIT_FAILURE;
		default:
			warnx("Unknown util_lockfile rc %d", rc);
			return EXIT_FAILURE;
		}
		break;
	case ACTION_LOCK_AND_RELEASE:
		rc = util_lockfile_lock(path, retries);
		switch (rc) {
		case UTIL_LOCKFILE_OK:
			printf("lock acquired successfully, holding for 2 seconds\n");
			break;
		case UTIL_LOCKFILE_LOCK_FAIL:
			warnx("lock was not acquired; already held");
			return EXIT_FAILURE;
		case UTIL_LOCKFILE_ERR:
			warnx("lock was not acquired; file error");
			return EXIT_FAILURE;
		default:
			warnx("Unknown util_lockfile rc %d", rc);
			return EXIT_FAILURE;
		}
		/* Briefly sleep while holding the lock */
		sleep(2);
		rc = util_lockfile_release(path);
		switch (rc) {
		case UTIL_LOCKFILE_OK:
			printf("lock released successfully\n");
			break;
		case UTIL_LOCKFILE_RELEASE_NONE:
			warnx("lock file did not exist");
			return EXIT_FAILURE;
		case UTIL_LOCKFILE_RELEASE_FAIL:
			warnx("lock was not held by the specified pid");
			return EXIT_FAILURE;
		case UTIL_LOCKFILE_ERR:
			warnx("lock was not released; file error");
			return EXIT_FAILURE;
		default:
			warnx("Unknown util_lockfile rc %d", rc);
			return EXIT_FAILURE;
		}
		break;
	default:
		warnx("Unknown util_lockfile action");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
//! [code]
