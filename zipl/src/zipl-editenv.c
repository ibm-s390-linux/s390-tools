/*
 * zipl-editenv: Environment Editor for zSeries Initial Program Loader
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <assert.h>
#include "disk.h"
#include "error.h"
#include "misc.h"
#include "bootmap.h"
#include "envblk.h"
#include "lib/util_prg.h"
#include "lib/util_opt.h"
#include "lib/util_part.h"
#include "lib/util_path.h"
#include "lib/util_proc.h"

/* from linux/fs.h */
#define FIBMAP		_IO(0x00, 1)

static const struct util_prg prg = {
	.desc = "zipl-editenv: Environment Editor for zSeries Initial Program Loader",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2021,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

int verbose;
static char *bootmap_dir;
static char *site_id;
static char *eff_site_id;

enum op_id {
	INVALID_OP_ID,
	SET_OP_ID,
	UNSET_OP_ID,
	RESET_OP_ID,
	LIST_OP_ID,
	LAST_OP_ID
};

static char *op_desc[LAST_OP_ID] = {"invalid", "set", "unset", "reset", "list"};

struct zipl_envblk {
	struct misc_fd mfd;
	char *buf;
	off_t offset;
	int size;
	unsigned int need_update:1;
};

static char *opcode2desc(enum op_id opcode)
{
	return op_desc[opcode];
}

static void zipl_envblk_init(struct zipl_envblk *zeb)
{
	memset(zeb, 0, sizeof(*zeb));
	zeb->mfd.fd = -1;
}

static int do_list(char *envblk, unsigned int envblk_size)
{
	assert(!site_id || !eff_site_id);

	if (site_id)
		return envblk_list_site(envblk,
					envblk_size,
					atoi(site_id));
	if (eff_site_id)
		return envblk_list_effective_site(envblk,
						  envblk_size,
						  atoi(eff_site_id));
	return envblk_list_all(envblk, envblk_size, 0);
}

/**
 * sync the content of the environment block with disk
 */
static int envblk_update(struct zipl_envblk *zeb)
{
	struct util_proc_part_entry part_entry;
	struct stat info;
	blocknum_t blknr;
	char *dev_name;
	int dev_fd;

	if (fstat(zeb->mfd.fd, &info))
		return -1;

	if (util_proc_part_get_entry(info.st_dev, &part_entry) != 0)
		return -1;

	dev_name = misc_make_path("/dev", part_entry.name);
	if (!dev_name) {
		error_reason("Could not make path for %s", part_entry.name);
		return -1;
	}
	dev_fd = open(dev_name, O_RDWR | O_DIRECT);
	if (dev_fd < 0) {
		error_reason("Could not open file %s", dev_name);
		free(dev_name);
		goto error;
	}
	free(dev_name);
	/*
	 * det disk address of the environment block
	 */
	if (fs_map(zeb->mfd.fd, zeb->offset, &blknr, zeb->size) != 0)
		goto error_close;

	if (lseek64(dev_fd, blknr * (uint64_t)zeb->size, SEEK_SET) < 0) {
		error_reason(strerror(errno));
		goto error_close;
	}
	if (write(dev_fd, zeb->buf, zeb->size) != zeb->size) {
		error_reason("Could not update physical block %ld on %s",
			     blknr, part_entry.name);
		goto error_close;
	}
	if (verbose)
		printf("Physical block %ld on %s got updated\n",
		       blknr, part_entry.name);

	util_proc_part_free_entry(&part_entry);
	return 0;
error_close:
	close(dev_fd);
error:
	util_proc_part_free_entry(&part_entry);
	return -1;
}

static int envblk_close(struct zipl_envblk *zeb)
{
	if (zeb->buf != NULL) {
		free(zeb->buf);
		zeb->buf = NULL;
	}
	if (zeb->mfd.fd < 0)
		return 0;

	if (close(zeb->mfd.fd) == 0) {
		zeb->mfd.fd = -1;
		return 0;
	}
	return -1;
}

/**
 * Open a regular file, which contains environment block, and
 * read that block to a buffer. Fill in environment block info
 * ZEB with valid values
 */
static int envblk_open(struct zipl_envblk *zeb)
{
	char *bootmap_file;

	if (zeb->mfd.fd >= 0)
		/*  it was opened before */
		return 0;
	bootmap_file =
		misc_make_path(bootmap_dir != NULL ? bootmap_dir : "/boot",
			       "bootmap");
	if (!bootmap_file) {
		error_reason("Could not make path for bootmap file");
		return -1;
	}
	zeb->mfd.fd = open(bootmap_file, O_RDONLY);
	if (zeb->mfd.fd < 0) {
		error_reason("Could not open bootmap file %s: %s",
			     bootmap_file, strerror(errno));
		free(bootmap_file);
		bootmap_file = NULL;
		return -1;
	}
	if (verbose)
		printf("Processing bootmap file at %s\n", bootmap_file);

	if (envblk_size_get(&zeb->mfd, &zeb->size)) {
		error_reason("Could not get environment block size");
		goto error;
	}
	if (envblk_offset_get(&zeb->mfd, &zeb->offset)) {
		error_reason("Could not get environment block location");
		goto error;
	}
	if (zeb->offset == 0) {
		error_reason("Environment not installed - please run zipl");
		goto error;
	}
	/* reopen for direct operations */
	close(zeb->mfd.fd);
	zeb->mfd.fd = open(bootmap_file, O_RDWR | O_DIRECT);
	if (zeb->mfd.fd < 0) {
		error_reason("Could not open environment block at %s",
			     bootmap_file);
		goto error;
	}
	free(bootmap_file);
	bootmap_file = NULL;

	zeb->buf = aligned_alloc(zeb->size, zeb->size);
	if (!zeb->buf) {
		error_reason("Could not allocate aligned memory region");
		goto error;
	}
	if (lseek(zeb->mfd.fd, zeb->offset, SEEK_SET) < 0) {
		error_reason(strerror(errno));
		goto error;
	}
	if (read(zeb->mfd.fd, zeb->buf, zeb->size) != zeb->size) {
		error_reason("Could not read environment block");
		goto error;
	}
	if (memcmp(zeb->buf, ZIPL_ENVBLK_SIGNATURE,
		sizeof(ZIPL_ENVBLK_SIGNATURE) - 1) != 0) {
		error_reason("Found corrupted environment block - please run zipl");
		goto error;
	}
	return 0;
error:
	if (bootmap_file)
		free(bootmap_file);
	envblk_close(zeb);
	return -1;
}

static char *build_prefixed_name(char *arg)
{
	char *name = NULL;

	if (!site_id)
		return strdup(arg);

	name = misc_malloc(strlen(arg) + 1);
	if (name) {
		name[0] = *site_id;
		strcpy(name + 1, arg);
	}
	return name;
}

static int env_list(struct zipl_envblk *zeb)
{
	if (envblk_open(zeb))
		return -1;
	return do_list(zeb->buf, strnlen(zeb->buf, zeb->size));
}

static int env_set(struct zipl_envblk *zeb, char *arg)
{
	char *pname;
	char *value;

	if (envblk_open(zeb))
		return -1;

	pname = build_prefixed_name(arg);
	if (!pname) {
		error_reason(strerror(errno));
		return -1;
	}
	/*
	 * identify name and locate value
	 */
	value = strchr(pname, '=');
	if (!value || value == pname) {
		/* name is not identified */
		error_reason("Invalid argument %s", arg);
		goto error;
	}
	*value = '\0';
	value++;

	if (envblk_check_name(get_name(site_id, pname),
			      get_name_len(site_id, pname))) {
		error_reason("Unacceptable name '%s'",
			     get_name(site_id, pname));
		goto error;
	}
	if (envblk_set(zeb->buf, zeb->size, pname, value) == 0) {
		free(pname);
		zeb->need_update = 1;
		return 0;
	}
error:
	free(pname);
	return -1;
}

static int env_unset(struct zipl_envblk *zeb, char *arg)
{
	char *pname;

	if (envblk_open(zeb))
		return -1;
	/*
	 * check name for validness
	 */
	if (strchr(arg, '=') != NULL) {
		error_reason("Invalid argument %s", arg);
		return -1;
	}
	pname = build_prefixed_name(arg);
	if (!pname) {
		error_reason(strerror(errno));
		return -1;
	}
	if (envblk_unset(zeb->buf, strnlen(zeb->buf, zeb->size),
			 pname, site_id) == 0) {
		zeb->need_update = 1;
		free(pname);
		return 0;
	}
	free(pname);
	return -1;
}

static int env_reset(struct zipl_envblk *zeb)
{
	if (envblk_open(zeb))
		return -1;
	if (site_id)
		envblk_remove_namespace(zeb->buf, zeb->size, site_id);
	else
		envblk_blank(zeb->buf, zeb->size);
	zeb->need_update = 1;
	return 0;
}

static int save_op(enum op_id *dst, enum op_id src)
{
	if (*dst != INVALID_OP_ID) {
		error_reason("Can't perform more than one operation (%s and %s) at a time\n",
			     opcode2desc(*dst), opcode2desc(src));
		return -EINVAL;
	}
	*dst = src;
	return 0;
}

static int save_op_arg(enum op_id *dst, enum op_id src,
		       char **dst_arg, char *src_arg)
{
	int ret;

	ret = save_op(dst, src);
	if (ret)
		return ret;
	*dst_arg = strdup(src_arg);
	if (*dst_arg == NULL) {
		error_reason("Couldn't copy the argument\n");
		return -ENOMEM;
	}
	return 0;
}

static int set_site_id_common(char *arg, char **id)
{
	long val;
	char *endptr;

	val = strtol(arg, &endptr, 10);
	if (endptr == arg || *endptr != '\0') {
		error_reason("Site-ID '%s' is not a decimal number", arg);
		return -EINVAL;
	}
	if (val < 0 || val > 9) {
		error_reason("Unsupported site-ID '%s'", arg);
		return -EINVAL;
	}
	if (endptr - arg > 1) {
		/* case of '00...0' */
		error_reason("Site-ID '%s' is not a decimal number", arg);
		return -EINVAL;
	}
	*id = strdup(arg);
	if (!*id) {
		error_reason(strerror(errno));
		return -ENOMEM;
	}
	/* larger IDs are unsupported */
	assert(strlen(*id) == 1);
	return 0;
}

#define warn_on_incompat_site_opts				\
	error_reason("options %s and %s are incompatible",	\
		     "'-S (--site)'", "'-E (--effective-site)'")

static int set_site_id(char *arg)
{
	if (eff_site_id) {
		warn_on_incompat_site_opts;
		return -EINVAL;
	}
	return set_site_id_common(arg, &site_id);
}

static int set_effective_site_id(char *arg)
{
	if (site_id) {
		warn_on_incompat_site_opts;
		return -EINVAL;
	}
	return set_site_id_common(arg, &eff_site_id);
}

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS WITHOUT ARGUMENTS"),
	{
		.option = { "list", no_argument, NULL, 'l'},
		.desc = "print list of zIPL environment variables with their values",
	},
	{
		.option = { "reset", no_argument, NULL, 'r'},
		.desc = "remove all variables from zIPL environment",
	},
	{
		.option = { "verbose", no_argument, NULL, 'V'},
		.desc = "provide more information",
	},
	UTIL_OPT_SECTION("OPTIONS WITH ARGUMENTS"),
	{
		.option = { "target", required_argument, NULL, 't'},
		.argument = "DIR",
		.desc = "specify directory, where bootmap file is located",
	},
	{
		.option = { "site", required_argument, NULL, 'S'},
		.argument = "SITE",
		.desc = "specify site ID",
	},
	{
		.option = { "effective-site", required_argument, NULL, 'E'},
		.argument = "SITE",
		.desc = "specify effective site ID",
	},
	{
		.option = { "set", required_argument, NULL, 's'},
		.argument = "NAME=VALUE",
		.desc = "assign value VALUE to variable NAME",
	},
	{
		.option = { "unset", required_argument, NULL, 'u'},
		.argument = "NAME",
		.desc = "remove variable NAME from zIPL environment",
	},
	UTIL_OPT_SECTION("STANDARD OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END,
};

int main(int argc, char *argv[])
{
	enum op_id opcode = INVALID_OP_ID;
	struct zipl_envblk zeb;
	char *saved_arg = NULL;
	int ret = 0;
	int c;

	zipl_envblk_init(&zeb);
	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			goto out;
		case 'v':
			util_prg_print_version();
			goto out;
		case 'V':
			verbose = 1;
			break;
		case 't':
			bootmap_dir = strdup(optarg);
			if (!bootmap_dir)
				ret = -1;
			break;
		case 'S':
			ret = set_site_id(optarg);
			break;
		case 'E':
			ret = set_effective_site_id(optarg);
			break;
		case 'r':
			ret = save_op(&opcode, RESET_OP_ID);
			break;
		case 'l':
			ret = save_op(&opcode, LIST_OP_ID);
			break;
		case 's':
			ret = save_op_arg(&opcode, SET_OP_ID,
					  &saved_arg, optarg);
			break;
		case 'u':
			ret = save_op_arg(&opcode, UNSET_OP_ID,
					  &saved_arg, optarg);
			break;
		default:
			util_opt_print_parse_error(c, argv);
			ret = -1;
		}
		if (ret)
			goto out;
	}
	if (optind < argc) {
		fprintf(stderr, "%s: Unknown command", argv[0]);
		while (optind < argc)
			printf(" %s", argv[optind++]);
		fprintf(stderr, "\n");
		goto out;
	}
	switch (opcode) {
	case SET_OP_ID:
		ret = env_set(&zeb, saved_arg);
		break;
	case UNSET_OP_ID:
		ret = env_unset(&zeb, saved_arg);
		break;
	case RESET_OP_ID:
		ret = env_reset(&zeb);
		break;
	case LIST_OP_ID:
		ret = env_list(&zeb);
		break;
	default:
		fprintf(stderr,
			"%s: Missing command\nUse '%s --help' for more information\n",
			argv[0], argv[0]);
		break;
	}
out:
	if (zeb.need_update)
		ret = envblk_update(&zeb);

	envblk_close(&zeb);
	free(saved_arg);
	free(bootmap_dir);
	free(site_id);
	free(eff_site_id);
	if (ret) {
		error_print();
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
