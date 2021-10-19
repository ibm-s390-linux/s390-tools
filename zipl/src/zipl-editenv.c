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
#define FIGETBSZ	_IO(0x00, 2)

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
	int fd;
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
	zeb->fd = -1;
}

static void print_name_value(char *this)
{
	printf("%s\n", this);
}

static int do_list(char *envblk, unsigned int envblk_size)
{
	return envblk_scan(envblk, envblk_size, print_name_value);
}

static int do_set(char *envblk, unsigned int envblk_size,
		  const char *name, const char *new_val)
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
			} else
				memmove(s + new_val_len, s + cur_val_len,
					end - (s + new_val_len));
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
	 * copy the new value and terminate it with a new line symbol
	 */
	memcpy(s, new_val, new_val_len);
	s[new_val_len] = '\n';
	return 0;
}

static int do_unset(char *envblk, int envblk_len, const char *name)
{
	unsigned int name_len;
	char *s, *end;

	name_len = strlen(name);
	s = envblk + sizeof(ZIPL_ENVBLK_SIGNATURE) - 1;
	end = envblk + envblk_len;

	while (end - s >= name_len + 2 /* minimal length of
					* pattern "name=foo"
					*/) {
		if (memcmp(s, name, name_len) == 0 && s[name_len] == '=') {
			/*
			 * name was found. Locate the whole
			 * "named" line and cut it including
			 * the trailing "\n"
			 */
			unsigned int cut_len = name_len + 1;

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
	error_reason("Name %s not found", name);
	return -1;
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

	if (fstat(zeb->fd, &info))
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
	if (fs_map(zeb->fd, zeb->offset, &blknr, zeb->size) != 0)
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
	if (zeb->fd < 0)
		return 0;

	if (close(zeb->fd) == 0) {
		zeb->fd = -1;
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

	if (zeb->fd >= 0)
		/*  it was opened before */
		return 0;
	bootmap_file =
		misc_make_path(bootmap_dir != NULL ? bootmap_dir : "/boot",
			       "bootmap");
	if (!bootmap_file) {
		error_reason("Could not make path for bootmap file");
		return -1;
	}
	zeb->fd = open(bootmap_file, O_RDONLY);
	if (zeb->fd < 0) {
		error_reason("Could not open bootmap file %s: %s",
			     bootmap_file, strerror(errno));
		free(bootmap_file);
		bootmap_file = NULL;
		return -1;
	}
	if (verbose)
		printf("Processing bootmap file at %s\n", bootmap_file);

	if (envblk_size_get(zeb->fd, &zeb->size)) {
		error_reason("Could not get environment block size");
		goto error;
	}
	if (envblk_offset_get(zeb->fd, &zeb->offset)) {
		error_reason("Could not get environment block location");
		goto error;
	}
	if (zeb->offset == 0) {
		error_reason("Environment not installed - please run zipl");
		goto error;
	}
	/* reopen for direct operations */
	close(zeb->fd);
	zeb->fd = open(bootmap_file, O_RDWR | O_DIRECT);
	if (zeb->fd < 0) {
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
	if (lseek(zeb->fd, zeb->offset, SEEK_SET) < 0) {
		error_reason(strerror(errno));
		goto error;
	}
	if (read(zeb->fd, zeb->buf, zeb->size) != zeb->size) {
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

static int env_list(struct zipl_envblk *zeb)
{
	if (envblk_open(zeb))
		return -1;
	return do_list(zeb->buf, strnlen(zeb->buf, zeb->size));
}

static int env_set(struct zipl_envblk *zeb, char *arg)
{
	char *name, *value;

	if (envblk_open(zeb))
		return -1;
	/*
	 * parse the argument, locate name and value
	 */
	name = strdup(arg);
	if (!name)
		return -1;

	value = strchr(name, '=');
	if (!value || value == name) {
		/* name is not identified */
		error_reason("Invalid argument %s", arg);
		goto error;
	}
	*value = '\0';
	value++;

	if (envblk_check_name(name, strlen(name))) {
		error_reason("Unacceptable name '%s'", name);
		goto error;
	}
	if (do_set(zeb->buf, zeb->size, name, value) == 0) {
		free(name);
		zeb->need_update = 1;
		return 0;
	}
error:
	free(name);
	return -1;
}

static int env_unset(struct zipl_envblk *zeb, char *name)
{
	if (envblk_open(zeb))
		return -1;
	/*
	 * check name for validness
	 */
	if (strchr(name, '=') != NULL) {
		error_reason("Invalid argument %s", name);
		return -1;
	}
	if (do_unset(zeb->buf, strnlen(zeb->buf, zeb->size), name) == 0) {
		zeb->need_update = 1;
		return 0;
	}
	return -1;
}

static void env_blank(char *envblk, int envblk_len)
{
	memset(envblk + sizeof(ZIPL_ENVBLK_SIGNATURE) - 1, '\0',
	       envblk_len - sizeof(ZIPL_ENVBLK_SIGNATURE) + 1);
}

static int env_reset(struct zipl_envblk *zeb)
{
	if (envblk_open(zeb))
		return -1;

	env_blank(zeb->buf, zeb->size);
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

	if (argc < 2) {
		fprintf(stderr,
			"%s: Missing command\nUse 'zipl-editenv --help' for more information\n",
			argv[0]);
		return EXIT_FAILURE;
	}
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
			bootmap_dir = optarg;
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
		break;
	}
out:
	if (zeb.need_update)
		ret = envblk_update(&zeb);

	envblk_close(&zeb);
	if (saved_arg != NULL)
		free(saved_arg);
	if (ret) {
		error_print();
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
