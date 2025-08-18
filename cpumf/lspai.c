/* Copyright IBM Corp. 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/* List available Processor Assist Instrumentation (PAI) counters.  */

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_fmt.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_scandir.h"
#include "lib/libcpumf.h"

#define OPT_FORMAT		256	/* --format XXX option */

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT },
		.argument = "FORMAT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List counters in specified FORMAT (" FMT_TYPE_NAMES ")"
	},
	{
		.option = { "numeric", no_argument, NULL, 'n' },
		.desc = "Sort PAI counters by counter number"
	},
	{
		.option = { "type", required_argument, NULL, 't' },
		.argument = "TYPE",
		.desc = "Type of PAI counters to show: crypto, nnpa"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static const struct util_prg prg = {
	.desc = "List Processor Assist Information counter sets",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2023,
			.pub_last = 2023,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static bool numsort;		/* If true sort counter numerically */
static int output_format = -1;	/* Generate style if >= 0 */

#define PAI_PATH	"/bus/event_source/devices/%s"

enum pai_types {		/* Bit mask for supported PAI counters */
	pai_type_crypto = 0,	/* PAI Crypto Counters */
	pai_type_nnpa = 1,	/* PAI NNPA Counters */
	pai_type_max = 2,	/* PAI maximum value, must be last */
};

static int pai_types_show;

struct pai_ctrname {		/* List of defined counters */
	char *name;		/* Counter name */
	unsigned long nr;	/* Counter number */
};

struct pai_node {		/* Head for PAI counter sets */
	struct util_list_node node;	/* Successor in PAI counter set list */
	enum pai_types type;	/* PAI type */
	int pmu;		/* Assigned PMU type number */
	const char *name;	/* Counter set name */
	char *name_uc;		/* Counter set name upper case */
	const char *sysfs_name;	/* Counter set name in /sysfs tree */
	const char *filter_name;	/* Counter set name for scandir filter */
	struct pai_ctrname *ctrlist;	/* List of counter names & numbers */
	size_t ctrsize;		/* Total size in bytes of ctrlist */
	int ctridx;		/* Index of last entry used in ctrlist */
	unsigned long base;	/* Base number for counter set */
};

static struct util_list pai_list;

/* Return base of counter set, this is the first counter of this set. */
static unsigned long pai_type_base(enum pai_types t)
{
	switch (t) {
	case pai_type_crypto:
		return 0x1000;
	case pai_type_nnpa:
		return 0x1800;
	case pai_type_max:
		break;
	}
	return 0;
}

/* Test PAI counter name from command line option. */
static const char *pai_type_name(enum pai_types t)
{
	switch (t) {
	case pai_type_crypto:
		return "crypto";
	case pai_type_nnpa:
		return "nnpa";
	case pai_type_max:
		break;
	}
	return "unknown";
}

/* Convert PAI counter type to sysfs directory name. Only validated
 * input at this time.
 */
static const char *pai_type_sysfs(enum pai_types t)
{
	if (t == pai_type_crypto)
		return "pai_crypto";
	return "pai_ext";
}

/* Convert PAI counter type to sysfs directory name filter for scandir(). */
static const char *pai_type_filter(enum pai_types t)
{
	if (t == pai_type_nnpa)
		return "^NNPA";
	return "[^.]";		/* Matches anything but . and .. in sysfs */
}

/* Sort PAI counter names by assigned counter number. */
static int pai_ctrcmp(const void *p1, const void *p2)
{
	struct pai_ctrname *l = (struct pai_ctrname *)p1;
	struct pai_ctrname *r = (struct pai_ctrname *)p2;

	return l->nr > r->nr ? 1 : -1;
}

/* Convert string to upper case. */
static char *str2uc(const char *s)
{
	char *uc = util_strdup(s), *old_uc = uc;

	for (; *uc; ++uc)
		*uc = toupper(*uc);
	return old_uc;
}

/* Read counter names and assigned event number from sysfs file tree.
 * Exit when sysfs directory can not be scanned.
 */
static void read_counternames(struct pai_node *node)
{
	int i, more = 0, ctr = 0, count = 0;
	struct dirent **namelist = NULL;
	char *path, *ctrpath;

	/* Read counter names and assigned event number. */
	path = util_path_sysfs(PAI_PATH "/events", node->sysfs_name);
	count = util_scandir(&namelist, alphasort, path, node->filter_name);
	if (count <= 0)
		errx(EXIT_FAILURE, "Cannot open %s", path);

	node->ctrsize = count * sizeof(*node->ctrlist);
	node->ctrlist = util_malloc(node->ctrsize);
	for (i = 0; i < count && ctr >= 0; i++) {
		util_asprintf(&ctrpath, "%s/%s", path, namelist[i]->d_name);
		if (util_file_read_va(ctrpath, "event=%x", &ctr) == 1) {
			node->ctrlist[node->ctridx].name = util_strdup(namelist[i]->d_name);
			node->ctrlist[node->ctridx++].nr = ctr;
			more++;
		} else {
			warnx("Cannot parse %s", ctrpath);
		}
		free(ctrpath);
	}
	util_scandir_free(namelist, count);
	free(path);

	if (numsort && more > 1)
		qsort(node->ctrlist, more, sizeof(*node->ctrlist), pai_ctrcmp);
}

static void format_painode(enum util_fmt_t fmt)
{
	struct pai_node *node;

	util_fmt_init(stdout, fmt, FMT_HANDLEINT, 1);
	util_fmt_obj_start(FMT_DEFAULT, NULL);
	util_list_iterate(&pai_list, node) {
		util_fmt_obj_start(FMT_DEFAULT, "pmu");
		util_fmt_pair(FMT_PERSIST, "base", "%d",  node->base);
		util_fmt_pair(FMT_PERSIST, "type", "%d",  node->pmu);
		util_fmt_pair(FMT_QUOTE | FMT_PERSIST, "pmu-name", "%s", node->sysfs_name);
		util_fmt_obj_start(FMT_LIST, "counters");
		for (int i = 0; i < node->ctridx; ++i) {
			util_fmt_obj_start(FMT_ROW, "counter");
			util_fmt_pair(FMT_QUOTE, "name", "%s", node->ctrlist[i].name);
			util_fmt_pair(FMT_DEFAULT, "config", "%d", node->ctrlist[i].nr);
			util_fmt_pair(FMT_DEFAULT, "number", "%d",
				      node->ctrlist[i].nr - node->base);
			util_fmt_obj_end();
		}
		util_fmt_obj_end();		/* Counters */
		util_fmt_obj_end();		/* PMU */
	}
	util_fmt_obj_end();
	util_fmt_exit();
}

static void list_painode(void)
{
	struct pai_node *node;
	int indent = 0;
	int offset = 0;

	if (output_format != -1) {
		format_painode(output_format);
		return;
	}

	util_list_iterate(&pai_list, node) {
		for (int i = 0; i < node->ctridx; ++i)
			indent = MAX((size_t)indent, strlen(node->ctrlist[i].name));
	}

	printf("RAW %*s NAME %*s DESCRIPTION\n", 3, "", indent - 5, "");
	util_list_iterate(&pai_list, node) {
		for (int i = 0; i < node->ctridx; ++i) {
			printf("%d:%ld %s", node->pmu,
			       node->ctrlist[i].nr, node->ctrlist[i].name);

			offset = indent - strlen(node->ctrlist[i].name) + 1;
			printf("%*s", offset, "");

			printf("Counter %ld / PAI %s counter set\n",
			       node->ctrlist[i].nr - node->base, node->name_uc);
		}
	}
}

/* Release all memory allocated at make_painode(). */
static void free_painode(void)
{
	struct pai_node *next, *node;

	util_list_iterate_safe(&pai_list, node, next) {
		free(node->name_uc);
		for (int i = 0; i < node->ctridx; ++i)
			free(node->ctrlist[i].name);
		free(node->ctrlist);
		free(node);
	}
}

static void make_painode(enum pai_types t)
{
	struct pai_node *node = util_zalloc(sizeof(*node));
	char *path;

	node->type = t;
	node->sysfs_name = pai_type_sysfs(t);
	node->name = pai_type_name(t);
	node->name_uc = str2uc(node->name);
	node->filter_name = pai_type_filter(t);
	node->base = pai_type_base(t);

	/* Read PMU type number. */
	util_asprintf(&path, PAI_PATH, node->sysfs_name);
	node->pmu = libcpumf_pmutype(path);
	if (node->pmu < 0)
		errx(EXIT_FAILURE, "Cannot open %s", path);
	free(path);

	read_counternames(node);

	util_list_add_tail(&pai_list, node);
}

static int painode_cmp(void *a, void *b, void *UNUSED(data))
{
	struct pai_node *n1 = (struct pai_node *)a;
	struct pai_node *n2 = (struct pai_node *)b;

	return n1->pmu < n2->pmu ? -1 : 1;
}

static void sort_painode(void)
{
	util_list_sort(&pai_list, painode_cmp, NULL);
}

/* Check for hardware support and return false if not available. */
static bool have_support(enum pai_types t)
{
	const char *sysfn = pai_type_sysfs(t);
	char *path = util_path_sysfs(PAI_PATH, sysfn);
	bool rc = true;

	if (!util_path_is_dir(path)) {
		warnx("No support for PAI %s facility", pai_type_name(t));
		rc = false;
	}
	free(path);
	return rc;
}

/*
 * Check the argument for option -t. It must be a valid PAI counter set.
 * Exit when an invalid PAI counter set name has been specified.
 */
static void check_type_name(const char *type)
{
	bool no_match = true;
	enum pai_types i;
	const char *fn;

	for (i = pai_type_crypto; i < pai_type_max; ++i) {
		fn = pai_type_name(i);
		if (!strcasecmp(fn, type)) {
			pai_types_show |= (1 << i);
			no_match = false;
		}
	}
	if (no_match)
		errx(EXIT_FAILURE, "Invalid argument for -t %s", type);
}

int main(int argc, char **argv)
{
	enum util_fmt_t fmt;
	int ch;

	util_list_init(&pai_list, struct pai_node, node);
	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while ((ch = util_opt_getopt_long(argc, argv)) != -1) {
		switch (ch) {
		default:
			util_opt_print_parse_error(ch, argv);
			return EXIT_FAILURE;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		case 'n':
			numsort = true;
			break;
		case 't':
			check_type_name(optarg);
			break;
		case OPT_FORMAT:
			if (!util_fmt_name_to_type(optarg, &fmt))
				errx(EXIT_FAILURE, "Supported formats:" FMT_TYPE_NAMES);
			output_format = fmt;
			break;
		}
	}

	/* Nothing specified, show all PAI counters */
	if (!pai_types_show)
		pai_types_show = (1 << pai_type_crypto) | (1 << pai_type_nnpa);

	/* Check for hardware support */
	for (enum pai_types i = pai_type_crypto; i < pai_type_max; ++i) {
		if ((pai_types_show & (1 << i))) {
			if (!have_support(i))
				pai_types_show &= ~(1 << i);
			else
				make_painode(i);
		}
	}
	sort_painode();
	list_painode();
	free_painode();
	return ch;
}
