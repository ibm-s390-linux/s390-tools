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
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <linux/perf_event.h>

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

#define STR_SUB(x) #x
#define STR(x)	   STR_SUB(x)

#define OPT_FORMAT		256	/* --format XXX option */
#define DEFAULT_LOOP_INTERVAL	60	/* loop interval in seconds */

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "all", no_argument, NULL, 'a' },
		.desc = "Displays all CPUs in output"
	},
	{
		.option = { "delta", no_argument, NULL, 'd' },
		.desc = "Display delta counter values"
	},
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT },
		.argument = "FORMAT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List counters in specified FORMAT (" FMT_TYPE_NAMES ")"
	},
	{
		.option = { "loops", required_argument, NULL, 'l' },
		.argument = "COUNT",
		.desc = "Number of read operations"
	},
	{
		.option = { "interval", required_argument, NULL, 'i' },
		.argument = "SECONDS",
		.desc = "Time to wait between loop iterations (default "
			STR(DEFAULT_LOOP_INTERVAL) "s)"
	},
	{
		.option = { "numeric", no_argument, NULL, 'n' },
		.desc = "Sort PAI counters by counter number"
	},
	{
		.option = { "short", no_argument, NULL, 's' },
		.desc = "Abbreviate counter name with counter set letter and number"
	},
	{
		.option = { "type", required_argument, NULL, 't' },
		.argument = "TYPE",
		.desc = "Type of PAI counters to show: crypto, nnpa"
	},
	{
		.option = { "hex0x", no_argument, NULL, 'X' },
		.desc = "Counter values in hexadecimal format with leading 0x"
	},
	{
		.option = { "hex", no_argument, NULL, 'x' },
		.desc = "Counter values in hexadecimal format"
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
			.pub_last = 2025,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static bool allcpu;		/* Show counter values per CPU */
static bool numsort;		/* If true sort counter numerically */
static bool shortname;		/* Use abbreviated counter names */
static bool delta, firstread;	/* Display delta values */
static int output_format = -1;	/* Generate style if >= 0 */
static unsigned int max_cpus;	/* # of CPUs to read counter values from */
static unsigned int max_fds;	/* # of file descriptor to read counter values */
static unsigned long loops;	/* # loops */
static unsigned long read_interval = DEFAULT_LOOP_INTERVAL;
static cpu_set_t cpu_online_mask;
static char *ctrformat = "%ld";	/* Default counter output format */

#define PAI_PATH	"/bus/event_source/devices/%s"

enum pai_types {		/* Bit mask for supported PAI counters */
	pai_type_crypto = 0,	/* PAI Crypto Counters */
	pai_type_nnpa = 1,	/* PAI NNPA Counters */
	pai_type_max = 2,	/* PAI maximum value, must be last */
};

static int pai_types_show;

struct pai_cpudata {		/* Event data per CPU */
	int fd;			/* Event file descriptor */
	int cpu;		/* CPU number */
	unsigned long value;	/* Event value */
	unsigned long prev_value;	/* Previous value for deltas */
};

struct pai_ctrname {		/* List of defined counters */
	char *name;		/* Counter name */
	unsigned long nr;	/* Counter number */
	unsigned long total;	/* Total count on all CPus */
	struct pai_cpudata *data; /* Counter data per CPU */
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

/* Return character for this counter set. */
static char pai_type_char(enum pai_types t)
{
	switch (t) {
	case pai_type_crypto:
		return 'C';
	case pai_type_nnpa:
		return 'N';
	case pai_type_max:
		break;
	}
	return 'U';
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
			node->ctrlist[node->ctridx].data = NULL;
			node->ctrlist[node->ctridx].name = util_strdup(namelist[i]->d_name);
			node->ctrlist[node->ctridx++].nr = ctr;
			more++;
			max_fds++;
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
			if (shortname)
				util_fmt_pair(FMT_QUOTE, "name", "%c%d",
					      pai_type_char(node->type),
					      node->ctrlist[i].nr - node->base);
			util_fmt_pair(FMT_DEFAULT, "config", "%d", node->ctrlist[i].nr);
			util_fmt_pair(FMT_DEFAULT, "id", "%d", node->ctrlist[i].nr - node->base);
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
		for (int i = 0; i < node->ctridx; ++i) {
			free(node->ctrlist[i].name);
			free(node->ctrlist[i].data);
		}
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

/* Read counter value. */
static unsigned long event_read(int fd)
{
	unsigned long count;
	int rc;

	rc = read(fd, &count, sizeof(count));
	if (rc != sizeof(count))
		err(EXIT_FAILURE, "Failed to read counter value");
	return count;
}

/* Write header. */
static void line_header(void)
{
	struct pai_node *node;
	static bool header;
	bool comma = false;

	if (header)
		return;		  /* Printed already */
	printf("Date,Time,CPU,"); /* Print counter name and number */
	util_list_iterate(&pai_list, node) {
		for (int i = 0; i < node->ctridx; ++i) {
			if (comma)
				putchar(',');
			if (shortname) {
				printf("%c%ld", pai_type_char(node->type),
				       node->ctrlist[i].nr - node->base);
			} else {
				printf("%s(%ld)", node->ctrlist[i].name ?: node->name_uc,
				       node->ctrlist[i].nr - node->base);
			}
			comma = true;
		}
	}
	putchar('\n');
	header = true;
}

/* Print CPU specific counter values. */
static void line_cpu(char *header)
{
	struct pai_cpudata *data;
	struct pai_node *node;
	bool comma;
	char txt[16];

	for (unsigned int h = 0; h < max_cpus; ++h) {
		comma = false;
		util_list_iterate(&pai_list, node) {
			for (int i = 0; i < node->ctridx; ++i) {
				data = &node->ctrlist[i].data[h];
				if (!comma) {
					snprintf(txt, sizeof(txt), "CPU%d,", data->cpu);
					printf("%s,%s", header, txt);
				} else {
					putchar(',');
				}
				printf(ctrformat, data->value);
				comma = true;
			}
		}
		putchar('\n');
	}
}

/* Write an output line. */
static void line_out(char *header)
{
	struct pai_node *node;
	bool comma;

	line_header();
	if (allcpu)
		line_cpu(header);

	/* Print total count of all CPUs */
	printf("%s,%s,", header, delta && !firstread ? "Delta" : "Total");
	comma = false;
	util_list_iterate(&pai_list, node) {
		for (int i = 0; i < node->ctridx; ++i) {
			if (comma)
				putchar(',');
			printf(ctrformat, node->ctrlist[i].total);
			comma = true;
		}
	}
	putchar('\n');
}

/* Write a formatted line. */
static void format_line_out(time_t now, char *now_text)
{
	static unsigned int called;
	struct pai_node *node;
	char cpuid[16];

	if (!called) {
		util_fmt_init(stdout, output_format, FMT_DEFAULT | FMT_HANDLEINT, 1);
		util_fmt_obj_start(FMT_DEFAULT, NULL);
		util_fmt_obj_start(FMT_LIST, "measurements");
	}
	util_list_iterate(&pai_list, node) {
		util_fmt_obj_start(FMT_DEFAULT, "entry");
		util_fmt_pair(FMT_PERSIST, "iteration", "%d", called++);
		util_fmt_pair(FMT_PERSIST, "time_epoch", "%d", now);
		util_fmt_pair(FMT_QUOTE | FMT_PERSIST, "time", "%s", now_text);
		util_fmt_pair(FMT_QUOTE | FMT_PERSIST, "valuetype",
			      (delta && !firstread) ? "delta" : "total");
		util_fmt_obj_start(FMT_LIST, "counters");
		for (int i = 0; i < node->ctridx; ++i) {
			util_fmt_obj_start(FMT_ROW, "counter");
			util_fmt_pair(FMT_QUOTE, "name", "%s", node->ctrlist[i].name);
			if (shortname)
				util_fmt_pair(FMT_QUOTE, "shortname", "%c%d",
					      pai_type_char(node->type),
					      node->ctrlist[i].nr - node->base);
			util_fmt_pair(FMT_DEFAULT, "config", "%d", node->ctrlist[i].nr);
			util_fmt_pair(FMT_DEFAULT, "id", "%d", node->ctrlist[i].nr - node->base);
			util_fmt_pair(FMT_DEFAULT, "value", ctrformat, node->ctrlist[i].total);
			if (allcpu) {
				for (unsigned int j = 0; j < max_cpus; ++j) {
					snprintf(cpuid, sizeof(cpuid), "cpu%d", j);
					util_fmt_pair(FMT_DEFAULT, cpuid, ctrformat,
						      node->ctrlist[i].data[j].value);
				}
			}
			util_fmt_obj_end();
		}
		util_fmt_obj_end(); /* Counters */
		util_fmt_obj_end(); /* Entry */
	}
}

/* Terminate formatted output. */
static void format_line_end(void)
{
	util_fmt_obj_end(); /* Iteration */
	util_fmt_obj_end(); /* Default */
	util_fmt_exit();
}

/* Display counter values. */
static void show_values(void)
{
	time_t now = time(NULL);
	struct tm *now_tm;
	char now_text[32];

	now_tm = localtime(&now);
	if (output_format != -1) {
		strftime(now_text, sizeof(now_text), "%F %T%z", now_tm);
		format_line_out(now, now_text);
	} else {
		strftime(now_text, sizeof(now_text), "%F,%T", now_tm);
		line_out(now_text);
	}
}

/* Read each counter value. */
static void read_painode(void)
{
	struct pai_cpudata *data;
	struct pai_node *node;
	unsigned long value;

	util_list_iterate(&pai_list, node) {
		for (int i = 0; i < node->ctridx; ++i) {
			node->ctrlist[i].total = 0;
			for (size_t j = 0; j < max_cpus; ++j) {
				data = &node->ctrlist[i].data[j];
				value = event_read(data->fd);
				if (delta) {
					data->value = value - data->prev_value;
					data->prev_value = value;
				} else {
					data->value = value;
				}
				node->ctrlist[i].total += data->value;
			}
		}
	}
}

static void wait_painode(void)
{
	for (unsigned long i = 0; i < loops; ++i) {
		read_painode();
		show_values();
		if (i + 1 < loops)
			sleep(read_interval);
		firstread = false;
	}
	format_line_end();
}

/* Install one event. */
static int event_add(int cpu, int idx, struct pai_node *node)
{
	struct perf_event_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.config = node->ctrlist[idx].nr;
	attr.type = node->pmu;
	fd = perf_event_open(&attr, -1, cpu, -1, 0);
	if (fd == -1)
		err(EXIT_FAILURE, "Failed to open perf event: file descriptor not available");
	return fd;
}

/* Increase number of file descriptors this process can open. */
static void event_fdlimit(void)
{
	unsigned int needed = 3 + max_fds * max_cpus;
	struct rlimit rlimit;

	if (getrlimit(RLIMIT_NOFILE, &rlimit) == -1)
		err(EXIT_FAILURE, "Failed to read RLIMIT_NOFILE");
	if (needed > rlimit.rlim_cur)
		rlimit.rlim_cur = needed;
	if (setrlimit(RLIMIT_NOFILE, &rlimit) == -1)
		err(EXIT_FAILURE, "Failed to set RLIMIT_NOFILE");
}

/* Install all events and iterate over requested read operations. */
static void event_painode(void)
{
	size_t pai_cpudata_sz = sizeof(struct pai_cpudata) * max_cpus;
	struct pai_cpudata *data;
	struct pai_node *node;

	event_fdlimit();
	util_list_iterate(&pai_list, node) {
		for (int i = 0; i < node->ctridx; ++i) {
			node->ctrlist[i].data = util_malloc(pai_cpudata_sz);
			data = node->ctrlist[i].data;
			for (unsigned int j = 0; j < CPU_SETSIZE; ++j) {
				if (CPU_ISSET(j, &cpu_online_mask)) {
					data->cpu = j;
					data->fd = event_add(j, i, node);
					data->value = 0;
					data->prev_value = 0;
					++data;
				}
			}
		}
	}
	wait_painode();
	util_list_iterate(&pai_list, node) {
		for (int i = 0; i < node->ctridx; ++i) {
			for (unsigned int j = 0; j < max_cpus; ++j)
				close(node->ctrlist[i].data[j].fd);
		}
	}
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

/*
 * Get list of specified CPUs from command line. Check if these CPUs
 * exist and are online. Ignore those CPUs which are not available and
 * issue one warning when CPUs have been specified but are not online.
 */
static void get_cpulist(char *parm)
{
	bool warned = false;
	cpu_set_t cpulist;
	int i, rc;

	CPU_ZERO(&cpulist);
	rc = libcpumf_cpuset(parm, &cpulist);
	if (rc)
		err(EXIT_FAILURE, "Cannot parse cpulist %s", parm);
	for (i = 0; i < CPU_SETSIZE; ++i) {
		if (CPU_ISSET(i, &cpulist) && !CPU_ISSET(i, &cpu_online_mask)) {
			if (!warned) {
				warnx("some CPU(s) are offline, ignored");
				warned = true;
			}
		}
		if (!CPU_ISSET(i, &cpulist) && CPU_ISSET(i, &cpu_online_mask))
			CPU_CLR(i, &cpu_online_mask);
	}
}

int main(int argc, char **argv)
{
	bool list_only = true;
	enum util_fmt_t fmt;
	bool i_flag = false;
	bool l_flag = false;
	char *endchar;
	int ch;

	util_list_init(&pai_list, struct pai_node, node);
	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while ((ch = util_opt_getopt_long(argc, argv)) != -1) {
		switch (ch) {
		default:
			util_opt_print_parse_error(ch, argv);
			return EXIT_FAILURE;
		case 'a':
			allcpu = true;
			list_only = false;
			break;
		case 'd':
			delta = true;
			firstread = true;
			list_only = false;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		case 'i':
			i_flag = true;
			list_only = false;
			errno = 0;
			read_interval = strtoul(optarg, &endchar, 0);
			if (errno || *endchar)
				errx(EXIT_FAILURE, "Invalid argument for -%c", ch);
			break;
		case 'l':
			l_flag = true;
			list_only = false;
			errno = 0;
			loops = strtoul(optarg, &endchar, 0);
			if (errno || *endchar)
				errx(EXIT_FAILURE, "Invalid argument for -%c", ch);
			break;
		case 'n':
			numsort = true;
			break;
		case 's':
			list_only = false;
			shortname = true;
			break;
		case 't':
			check_type_name(optarg);
			break;
		case 'x':
			list_only = false;
			ctrformat = "%lx";
			break;
		case 'X':
			list_only = false;
			ctrformat = "%#lx";
			break;
		case OPT_FORMAT:
			if (!util_fmt_name_to_type(optarg, &fmt))
				errx(EXIT_FAILURE, "Supported formats:" FMT_TYPE_NAMES);
			output_format = fmt;
			break;
		}
	}

	if (i_flag && !l_flag) {
		util_prg_print_help();
		util_opt_print_help();
		return EXIT_FAILURE;
	}

	/*
	 * Read currently online CPUs and create a bit mask.
	 * This bitmap of online CPUs is used to check command line parameter
	 * for valid CPUs
	 * When any of the flags which set variable list_only to false have
	 * be specified, lets also show the counter value, not just list them.
	 */
	if (optind < argc) /* List of CPUs on command line */
		list_only = false;
	if (!list_only) { /* Show counter values */
		ch = libcpumf_cpuset_fn(S390_CPUS_ONLINE, &cpu_online_mask);
		if (ch)
			err(EXIT_FAILURE, "Cannot read file /sys/" S390_CPUS_ONLINE);
		while (optind < argc)
			get_cpulist(argv[optind++]);
		max_cpus = CPU_COUNT(&cpu_online_mask);
		if (!loops)
			loops = 1;
	}

	/* Nothing specified, use all PAI counters */
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
	ch = EXIT_SUCCESS;
	if (!list_only)
		event_painode();
	else
		list_painode();
	free_painode();
	return ch;
}
