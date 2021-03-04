/* Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/* CPU Measurements counter facility counter sets can be extracted by a
 * device driver accessible by opening device /dev/hwctr.
 * This program extracts complete counter set using this device.
 * Counter sets are per CPU, the interface allows to specify counter sets
 * for individual CPUs.  The supported flags are executed from left to
 * right, the first error encountered stops the execution of the program.
 */

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/util_base.h"
#include "lib/util_path.h"
#include "lib/util_scandir.h"
#include "lib/util_libc.h"

#include "lshwc.h"

#define SERVICELEVEL	"/proc/service_levels"
#define CPUS_ONLINE	"/sys/devices/system/cpu/online"
#define CPUS_POSSIBLE	"/sys/devices/system/cpu/possible"
#define CPUS_KERNELMAX	"/sys/devices/system/cpu/kernel_max"
#define MAXCTRS		512

static const unsigned int ioctlsleep = 60;
static unsigned int read_interval = ioctlsleep, cfvn, csvn, authorization;
static unsigned long loop_count = 1;
static unsigned char *ioctlbuffer;
static bool allcpu;

static unsigned int max_possible_cpus;	/* No of possible CPUs */
struct ctrname {		/* List of defined counters */
	char *name;		/* Counter name */
	bool hitcnt;		/* Counter number read from ioctl() */
	unsigned long total;	/* Total counter value */
	unsigned long *ccv;	/* Per CPU counter value */
} ctrname[MAXCTRS];

/* Open file and extract counter number */
static int read_counter(const char *p)
{
	FILE *fp = fopen(p, "r");
	int rc = 0, ctr;

	if (fp) {
		rc = fscanf(fp, "event=%x", &ctr);
		fclose(fp);
	}
	return rc == 1 ? ctr : -EINVAL;
}

static int add_countername(char *name, int nr)
{
	ctrname[nr].name = strdup(name);
	return ctrname[nr].name ? 0 : -ENOMEM;
}

static bool read_counternames(void)
{
	struct dirent **namelist = NULL;
	int i, ctr = 0, count = 0;
	char *path, *ctrpath;

	path = util_path_sysfs("/bus/event_source/devices/cpum_cf/events/");
	count = util_scandir(&namelist, alphasort, path, "[^.]");
	if (count <= 0) {
		warnx("Cannot open %s", path);
		free(path);
		return false;
	}
	for (i = 0; i < count && ctr >= 0; i++) {
		util_asprintf(&ctrpath, "%s/%s", path, namelist[i]->d_name);
		ctr = read_counter(ctrpath);
		free(ctrpath);
		if (ctr >= 0)
			ctr = add_countername(namelist[i]->d_name, ctr);
	}
	if (ctr < 0)
		warnx("Cannot parse %s", path);
	util_scandir_free(namelist, count);
	free(path);
	return ctr < 0 ? false : true;
}

static void free_counternames(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(ctrname); ++i) {
		free(ctrname[i].name);
		free(ctrname[i].ccv);
	}
}

static struct check_result {
	bool cpu_pos;			/* CPU Number possible */
	bool cpu_req;			/* CPU Number requested */
	bool cpu_hit;			/* CPU Number received */
	unsigned char sets_req;		/* Counters sets requested */
	unsigned char sets_hit;		/* Counters sets received */
} *check;

static bool check_set(unsigned long a, unsigned long b, unsigned long sets)
{
	if (a > b)
		return false;
	for (; a <= b; ++a) {
		if (a >= max_possible_cpus || !check[a].cpu_pos)
			return false;
		check[a].cpu_req = true;
		check[a].sets_req = sets;
	}
	return true;
}

/*
 * Functions to parse command line parameters
 * Convert a number from ascii to int.
 */
static unsigned long getnumber(char *word, char stopchar)
{
	unsigned long no;
	char *endp;

	no = strtoul(word, &endp, 0);
	if (*endp != stopchar)
		errx(EXIT_FAILURE, "Invalid parameter %s", word);
	return no;
}

/* Remove all whitespace from string.  */
static void kill_whitespace(char *s)
{
	char *cp = s;

	for (; *s != '\0'; ++s) {
		if (isspace(*s))
			continue;
		if (isprint(*s))
			*cp++ = *s;
	}
	*cp = '\0';
}

/* Read file to get all online CPUs */
static bool get_cpus(char *file, char *buf, size_t bufsz)
{
	char fmt[16];
	FILE *slp;
	int rc;

	slp = fopen(file, "r");
	if (!slp) {
		warnx("Cannot open %s", file);
		return false;
	}
	snprintf(fmt, sizeof(fmt), "%%%zus", bufsz - 1);
	rc = fscanf(slp, fmt, buf);
	fclose(slp);
	if (rc != 1)
		warnx("Cannot parse %s", file);
	return rc == 1 ? true : false;
}

/* Parse counter set specification */
static unsigned long parse_ctrset(char *cp)
{
	unsigned long x = 0;

	for (; *cp; ++cp) {
		switch (tolower(*cp)) {
		case 'b':
			x |= S390_HWCTR_BASIC;
			break;
		case 'c':
			x |= S390_HWCTR_CRYPTO;
			break;
		case 'e':
			x |= S390_HWCTR_EXT;
			break;
		case 'm':
			x |= S390_HWCTR_MT_DIAG;
			break;
		case 'p':
		case 'u':
			x |= S390_HWCTR_USER;
			break;
		case 'a':
			x |= S390_HWCTR_ALL;
			break;
		default:
			errx(EXIT_FAILURE,
			     "Invalid counter set specification '%c'", *cp);
		}
	}
	return x;
}

static char *show_ctrset(unsigned long set)
{
	static char text[16];
	int i = 0;

	if (set & S390_HWCTR_BASIC)
		text[i++] = 'B';
	if (set & S390_HWCTR_CRYPTO)
		text[i++] = 'C';
	if (set & S390_HWCTR_EXT)
		text[i++] = 'E';
	if (set & S390_HWCTR_MT_DIAG)
		text[i++] = 'M';
	if (set & S390_HWCTR_USER)
		text[i++] = 'U';
	text[i] = '\0';
	return text;
}

/* Parse CPU list and counter sets */
static void parse_cpulist(char *parm, struct s390_hwctr_start *start)
{
	__u64 *words = start->cpumask;
	unsigned long i, no_a, no_b;
	char *cp, *tokens[16];		/* Used to parse command line params */
	char cpubuf[256];

	start->data_bytes = 0;
	if (parm)
		kill_whitespace(parm);
	if (!parm || *parm == ':') {
		/* No CPU list or just counter sets */
		if (!get_cpus(CPUS_ONLINE, cpubuf, sizeof(cpubuf)))
			exit(EXIT_FAILURE);
		if (parm)
			strcat(cpubuf, parm);
		parm = cpubuf;
	}

	cp = strchr(parm, ':');
	if (cp) {		/* Handle counter set */
		*cp = '\0';
		start->counter_sets = parse_ctrset(++cp);
	} else {
		start->counter_sets = S390_HWCTR_ALL;
	}
	/* Check with authorized counter sets */
	if ((start->counter_sets & authorization) != start->counter_sets) {
		unsigned int noton = ~(start->counter_sets & authorization);

		start->counter_sets &= authorization;
		if (!start->counter_sets)
			errx(EXIT_FAILURE, "No counter sets are authorized");
		warnx("One or more counter sets are not authorized: %s",
		      show_ctrset(noton));
	}

	for (i = 0; i < ARRAY_SIZE(tokens) && (tokens[i] = strtok(parm, ",")) != 0;
	    ++i, parm = 0) {
		cp = strchr(tokens[i], '-');	/* Range character? */
		if (cp) {
			no_a = getnumber(tokens[i], *cp);
			no_b = getnumber(++cp, '\0');
		} else {
			no_b = getnumber(tokens[i], '\0');
			no_a = no_b;
		}
		if (!check_set(no_a, no_b, start->counter_sets))
			errx(EXIT_FAILURE, "Invalid CPU list %s", tokens[i]);
	}

	/* Convert the CPU list to a bitmask for kernel cpumask_t */
	for (i = 0, no_b = 0; i < max_possible_cpus; ++i) {
		if (check[i].cpu_req) {
			no_a = i % __BITS_PER_LONG;
			no_b = i / __BITS_PER_LONG;
			words[no_b] |= 1ULL << no_a;
		}
	}
	/* no_b is highest used index, swap array */
	start->cpumask_len = (no_b + 1) * 8;
	for (no_a = 0; no_a < no_b; ++no_a, --no_b) {
		__u64 tmp =  words[no_a];

		words[no_a] = words[no_b];
		words[no_b] = tmp;
	}
	start->version = S390_HWCTR_START_VERSION;
}

static bool check_setpossible(void)
{
	char *cp, *parm, *tokens[16];	/* Used to parse command line params */
	unsigned long i, no_a, no_b;
	char cpubuf[1024];

	if (!get_cpus(CPUS_KERNELMAX, cpubuf, sizeof(cpubuf)))
		return false;
	max_possible_cpus = getnumber(cpubuf, '\0') + 1;
	check = calloc(max_possible_cpus, sizeof(*check));
	if (!check)
		err(EXIT_FAILURE, "Maximum CPUs %u", max_possible_cpus);
	if (!get_cpus(CPUS_POSSIBLE, cpubuf, sizeof(cpubuf))) {
		free(check);
		return false;
	}
	parm = cpubuf;
	for (i = 0; i < ARRAY_SIZE(tokens) && (tokens[i] = strtok(parm, ","));
							++i, parm = 0) {
		cp = strchr(tokens[i], '-');
		if (cp) {		/* Range */
			no_a = getnumber(tokens[i], *cp);
			no_b = getnumber(++cp, '\0');
		} else {
			no_b = getnumber(tokens[i], '\0');
			no_a = no_b;
		}
		for (; no_a <= no_b; ++no_a)
			check[no_a].cpu_pos = true;
	}
	return true;
}

static void show_header(void)
{
	static bool header;
	bool comma = false;

	if (header)
		return;			/* Printed already */
	printf("Date,Time,CPU,");	/* Print counter name and number */
	for (size_t i = 0; i < ARRAY_SIZE(ctrname); ++i) {
		if (!ctrname[i].hitcnt)
			continue;
		if (comma)
			putchar(',');
		printf("%s(%ld)", ctrname[i].name ?: "Counter", i);
		comma = true;
	}
	putchar('\n');
	header = true;
}

static void line(char *header)
{
	bool comma;

	show_header();
	if (allcpu) {
		for (unsigned int h = 0; h < max_possible_cpus; ++h) {
			char txt[16];

			if (!check[h].cpu_hit)
				continue;
			comma = false;
			snprintf(txt, sizeof(txt), "CPU%d,", h);
			printf("%s%s", header, txt);
			for (size_t i = 0; i < ARRAY_SIZE(ctrname); ++i) {
				if (!ctrname[i].hitcnt)
					continue;
				if (comma)
					putchar(',');
				printf("%ld", ctrname[i].ccv[h]);
				comma = true;
			}
			putchar('\n');
		}
	}

	/* Print total count of all CPUs */
	printf("%sTotal,", header);
	comma = false;
	for (size_t i = 0; i < ARRAY_SIZE(ctrname); ++i) {
		if (!ctrname[i].hitcnt)
			continue;
		if (comma)
			putchar(',');
		printf("%ld", ctrname[i].total);
		comma = true;
	}
	putchar('\n');
}

static void show(void)
{
	time_t now = time(NULL);
	struct tm *now_tm;
	char now_text[32];

	now_tm = localtime(&now);
	strftime(now_text, sizeof(now_text), "%F,%T,", now_tm);
	line(now_text);
}

/* Return Counter set size numbers (in counters) */
static unsigned int ctrset_size(int set)
{
	switch (set) {
	case S390_HWCTR_BASIC:
		return 6;
	case S390_HWCTR_USER:
		return (cfvn == 1) ? 6 : 2;
	case S390_HWCTR_CRYPTO:
		return (csvn <= 5) ? 16 : 20;
	case S390_HWCTR_EXT:
		switch (csvn) {
		case 1:	return 32;
		case 2:	return 48;
		case 3:
		case 4:
		case 5: return 128;
		}
		return 160;
	case S390_HWCTR_MT_DIAG:
		switch (csvn) {
		case 1:
		case 2:
		case 3:	return 0;
		}
		return 48;
	}
	return 0;
}

/* Return counter set offset numbers */
static int ctrset_offset(int set)
{
	switch (set) {
	case S390_HWCTR_BASIC:
		return 0;
	case S390_HWCTR_USER:
		return 32;
	case S390_HWCTR_CRYPTO:
		return 64;
	case S390_HWCTR_EXT:
		return 128;
	case S390_HWCTR_MT_DIAG:
		return 448;
	}
	return 0;
}

static bool set_and_size_ok(struct s390_hwctr_setdata *p)
{
	switch (p->set) {
	case S390_HWCTR_BASIC:
	case S390_HWCTR_USER:
	case S390_HWCTR_CRYPTO:
	case S390_HWCTR_EXT:
	case S390_HWCTR_MT_DIAG:
		return p->no_cnts == ctrset_size(p->set);
	}
	return false;
}

static bool add_countervalue(size_t idx, unsigned int cpu, unsigned long value)
{
	if (idx >= ARRAY_SIZE(ctrname)) {
		warnx("Invalid counter number %zu", idx);
		return false;
	}
	if (cpu >= max_possible_cpus) {
		warnx("Invalid CPU number %d", cpu);
		return false;
	}
	if (!ctrname[idx].ccv)		/* Unknown counter */
		ctrname[idx].ccv = calloc(max_possible_cpus,
					  sizeof(unsigned long));
	if (ctrname[idx].ccv)
		ctrname[idx].ccv[cpu] += value;
	ctrname[idx].total += value;
	ctrname[idx].hitcnt = true;
	return true;
}

static int test_read(struct s390_hwctr_read *read)
{
	void *base = &read->data;
	size_t offset = 0;

	/* Clear previous hit counters */
	for (unsigned int i = 0; i < max_possible_cpus; ++i) {
		check[i].sets_hit = 0;
		check[i].cpu_hit = false;
	}

	/* Iterate over all CPUs */
	for (unsigned int i = 0; i < read->no_cpus; ++i) {
		struct s390_hwctr_cpudata *cp = base + offset;

		check[cp->cpu_nr].cpu_hit = true;
		check[cp->cpu_nr].sets_hit = 0;

		offset += sizeof(cp->cpu_nr) + sizeof(cp->no_sets);
		/* Iterate over all counter sets */
		for (unsigned int j = 0; j < cp->no_sets; ++j) {
			struct s390_hwctr_setdata *sp = base + offset;

			check[cp->cpu_nr].sets_hit |= sp->set;
			offset += sizeof(sp->set) + sizeof(sp->no_cnts);
			if (!set_and_size_ok(sp)) {
				warnx("CPU %d inconsistent set %d size %d",
				      cp->cpu_nr, sp->set, sp->no_cnts);
				return -1;
			}
			/* Iterate over all counters in each set */
			for (unsigned int k = 0; k < sp->no_cnts; ++k) {
				__u64 value;
				void *addr = base + offset;
				size_t idx = ctrset_offset(sp->set) + k;

				memcpy(&value, addr, sizeof(value));
				offset += sizeof(value);
				if (!add_countervalue(idx, cp->cpu_nr, value))
					return -1;
			}
		}
	}
	show();
	return 0;
}

static int do_open(void)
{
	int fd = open(S390_HWCTR_DEVICE, O_RDWR);

	if (fd < 0)
		warn(S390_HWCTR_DEVICE);
	return fd;
}

static int do_stop(int ioctlfd)
{
	int rc = ioctl(ioctlfd, S390_HWCTR_STOP, 0);

	if (rc < 0)
		warn("ioctl S390_HWCTR_STOP");
	return rc;
}

static int do_start(int ioctlfd, struct s390_hwctr_start *start)
{
	int rc = ioctl(ioctlfd, S390_HWCTR_START, start);

	if (rc < 0)
		warn("ioctl S390_HWCTR_START");
	return rc;
}

static int do_read(int ioctlfd)
{
	size_t ioctlbuffer_len = PAGE_SIZE * max_possible_cpus +
				 sizeof(struct s390_hwctr_read);
	struct s390_hwctr_read *read;
	int rc;

	if (!ioctlbuffer) {
		ioctlbuffer = malloc(ioctlbuffer_len);
		if (!ioctlbuffer) {
			warn("ioctl S390_HWCTR_START");
			return -ENOMEM;
		}
	}
	read = (struct s390_hwctr_read *)ioctlbuffer;
	rc = ioctl(ioctlfd, S390_HWCTR_READ, read);
	if (!rc)
		rc = test_read(read);
	else
		warn("ioctl S390_HWCTR_READ");
	return rc;
}

static void do_sleep(void)
{
	struct timespec req = {
		.tv_sec = read_interval,
		.tv_nsec = 0
	};

	nanosleep(&req, NULL);
}

/* Execute commands and report first error */
static int do_it(char *s)
{
	struct s390_hwctr_start start;
	int ioctlfd;
	int rc;

	memset(&start, 0, sizeof(start));
	rc = max_possible_cpus / sizeof(__u64);
	start.cpumask = alloca(max_possible_cpus / sizeof(__u64));
	memset(start.cpumask, 0, rc);
	parse_cpulist(s, &start);
	errno = 0;
	ioctlfd = do_open();
	if (ioctlfd  < 0)
		return EXIT_FAILURE;

	rc = do_start(ioctlfd, &start);
	if (rc < 0) {
		close(ioctlfd);
		return EXIT_FAILURE;
	}

	for (unsigned long i = 0; !rc && i < loop_count; ++i) {
		rc = do_read(ioctlfd);
		if (rc) {
			close(ioctlfd);
			return EXIT_FAILURE;
		}
		if (read_interval && i + 1 < loop_count)
			do_sleep();
	}
	rc = do_stop(ioctlfd);
	close(ioctlfd);
	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* Read counter first and second version number */
static bool get_cvn(void)
{
	char *linep = NULL;
	bool good = false;
	size_t line_sz;
	ssize_t nbytes;
	FILE *slp;

	slp = fopen(SERVICELEVEL, "r");
	if (!slp) {
		warn(SERVICELEVEL);
		return false;
	}
	while ((nbytes = getline(&linep, &line_sz, slp)) != EOF) {
		if (!strncmp(linep, "CPU-MF: Counter facility:", 25)) {
			int rc;

			rc = sscanf(linep, "CPU-MF: Counter facility: version=%d.%d authorization=%x",
				    &cfvn, &csvn, &authorization);
			good = rc == 3;
			if (!good)
				warnx("Cannot parse line %s", linep);
			break;
		}
	}
	fclose(slp);
	free(linep);
	return good;
}

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "all", no_argument, NULL, 'a' },
		.desc = "Displays all CPUs in output"
	},
	{
		.option = { "loop", required_argument, NULL, 'l' },
		.argument = "NUMBER",
		.desc = "Specifies loop count for next read"
	},
	{
		.option = { "interval", required_argument, NULL, 'i' },
		.argument = "NUMBER",
		.desc = "Specifies interval between read operations (seconds)"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static const struct util_prg prg = {
	.desc = "Read CPU Measurement facility counter sets",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2021,
			.pub_last = 2021,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/* Check for hardware support and exit if not available */
static void have_support(void)
{
	struct stat statbuf;

	if (stat(S390_HWCTR_DEVICE, &statbuf) == -1)
		errx(EXIT_FAILURE,
		     "No support for CPU Measurement Counter set facility");
}

int main(int argc, char **argv)
{
	char *slash;
	int ch;

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
		case 'l':
			errno = 0;
			loop_count = strtoul(optarg, &slash, 0);
			if (errno || *slash)
				errx(EXIT_FAILURE, "Invalid argument for -%c",
				     ch);
			break;
		case 'i':
			errno = 0;
			read_interval = (unsigned int)strtoul(optarg, &slash, 0);
			if (errno || *slash)
				errx(EXIT_FAILURE, "Invalid argument for -%c", ch);
			break;
		case 'a':
			allcpu = true;
			break;
		}
	}

	have_support();
	if (!get_cvn())
		return EXIT_FAILURE;
	if (!check_setpossible())
		return EXIT_FAILURE;
	if (!read_counternames()) {
		free(check);
		return EXIT_FAILURE;
	}

	if (optind >= argc) {
		ch = do_it(NULL);
	} else {
		while (optind < argc) {
			ch = do_it(argv[optind++]);
			if (ch)
				break;
		}
	}
	free_counternames();
	free(check);
	return ch;
}
