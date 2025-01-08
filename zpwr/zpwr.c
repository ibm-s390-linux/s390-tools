/*
 * zpwr - Display power readings of s390 computing environment.
 *
 * Display power readings for resources in s390 computing environment from
 * power information block (pib).
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include "lib/util_base.h"
#include "lib/util_fmt.h"
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "zpwr.h"

#define DIAG		"/dev/diag"
#define NANO		1000000000ULL
#define NUMUNIT		5
#define NAMELEN		8
#define COMPWIDTH	27
#define OPT_FORMAT	256

enum part_power {
	CPU,
	STORAGE,
	IO,
	MAX_PM_PARTITION,
};

enum cpc_power {
	TOTAL,
	UNASSIGNED,
	INFRA,
	MAX_PM_CPC,
};

struct zpwrinfo {
	u64 part[MAX_PM_PARTITION];
	u64 cpc[MAX_PM_CPC];
	bool pvalid;
	bool cvalid;
};

static const char *simplefmt_part[MAX_PM_PARTITION] = {
	"LPAR CPU:",
	"LPAR Storage:",
	"LPAR I/O:",
};

static const char *simplefmt_cpc[MAX_PM_CPC] = {
	"CPC Total:",
	"CPC Unassigned Resources:",
	"CPC Infrastructure:",
};

static const char *complexfmt_part[MAX_PM_PARTITION] = {
	"cpu",
	"storage",
	"io",
};

static const char *complexfmt_cpc[MAX_PM_CPC] = {
	"total",
	"unassigned_resources",
	"infrastructure",
};

static const struct util_prg prg = {
	.desc = "Power readings of s390 computing environment",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2025,
			.pub_last = 2025,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT },
		.argument = "FORMAT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List data in specified FORMAT (" FMT_TYPE_NAMES ")",
	},
	{
		.option = { "delay", required_argument, NULL, 'd' },
		.argument = "NUMBER",
		.desc = "Power readings after delay (seconds)",
	},
	{
		.option = { "count", required_argument, NULL, 'c' },
		.argument = "NUMBER",
		.desc = "Number of power readings",
	},
	{
		.option = { "stream", no_argument, NULL, 's' },
		.desc = "Power readings in stream mode",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static int get_max_column_width(struct zpwrinfo *pinfo)
{
	u64 max = 0;
	int i, col;

	for (i = 0; i < MAX_PM_PARTITION; i++) {
		if (pinfo->part[i] > max)
			max = pinfo->part[i];
	}
	for (i = 0; i < MAX_PM_CPC; i++) {
		if (pinfo->cpc[i] > max)
			max = pinfo->cpc[i];
	}
	col = (int)log10((double)max) + 1;
	/* power unit and space consideration */
	col += 3;
	return col;
}

static char *get_human_readable_unit(u64 val)
{
	const char *unitstr[NUMUNIT] = { "uW", "mW", " W", "kW", "MW" };
	int exponent[NUMUNIT] = { 1, 3, 6, 9, 12 }, unitindex = 0, i;
	double res, smallestres = (double)val;
	char *buf;

	for (i = 1; i < NUMUNIT; i++) {
		res = (double)val / pow(10, exponent[i]);
		if ((u64)res && res < smallestres) {
			smallestres = res;
			unitindex = i;
		}
	}
	util_asprintf(&buf, "%.2f %s", smallestres, unitstr[unitindex]);
	return buf;
}

static double get_human_readable_interval(u64 val, bool *seconds)
{
	double res;

	res = (double)val / pow(10, 9);
	if ((u64)res)
		*seconds = true;
	else
		*seconds = false;
	return *seconds ? res : (double)val;
}

/* From linux arch/s390/include/asm/timex.h */
static unsigned long tod_to_ns(unsigned long todval)
{
	return ((todval >> 9) * 125) + (((todval & 0x1ff) * 125) >> 9);
}

static void reset_zpwrinfo(struct zpwrinfo *pinfo, struct pib *pib,
			   unsigned long buffersize)
{
	memset(pinfo, 0, sizeof(*pinfo));
	memset(pib, 0, buffersize);
}

static void print_zpwrinfo(struct zpwrinfo *pinfo, u64 iteration,
			   int fmt_specified, u64 interval)
{
	enum util_fmt_mflags_t fmt_mflags = FMT_DEFAULT;
	bool secondflag = false;
	struct timespec ts;
	char timestr[30];
	char *simplestr;
	int i, colwidth;
	struct tm *tm;

	if (!fmt_specified) {
		colwidth = get_max_column_width(pinfo);
		for (i = 0; i < MAX_PM_PARTITION; i++) {
			if (!pinfo->pvalid)
				break;
			printf("%-*s", COMPWIDTH, simplefmt_part[i]);
			simplestr = get_human_readable_unit(pinfo->part[i]);
			printf("%*s\n", colwidth, simplestr);
			free(simplestr);
		}
		printf("\n");
		for (i = 0; i < MAX_PM_CPC; i++) {
			if (!pinfo->cvalid)
				break;
			printf("%-*s", COMPWIDTH, simplefmt_cpc[i]);
			simplestr = get_human_readable_unit(pinfo->cpc[i]);
			printf("%*s\n", colwidth, simplestr);
			free(simplestr);
		}
		printf("\n");
		printf("Update interval: %.2f %s\n",
		       get_human_readable_interval(interval, &secondflag),
		       secondflag ? "s" : "ns");
		return;
	}
	clock_gettime(CLOCK_REALTIME, &ts);
	tm = localtime(&ts.tv_sec);
	strftime(timestr, sizeof(timestr), "%F %T%z", tm);
	util_fmt_obj_start(FMT_ROW, "iteration");
	util_fmt_pair(fmt_mflags, "iteration", "%llu", iteration);
	util_fmt_pair(fmt_mflags, "time", "%s", timestr);
	util_fmt_pair(fmt_mflags, "time_epoch_sec", "%lld", ts.tv_sec);
	util_fmt_pair(fmt_mflags, "time_epoch_nsec", "%ld", ts.tv_nsec);
	util_fmt_pair(fmt_mflags, "update_interval", "%llu", interval);
	util_fmt_obj_start(FMT_LIST, "lpar");
	for (i = 0; i < MAX_PM_PARTITION; i++)
		util_fmt_pair(pinfo->pvalid ? fmt_mflags : fmt_mflags | FMT_INVAL,
			      complexfmt_part[i], "%llu", pinfo->part[i]);
	util_fmt_obj_end(); /* End of lpar list */
	util_fmt_obj_start(FMT_LIST, "cpc");
	for (i = 0; i < MAX_PM_CPC; i++)
		util_fmt_pair(pinfo->cvalid ? fmt_mflags : fmt_mflags | FMT_INVAL,
			      complexfmt_cpc[i], "%llu", pinfo->cpc[i]);
	util_fmt_obj_end(); /* End of cpc list */
	util_fmt_obj_end(); /* End of iteration row */
}

static int read_zpwrinfo(struct zpwrinfo *pinfo, struct pib *pib)
{
	struct pib_prologue *prologue;
	int i, comp, max = 0, rc = 0;
	u64 *curr_zpwrinfo;
	u8 *metrics;
	void *ptr;

	ptr = (u8 *)pib + pib->hlen;
	prologue = ptr;
	for (i = 0; i < pib->num; i++) {
		metrics = (u8 *)prologue + sizeof(*prologue);
		if (prologue->format == 0) {
			curr_zpwrinfo = pinfo->part;
			max = MAX_PM_PARTITION;
			pinfo->pvalid = true;
		} else if (prologue->format == 1) {
			curr_zpwrinfo = pinfo->cpc;
			max = MAX_PM_CPC;
			pinfo->cvalid = true;
		} else {
			rc = -EINVAL;
			warnx("Unknown format detected:%d\n", prologue->format);
			break;
		}
		metrics += NAMELEN;
		for (comp = 0; comp < max; comp++) {
			memcpy(&curr_zpwrinfo[comp], metrics, sizeof(u64));
			metrics += sizeof(u64);
		}
		ptr = (u8 *)prologue + prologue->len;
		prologue = ptr;
	}
	return rc;
}

static void fmt_start(enum util_fmt_t fmt, unsigned int fmt_flags,
		      int fmt_specified)
{
	if (!fmt_specified)
		return;
	util_fmt_init(stdout, fmt, fmt_flags, 1);
	if (fmt != FMT_JSONSEQ)
		util_fmt_obj_start(FMT_LIST, "zpwr");
}

static void fmt_end(enum util_fmt_t fmt, int fmt_specified)
{
	if (!fmt_specified)
		return;
	if (fmt != FMT_JSONSEQ)
		util_fmt_obj_end(); /* zpwr[] */
	util_fmt_exit();
}

int main(int argc, char *argv[])
{
	enum util_fmt_flags_t fmt_flags = FMT_HANDLEINT | FMT_QUOTEALL | FMT_KEEPINVAL;
	int ch, fd, rc = EXIT_FAILURE, fmt_specified = 0;
	bool stream = false, init = true;
	enum util_fmt_t fmt = FMT_JSON;
	u64 init_seq, interval = 0;
	long count = 0, delay = 0;
	struct diag324_pib data;
	struct zpwrinfo *pinfo;
	struct timespec ts;
	size_t buffersize;
	struct pib *pib;
	struct stat st;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);
	while (1) {
		ch = util_opt_getopt_long(argc, argv);
		if (ch == -1)
			break;
		switch (ch) {
		case 'c':
			errno = 0;
			count = strtoul(optarg, NULL, 0);
			if (errno || count <= 0)
				errx(EXIT_FAILURE, "Positive number expected for option -%c", ch);
			break;
		case 'd':
			errno = 0;
			delay = strtoul(optarg, NULL, 0);
			if (errno || delay <= 0)
				errx(EXIT_FAILURE, "Positive number expected for option -%c", ch);
			break;
		case 's':
			stream = true;
			break;
		case OPT_FORMAT:
			if (!util_fmt_name_to_type(optarg, &fmt)) {
				errx(EXIT_FAILURE, "Supported formats: %s", FMT_TYPE_NAMES);
			} else {
				if (fmt == FMT_CSV)
					fmt_flags |= FMT_NOMETA;
				else
					fmt_flags |= FMT_DEFAULT;
				fmt_specified = 1;
			}
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		default:
			util_opt_print_parse_error(ch, argv);
			return EXIT_FAILURE;
		}
	}
	if (stream && delay)
		errx(EXIT_FAILURE, "-s and -d option are mutually exclusive");
	if (count && !delay && !stream)
		errx(EXIT_FAILURE, "-c option can only be used in conjunction with -d or -s");
	if (stat(DIAG, &st) == -1)
		errx(EXIT_FAILURE, "Missing kernel support to retrieve power readings");
	fd = open(DIAG, O_RDONLY);
	if (fd < 0)
		err(EXIT_FAILURE, "Open failed: %s", DIAG);
	rc = ioctl(fd, DIAG324_GET_PIBLEN, &buffersize);
	if (rc && errno == EOPNOTSUPP) {
		warnx("The machine does not support retrieving power readings");
		goto out;
	} else if (rc) {
		warn("Ioctl (DIAG324_GET_PIBLEN) failed");
		goto out;
	}
	pinfo = calloc(1, sizeof(*pinfo));
	if (!pinfo) {
		warnx("Allocation of pinfo failed");
		goto out;
	}
	pib = calloc(1, buffersize);
	if (!pib) {
		free(pinfo);
		warnx("Allocation of pib failed");
		goto out;
	}
	data.address = (u64)pib;
	fmt_start(fmt, fmt_flags, fmt_specified);
	while (true) {
		rc = ioctl(fd, DIAG324_GET_PIBBUF, &data);
		if (rc != 0 && errno != EBUSY) {
			warn("Ioctl (DIAG324_GET_PIBBUF) failed");
			goto out_free;
		}
		rc = read_zpwrinfo(pinfo, pib);
		if (rc)
			goto out_free;
		if (init) {
			init_seq = data.sequence;
			init = false;
		}
		interval = tod_to_ns(pib->intv);
		print_zpwrinfo(pinfo, data.sequence - init_seq, fmt_specified, interval);
		reset_zpwrinfo(pinfo, pib, buffersize);
		if (stream) {
			ts.tv_sec = interval / NANO;
			ts.tv_nsec = interval % NANO;
		} else {
			ts.tv_sec = delay;
			ts.tv_nsec = 0;
		}
		if ((stream || delay) && !count) {
			nanosleep(&ts, NULL);
			continue;
		} else if (--count > 0) {
			nanosleep(&ts, NULL);
			continue;
		} else {
			break;
		}
	}
	fmt_end(fmt, fmt_specified);
out_free:
	free(pinfo);
	free(pib);
out:
	close(fd);
	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
