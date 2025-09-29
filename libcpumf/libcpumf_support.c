/* Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "lib/libcpumf.h"
#include "lib/util_path.h"
#include "lib/util_libc.h"

#define	SERVICELEVEL	"/proc/service_levels"

bool libcpumf_cpumcf_info(int *cfvn, int *csvn, int *auth)
{
	char *linep = NULL;
	bool rc = false;
	size_t line_sz;
	ssize_t nbytes;
	FILE *fp;

	fp = fopen(SERVICELEVEL, "r");
	if (!fp)
		err(EXIT_FAILURE, SERVICELEVEL);

	while ((nbytes = getline(&linep, &line_sz, fp)) != EOF) {
		if (!strncmp(linep, "CPU-MF: Counter facility:", 25)) {
			int cnt = sscanf(linep, "CPU-MF: Counter facility:"
					 " version=%d.%d authorization=%x",
					 cfvn, csvn, auth);
			if (cnt != 3) {
				warnx("Can not parse line %s", linep);
				goto out;
			}
			rc = true;
			break;
		}
	}
out:
	fclose(fp);
	free(linep);

	return rc;
}

bool libcpumf_have_cpumcf(void)
{
	int cfvn, csvn, auth;

	return libcpumf_cpumcf_info(&cfvn, &csvn, &auth);
}

bool libcpumf_cpumsf_info(unsigned long *min, unsigned long *max,
			  unsigned long *speed, int *basic_sz, int *diag_sz)
{
	char *linep = NULL;
	bool rc = true;
	size_t line_sz;
	ssize_t nbytes;
	int hit = 0;
	FILE *fp;

	fp = fopen(SERVICELEVEL, "r");
	if (!fp)
		err(EXIT_FAILURE, SERVICELEVEL);

	while ((nbytes = getline(&linep, &line_sz, fp)) != EOF) {
		int ok;

		if (!strncmp(linep, "CPU-MF: Sampling facility: min", 30)) {
			ok = sscanf(linep, "CPU-MF: Sampling facility:"
				    " min_rate=%ld max_rate=%ld cpu_speed=%ld",
				    min, max, speed);
			if (ok != 3) {
				warnx("Can not parse line %s", linep);
				goto out;
			}
			hit += 1;
		}
		if (!strncmp(linep, "CPU-MF: Sampling facility: mode=basic", 37)) {
			ok = sscanf(linep, "CPU-MF: Sampling facility:"
				    " mode=basic sample_size=%u", basic_sz);
			if (ok != 1) {
				warnx("Can not parse line %s", linep);
				goto out;
			}
			hit += 1;
		}
		if (!strncmp(linep, "CPU-MF: Sampling facility: mode=diag", 36)) {
			ok = sscanf(linep, "CPU-MF: Sampling facility:"
				    " mode=diagnostic sample_size=%u",
				    diag_sz);
			if (ok != 1) {
				warnx("Can not parse line %s", linep);
				goto out;
			}
			hit += 1;
		}
	}
out:
	fclose(fp);
	free(linep);
	if (hit != 3)
		rc = false;

	return rc;
}

bool libcpumf_have_cpumsf(void)
{
	unsigned long a, b, c;
	int basic_sz, diag_sz;

	return libcpumf_cpumsf_info(&a, &b, &c, &basic_sz, &diag_sz);
}

bool libcpumf_have_sfb(void)
{
	unsigned long a, b;

	return libcpumf_sfb_info(&a, &b);
}

bool libcpumf_sfb_info(unsigned long *min, unsigned long *max)
{
	int rc = false;
	char *path;
	FILE *fp;

	path = util_path_sysfs(S390_CPUMSF_BUFFERSZ);
	fp = fopen(path, "r");
	if (!fp)
		err(EXIT_FAILURE, "%s", path);
	if (fscanf(fp, "%lu,%lu", min, max) == 2)
		rc = true;
	fclose(fp);
	free(path);
	return rc;
}

static bool libcpumf_have_pai_sysfs(char *p)
{
	char *path;
	bool ret;

	path = util_path_sysfs(p);
	ret = util_path_exists(path);
	free(path);
	return ret;
}

bool libcpumf_have_pai_crypto(void)
{
	return libcpumf_have_pai_sysfs(S390_SYSFS_PAI_CRYPTO);
}

bool libcpumf_have_pai_ext(void)
{
	return libcpumf_have_pai_sysfs(S390_SYSFS_PAI_EXT);
}

bool libcpumf_have_pai_nnpa(void)
{
	return libcpumf_have_pai_sysfs(S390_SYSFS_PAI_NNPA);
}

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
		     unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

bool ctr_in_list(char *name, char *ctrlist)
{
	char *token;
	char *list;

	if (!ctrlist) /* No --counters means all counters */
		return true;

	list = util_strdup(ctrlist);
	token = strtok(list, ",");
	while (token) {
		if (strcmp(token, name) == 0) {
			free(list);
			return true;
		}
		token = strtok(NULL, ",");
	}

	free(list);
	return false;
}
