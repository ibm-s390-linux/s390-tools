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
	FILE *fp;

	fp = fopen(S390_CPUMSF_BUFFERSZ, "r");
	if (!fp)
		err(EXIT_FAILURE, "%s", S390_CPUMSF_BUFFERSZ);
	if (fscanf(fp, "%lu,%lu", min, max) == 2)
		rc = true;
	fclose(fp);
	return rc;
}

bool libcpumf_have_pai_crypto(void)
{
	struct stat statbuf;

	return (stat(S390_SYSFS_PAI_CRYPTO, &statbuf) == -1) ? false : true;
}

bool libcpumf_have_pai_nnpa(void)
{
	struct stat statbuf;

	return (stat(S390_SYSFS_PAI_NNPA, &statbuf) == -1) ? false : true;
}
