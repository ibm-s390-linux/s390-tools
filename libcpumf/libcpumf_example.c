/* Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "lib/libcpumf.h"

int main(void)
{
	unsigned long min, max, speed, sfb_min, sfb_max;
	int rc, pmu, cfvn, csvn, auth;
	char *pmuname;
	cpu_set_t set;

	pmu = libcpumf_pmutype(S390_CPUMF_CF);
	if (pmu >= 0)
		printf("PMU %stype %d\n", S390_CPUMF_CF, pmu);
	else
		printf("PMU %stype error %d\n", S390_CPUMF_CF, errno);
	pmu = libcpumf_pmutype(S390_CPUMF_SF);
	if (pmu >= 0)
		printf("PMU %stype %d\n", S390_CPUMF_SF, pmu);
	else
		printf("PMU %stype error %d\n", S390_CPUMF_SF, errno);
	pmu = libcpumf_pmutype(S390_CPUMF_CFDIAG);
	if (pmu >= 0)
		printf("PMU %stype %d\n", S390_CPUMF_CFDIAG, pmu);
	else
		printf("PMU %stype error %d\n", S390_CPUMF_CFDIAG, errno);

	rc = libcpumf_cpuset_fn(S390_CPUS_ONLINE, &set);
	if (rc == 0) {
		puts("Online CPUs:");
		for (int i = 0; i < CPU_SETSIZE; ++i)
			if (CPU_ISSET(i, &set))
				printf("%d ", i);
		putchar('\n');
	}
	rc = libcpumf_cpuset("0-7,9,11-12 ,15", &set);
	if (rc == 0) {
		puts("String CPUs:");
		for (int i = 0; i < CPU_SETSIZE; ++i)
			if (CPU_ISSET(i, &set))
				printf("%d ", i);
		putchar('\n');
	} else {
		printf("libcpumf_cpuset input invalid %d\n", errno);
	}

	printf("CPUMCF support %d\n", libcpumf_have_cpumcf());
	rc = libcpumf_cpumcf_info(&cfvn, &csvn, &auth);
	printf("libcpumf_cpumcf_info %d", rc);
	if (rc)
		printf(" cfvn %d csvn %d authorization %#x", cfvn, csvn, auth);
	putchar('\n');

	printf("CPUMSF support %d\n", libcpumf_have_cpumsf());
	rc = libcpumf_cpumsf_info(&min, &max, &speed, &cfvn, &csvn);
	printf("libcpumf_cpumsf_info %d", rc);
	if (rc)
		printf(" min %ld max %ld speed %#lx basic %d diag %d", min,
		       max, speed, cfvn, csvn);
	putchar('\n');

	printf("CPUMSF have sfb %d\n", libcpumf_have_sfb());
	rc = libcpumf_sfb_info(&sfb_min, &sfb_max);
	printf("libcpumf_sfb_info %d", rc);
	if (rc)
		printf(" sfb_min %lu sfb_max %lu", sfb_min, sfb_max);
	putchar('\n');

	printf("PAI crypto support %d\n", libcpumf_have_pai_crypto());

	rc = libcpumf_pmuname(10, &pmuname);
	if (rc) {
		printf("PMU type 10 PMU name lookup error %d\n", rc);
	} else {
		printf("PMU type 10 PMU name %s\n", pmuname);
		free(pmuname);
	}
	return EXIT_SUCCESS;
}
