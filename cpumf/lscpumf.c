/*
 * lscpumf -  Show CPU Measurement Facility Characteristics
 *
 * Copyright IBM Corp. 2020, 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/user.h>
#include <stdbool.h>
#include <unistd.h>

#include <linux/perf_event.h>

#include "lib/util_arch.h"
#include "lib/util_base.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"

#include "lib/libcpumf.h"

#define	ACTION_NONE	0
#define	ACTION_INFO	1
#define	ACTION_CNT	2
#define	ACTION_CNTALL	3
#define	ACTION_SAMPLE	4
static bool actions[ACTION_SAMPLE + 1];	/* Specified command line options */

/* This defines the number of pages a Sample Data Buffer Table (SDBT) can hold
 * as payload data. Each SDBT is one PAGE (4096 bytes) and contains 512 eight
 * byte data pointers to Sample Data Buffers (SDB). The last entry of a SDBT
 * points to another SDBT and can not store payload.
 */
#define	PER_SDBT_SIZE	511

/* File names to read data from */

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "list-counters", no_argument, NULL, 'c' },
		.desc = "Lists counters for which the LPAR is authorized.",
	},
	{
		.option = { "list-all-counters", no_argument, NULL, 'C' },
		.desc = "Lists counters regardless of LPAR authorization.",
	},
	{
		.option = { "name", no_argument, NULL, 'n' },
		.desc = "Displays counter names.",
	},
	{
		.option = { "info", no_argument, NULL, 'i' },
		.desc = "Displays detailed information.",
	},
	{
		.option = { "list-sampling-events", no_argument, NULL, 's' },
		.desc = "Lists sampling events for which the LPAR is authorized.",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static const struct util_prg prg = {
	.desc = "List CPU Measurement facility charactertics",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2020,
			.pub_last = 2020,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static char prefix[32];			/* Counter prefix */
static bool show_names;

static struct cpumf_info {
	int first_vn;			/* Counter facility first version nr */
	int second_vn;			/* Counter facility second version nr */
	int authorization;		/* Counter facility  authorization */
	unsigned long min_rate;		/* Minimum sampling rate */
	unsigned long max_rate;		/* Maximum sampling rate */
	unsigned long cpu_speed;	/* CPU Cycles per micro second */
	int basic_sample_sz;		/* # of Bytes per basic sample */
	int diag_sample_sz;		/* # of bytes per diagnostic sample */
	bool have_counter;		/* CPUM counter facility detected */
	bool have_samples;		/* CPUM sampling facility detected */
	unsigned long min_sfb;		/* Minimum sampling buffer size */
	unsigned long max_sfb;		/* Maximum sampling buffer size */
	unsigned short machine_type;	/* Machine Type */
} cpumf;


/*
 * Samples definition are identical on all machines. No versioning.
 */
static struct samples {		/* Sample definition for all machines */
	unsigned long counter;		/* Sample number */
	char *name;			/* Counter name see SA23-2261 */
	char *desc;			/* Short description */
	char *longdesc;			/* Long description */
} def_samples[] = {
	{
		.counter = 0xB0000,
		.name = "SF_CYCLES_BASIC",
		.desc = "Sample CPU Cycles Using Basic-sampling Mode.",
		.longdesc = "Sample CPU Cycles Using Basic-sampling Mode."
	},
	{
		.counter = 0xBD000,
		.name = "SF_CYCLES_BASIC_DIAG",
		.desc = "Sample CPU Cycle Using Diagnostic-sampling Mode\n"
			"                (not for ordinary use).",
		.longdesc = "Sample CPU Cycle Using Diagnostic-sampling Mode\n"
			"                (not for ordinary use).",
	}
};

/*
 * For exact details and clarifications see document SA23-2260-06 and
 * SA23-2261-06 (January 2020).
 *
 * Counter definitions vary, depending on machine and version numbering.
 * The CPU Measurement facility has a first and second version number.
 *
 * The first version number governs basic counter set and the
 * problem state counter set. Currently used are first version numbers 1 and 3.
 * The counter numbers are identifical for version number 1 and 3, but
 * have different purpose and description.
 *
 * The second version number governs the crypto counter set. Currently used
 * are numbers 1, 2, 3, 4, 5 and 6. Numbers 1 to 5 use the same counter numbers
 * and definitions. Number 6 adds 4 more deflate counters but leaves
 * the other counters in this counter set unchanged.
 *
 * The second version number also governs the extended counter set range.
 * The definition of each extended counter set is machine specific and
 * determined by machine number. Extended counter set ranges are:
 * Second version number and range:
 * Second version number: 1	Range 128 to 159 inclusive (32 counters)
 * Second version number: 2	Range 128 to 175 inclusive (48 counters)
 * Second version number: 3,4,5 Range 128 to 255 inclusive (128 counters)
 * Second version number: 6     Range 128 to 287 inclusive (160 counters)
 *
 * The second version number also governs the MT-diagnostic counter set range.
 * Second version number: 1,2,3 none installed
 * Second version number: >3    Range 448 to 495 inclusive (48 counters)
 */

struct counters {
	int ctrnum;
	int ctrset;
	char *name;
	char *desc;
};

static struct counters cpumcf_fvn1_counters[] = {
	{
		.ctrnum = 0,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "CPU_CYCLES",
		.desc = "Cycle Count",
	},
	{
		.ctrnum = 1,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "INSTRUCTIONS",
		.desc = "Instruction Count",
	},
	{
		.ctrnum = 2,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "L1I_DIR_WRITES",
		.desc = "Level-1 I-Cache Directory Write Count",
	},
	{
		.ctrnum = 3,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "L1I_PENALTY_CYCLES",
		.desc = "Level-1 I-Cache Penalty Cycle Count",
	},
	{
		.ctrnum = 4,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "L1D_DIR_WRITES",
		.desc = "Level-1 D-Cache Directory Write Count",
	},
	{
		.ctrnum = 5,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "L1D_PENALTY_CYCLES",
		.desc = "Level-1 D-Cache Penalty Cycle Count",
	},
	{
		.ctrnum = 32,
		.ctrset = CPUMF_CTRSET_PROBLEM_STATE,
		.name = "PROBLEM_STATE_CPU_CYCLES",
		.desc = "Problem-State Cycle Count",
	},
	{
		.ctrnum = 33,
		.ctrset = CPUMF_CTRSET_PROBLEM_STATE,
		.name = "PROBLEM_STATE_INSTRUCTIONS",
		.desc = "Problem-State Instruction Count",
	},
	{
		.ctrnum = 34,
		.ctrset = CPUMF_CTRSET_PROBLEM_STATE,
		.name = "PROBLEM_STATE_L1I_DIR_WRITES",
		.desc = "Problem-State Level-1 I-Cache Directory Write Count",
	},
	{
		.ctrnum = 35,
		.ctrset = CPUMF_CTRSET_PROBLEM_STATE,
		.name = "PROBLEM_STATE_L1I_PENALTY_CYCLES",
		.desc = "Problem-State Level-1 I-Cache Penalty Cycle Count",
	},
	{
		.ctrnum = 36,
		.ctrset = CPUMF_CTRSET_PROBLEM_STATE,
		.name = "PROBLEM_STATE_L1D_DIR_WRITES",
		.desc = "Problem-State Level-1 D-Cache Directory Write Count",
	},
	{
		.ctrnum = 37,
		.ctrset = CPUMF_CTRSET_PROBLEM_STATE,
		.name = "PROBLEM_STATE_L1D_PENALTY_CYCLES",
		.desc = "Problem-State Level-1 D-Cache Penalty Cycle Count",
	},
};

static struct counters cpumcf_fvn3_counters[] = {
	{
		.ctrnum = 0,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "CPU_CYCLES",
		.desc = "Cycle Count",
	},
	{
		.ctrnum = 1,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "INSTRUCTIONS",
		.desc = "Instruction Count",
	},
	{
		.ctrnum = 2,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "L1I_DIR_WRITES",
		.desc = "Level-1 I-Cache Directory Write Count",
	},
	{
		.ctrnum = 3,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "L1I_PENALTY_CYCLES",
		.desc = "Level-1 I-Cache Penalty Cycle Count",
	},
	{
		.ctrnum = 4,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "L1D_DIR_WRITES",
		.desc = "Level-1 D-Cache Directory Write Count",
	},
	{
		.ctrnum = 5,
		.ctrset = CPUMF_CTRSET_BASIC,
		.name = "L1D_PENALTY_CYCLES",
		.desc = "Level-1 D-Cache Penalty Cycle Count",
	},
	{
		.ctrnum = 32,
		.ctrset = CPUMF_CTRSET_PROBLEM_STATE,
		.name = "PROBLEM_STATE_CPU_CYCLES",
		.desc = "Problem-State Cycle Count",
	},
	{
		.ctrnum = 33,
		.ctrset = CPUMF_CTRSET_PROBLEM_STATE,
		.name = "PROBLEM_STATE_INSTRUCTIONS",
		.desc = "Problem-State Instruction Count",
	},
};

static struct counters cpumcf_svn_12345_counters[] = {
	{
		.ctrnum = 64,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "PRNG_FUNCTIONS",
		.desc = "Total number of the PRNG functions issued by the"
			"\n\t\tCPU",
	},
	{
		.ctrnum = 65,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "PRNG_CYCLES",
		.desc = "Total number of CPU cycles when the DEA/AES"
			"\n\t\tcoprocessor is busy performing PRNG functions"
			"\n\t\tissued by the CPU",
	},
	{
		.ctrnum = 66,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "PRNG_BLOCKED_FUNCTIONS",
		.desc = "Total number of the PRNG functions that are issued"
			"\n\t\tby the CPU and are blocked because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 67,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "PRNG_BLOCKED_CYCLES",
		.desc = "Total number of CPU cycles blocked for the PRNG"
			"\n\t\tfunctions issued by the CPU because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 68,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "SHA_FUNCTIONS",
		.desc = "Total number of SHA functions issued by the CPU",
	},
	{
		.ctrnum = 69,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "SHA_CYCLES",
		.desc = "Total number of CPU cycles when the SHA coprocessor"
			"\n\t\tis busy performing the SHA functions issued by the"
			"\n\t\tCPU",
	},
	{
		.ctrnum = 70,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "SHA_BLOCKED_FUNCTIONS",
		.desc = "Total number of the SHA functions that are issued"
			"\n\t\tby the CPU and are blocked because the SHA"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 71,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "SHA_BLOCKED_CYCLES",
		.desc = "Total number of CPU cycles blocked for the SHA"
			"\n\t\tfunctions issued by the CPU because the SHA"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 72,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "DEA_FUNCTIONS",
		.desc = "Total number of the DEA functions issued by the CPU",
	},
	{
		.ctrnum = 73,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "DEA_CYCLES",
		.desc = "Total number of CPU cycles when the DEA/AES"
			"\n\t\tcoprocessor is busy performing the DEA functions"
			"\n\t\tissued by the CPU",
	},
	{
		.ctrnum = 74,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "DEA_BLOCKED_FUNCTIONS",
		.desc = "Total number of the DEA functions that are issued"
			"\n\t\tby the CPU and are blocked because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 75,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "DEA_BLOCKED_CYCLES",
		.desc = "Total number of CPU cycles blocked for the DEA"
			"\n\t\tfunctions issued by the CPU because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 76,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "AES_FUNCTIONS",
		.desc = "Total number of AES functions issued by the CPU",
	},
	{
		.ctrnum = 77,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "AES_CYCLES",
		.desc = "Total number of CPU cycles when the DEA/AES"
			"\n\t\tcoprocessor is busy performing the AES functions"
			"\n\t\tissued by the CPU",
	},
	{
		.ctrnum = 78,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "AES_BLOCKED_FUNCTIONS",
		.desc = "Total number of AES functions that are issued by"
			"\n\t\tthe CPU and are blocked because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 79,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "AES_BLOCKED_CYCLES",
		.desc = "Total number of CPU cycles blocked for the AES"
			"\n\t\tfunctions issued by the CPU because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
};

static struct counters cpumcf_svn_6_counters[] = {
	{
		.ctrnum = 64,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "PRNG_FUNCTIONS",
		.desc = "Total number of the PRNG functions issued by the"
			"\n\t\tCPU",
	},
	{
		.ctrnum = 65,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "PRNG_CYCLES",
		.desc = "Total number of CPU cycles when the DEA/AES"
			"\n\t\tcoprocessor is busy performing PRNG functions"
			"\n\t\tissued by the CPU",
	},
	{
		.ctrnum = 66,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "PRNG_BLOCKED_FUNCTIONS",
		.desc = "Total number of the PRNG functions that are issued"
			"\n\t\tby the CPU and are blocked because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 67,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "PRNG_BLOCKED_CYCLES",
		.desc = "Total number of CPU cycles blocked for the PRNG"
			"\n\t\tfunctions issued by the CPU because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 68,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "SHA_FUNCTIONS",
		.desc = "Total number of SHA functions issued by the CPU",
	},
	{
		.ctrnum = 69,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "SHA_CYCLES",
		.desc = "Total number of CPU cycles when the SHA coprocessor"
			"\n\t\tis busy performing the SHA functions issued by the"
			"\n\t\tCPU",
	},
	{
		.ctrnum = 70,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "SHA_BLOCKED_FUNCTIONS",
		.desc = "Total number of the SHA functions that are issued"
			"\n\t\tby the CPU and are blocked because the SHA"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 71,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "SHA_BLOCKED_CYCLES",
		.desc = "Total number of CPU cycles blocked for the SHA"
			"\n\t\tfunctions issued by the CPU because the SHA"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 72,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "DEA_FUNCTIONS",
		.desc = "Total number of the DEA functions issued by the CPU",
	},
	{
		.ctrnum = 73,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "DEA_CYCLES",
		.desc = "Total number of CPU cycles when the DEA/AES"
			"\n\t\tcoprocessor is busy performing the DEA functions"
			"\n\t\tissued by the CPU",
	},
	{
		.ctrnum = 74,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "DEA_BLOCKED_FUNCTIONS",
		.desc = "Total number of the DEA functions that are issued"
			"\n\t\tby the CPU and are blocked because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 75,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "DEA_BLOCKED_CYCLES",
		.desc = "Total number of CPU cycles blocked for the DEA"
			"\n\t\tfunctions issued by the CPU because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 76,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "AES_FUNCTIONS",
		.desc = "Total number of AES functions issued by the CPU",
	},
	{
		.ctrnum = 77,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "AES_CYCLES",
		.desc = "Total number of CPU cycles when the DEA/AES"
			"\n\t\tcoprocessor is busy performing the AES functions"
			"\n\t\tissued by the CPU",
	},
	{
		.ctrnum = 78,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "AES_BLOCKED_FUNCTIONS",
		.desc = "Total number of AES functions that are issued by"
			"\n\t\tthe CPU and are blocked because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 79,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "AES_BLOCKED_CYCLES",
		.desc = "Total number of CPU cycles blocked for the AES"
			"\n\t\tfunctions issued by the CPU because the DEA/AES"
			"\n\t\tcoprocessor is busy performing a function issued by"
			"\n\t\tanother CPU",
	},
	{
		.ctrnum = 80,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "ECC_FUNCTION_COUNT",
		.desc = "This counter counts the total number of the"
			"\n\t\telliptic-curve cryptography (ECC) functions issued"
			"\n\t\tby the CPU.",
	},
	{
		.ctrnum = 81,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "ECC_CYCLES_COUNT",
		.desc = "This counter counts the total number of CPU cycles"
			"\n\t\twhen the ECC coprocessor is busy performing the"
			"\n\t\telliptic-curve cryptography (ECC) functions issued"
			"\n\t\tby the CPU.",
	},
	{
		.ctrnum = 82,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "ECC_BLOCKED_FUNCTION_COUNT",
		.desc = "This counter counts the total number of the"
			"\n\t\telliptic-curve cryptography (ECC) functions that"
			"\n\t\tare issued by the CPU and are blocked because the"
			"\n\t\tECC coprocessor is busy performing a function"
			"\n\t\tissued by another CPU.",
	},
	{
		.ctrnum = 83,
		.ctrset = CPUMF_CTRSET_CRYPTO,
		.name = "ECC_BLOCKED_CYCLES_COUNT",
		.desc = "This counter counts the total number of CPU cycles"
			"\n\t\tblocked for the elliptic-curve cryptography (ECC)"
			"\n\t\tfunctions issued by the CPU because the ECC"
			"\n\t\tcoprocessor is busy perform- ing a function issued"
			"\n\t\tby another CPU.",
	},
};

static struct counters cpumcf_z10_counters[] = {
	{
		.ctrnum = 128,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_L2_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the returned cache line was sourced from the"
			"\n\t\tLevel-2 (L1.5) cache",
	},
	{
		.ctrnum = 129,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L2_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the installed cache line was sourced from the"
			"\n\t\tLevel-2 (L1.5) cache",
	},
	{
		.ctrnum = 130,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_L3_LOCAL_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the installed cache line was sourced from the"
			"\n\t\tLevel-3 cache that is on the same book as the"
			"\n\t\tInstruction cache (Local L2 cache)",
	},
	{
		.ctrnum = 131,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L3_LOCAL_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the installation cache line was source from"
			"\n\t\tthe Level-3 cache that is on the same book as the"
			"\n\t\tData cache (Local L2 cache)",
	},
	{
		.ctrnum = 132,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_L3_REMOTE_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the installed cache line was sourced from a"
			"\n\t\tLevel-3 cache that is not on the same book as the"
			"\n\t\tInstruction cache (Remote L2 cache)",
	},
	{
		.ctrnum = 133,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L3_REMOTE_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the installed cache line was sourced from a"
			"\n\t\tLevel-3 cache that is not on the same book as the"
			"\n\t\tData cache (Remote L2 cache)",
	},
	{
		.ctrnum = 134,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_LMEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the installed cache line was sourced from"
			"\n\t\tmemory that is attached to the same book as the"
			"\n\t\tData cache (Local Memory)",
	},
	{
		.ctrnum = 135,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_LMEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache where the"
			"\n\t\tinstalled cache line was sourced from memory that"
			"\n\t\tis attached to the s ame book as the Instruction"
			"\n\t\tcache (Local Memory)",
	},
	{
		.ctrnum = 136,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_RO_EXCL_WRITES",
		.desc = "A directory write to the Level-1 D-Cache where the"
			"\n\t\tline was originally in a Read-Only state in the"
			"\n\t\tcache but has been updated to be in the Exclusive"
			"\n\t\tstate that allows stores to the cache line",
	},
	{
		.ctrnum = 137,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_CACHELINE_INVALIDATES",
		.desc = "A cache line in the Level-1 I-Cache has been"
			"\n\t\tinvalidated by a store on the same CPU as the Level-"
			"\n\t\t1 I-Cache",
	},
	{
		.ctrnum = 138,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB1_WRITES",
		.desc = "A translation entry has been written into the Level-"
			"\n\t\t1 Instruction Translation Lookaside Buffer",
	},
	{
		.ctrnum = 139,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tData Translation Lookaside Buffer",
	},
	{
		.ctrnum = 140,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_PTE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Page Table Entry arrays",
	},
	{
		.ctrnum = 141,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Common Region Segment Table Entry arrays",
	},
	{
		.ctrnum = 142,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_HPAGE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Common Region Segment Table Entry arrays for a"
			"\n\t\tone-megabyte large page translation",
	},
	{
		.ctrnum = 145,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB1_MISSES",
		.desc = "Level-1 Instruction TLB miss in progress."
			"\n\t\tIncremented by one for every cycle an ITLB1 miss is"
			"\n\t\tin progress",
	},
	{
		.ctrnum = 146,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_MISSES",
		.desc = "Level-1 Data TLB miss in progress. Incremented by"
			"\n\t\tone for every cycle an DTLB1 miss is in progress",
	},
	{
		.ctrnum = 147,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L2C_STORES_SENT",
		.desc = "Incremented by one for every store sent to Level-2"
			"\n\t\t(L1.5) cache",
	},
};

static struct counters cpumcf_z196_counters[] = {
	{
		.ctrnum = 128,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L2_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the returned cache line was sourced from the"
			"\n\t\tLevel-2 cache",
	},
	{
		.ctrnum = 129,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_L2_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the returned cache line was sourced from the"
			"\n\t\tLevel-2 cache",
	},
	{
		.ctrnum = 130,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_MISSES",
		.desc = "Level-1 Data TLB miss in progress. Incremented by"
			"\n\t\tone for every cycle a DTLB1 miss is in progress.",
	},
	{
		.ctrnum = 131,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB1_MISSES",
		.desc = "Level-1 Instruction TLB miss in progress."
			"\n\t\tIncremented by one for every cycle a ITLB1 miss is"
			"\n\t\tin progress.",
	},
	{
		.ctrnum = 133,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L2C_STORES_SENT",
		.desc = "Incremented by one for every store sent to Level-2"
			"\n\t\tcache",
	},
	{
		.ctrnum = 134,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFBOOK_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOff Book Level-3 cache",
	},
	{
		.ctrnum = 135,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONBOOK_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOn Book Level-4 cache",
	},
	{
		.ctrnum = 136,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONBOOK_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOn Book Level-4 cache",
	},
	{
		.ctrnum = 137,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_RO_EXCL_WRITES",
		.desc = "A directory write to the Level-1 D-Cache where the"
			"\n\t\tline was originally in a Read-Only state in the"
			"\n\t\tcache but has been updated to be in the Exclusive"
			"\n\t\tstate that allows stores to the cache line",
	},
	{
		.ctrnum = 138,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFBOOK_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOff Book Level-4 cache",
	},
	{
		.ctrnum = 139,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFBOOK_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOff Book Level-4 cache",
	},
	{
		.ctrnum = 140,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_HPAGE_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tData Translation Lookaside Buffer for a one-"
			"\n\t\tmegabyte page",
	},
	{
		.ctrnum = 141,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_LMEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache where the"
			"\n\t\tinstalled cache line was sourced from memory that"
			"\n\t\tis attached to the same book as the Data cache"
			"\n\t\t(Local Memory)",
	},
	{
		.ctrnum = 142,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_LMEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache where the"
			"\n\t\tinstalled cache line was sourced from memory that"
			"\n\t\tis attached to the same book as the Instruction"
			"\n\t\tcache (Local Memory)",
	},
	{
		.ctrnum = 143,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFBOOK_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOff Book Level-3 cache",
	},
	{
		.ctrnum = 144,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tData Translation Lookaside Buffer",
	},
	{
		.ctrnum = 145,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB1_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tInstruction Translation Lookaside Buffer",
	},
	{
		.ctrnum = 146,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_PTE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Page Table Entry arrays",
	},
	{
		.ctrnum = 147,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_HPAGE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Common Region Segment Table Entry arrays for a"
			"\n\t\tone-megabyte large page translation",
	},
	{
		.ctrnum = 148,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Common Region Segment Table Entry arrays",
	},
	{
		.ctrnum = 150,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOn Chip Level-3 cache",
	},
	{
		.ctrnum = 152,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 D-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOff Chip/On Book Level-3 cache",
	},
	{
		.ctrnum = 153,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOn Chip Level-3 cache",
	},
	{
		.ctrnum = 155,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 I-Cache directory"
			"\n\t\twhere the returned cache line was sourced from an"
			"\n\t\tOff Chip/On Book Level-3 cache",
	},
};

static struct counters cpumcf_zec12_counters[] = {
	{
		.ctrnum = 128,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_MISSES",
		.desc = "Level-1 Data TLB miss in progress. Incremented by"
			"\n\t\tone for every cycle a DTLB1 miss is in progress.",
	},
	{
		.ctrnum = 129,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB1_MISSES",
		.desc = "Level-1 Instruction TLB miss in progress."
			"\n\t\tIncremented by one for every cycle a ITLB1 miss is"
			"\n\t\tin progress.",
	},
	{
		.ctrnum = 130,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L2I_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Instruction cache",
	},
	{
		.ctrnum = 131,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_L2I_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Instruction cache",
	},
	{
		.ctrnum = 132,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L2D_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Data cache",
	},
	{
		.ctrnum = 133,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tData Translation Lookaside Buffer",
	},
	{
		.ctrnum = 135,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_LMEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache where"
			"\n\t\tthe installed cache line was sourced from memory"
			"\n\t\tthat is attached to the same book as the Data cache"
			"\n\t\t(Local Memory)",
	},
	{
		.ctrnum = 137,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_LMEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\twhere the installed cache line was sourced from"
			"\n\t\tmemory that is attached to the same book as the"
			"\n\t\tInstruction cache (Local Memory)",
	},
	{
		.ctrnum = 138,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_RO_EXCL_WRITES",
		.desc = "A directory write to the Level-1 D-Cache where the"
			"\n\t\tline was originally in a Read-Only state in the"
			"\n\t\tcache but has been updated to be in the Exclusive"
			"\n\t\tstate that allows stores to the cache line",
	},
	{
		.ctrnum = 139,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_HPAGE_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tData Translation Lookaside Buffer for a one-"
			"\n\t\tmegabyte page",
	},
	{
		.ctrnum = 140,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB1_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tInstruction Translation Lookaside Buffer",
	},
	{
		.ctrnum = 141,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_PTE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Page Table Entry arrays",
	},
	{
		.ctrnum = 142,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_HPAGE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Common Region Segment Table Entry arrays for a"
			"\n\t\tone-megabyte large page translation",
	},
	{
		.ctrnum = 143,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Common Region Segment Table Entry arrays",
	},
	{
		.ctrnum = 144,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On Chip Level-3 cache without intervention",
	},
	{
		.ctrnum = 145,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Chip/On Book Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 146,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFBOOK_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Book Level-3 cache without intervention",
	},
	{
		.ctrnum = 147,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONBOOK_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On Book Level-4 cache",
	},
	{
		.ctrnum = 148,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFBOOK_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Book Level-4 cache",
	},
	{
		.ctrnum = 149,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TEND",
		.desc = "A TEND instruction has completed in a"
			"\n\t\tnonconstrained transactional-execution mode",
	},
	{
		.ctrnum = 150,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom a On Chip Level-3 cache with intervention",
	},
	{
		.ctrnum = 151,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Chip/On Book Level-3 cache with"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 152,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFBOOK_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Book Level-3 cache with intervention",
	},
	{
		.ctrnum = 153,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On Chip Level-3 cache without intervention",
	},
	{
		.ctrnum = 154,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Chip/On Book Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 155,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFBOOK_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Book Level-3 cache without intervention",
	},
	{
		.ctrnum = 156,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONBOOK_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On Book Level-4 cache",
	},
	{
		.ctrnum = 157,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFBOOK_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Book Level-4 cache",
	},
	{
		.ctrnum = 158,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TEND",
		.desc = "A TEND instruction has completed in a constrained"
			"\n\t\ttransactional-execution mode",
	},
	{
		.ctrnum = 159,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On Chip Level-3 cache with intervention",
	},
	{
		.ctrnum = 160,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Chip/On Book Level-3 cache with"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 161,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFBOOK_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off Book Level-3 cache with intervention",
	},
	{
		.ctrnum = 177,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TABORT",
		.desc = "A transaction abort has occurred in a"
			"\n\t\tnonconstrained transactional-execution mode",
	},
	{
		.ctrnum = 178,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_NO_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is not"
			"\n\t\tusing any special logic to allow the transaction to"
			"\n\t\tcomplete",
	},
	{
		.ctrnum = 179,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is using"
			"\n\t\tspecial logic to allow the transaction to complete",
	},
};

static struct counters cpumcf_z13_counters[] = {
	{
		.ctrnum = 128,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_RO_EXCL_WRITES",
		.desc = "A directory write to the Level-1 Data cache where"
			"\n\t\tthe line was originally in a Read-Only state in the"
			"\n\t\tcache but has been updated to be in the Exclusive"
			"\n\t\tstate that allows stores to the cache line.",
	},
	{
		.ctrnum = 129,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tData Translation Lookaside Buffer",
	},
	{
		.ctrnum = 130,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_MISSES",
		.desc = "Level-1 Data TLB miss in progress. Incremented by"
			"\n\t\tone for every cycle a DTLB1 miss is in progress.",
	},
	{
		.ctrnum = 131,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_HPAGE_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tData Translation Lookaside Buffer for a one-"
			"\n\t\tmegabyte page",
	},
	{
		.ctrnum = 132,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB1_GPAGE_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tData Translation Lookaside Buffer for a two-"
			"\n\t\tgigabyte page.",
	},
	{
		.ctrnum = 133,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L2D_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Data cache",
	},
	{
		.ctrnum = 134,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB1_WRITES",
		.desc = "A translation entry has been written to the Level-1"
			"\n\t\tInstruction Translation Lookaside Buffer",
	},
	{
		.ctrnum = 135,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB1_MISSES",
		.desc = "Level-1 Instruction TLB miss in progress."
			"\n\t\tIncremented by one for every cycle an ITLB1 miss is"
			"\n\t\tin progress",
	},
	{
		.ctrnum = 136,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_L2I_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Instruction cache",
	},
	{
		.ctrnum = 137,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_PTE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Page Table Entry arrays",
	},
	{
		.ctrnum = 138,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_HPAGE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Combined Region Segment Table Entry arrays for"
			"\n\t\ta one-megabyte large page translation",
	},
	{
		.ctrnum = 139,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_WRITES",
		.desc = "A translation entry has been written to the Level-2"
			"\n\t\tTLB Combined Region Segment Table Entry arrays",
	},
	{
		.ctrnum = 140,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TEND",
		.desc = "A TEND instruction has completed in a constrained"
			"\n\t\ttransactional-execution mode",
	},
	{
		.ctrnum = 141,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TEND",
		.desc = "A TEND instruction has completed in a non-"
			"\n\t\tconstrained transactional-execution mode",
	},
	{
		.ctrnum = 143,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1C_TLB1_MISSES",
		.desc = "Increments by one for any cycle where a Level-1"
			"\n\t\tcache or Level-1 TLB miss is in progress.",
	},
	{
		.ctrnum = 144,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache without intervention",
	},
	{
		.ctrnum = 145,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache with intervention",
	},
	{
		.ctrnum = 146,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONNODE_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Node Level-4 cache",
	},
	{
		.ctrnum = 147,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONNODE_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Node Level-3 cache with intervention",
	},
	{
		.ctrnum = 148,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONNODE_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Node Level-3 cache without intervention",
	},
	{
		.ctrnum = 149,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-4 cache",
	},
	{
		.ctrnum = 150,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONDRAWER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-3 cache with intervention",
	},
	{
		.ctrnum = 151,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONDRAWER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 152,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_SCOL_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Same-Column Level-4 cache",
	},
	{
		.ctrnum = 153,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_SCOL_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Same-Column Level-3 cache with"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 154,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_SCOL_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Same-Column Level-3 cache"
			"\n\t\twithout intervention",
	},
	{
		.ctrnum = 155,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_FCOL_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Far-Column Level-4 cache",
	},
	{
		.ctrnum = 156,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_FCOL_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Far-Column Level-3 cache with"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 157,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_FCOL_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Far-Column Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 158,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONNODE_MEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Node memory",
	},
	{
		.ctrnum = 159,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONDRAWER_MEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer memory",
	},
	{
		.ctrnum = 160,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_MEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer memory",
	},
	{
		.ctrnum = 161,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_MEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip memory",
	},
	{
		.ctrnum = 162,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache without intervention",
	},
	{
		.ctrnum = 163,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On Chip Level-3 cache with intervention",
	},
	{
		.ctrnum = 164,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONNODE_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Node Level-4 cache",
	},
	{
		.ctrnum = 165,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONNODE_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Node Level-3 cache with intervention",
	},
	{
		.ctrnum = 166,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONNODE_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Node Level-3 cache without intervention",
	},
	{
		.ctrnum = 167,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-4 cache",
	},
	{
		.ctrnum = 168,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONDRAWER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-3 cache with intervention",
	},
	{
		.ctrnum = 169,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONDRAWER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 170,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_SCOL_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Same-Column Level-4 cache",
	},
	{
		.ctrnum = 171,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_SCOL_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Same-Column Level-3 cache with"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 172,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_SCOL_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Same-Column Level-3 cache"
			"\n\t\twithout intervention",
	},
	{
		.ctrnum = 173,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_FCOL_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Far-Column Level-4 cache",
	},
	{
		.ctrnum = 174,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_FCOL_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Far-Column Level-3 cache with"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 175,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_FCOL_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Far-Column Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 176,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONNODE_MEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Node memory",
	},
	{
		.ctrnum = 177,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONDRAWER_MEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer memory",
	},
	{
		.ctrnum = 178,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_MEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer memory",
	},
	{
		.ctrnum = 179,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_MEM_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip memory",
	},
	{
		.ctrnum = 218,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TABORT",
		.desc = "A transaction abort has occurred in a non-"
			"\n\t\tconstrained transactional-execution mode",
	},
	{
		.ctrnum = 219,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_NO_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is not"
			"\n\t\tusing any special logic to allow the transaction to"
			"\n\t\tcomplete",
	},
	{
		.ctrnum = 220,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is using"
			"\n\t\tspecial logic to allow the transaction to complete",
	},
	{
		.ctrnum = 448,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_ONE_THR_ACTIVE",
		.desc = "Cycle count with one thread active",
	},
	{
		.ctrnum = 449,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_TWO_THR_ACTIVE",
		.desc = "Cycle count with two threads active",
	},
};

static struct counters cpumcf_z14_counters[] = {
	{
		.ctrnum = 128,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_RO_EXCL_WRITES",
		.desc = "A directory write to the Level-1 Data cache where"
			"\n\t\tthe line was originally in a Read-Only state in the"
			"\n\t\tcache but has been updated to be in the Exclusive"
			"\n\t\tstate that allows stores to the cache line",
	},
	{
		.ctrnum = 129,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_WRITES",
		.desc = "A translation has been written into The Translation"
			"\n\t\tLookaside Buffer 2 (TLB2) and the request was made"
			"\n\t\tby the data cache",
	},
	{
		.ctrnum = 130,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_MISSES",
		.desc = "A TLB2 miss is in progress for a request made by"
			"\n\t\tthe data cache. Incremented by one for every TLB2"
			"\n\t\tmiss in progress for the Level-1 Data cache on this"
			"\n\t\tcycle",
	},
	{
		.ctrnum = 131,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_HPAGE_WRITES",
		.desc = "A translation entry was written into the Combined"
			"\n\t\tRegion and Segment Table Entry array in the Level-2"
			"\n\t\tTLB for a one-megabyte page or a Last Host"
			"\n\t\tTranslation was done",
	},
	{
		.ctrnum = 132,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_GPAGE_WRITES",
		.desc = "A translation entry for a two-gigabyte page was"
			"\n\t\twritten into the Level-2 TLB",
	},
	{
		.ctrnum = 133,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L2D_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Data cache",
	},
	{
		.ctrnum = 134,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB2_WRITES",
		.desc = "A translation entry has been written into the"
			"\n\t\tTranslation Lookaside Buffer 2 (TLB2) and the"
			"\n\t\trequest was made by the instruction cache",
	},
	{
		.ctrnum = 135,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB2_MISSES",
		.desc = "A TLB2 miss is in progress for a request made by"
			"\n\t\tthe instruction cache. Incremented by one for every"
			"\n\t\tTLB2 miss in progress for the Level-1 Instruction"
			"\n\t\tcache in a cycle",
	},
	{
		.ctrnum = 136,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_L2I_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Instruction cache",
	},
	{
		.ctrnum = 137,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_PTE_WRITES",
		.desc = "A translation entry was written into the Page Table"
			"\n\t\tEntry array in the Level-2 TLB",
	},
	{
		.ctrnum = 138,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_WRITES",
		.desc = "Translation entries were written into the Combined"
			"\n\t\tRegion and Segment Table Entry array and the Page"
			"\n\t\tTable Entry array in the Level-2 TLB",
	},
	{
		.ctrnum = 139,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_ENGINES_BUSY",
		.desc = "The number of Level-2 TLB translation engines busy"
			"\n\t\tin a cycle",
	},
	{
		.ctrnum = 140,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TEND",
		.desc = "A TEND instruction has completed in a constrained"
			"\n\t\ttransactional-execution mode",
	},
	{
		.ctrnum = 141,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TEND",
		.desc = "A TEND instruction has completed in a non-"
			"\n\t\tconstrained transactional-execution mode",
	},
	{
		.ctrnum = 143,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1C_TLB2_MISSES",
		.desc = "Increments by one for any cycle where a level-1"
			"\n\t\tcache or level-2 TLB miss is in progress",
	},
	{
		.ctrnum = 144,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache without intervention",
	},
	{
		.ctrnum = 145,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip memory",
	},
	{
		.ctrnum = 146,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache with intervention",
	},
	{
		.ctrnum = 147,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCLUSTER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Cluster Level-3 cache withountervention",
	},
	{
		.ctrnum = 148,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCLUSTER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Cluster memory",
	},
	{
		.ctrnum = 149,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCLUSTER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Cluster Level-3 cache with intervention",
	},
	{
		.ctrnum = 150,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCLUSTER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Cluster Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 151,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCLUSTER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Cluster memory",
	},
	{
		.ctrnum = 152,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCLUSTER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Cluster Level-3 cache with intervention",
	},
	{
		.ctrnum = 153,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 154,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer memory",
	},
	{
		.ctrnum = 155,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-3 cache with intervention",
	},
	{
		.ctrnum = 156,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer Level-4 cache",
	},
	{
		.ctrnum = 157,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer Level-4 cache",
	},
	{
		.ctrnum = 158,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES_RO",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip L3 but a read-only invalidate was done"
			"\n\t\tto remove other copies of the cache line",
	},
	{
		.ctrnum = 162,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache without intervention",
	},
	{
		.ctrnum = 163,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip memory",
	},
	{
		.ctrnum = 164,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache with intervention",
	},
	{
		.ctrnum = 165,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCLUSTER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Cluster Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 166,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCLUSTER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Cluster memory",
	},
	{
		.ctrnum = 167,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCLUSTER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Cluster Level-3 cache with intervention",
	},
	{
		.ctrnum = 168,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCLUSTER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Cluster Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 169,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCLUSTER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Cluster memory",
	},
	{
		.ctrnum = 170,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCLUSTER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Cluster Level-3 cache with intervention",
	},
	{
		.ctrnum = 171,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 172,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer memory",
	},
	{
		.ctrnum = 173,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-3 cache with intervention",
	},
	{
		.ctrnum = 174,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer Level-4 cache",
	},
	{
		.ctrnum = 175,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer Level-4 cache",
	},
	{
		.ctrnum = 224,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "BCD_DFP_EXECUTION_SLOTS",
		.desc = "Count of floating point execution slots used for"
			"\n\t\tfinished Binary Coded Decimal to Decimal Floating"
			"\n\t\tPoint conversions. Instructions: CDZT, CXZT, CZDT,"
			"\n\t\tCZXT",
	},
	{
		.ctrnum = 225,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "VX_BCD_EXECUTION_SLOTS",
		.desc = "Count of floating point execution slots used for"
			"\n\t\tfinished vector arithmetic Binary Coded Decimal"
			"\n\t\tinstructions. Instructions: VAP, VSP, VMPVMSP, VDP,"
			"\n\t\tVSDP, VRP, VLIP, VSRP, VPSOPVCP, VTP, VPKZ, VUPKZ,"
			"\n\t\tVCVB, VCVBG, VCVDVCVDG",
	},
	{
		.ctrnum = 226,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DECIMAL_INSTRUCTIONS",
		.desc = "Decimal instructions dispatched. Instructions: CVB,"
			"\n\t\tCVD, AP, CP, DP, ED, EDMK, MP, SRP, SP, ZAP",
	},
	{
		.ctrnum = 232,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "LAST_HOST_TRANSLATIONS",
		.desc = "Last Host Translation done",
	},
	{
		.ctrnum = 243,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TABORT",
		.desc = "A transaction abort has occurred in a non-"
			"\n\t\tconstrained transactional-execution mode",
	},
	{
		.ctrnum = 244,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_NO_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is not"
			"\n\t\tusing any special logic to allow the transaction to"
			"\n\t\tcomplete",
	},
	{
		.ctrnum = 245,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is using"
			"\n\t\tspecial logic to allow the transaction to complete",
	},
	{
		.ctrnum = 448,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_ONE_THR_ACTIVE",
		.desc = "Cycle count with one thread active",
	},
	{
		.ctrnum = 449,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_TWO_THR_ACTIVE",
		.desc = "Cycle count with two threads active",
	},
};

static struct counters cpumcf_z15_counters[] = {
	{
		.ctrnum = 128,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_RO_EXCL_WRITES",
		.desc = "A directory write to the Level-1 Data cache where"
			"\n\t\tthe line was originally in a Read-Only state in the"
			"\n\t\tcache but has been updated to be in the Exclusive"
			"\n\t\tstate that allows stores to the cache line",
	},
	{
		.ctrnum = 129,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_WRITES",
		.desc = "A translation has been written into The Translation"
			"\n\t\tLookaside Buffer 2 (TLB2) and the request was made"
			"\n\t\tby the data cache",
	},
	{
		.ctrnum = 130,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_MISSES",
		.desc = "A TLB2 miss is in progress for a request made by"
			"\n\t\tthe data cache. Incremented by one for every TLB2"
			"\n\t\tmiss in progress for the Level-1 Data cache on this"
			"\n\t\tcycle",
	},
	{
		.ctrnum = 131,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_HPAGE_WRITES",
		.desc = "A translation entry was written into the Combined"
			"\n\t\tRegion and Segment Table Entry array in the Level-2"
			"\n\t\tTLB for a one-megabyte page",
	},
	{
		.ctrnum = 132,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_GPAGE_WRITES",
		.desc = "A translation entry for a two-gigabyte page was"
			"\n\t\twritten into the Level-2 TLB",
	},
	{
		.ctrnum = 133,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_L2D_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Data cache",
	},
	{
		.ctrnum = 134,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB2_WRITES",
		.desc = "A translation entry has been written into the"
			"\n\t\tTranslation Lookaside Buffer 2 (TLB2) and the"
			"\n\t\trequest was made by the instruction cache",
	},
	{
		.ctrnum = 135,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB2_MISSES",
		.desc = "A TLB2 miss is in progress for a request made by"
			"\n\t\tthe instruction cache. Incremented by one for every"
			"\n\t\tTLB2 miss in progress for the Level-1 Instruction"
			"\n\t\tcache in a cycle",
	},
	{
		.ctrnum = 136,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_L2I_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the Level-2 Instruction cache",
	},
	{
		.ctrnum = 137,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_PTE_WRITES",
		.desc = "A translation entry was written into the Page Table"
			"\n\t\tEntry array in the Level-2 TLB",
	},
	{
		.ctrnum = 138,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_WRITES",
		.desc = "Translation entries were written into the Combined"
			"\n\t\tRegion and Segment Table Entry array and the Page"
			"\n\t\tTable Entry array in the Level-2 TLB",
	},
	{
		.ctrnum = 139,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_ENGINES_BUSY",
		.desc = "The number of Level-2 TLB translation engines busy"
			"\n\t\tin a cycle",
	},
	{
		.ctrnum = 140,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TEND",
		.desc = "A TEND instruction has completed in a constrained"
			"\n\t\ttransactional-execution mode",
	},
	{
		.ctrnum = 141,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TEND",
		.desc = "A TEND instruction has completed in a non-"
			"\n\t\tconstrained transactional-execution mode",
	},
	{
		.ctrnum = 143,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1C_TLB2_MISSES",
		.desc = "Increments by one for any cycle where a level-1"
			"\n\t\tcache or level-2 TLB miss is in progress",
	},
	{
		.ctrnum = 144,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache without intervention",
	},
	{
		.ctrnum = 145,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip memory",
	},
	{
		.ctrnum = 146,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache with intervention",
	},
	{
		.ctrnum = 147,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCLUSTER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Cluster Level-3 cache withountervention",
	},
	{
		.ctrnum = 148,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCLUSTER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Cluster memory",
	},
	{
		.ctrnum = 149,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCLUSTER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Cluster Level-3 cache with intervention",
	},
	{
		.ctrnum = 150,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCLUSTER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Cluster Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 151,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCLUSTER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Cluster memory",
	},
	{
		.ctrnum = 152,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFCLUSTER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Cluster Level-3 cache with intervention",
	},
	{
		.ctrnum = 153,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 154,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer memory",
	},
	{
		.ctrnum = 155,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-3 cache with intervention",
	},
	{
		.ctrnum = 156,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer Level-4 cache",
	},
	{
		.ctrnum = 157,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_OFFDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer Level-4 cache",
	},
	{
		.ctrnum = 158,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_ONCHIP_L3_SOURCED_WRITES_RO",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip L3 but a read-only invalidate was done"
			"\n\t\tto remove other copies of the cache line",
	},
	{
		.ctrnum = 162,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache without intervention",
	},
	{
		.ctrnum = 163,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip memory",
	},
	{
		.ctrnum = 164,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCHIP_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-3 cache with intervention",
	},
	{
		.ctrnum = 165,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCLUSTER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Cluster Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 166,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCLUSTER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Cluster memory",
	},
	{
		.ctrnum = 167,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONCLUSTER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Cluster Level-3 cache with intervention",
	},
	{
		.ctrnum = 168,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCLUSTER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Cluster Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 169,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCLUSTER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Cluster memory",
	},
	{
		.ctrnum = 170,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFCLUSTER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Cluster Level-3 cache with intervention",
	},
	{
		.ctrnum = 171,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_L3_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-3 cache without"
			"\n\t\tintervention",
	},
	{
		.ctrnum = 172,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_MEMORY_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer memory",
	},
	{
		.ctrnum = 173,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_L3_SOURCED_WRITES_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-3 cache with intervention",
	},
	{
		.ctrnum = 174,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_ONDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer Level-4 cache",
	},
	{
		.ctrnum = 175,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1I_OFFDRAWER_L4_SOURCED_WRITES",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer Level-4 cache",
	},
	{
		.ctrnum = 224,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "BCD_DFP_EXECUTION_SLOTS",
		.desc = "Count of floating point execution slots used for"
			"\n\t\tfinished Binary Coded Decimal to Decimal Floating"
			"\n\t\tPoint conversions. Instructions: CDZT, CXZT, CZDT,"
			"\n\t\tCZXT",
	},
	{
		.ctrnum = 225,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "VX_BCD_EXECUTION_SLOTS",
		.desc = "Count of floating point execution slots used for"
			"\n\t\tfinished vector arithmetic Binary Coded Decimal"
			"\n\t\tinstructions. Instructions: VAP, VSP, VMPVMSP, VDP,"
			"\n\t\tVSDP, VRP, VLIP, VSRP, VPSOPVCP, VTP, VPKZ, VUPKZ,"
			"\n\t\tVCVB, VCVBG, VCVDVCVDG",
	},
	{
		.ctrnum = 226,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DECIMAL_INSTRUCTIONS",
		.desc = "Decimal instructions dispatched. Instructions: CVB,"
			"\n\t\tCVD, AP, CP, DP, ED, EDMK, MP, SRP, SP, ZAP",
	},
	{
		.ctrnum = 232,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "LAST_HOST_TRANSLATIONS",
		.desc = "Last Host Translation done",
	},
	{
		.ctrnum = 243,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TABORT",
		.desc = "A transaction abort has occurred in a non-"
			"\n\t\tconstrained transactional-execution mode",
	},
	{
		.ctrnum = 244,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_NO_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is not"
			"\n\t\tusing any special logic to allow the transaction to"
			"\n\t\tcomplete",
	},
	{
		.ctrnum = 245,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is using"
			"\n\t\tspecial logic to allow the transaction to complete",
	},
	{
		.ctrnum = 247,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_ACCESS",
		.desc = "Cycles CPU spent obtaining access to Deflate unit",
	},
	{
		.ctrnum = 252,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_CYCLES",
		.desc = "Cycles CPU is using Deflate unit",
	},
	{
		.ctrnum = 264,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_CC",
		.desc = "Increments by one for every DEFLATE CONVERSION CALL"
			"\n\t\tinstruction executed",
	},
	{
		.ctrnum = 265,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = NULL,
		.desc = "Increments by one for every DEFLATE CONVERSION CALL"
			"\n\t\tinstruction executed that ended in Condition Codes"
			"\n\t\t0, 1 or 2",
	},
	{
		.ctrnum = 448,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_ONE_THR_ACTIVE",
		.desc = "Cycle count with one thread active",
	},
	{
		.ctrnum = 449,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_TWO_THR_ACTIVE",
		.desc = "Cycle count with two threads active",
	},
};

static struct counters cpumcf_z16_counters[] = {
	{
		.ctrnum = 128,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_RO_EXCL_WRITES",
		.desc = "A directory write to the Level-1 Data cache where"
			"\n\t\tthe line was originally in a Read-Only state in the"
			"\n\t\tcache but has been updated to be in the Exclusive"
			"\n\t\tstate that allows stores to the cache line.",
	},
	{
		.ctrnum = 129,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_WRITES",
		.desc = "A translation has been written into The Translation"
			"\n\t\tLookaside Buffer 2 (TLB2) and the request was made"
			"\n\t\tby the Level-1 Data cache. This is a replacement"
			"\n\t\tfor what was provided for the DTLB on z13 and prior"
			"\n\t\tmachines.",
	},
	{
		.ctrnum = 130,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_MISSES",
		.desc = "A TLB2 miss is in progress for a request made by"
			"\n\t\tthe Level-1 Data cache. Incremented by one for"
			"\n\t\tevery TLB2 miss in progress for the Level-1 Data"
			"\n\t\tcache on this cycle. This is a replacement for what"
			"\n\t\twas provided for the DTLB on z13 and prior"
			"\n\t\tmachines.",
	},
	{
		.ctrnum = 131,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "CRSTE_1MB_WRITES",
		.desc = "A translation entry was written into the Combined"
			"\n\t\tRegion and Segment Table Entry array in the Level-2"
			"\n\t\tTLB for a one-megabyte page.",
	},
	{
		.ctrnum = 132,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_GPAGE_WRITES",
		.desc = "A translation entry for a two-gigabyte page was"
			"\n\t\twritten into the Level-2 TLB.",
	},
	{
		.ctrnum = 134,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB2_WRITES",
		.desc = "A translation entry has been written into the"
			"\n\t\tTranslation Lookaside Buffer 2 (TLB2) and the"
			"\n\t\trequest was made by the instruction cache. This is"
			"\n\t\ta replacement for what was provided for the ITLB on"
			"\n\t\tz13 and prior machines.",
	},
	{
		.ctrnum = 135,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB2_MISSES",
		.desc = "A TLB2 miss is in progress for a request made by"
			"\n\t\tthe Level-1 Instruction cache. Incremented by one"
			"\n\t\tfor every TLB2 miss in progress for the Level-1"
			"\n\t\tInstruction cache in a cycle. This is a replacement"
			"\n\t\tfor what was provided for the ITLB on z13 and prior"
			"\n\t\tmachines.",
	},
	{
		.ctrnum = 137,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_PTE_WRITES",
		.desc = "A translation entry was written into the Page Table"
			"\n\t\tEntry array in the Level-2 TLB.",
	},
	{
		.ctrnum = 138,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_WRITES",
		.desc = "Translation entries were written into the Combined"
			"\n\t\tRegion and Segment Table Entry array and the Page"
			"\n\t\tTable Entry array in the Level-2 TLB.",
	},
	{
		.ctrnum = 139,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_ENGINES_BUSY",
		.desc = "The number of Level-2 TLB translation engines busy"
			"\n\t\tin a cycle.",
	},
	{
		.ctrnum = 140,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TEND",
		.desc = "A TEND instruction has completed in a constrained"
			"\n\t\ttransactional-execution mode.",
	},
	{
		.ctrnum = 141,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TEND",
		.desc = "A TEND instruction has completed in a non-"
			"\n\t\tconstrained transactional-execution mode.",
	},
	{
		.ctrnum = 143,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1C_TLB2_MISSES",
		.desc = "Increments by one for any cycle where a level-1"
			"\n\t\tcache or level-2 TLB miss is in progress.",
	},
	{
		.ctrnum = 145,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_REQ",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestor’s Level-2 cache.",
	},
	{
		.ctrnum = 146,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_REQ_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestor’s Level-2 cache with"
			"\n\t\tintervention.",
	},
	{
		.ctrnum = 147,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_REQ_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestor’s Level-2 cache after using"
			"\n\t\tchip level horizontal persistence, Chip-HP hit.",
	},
	{
		.ctrnum = 148,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_REQ_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestor’s Level-2 cache after using"
			"\n\t\tdrawer level horizontal persistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 149,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache.",
	},
	{
		.ctrnum = 150,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache with intervention.",
	},
	{
		.ctrnum = 151,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache after using chip"
			"\n\t\tlevel horizontal persistence, Chip-HP hit.",
	},
	{
		.ctrnum = 152,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache using drawer level"
			"\n\t\thorizontal persistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 153,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_MODULE",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Module Level-2 cache.",
	},
	{
		.ctrnum = 154,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_DRAWER",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-2 cache.",
	},
	{
		.ctrnum = 155,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_OFF_DRAWER",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-2 cache.",
	},
	{
		.ctrnum = 156,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP_MEMORY",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip memory.",
	},
	{
		.ctrnum = 157,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_MODULE_MEMORY",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Module memory.",
	},
	{
		.ctrnum = 158,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_DRAWER_MEMORY",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer memory.",
	},
	{
		.ctrnum = 159,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_OFF_DRAWER_MEMORY",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer memory.",
	},
	{
		.ctrnum = 160,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_MODULE_IV",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Module Level-2"
			"\n\t\tcache with intervention.",
	},
	{
		.ctrnum = 161,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_MODULE_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Module Level-2"
			"\n\t\tcache using chip horizontal persistence, Chip-HP"
			"\n\t\thit.",
	},
	{
		.ctrnum = 162,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_MODULE_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Module Level-2"
			"\n\t\tcache using drawer level horizontal persistence,"
			"\n\t\tDrawer-HP hit.",
	},
	{
		.ctrnum = 163,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_DRAWER_IV",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Drawer Level-2"
			"\n\t\tcache with intervention.",
	},
	{
		.ctrnum = 164,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_DRAWER_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tinstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Drawer Level-2"
			"\n\t\tcache using chip level horizontal persistence, Chip-"
			"\n\t\tHP hit.",
	},
	{
		.ctrnum = 165,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_DRAWER_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tinstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Drawer Level-2"
			"\n\t\tcache using drawer level horizontal persistence,"
			"\n\t\tDrawer-HP hit.",
	},
	{
		.ctrnum = 166,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_OFF_DRAWER_IV",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tinstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an Off-Drawer Level-2"
			"\n\t\tcache with intervention.",
	},
	{
		.ctrnum = 167,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_OFF_DRAWER_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tinstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an Off-Drawer Level-2"
			"\n\t\tcache using chip level horizontal persistence, Chip-"
			"\n\t\tHP hit.",
	},
	{
		.ctrnum = 168,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_OFF_DRAWER_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an Off-Drawer Level-2"
			"\n\t\tcache using drawer level horizontal persistence,"
			"\n\t\tDrawer-HP hit.",
	},
	{
		.ctrnum = 169,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_REQ",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tthe requestors Level-2 cache.",
	},
	{
		.ctrnum = 170,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_REQ_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache with"
			"\n\t\tintervention.",
	},
	{
		.ctrnum = 171,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_REQ_CHIP_HIT",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache using chip level"
			"\n\t\thorizontal persistence, Chip-HP hit.",
	},
	{
		.ctrnum = 172,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_REQ_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestor’s Level-2 cache using drawer"
			"\n\t\tlevel horizontal persistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 173,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache.",
	},
	{
		.ctrnum = 174,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tan On-Chip Level-2 cache with intervention.",
	},
	{
		.ctrnum = 175,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP_CHIP_HIT",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache using chip level"
			"\n\t\thorizontal persistence, Chip-HP hit.",
	},
	{
		.ctrnum = 176,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip level 2 cache using drawer level"
			"\n\t\thorizontal persistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 177,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_MODULE",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Module Level-2 cache.",
	},
	{
		.ctrnum = 178,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_DRAWER",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tan On-Drawer Level-2 cache.",
	},
	{
		.ctrnum = 179,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_OFF_DRAWER",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tan Off-Drawer Level-2 cache.",
	},
	{
		.ctrnum = 180,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP_MEMORY",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Chip memory.",
	},
	{
		.ctrnum = 181,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_MODULE_MEMORY",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Module memory.",
	},
	{
		.ctrnum = 182,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_DRAWER_MEMORY",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom On-Drawer memory.",
	},
	{
		.ctrnum = 183,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_OFF_DRAWER_MEMORY",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom Off-Drawer memory.",
	},
	{
		.ctrnum = 224,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "BCD_DFP_EXECUTION_SLOTS",
		.desc = "Count of floating point execution slots used for"
			"\n\t\tfinished Binary Coded Decimal to Decimal Floating"
			"\n\t\tPoint conversions. Instructions: CDZT, CXZT, CZDT,"
			"\n\t\tCZXT.",
	},
	{
		.ctrnum = 225,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "VX_BCD_EXECUTION_SLOTS",
		.desc = "Count of floating point execution slots used for"
			"\n\t\tfinished vector arithmetic Binary Coded Decimal"
			"\n\t\tinstructions. Instructions: VAP, VSP, VMP, VMSP,"
			"\n\t\tVDP, VSDP, VRP, VLIP, VSRP, VPSOP, VCP, VTP, VPKZ,"
			"\n\t\tVUPKZ, VCVB, VCVBG, VCVD, VCVDG.",
	},
	{
		.ctrnum = 226,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DECIMAL_INSTRUCTIONS",
		.desc = "Decimal instruction dispatched. Instructions: CVB,"
			"\n\t\tCVD, AP, CP, DP, ED, EDMK, MP, SRP, SP, ZAP.",
	},
	{
		.ctrnum = 232,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "LAST_HOST_TRANSLATIONS",
		.desc = "Last Host Translation done",
	},
	{
		.ctrnum = 244,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TABORT",
		.desc = "A transaction abort has occurred in a non-"
			"\n\t\tconstrained transactional-execution mode.",
	},
	{
		.ctrnum = 245,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_NO_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is not"
			"\n\t\tusing any special logic to allow the transaction to"
			"\n\t\tcomplete.",
	},
	{
		.ctrnum = 246,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is using"
			"\n\t\tspecial logic to allow the transaction to complete.",
	},
	{
		.ctrnum = 248,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_ACCESS",
		.desc = "Cycles CPU spent obtaining access to Deflate unit",
	},
	{
		.ctrnum = 253,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_CYCLES",
		.desc = "Cycles CPU is using Deflate unit",
	},
	{
		.ctrnum = 256,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "SORTL",
		.desc = "Increments by one for every SORT LISTS instruction"
			"\n\t\texecuted.",
	},
	{
		.ctrnum = 265,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_CC",
		.desc = "Increments by one for every DEFLATE CONVERSION CALL"
			"\n\t\tinstruction executed.",
	},
	{
		.ctrnum = 266,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_CCFINISH",
		.desc = "Increments by one for every DEFLATE CONVERSION CALL"
			"\n\t\tinstruction executed that ended in Condition Codes"
			"\n\t\t0, 1 or 2.",
	},
	{
		.ctrnum = 267,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_INVOCATIONS",
		.desc = "Increments by one for every Neural Network"
			"\n\t\tProcessing Assist instruction executed.",
	},
	{
		.ctrnum = 268,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_COMPLETIONS",
		.desc = "Increments by one for every Neural Network"
			"\n\t\tProcessing Assist instruction executed that ended"
			"\n\t\tin Condition Codes 0, 1 or 2.",
	},
	{
		.ctrnum = 269,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_WAIT_LOCK",
		.desc = "Cycles CPU spent obtaining access to IBM Z"
			"\n\t\tIntegrated Accelerator for AI.",
	},
	{
		.ctrnum = 270,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_HOLD_LOCK",
		.desc = "Cycles CPU is using IBM Z Integrated Accelerator"
			"\n\t\tfor AI.",
	},
	{
		.ctrnum = 448,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_ONE_THR_ACTIVE",
		.desc = "Cycle count with one thread active",
	},
	{
		.ctrnum = 449,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_TWO_THR_ACTIVE",
		.desc = "Cycle count with two threads active",
	},
};

static struct counters cpumcf_z17_counters[] = {
	{
		.ctrnum = 128,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1D_RO_EXCL_WRITES",
		.desc = "A directory write to the Level-1 Data cache where"
			"\n\t\tthe line was originally in a Read-Only state in the"
			"\n\t\tcache but has been updated to be in the Exclusive"
			"\n\t\tstate that allows stores to the cache line.",
	},
	{
		.ctrnum = 129,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_WRITES",
		.desc = "A translation has been written into The Translation"
			"\n\t\tLookaside Buffer 2 (TLB2) and the request was made"
			"\n\t\tby the Level-1 Data cache. This is a replacement"
			"\n\t\tfor what was provided for the DTLB on z13 and prior"
			"\n\t\tmachines.",
	},
	{
		.ctrnum = 130,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_MISSES",
		.desc = "A TLB2 miss is in progress for a request made by"
			"\n\t\tthe Level-1 Data cache. Incremented by one for"
			"\n\t\tevery TLB2 miss in progress for the Level-1 Data"
			"\n\t\tcache on this cycle. This is a replacement for what"
			"\n\t\twas provided for the DTLB on z13 and prior"
			"\n\t\tmachines.",
	},
	{
		.ctrnum = 131,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "CRSTE_1MB_WRITES",
		.desc = "A translation entry was written into the Combined"
			"\n\t\tRegion and Segment Table Entry array in the Level-2"
			"\n\t\tTLB for a one-megabyte page.",
	},
	{
		.ctrnum = 132,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DTLB2_GPAGE_WRITES",
		.desc = "A translation entry for a two-gigabyte page was"
			"\n\t\twritten into the Level-2 TLB.",
	},
	{
		.ctrnum = 134,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB2_WRITES",
		.desc = "A translation entry has been written into the"
			"\n\t\tTranslation Lookaside Buffer 2 (TLB2) and the"
			"\n\t\trequest was made by the Level-1 Instruction cache."
			"\n\t\tThis is a replacement for what was provided for the"
			"\n\t\tITLB on z13 and prior machines.",
	},
	{
		.ctrnum = 135,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ITLB2_MISSES",
		.desc = "A TLB2 miss is in progress for a request made by"
			"\n\t\tthe Level-1 Instruction cache. Incremented by one"
			"\n\t\tfor every TLB2 miss in progress for the Level-1"
			"\n\t\tInstruction cache in a cycle. This is a replacement"
			"\n\t\tfor what was provided for the ITLB on z13 and prior"
			"\n\t\tmachines.",
	},
	{
		.ctrnum = 137,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_PTE_WRITES",
		.desc = "A translation entry was written into the Page Table"
			"\n\t\tEntry array in the Level-2 TLB.",
	},
	{
		.ctrnum = 138,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_CRSTE_WRITES",
		.desc = "Translation entries were written into the Combined"
			"\n\t\tRegion and Segment Table Entry array and the Page"
			"\n\t\tTable Entry array in the Level-2 TLB.",
	},
	{
		.ctrnum = 139,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TLB2_ENGINES_BUSY",
		.desc = "The number of Level-2 TLB translation engines busy"
			"\n\t\tin a cycle.",
	},
	{
		.ctrnum = 140,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TEND",
		.desc = "A TEND instruction has completed in a constrained"
			"\n\t\ttransactional-execution mode.",
	},
	{
		.ctrnum = 141,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TEND",
		.desc = "A TEND instruction has completed in a non-"
			"\n\t\tconstrained transactional-execution mode.",
	},
	{
		.ctrnum = 143,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "L1C_TLB2_MISSES",
		.desc = "Increments by one for any cycle where a Level-1"
			"\n\t\tcache or Level-2 TLB miss is in progress.",
	},
	{
		.ctrnum = 145,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_REQ",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache.",
	},
	{
		.ctrnum = 146,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_REQ_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache with"
			"\n\t\tintervention.",
	},
	{
		.ctrnum = 147,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_REQ_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache after using"
			"\n\t\tchip level horizontal persistence, Chip-HP hit.",
	},
	{
		.ctrnum = 148,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_REQ_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache after using"
			"\n\t\tdrawer level horizontal persistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 149,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache.",
	},
	{
		.ctrnum = 150,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP_IV",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache with intervention.",
	},
	{
		.ctrnum = 151,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache after using chip"
			"\n\t\tlevel horizontal persistence, Chip-HP hit.",
	},
	{
		.ctrnum = 152,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache after using drawer"
			"\n\t\tlevel horizontal persistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 153,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_MODULE",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Module Level-2 cache.",
	},
	{
		.ctrnum = 154,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_DRAWER",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-2 cache.",
	},
	{
		.ctrnum = 155,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_OFF_DRAWER",
		.desc = "A directory write to the Level-1 Data cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-2 cache.",
	},
	{
		.ctrnum = 156,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_CHIP_MEMORY",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from On-Chip memory.",
	},
	{
		.ctrnum = 157,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_MODULE_MEMORY",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from On-Module memory.",
	},
	{
		.ctrnum = 158,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_ON_DRAWER_MEMORY",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from On-Drawer memory.",
	},
	{
		.ctrnum = 159,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DCW_OFF_DRAWER_MEMORY",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from Off-Drawer memory.",
	},
	{
		.ctrnum = 160,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_MODULE_IV",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Module Level-2"
			"\n\t\tcache with intervention.",
	},
	{
		.ctrnum = 161,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_MODULE_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Module Level-2"
			"\n\t\tcache after using chip level horizontal"
			"\n\t\tpersistence, Chip-HP hit.",
	},
	{
		.ctrnum = 162,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_MODULE_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Module Level-2"
			"\n\t\tcache after using drawer level horizontal"
			"\n\t\tpersistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 163,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_DRAWER_IV",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Drawer Level-2"
			"\n\t\tcache with intervention.",
	},
	{
		.ctrnum = 164,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_DRAWER_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tinstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Drawer Level-2"
			"\n\t\tcache after using chip level horizontal"
			"\n\t\tpersistence, Chip-HP hit.",
	},
	{
		.ctrnum = 165,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_ON_DRAWER_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tinstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an On-Drawer Level-2"
			"\n\t\tcache after using drawer level horizontal"
			"\n\t\tpersistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 166,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_OFF_DRAWER_IV",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tinstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an Off-Drawer Level-2"
			"\n\t\tcache with intervention.",
	},
	{
		.ctrnum = 167,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_OFF_DRAWER_CHIP_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tinstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an Off-Drawer Level-2"
			"\n\t\tcache after using chip level horizontal"
			"\n\t\tpersistence, Chip-HP hit.",
	},
	{
		.ctrnum = 168,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "IDCW_OFF_DRAWER_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Data or Level-1"
			"\n\t\tInstruction cache directory where the returned"
			"\n\t\tcache line was sourced from an Off-Drawer Level-2"
			"\n\t\tcache after using drawer level horizontal"
			"\n\t\tpersistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 169,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_REQ",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tthe requestors Level-2 cache.",
	},
	{
		.ctrnum = 170,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_REQ_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache with"
			"\n\t\tintervention.",
	},
	{
		.ctrnum = 171,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_REQ_CHIP_HIT",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache after using"
			"\n\t\tchip level horizontal persistence, Chip-HP hit.",
	},
	{
		.ctrnum = 172,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_REQ_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom the requestors Level-2 cache after using"
			"\n\t\tdrawer level horizontal persistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 173,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache.",
	},
	{
		.ctrnum = 174,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP_IV",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache with intervention.",
	},
	{
		.ctrnum = 175,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP_CHIP_HIT",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip Level-2 cache after using chip"
			"\n\t\tlevel horizontal persistence, Chip-HP hit.",
	},
	{
		.ctrnum = 176,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_CHIP_DRAWER_HIT",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Chip level 2 cache after using drawer"
			"\n\t\tlevel horizontal persistence, Drawer-HP hit.",
	},
	{
		.ctrnum = 177,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_MODULE",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Module Level-2 cache.",
	},
	{
		.ctrnum = 178,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_ON_DRAWER",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an On-Drawer Level-2 cache.",
	},
	{
		.ctrnum = 179,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "ICW_OFF_DRAWER",
		.desc = "A directory write to the Level-1 Instruction cache"
			"\n\t\tdirectory where the returned cache line was sourced"
			"\n\t\tfrom an Off-Drawer Level-2 cache.",
	},
	{
		.ctrnum = 202,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "CYCLES_SAMETHRD",
		.desc = "The number of cycles the CPU is not in wait state"
			"\n\t\tand the CPU is running by itself on the Core.",
	},
	{
		.ctrnum = 203,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "CYCLES_DIFFTHRD",
		.desc = "The number of cycles the CPU is not in wait state"
			"\n\t\tand the CPU is running with another thread on the"
			"\n\t\tCore.",
	},
	{
		.ctrnum = 204,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "INST_SAMETHRD",
		.desc = "The number of instructions executed on the CPU and"
			"\n\t\tthe CPU is running by itself on the Core.",
	},
	{
		.ctrnum = 205,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "INST_DIFFTHRD",
		.desc = "The number of instructions executed on the CPU and"
			"\n\t\tthe CPU is running with another thread on the Core.",
	},
	{
		.ctrnum = 206,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "WRONG_BRANCH_PREDICTION",
		.desc = "A count of the number of branches that were"
			"\n\t\tpredicted incorrectly by the branch prediction"
			"\n\t\tlogic in the Core. This includes incorrectly"
			"\n\t\tpredicted branches that are executed in Firmware."
			"\n\t\tExamples of instructions implemented in Firmware"
			"\n\t\tare complicated instructions like MVCL (Move"
			"\n\t\tCharacter Long) and PC (Program Call).",
	},
	{
		.ctrnum = 225,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "VX_BCD_EXECUTION_SLOTS",
		.desc = "Count of floating point execution slots used for"
			"\n\t\tfinished vector arithmetic Binary Coded Decimal"
			"\n\t\tinstructions. Instructions: VAP, VSP, VMP, VMSP,"
			"\n\t\tVDP, VSDP, VRP, VLIP, VSRP, VPSOP, VCP, VTP, VPKZ,"
			"\n\t\tVUPKZ, VCVB, VCVBG, VCVD, VCVDG, VSCHP, VSCSHP,"
			"\n\t\tVCSPH, VCLZDP, VPKZR, VSRPR, VUPKZH, VUPKZL, VTZ,"
			"\n\t\tVUPH, VUPL, VCVBX, VCVDX.",
	},
	{
		.ctrnum = 226,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DECIMAL_INSTRUCTIONS",
		.desc = "Decimal instruction dispatched. Instructions: CVB,"
			"\n\t\tCVD, AP, CP, DP, ED, EDMK, MP, SRP, SP, ZAP, TP.",
	},
	{
		.ctrnum = 232,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "LAST_HOST_TRANSLATIONS",
		.desc = "Last Host Translation done.",
	},
	{
		.ctrnum = 244,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_NC_TABORT",
		.desc = "A transaction abort has occurred in a non-"
			"\n\t\tconstrained transactional-execution mode.",
	},
	{
		.ctrnum = 245,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_NO_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is not"
			"\n\t\tusing any special logic to allow the transaction to"
			"\n\t\tcomplete.",
	},
	{
		.ctrnum = 246,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "TX_C_TABORT_SPECIAL",
		.desc = "A transaction abort has occurred in a constrained"
			"\n\t\ttransactional-execution mode and the CPU is using"
			"\n\t\tspecial logic to allow the transaction to complete.",
	},
	{
		.ctrnum = 248,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_ACCESS",
		.desc = "Cycles CPU spent obtaining access to Deflate unit.",
	},
	{
		.ctrnum = 253,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_CYCLES",
		.desc = "Cycles CPU is using Deflate unit.",
	},
	{
		.ctrnum = 256,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "SORTL",
		.desc = "Increments by one for every SORT LISTS (SORTL)"
			"\n\t\tinstruction executed.",
	},
	{
		.ctrnum = 265,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_CC",
		.desc = "Increments by one for every DEFLATE CONVERSION CALL"
			"\n\t\t(DFLTCC) instruction executed.",
	},
	{
		.ctrnum = 266,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "DFLT_CCFINISH",
		.desc = "Increments by one for every DEFLATE CONVERSION CALL"
			"\n\t\t(DFLTCC) instruction executed that ended in"
			"\n\t\tCondition Codes 0, 1 or 2.",
	},
	{
		.ctrnum = 267,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_INVOCATIONS",
		.desc = "Increments by one for every NEURAL NETWORK"
			"\n\t\tPROCESSING ASSIST (NNPA) instruction executed.",
	},
	{
		.ctrnum = 268,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_COMPLETIONS",
		.desc = "Increments by one for every NEURAL NETWORK"
			"\n\t\tPROCESSING ASSIST (NNPA) instruction executed that"
			"\n\t\tended in Condition Code 0.",
	},
	{
		.ctrnum = 269,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_WAIT_LOCK",
		.desc = "Cycles CPU spent obtaining access to IBM Z"
			"\n\t\tIntegrated Accelerator for AI.",
	},
	{
		.ctrnum = 270,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_HOLD_LOCK",
		.desc = "Cycles CPU is using IBM Z Integrated Accelerator"
			"\n\t\tfor AI.",
	},
	{
		.ctrnum = 272,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_INST_ONCHIP",
		.desc = "A NEURAL NETWORK PROCESSING ASSIST (NNPA)"
			"\n\t\tinstruction has used the Local On-Chip IBM Z"
			"\n\t\tIntegrated Accelerator for AI during its execution",
	},
	{
		.ctrnum = 273,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_INST_OFFCHIP",
		.desc = "A NEURAL NETWORK PROCESSING ASSIST (NNPA)"
			"\n\t\tinstruction has used an Off-Chip IBM Z Integrated"
			"\n\t\tAccelerator for AI during its execution.",
	},
	{
		.ctrnum = 274,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_INST_DIFF",
		.desc = "A NEURAL NETWORK PROCESSING ASSIST (NNPA)"
			"\n\t\tinstruction has used a different IBM Z Integrated"
			"\n\t\tAccelerator for AI since it was last executed.",
	},
	{
		.ctrnum = 276,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_4K_PREFETCH",
		.desc = "Number of 4K prefetches done for a remote IBM Z"
			"\n\t\tIntegated Accelerator for AI.",
	},
	{
		.ctrnum = 277,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_COMPL_LOCK",
		.desc = "A PERFORM LOCKED OPERATION (PLO) has completed.",
	},
	{
		.ctrnum = 278,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_RETRY_LOCK",
		.desc = "A PERFORM LOCKED OPERATION (PLO) has been retried and"
			"\n\t\tthe CPU did not use any special logic to allow the"
			"\n\t\tPLO to complete.",
	},
	{
		.ctrnum = 279,
		.ctrset = CPUMF_CTRSET_EXTENDED,
		.name = "NNPA_RETRY_LOCK_WITH_PLO",
		.desc = "A PERFORM LOCKED OPERATION (PLO) has been retried and"
			"\n\t\tthe CPU is using special logic to allow PLO to"
			"\n\t\tcomplete.",
	},
	{
		.ctrnum = 448,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_ONE_THR_ACTIVE",
		.desc = "Cycle count with one thread active",
	},
	{
		.ctrnum = 449,
		.ctrset = CPUMF_CTRSET_MT_DIAG,
		.name = "MT_DIAG_CYCLES_TWO_THR_ACTIVE",
		.desc = "Cycle count with two threads active",
	},
};

/* Return the type number of the CPU Measurement facility from the sysfs file.
 * If the type number is equal to PERF_TYPE_RAW, then the prefix is 'r' to
 * specify the raw counter number by the perf tool.
 * If perf_pmu_register() kernel function assigned any other (higher) type
 * number, set the prefix to <type-nr>:
 */
static void set_prefix(int nr)
{
	if (nr == PERF_TYPE_RAW)
		strcat(prefix, "r");
	else
		snprintf(prefix, sizeof(prefix), "%d:", nr);
}

/* Parse tool parameters. In case of --help or --version, print
 * respective text to stdout and exit.
 * Only handle one option and simulate behavior of previous tool.
 */
static int parse_args(int argc, char **argv)
{
	int opt;

	actions[ACTION_NONE] = true;
	while ((opt = util_opt_getopt_long(argc, argv)) != EOF) {
		switch (opt) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case 'i':
			actions[ACTION_INFO] = true;
			break;
		case 'n':
			show_names = true;
			break;
		case 's':
			actions[ACTION_SAMPLE] = true;
			break;
		case 'c':
			actions[ACTION_CNT] = true;
			break;
		case 'C':
			actions[ACTION_CNTALL] = true;
			break;
		default:
			util_opt_print_parse_error(opt, argv);
			exit(EXIT_FAILURE);
		}
	}
	if (actions[ACTION_INFO])
		return ACTION_INFO;
	else if (actions[ACTION_CNT])
		return ACTION_CNT;
	else if (actions[ACTION_CNTALL])
		return ACTION_CNTALL;
	else if (actions[ACTION_SAMPLE])
		return ACTION_SAMPLE;

	return ACTION_NONE;
}

static unsigned long tohz(unsigned long value, unsigned long cpuspeed)
{
	return 1000000 * cpuspeed / value;
}

static void human(char *buffer, size_t buffer_len, unsigned long bytes)
{
	const char bu[] = " KMGTPEZY";
	size_t unit = 0;

	while (bytes >= 1024 && unit < strlen(bu)) {
		bytes /= 1024;
		++unit;
	}
	snprintf(buffer, buffer_len, "%ld%cB", bytes, bu[unit]);
}

static unsigned long div_ceil(unsigned long a, unsigned long b)
{
	return (a + b - 1) / b;
}

static void show_info(struct cpumf_info *p, int details)
{
	if (!p->have_counter && !p->have_samples) {
		warnx("No CPU-measurement facilities detected");
		return;
	}
	if (p->have_counter) {
		printf("CPU-measurement Counter Facility\n");
		if (details) {
			printf("----------------------------------------------"
			       "----------------------------\n");
			printf("Version: %d.%d\n\n", p->first_vn, p->second_vn);
			printf("Authorized counter sets:\n");
			if (!p->authorization)
				printf("    None\n");
			if (0x2 & p->authorization)
				printf("    Basic counter Set\n");
			if (0x8 & p->authorization)
				printf("    Crypto-Activity counter Set\n");
			if (0x1 & p->authorization)
				printf("    Extended counter Set\n");
			if (0x20 & p->authorization)
				printf("    MT-diagnostic counter Set\n");
			if (0x4 & p->authorization)
				printf("    Problem-State counter Set\n");
			if (0x8000 & p->authorization)
				printf("    Coprocessor Group counter Set\n");
			printf("\nLinux perf event support: %s\n\n",
				!p->have_counter ? "No" : "Yes (PMU: cpum_cf)");

		}
	} else
		warnx("No CPU-measurement counter facility detected");
	if (p->have_samples) {
		unsigned long total, fdiag;
		char text[32];

		printf("CPU-measurement Sampling Facility\n");
		if (details) {
			printf("----------------------------------------------"
			       "----------------------------\n");
			printf("Sampling Interval:\n");
			printf("     Minimum: %10ld cycles"
			       " (approx. %9ld Hz)\n", p->min_rate,
			       tohz(p->min_rate, p->cpu_speed));
			printf("     Maximum: %10ld cycles"
			       " (approx. %9ld Hz)\n", p->max_rate,
			       tohz(p->max_rate, p->cpu_speed));
			printf("\n");
			printf("Authorized sampling modes:\n");
			printf("     basic:      (sample size: %3d bytes)\n",
			       p->basic_sample_sz);
			printf("     diagnostic: (sample size: %3d bytes)\n",
			       p->diag_sample_sz);

			printf("\nLinux perf event support: %s\n\n",
				!p->have_samples ? "No" : "Yes (PMU: cpum_sf)");

			printf("Current sampling buffer settings for"
			       " cpum_sf:\n");
			printf("    Basic-sampling mode\n");
			total = p->min_sfb + div_ceil(p->min_sfb, PER_SDBT_SIZE);
			human(text, sizeof(text), PAGE_SIZE * total);
			printf("	Minimum: %6ld"
			       " sample-data-blocks (%6s)\n", p->min_sfb, text);
			total = p->max_sfb + div_ceil(p->max_sfb, PER_SDBT_SIZE);
			human(text, sizeof(text), PAGE_SIZE * total);
			printf("	Maximum: %6ld"
			       " sample-data-blocks (%6s)\n\n", p->max_sfb,
			       text);

			printf("    Diagnostic-sampling mode"
					" (including basic-sampling)\n");
			fdiag = div_ceil(p->diag_sample_sz, p->basic_sample_sz);
			total = fdiag * p->min_sfb
				+ div_ceil(p->min_sfb, PER_SDBT_SIZE);
			human(text, sizeof(text), PAGE_SIZE * total);
			printf("	Minimum: %6ld"
			       " sample-data-blocks (%6s)\n",
			       fdiag * p->min_sfb, text);
			total = fdiag * p->max_sfb
				+ div_ceil(p->max_sfb * fdiag, PER_SDBT_SIZE);
			human(text, sizeof(text), PAGE_SIZE * total);
			printf("	Maximum: %6ld"
			       " sample-data-blocks (%6s)\n", fdiag * p->max_sfb,
			       text);
			printf("        Size factor: %2ld\n", fdiag);
		}
	} else
		warnx("No CPU-measurement sampling facility detected");
}

/* Set the counter name for z15 counter numbered 265. It is either named
 * DFLT_CCERROR or DFLT_CCFINISH, depending on the linux version. The
 * counter was renamed from CCERROR to CCFINISH in linux version 5.8.
 * Check for existence of file /sys/devices/cpum_cf/events/DLFT_CCERROR.
 */
static void read_ccerror(struct counters *cp, size_t cp_cnt)
{
	char *ctrname, *path;
	struct stat sbuf;
	size_t i = 0;

	path = util_path_sysfs("devices/cpum_cf/events/DFLT_CCERROR");
	if (!stat(path, &sbuf))
		ctrname = "DFLT_CCERROR";
	else
		ctrname = "DFLT_CCFINISH";
	free(path);
	/* Find DFLT_CC{FINISH,ERROR} in table and set name */
	for (struct counters *p = cp; i < cp_cnt; ++i, ++p)
		if (p->ctrnum == 265) {
			p->name = ctrname;
			break;
		}
}

/* Read allnecessary information from /sysfs file /proc/service_levels */
static int read_info(void)
{
	int rc = EXIT_FAILURE;

	cpumf.have_counter = libcpumf_cpumcf_info(&cpumf.first_vn,
						  &cpumf.second_vn,
						  &cpumf.authorization);
	cpumf.have_samples = libcpumf_cpumsf_info(&cpumf.min_rate,
						  &cpumf.max_rate,
						  &cpumf.cpu_speed,
						  &cpumf.basic_sample_sz,
						  &cpumf.diag_sample_sz);
	if (cpumf.have_samples)
		libcpumf_sfb_info(&cpumf.min_sfb, &cpumf.max_sfb);
	cpumf.machine_type = util_arch_machine_type();
	if (cpumf.machine_type == UTIL_ARCH_MACHINE_TYPE_UNKNOWN)
		rc = EXIT_FAILURE;
	else
		rc = EXIT_SUCCESS;
	return rc;
}

static void show_hdr(void)
{
	printf("================================================"
	       "==============================\n\n"
	       "Raw\n"
	       "event	Name	Description\n"
	       "---------------------------"
	       "---------------------------------------------------\n");
}

#define	FORMATS	"%s%5lx\t%s\n\n                %s\n                %s\n\n"
#define	FORMATC	"%s%d%s\n\n                %s\n                %s %d / %s\n\n"

static void show_sample(void)
{
	printf("Perf events for activating the sampling facility\n");
	show_hdr();
	for (unsigned int i = 0; i < ARRAY_SIZE(def_samples); ++i) {
		printf(FORMATS, prefix, def_samples[i].counter,
		       def_samples[i].name, def_samples[i].desc,
		       "This event is not associated with a counter set.");
	}
}

static const char *name_counterset(int snr)
{
	switch (snr) {
	case CPUMF_CTRSET_BASIC: return "Basic Counter Set.";
	case CPUMF_CTRSET_PROBLEM_STATE: return "Problem-State Counter Set.";
	case CPUMF_CTRSET_CRYPTO: return "Crypto-Activity Counter Set.";
	case CPUMF_CTRSET_EXTENDED: return "Extended Counter Set.";
	case CPUMF_CTRSET_MT_DIAG: return "MT-diagnostic Counter Set.";
	default: return "Unknown Counter Set.";
	}
}

/* Check if counter set this counter belongs to has been authorized. */
static bool auth_counterset(struct counters *cp)
{
	if (cp->ctrset == CPUMF_CTRSET_BASIC && (cpumf.authorization & 2))
		return true;
	if (cp->ctrset == CPUMF_CTRSET_PROBLEM_STATE && (cpumf.authorization & 4))
		return true;
	if (cp->ctrset == CPUMF_CTRSET_CRYPTO && (cpumf.authorization & 8))
		return true;
	if (cp->ctrset == CPUMF_CTRSET_EXTENDED && (cpumf.authorization & 1))
		return true;
	if (cp->ctrset == CPUMF_CTRSET_MT_DIAG && (cpumf.authorization & 0x20))
		return true;
	return false;
}

/* Return pointer to counter set and size. */
static struct counters *get_counter(int ctrset, size_t *len)
{
	struct counters *cp = NULL;

	*len = 0;
	switch (ctrset) {
	case CPUMF_CTRSET_BASIC:
		if (cpumf.first_vn == 1) {
			cp = cpumcf_fvn1_counters;
			*len = ARRAY_SIZE(cpumcf_fvn1_counters);
		} else {
			cp = cpumcf_fvn3_counters;
			*len = ARRAY_SIZE(cpumcf_fvn3_counters);
		}
		break;
	case CPUMF_CTRSET_CRYPTO:
		if (cpumf.second_vn <= 5) {
			cp = cpumcf_svn_12345_counters;
			*len = ARRAY_SIZE(cpumcf_svn_12345_counters);
		} else {
			cp = cpumcf_svn_6_counters;
			*len = ARRAY_SIZE(cpumcf_svn_6_counters);
		}
		break;
	case CPUMF_CTRSET_EXTENDED:
		switch (cpumf.machine_type) {
		case UTIL_ARCH_MACHINE_TYPE_Z10_EC:
		case UTIL_ARCH_MACHINE_TYPE_Z10_BC:
			cp = cpumcf_z10_counters;
			*len = ARRAY_SIZE(cpumcf_z10_counters);
			break;
		case UTIL_ARCH_MACHINE_TYPE_ZE_196:
		case UTIL_ARCH_MACHINE_TYPE_ZE_114:
			cp = cpumcf_z196_counters;
			*len = ARRAY_SIZE(cpumcf_z196_counters);
			break;
		case UTIL_ARCH_MACHINE_TYPE_ZE_EC12:
		case UTIL_ARCH_MACHINE_TYPE_ZE_BC12:
			cp = cpumcf_zec12_counters;
			*len = ARRAY_SIZE(cpumcf_zec12_counters);
			break;
		case UTIL_ARCH_MACHINE_TYPE_Z13:
		case UTIL_ARCH_MACHINE_TYPE_Z13_S:
			cp = cpumcf_z13_counters;
			*len = ARRAY_SIZE(cpumcf_z13_counters);
			break;
		case UTIL_ARCH_MACHINE_TYPE_Z14:
		case UTIL_ARCH_MACHINE_TYPE_Z14_ZR1:
			cp = cpumcf_z14_counters;
			*len = ARRAY_SIZE(cpumcf_z14_counters);
			break;
		case UTIL_ARCH_MACHINE_TYPE_Z15:
		case UTIL_ARCH_MACHINE_TYPE_Z15_T02:
			cp = cpumcf_z15_counters;
			*len = ARRAY_SIZE(cpumcf_z15_counters);
			read_ccerror(cp, *len);
			break;
		case UTIL_ARCH_MACHINE_TYPE_Z16:
		case UTIL_ARCH_MACHINE_TYPE_Z16_A02:
			cp = cpumcf_z16_counters;
			*len = ARRAY_SIZE(cpumcf_z16_counters);
			break;
		case UTIL_ARCH_MACHINE_TYPE_Z17:
		case UTIL_ARCH_MACHINE_TYPE_Z17_2:
			cp = cpumcf_z17_counters;
			*len = ARRAY_SIZE(cpumcf_z17_counters);
			break;
		}
		break;
	}
	return cp;
}

static void show_counterset(bool all, struct counters *cp, size_t cp_cnt)
{
	char cnt_name[128];

	for (size_t i = 0; i < cp_cnt; ++i, ++cp) {
		if (!all && !auth_counterset(cp))
			continue;
		if (show_names)
			snprintf(cnt_name, sizeof cnt_name, "/name=%s/",
				 cp->name);
		else
			snprintf(cnt_name, sizeof cnt_name, "\t%s",
				 cp->name);
		printf(FORMATC, prefix, cp->ctrnum, cnt_name,
		       cp->desc, "Counter", cp->ctrnum,
		       name_counterset(cp->ctrset));
	}
}

static void show_counter(bool all)
{
	struct counters *cp;
	size_t cp_cnt;

	printf("perf event counter list for %s\n",
	       util_arch_machine_type_str());
	show_hdr();
	/* Basic counter set */
	cp = get_counter(CPUMF_CTRSET_BASIC, &cp_cnt);
	show_counterset(all, cp, cp_cnt);
	/* Crypto counter set */
	cp = get_counter(CPUMF_CTRSET_CRYPTO, &cp_cnt);
	show_counterset(all, cp, cp_cnt);
	/* Extended counter set */
	cp = get_counter(CPUMF_CTRSET_EXTENDED, &cp_cnt);
	show_counterset(all, cp, cp_cnt);
}

int main(int argc, char **argv)
{
	bool all = false;
	int ret;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	ret = parse_args(argc, argv);
	if (read_info() == EXIT_FAILURE)
		return EXIT_FAILURE;

	switch (ret) {
	case ACTION_CNT:
	case ACTION_CNTALL:
		all = ret == ACTION_CNTALL;
		ret = libcpumf_pmutype(S390_CPUMF_CF);
		if (ret >= EXIT_SUCCESS) {
			set_prefix(ret);
			show_counter(all);
		}
		break;
	case ACTION_SAMPLE:
		ret = libcpumf_pmutype(S390_CPUMF_SF);
		if (ret >= EXIT_SUCCESS) {
			set_prefix(ret);
			show_sample();
		}
		break;
	case ACTION_NONE:
	case ACTION_INFO:
		show_info(&cpumf, ret == ACTION_INFO);
		ret = EXIT_SUCCESS;
		break;
	}
	return ret;
}
