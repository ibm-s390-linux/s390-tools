/**
 * util_arch_example - Example program for util_arch
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>

//! [code]
#include "lib/util_arch.h"
#include "lib/util_opt.h"
#include "lib/util_prg.h"

static const struct util_prg prg = {
	.desc = "Example for util_arch.",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2021,
			.pub_last = 2021,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static struct util_opt opt_vec[] = {
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

int main(int argc, char *argv[])
{
	int mach_type;
	unsigned long hsa_maxsize;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while (1) {
		int opt = util_opt_getopt_long(argc, argv);

		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case '?':
		default:
			fprintf(stderr, "Try '--help' for more information.\n");
			exit(EXIT_FAILURE);
		}
	}

	mach_type = util_arch_machine_type();
	hsa_maxsize = util_arch_hsa_maxsize();

	printf("Machine type:      %s (%d)\n",
	       util_arch_machine_type_to_str(mach_type), mach_type);
	printf("This machine type: %s\n", util_arch_machine_type_str());
	printf("HSA max. size:     %lu MiB\n", hsa_maxsize / (1024 * 1024));

	return EXIT_SUCCESS;
}
//! [code]
