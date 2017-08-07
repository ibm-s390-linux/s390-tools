/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * Command line parsing
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <getopt.h>
#include "cpuplugd.h"

void print_usage(int is_error, char program_name[]);
void print_version();
int foreground;
int debug;
char *configfile;
int cpu_idle_limit;

void parse_options(int argc, char **argv)
{
	int config_file_specified = -1;
	const struct option long_options[] = {
		{ "help", no_argument,       NULL, 'h'},
		{ "foreground", no_argument, NULL, 'f' },
		{ "config", required_argument, NULL, 'c' },
		{ "version", no_argument, NULL, 'v' },
		{ "verbose", no_argument, NULL, 'V'   },
		{ NULL, 0, NULL, 0}
	};

	/* dont run without any argument */
	if (argc == 0 || argc == 1)
		print_usage(0, argv[0]);
	while (optind < argc) {
		int index = -1;
		struct option *opt = 0;
		int result = getopt_long(argc, argv, "hfc:vVm",
			long_options, &index);
		if (result == -1)
			break;		/* end of list */
		switch (result) {
		case 'h':
			print_usage(0, argv[0]);
			break;
		case 'f':
			foreground = 1;
			break;
		case 'c':
			/*
			 * This prevents -cbla and enforces the
			 * user to specify -c bla
			 */
			if (strcmp(argv[optind-1], optarg) == 0) {
				configfile = optarg;
				config_file_specified = 1;
			} else {
				cpuplugd_error("Unrecognized option: %s\n",
					       optarg);
				exit(1);
			}
			break;
		case 'v':
			print_version();
			break;
		case 'V':
			debug = 1;
			break;
		case 0:
			/* all parameter that do not appear in the optstring */
			opt = (struct option *)&(long_options[index]);
			printf("'%s' was specified.",
			       opt->name);
			if (opt->has_arg == required_argument)
				printf("Arg: <%s>", optarg);
			printf("\n");
			break;
		case '?':
			printf("Try '%s' --help' for more information.\n",
				argv[0]);
			exit(1);
			break;
		case -1:
			/*
			 * We also run in this case if no argument was
			 * specified
			 */
			break;
		default:
			print_usage(0, argv[0]);
		}
	}
	if (config_file_specified == -1) {
		printf("You have to specify a configuration file!\n");
		printf("Try '%s' --help' for more information.\n", argv[0]);
		exit(1);
	}
}
