/*
 * vmconvert - Convert z/VM VMDUMPs into Linux lkcd dumps
 *
 * Main program
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <getopt.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "lib/vmdump.h"
#include "lib/zt_common.h"

static struct option longopts[] = {
	{"file",required_argument,0,'f'},
	{"help",no_argument,0,'h'},
	{"version",no_argument,0,'v'},
	{"output",required_argument,0,'o'},
	{0,0,0,0}
};

#define OPTSTRING "f:o:vh"
extern char *optarg;

/* Version info */
static const char version_text[] = "vmconvert: vmdump converter tool version "\
                                   RELEASE_STRING;

/* Copyright notice */
static const char copyright_notice[] = "Copyright IBM Corp. 2004, 2017";

/* Usage information */
static const char usage_text[] = \
"Usage: vmconvert -f VMDUMPFILE [-o OUTPUTFILE]\n" \
"       vmconvert VMDUMPFILE [OUTPUTFILE]\n" \
"\n" \
"Convert a vmdump into a lkcd (linux kernel crash dumps) dump.\n" \
"\n" \
"-h, --help                 Print this help, then exit.\n" \
"-v, --version              Print version information, then exit.\n" \
"-f, --file VMDUMPFILE      The vmdump file VMDUMPFILE, which should be\n"\
"                           converted.\n" \
"-o, --output OUTPUTFILE    The converted lkcd dump file OUTPUTFILE.\n"\
"                           The default file name is 'dump.lkcd'.\n";

/* Globals */
char inputFileName[1024];
char outputFileName[1024] = "dump.lkcd";

void 
parseOpts(int argc, char* argv[])
{
	int  inputFileSet = 0;
	int  outputFileSet = 0;
	int c, longIndex;
	while((c = getopt_long(argc, argv, OPTSTRING, longopts,
			       &longIndex)) != -1) {
		switch (c) {
			case 'f':
				strcpy(inputFileName, optarg);
				inputFileSet = 1;
				break;
			case 'o':
				strcpy(outputFileName, optarg);
				outputFileSet = 1;
				break;
			case 'h':
				printf("%s", usage_text);
				exit(0);
			case 'v':
				printf("%s\n", version_text);
				printf("%s\n", copyright_notice);
				exit(0);
			default:
				fprintf(stderr, "Try 'vmconvert --help' for"
						" more information.\n");
				exit(1);
		}
	}
	/* check for positional parameters */
	if (optind < argc) {
		int count = 0;
		while (optind < argc){
			if(!inputFileSet && count==0){
			strcpy(inputFileName, argv[optind]);
				inputFileSet = 1;
			} else if(!outputFileSet && count==1){
			strcpy(outputFileName, argv[optind]);
				outputFileSet = 1;
			} else if(count == 2){
				printf("%s", usage_text);
				exit(0);
			}
			count++;
			optind++;
		}
	}

	if(!inputFileSet){
		printf("%s: input file required - use '-f' option!\n",argv[0]);	
		exit(1);
	}
}
	
int
main(int argc, char* argv[])
{
	struct stat s;
	int rc;

	parseOpts(argc,argv);

	/* Check if output file already exists */
	if(stat(outputFileName,&s) == 0){
		char answer[100];
		printf("%s: overwrite file '%s'? ",argv[0],outputFileName);
		if(scanf("%s",answer) != 1)
			exit(1);
		if((strcmp(answer,"y") != 0) && (strcmp(answer,"yes") != 0))
			exit(0);
	}
	rc = vmdump_convert(inputFileName, outputFileName, argv[0]);
	if (!rc)
		printf("'%s' has been written successfully.\n", outputFileName);
	return rc;
}
