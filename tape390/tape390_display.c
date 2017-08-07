/*
 * tape390_display - Display messages on the display unit of a tape drive
 *
 * Copyright IBM Corp. 2002, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <getopt.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "tape390_common.h"

#define TAPE390_DISPLAY _IOW('d', 1, struct display_struct)

/*
 * The TAPE390_DISPLAY belongs to linux-2.5/include/asm-s390/tape390.h
 *
 * The TAPE390_DISPLAY ioctl calls the Load Display command
 * which transfers 17 bytes of data from the channel to the subsystem:
 *     - 1 format control byte, and
 *     - two 8-byte messages
 *
 * Format control byte:
 *   0-2: New Message Overlay
 *     3: Alternate Messages
 *     4: Blink Message
 *     5: Display Low/High Message
 *     6: Reserved
 *     7: Automatic Load Request
 *
 */
#define TAPE_MSGTYPE_STANDARD           0
#define TAPE_MSGTYPE_UNLOAD             1
#define TAPE_MSGTYPE_LOAD               2
#define TAPE_MSGTYPE_NOOP               3
#define TAPE_MSGTYPE_UNLOAD_LOAD        7

typedef struct display_struct {
	struct {
		unsigned char   type            :3;
		unsigned char   alternate       :1;
		unsigned char   blink           :1;
		unsigned char   use_second      :1;
		unsigned char   reserved        :1;
		unsigned char   load_request    :1;
	}                       cntrl;
	char                    message1[8];
	char                    message2[8];
} __attribute__ ((packed))      display_struct;

/*  definitions  */
static char *help_text =
	"tape390_display: display one or two 8-byte messages on the display"
	"unit of a tape drive\n"
	"\n"
	"Usage: tape390_display <options> \"<message1>\" [\"<message2>\"] "
	"<device>"
	"\n\n"
	"where <options> are:\n"
	"\t-b | --blink\n"
	"\t\twill cause a single message to blink every 2 seconds\n"
	"\t\t(this option has only effect with a single message)\n"
	"\t-h | --help\n"
	"\t\tprint this text\n"
	"\t-v | --version\n"
	"\t\toutput version information and exit\n"
	"\t-l | --load\n"
	"\t\twill try to load the next tape if the loader is in system mode\n"
	"\t-q | --quiet\n"
	"\t\twill suppress all warning messages\n"
	"\t-t | --type \"standard|load|unload|noop|reload\"\n"
	"\t\tcontrols how the message is displayed:\n"
	"\t\t\tstandard = until the next tape movement (default)\n"
	"\t\t\tload     = until a tape is loaded\n"
	"\t\t\tunload   = until a tape is unloaded\n"
	"\t\t\tnoop     = not at all (test purposes)\n"
	"\t\t\treload   = message1 until tape is unloaded and message2\n"
	"\t\t\t           when the next tape is loaded\n"
	"\n"
	"Note: Characters to be displayed include capital letters (A-Z), "
	"numerics (0-9)\n"
	"and special characters within single quotes. However not all "
	"characters\n"
	"might be displayed on all tape devices. Special characters that "
	"are supported\n"
	"for 3490 are '@$#,./()*&+-=%|:_<>?;'.\n";

static int quiet;

/* end of definitions */

static int typename2int(char *name)
{
	char *typenames[] = {
		"standard",
		"unload",
		"load",
		"noop",
		NULL,
		NULL,
		NULL,
		"reload"
	};
	int	i;

	for(i = 0; i < 8; i++) {
		if(typenames[i] == NULL)
			continue;
		if(strcmp(typenames[i], name) == 0) {
			return i;
		}
	}

	fprintf(stderr, "Invalid message type <%s>\n", name);
	return -1;
}

static void strchkcpy(char *tgt, const char *src)
{
	static	char *nowarn = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			       "@$#,./'()*&+-=%:_<>?; ";
	char	c;
	char	warned;

	warned = 0;
	for(c=0; c<8 && *(src+c); c++) {
		*(tgt+c) = toupper(*(src+c));
		if (index(nowarn, *(tgt+c)) == NULL && !quiet && !warned) {
			fprintf(
				stderr,
				"WARNING: Some special characters may not "
				"display on all device types.\n"
			);
			warned = 1;
		}
	}
}

int main(int argc, char *argv[]) {

	char			*options = "hblqt:v";
	struct option		 long_options[] = {
		{ "help",	 no_argument,		NULL, 'h' },
		{ "blink",	 no_argument,		NULL, 'b' },
		{ "load",	 no_argument,		NULL, 'l' },
		{ "quiet",	 no_argument,		NULL, 'q' },
		{ "type",	 required_argument,	NULL, 't' },
		{ "version",     no_argument,           NULL, 'v' },
		{ NULL,		 0,			NULL, 0   }
	};
	char			*pathname;
	int			 c;
	int			 fd, ret = 0;
	struct display_struct	 ds;

	/* set name of program */
	set_prog_name(basename(argv[0]));

	memset(&ds, 0, sizeof(ds));
	ds.cntrl.type = TAPE_MSGTYPE_STANDARD;

	while(
		(c = getopt_long(argc, argv, options, long_options, NULL))
		!= EOF
	) {
		switch(c) {
			case 'h':
				fprintf(stderr, "%s", help_text);
				exit(0);
			case 'b':
				ds.cntrl.blink = 1;
				break;
			case 'l':
				ds.cntrl.load_request = 1;
				break;
			case 'q':
				quiet = 1;
				break;
			case 't': {
				int type = typename2int(optarg);

				if(type < 0)
					exit(1);

				ds.cntrl.type = type;
				break;
			}
			case 'v': {
				printf("tape390_display: zSeries tape "
				       "display control program version %s\n",
					RELEASE_STRING);
				printf("Copyright IBM Corp. 2002, 2017\n");
				exit(0);
			}
			default:
				fprintf(stderr, "Try '%s --help' for more"
						" information.\n",prog_name);
				exit(1);
		}
	}

	if(optind + 2 < argc ) {
		if(
			ds.cntrl.type == TAPE_MSGTYPE_LOAD &&
			ds.cntrl.load_request
		) {
			if(!quiet) {
				fprintf(
					stderr,
					"WARNING: "
					"A <load> message with the "
					"--load option will only "
					"display the first"
					"\nmessage.\n"
				);
			}
		} else if(
			ds.cntrl.type == TAPE_MSGTYPE_UNLOAD_LOAD &&
			ds.cntrl.load_request
		) {
			if(!quiet) {
				fprintf(
					stderr,
					"WARNING: "
					"A <reload> message with the "
					"--load option will only "
					"display the second"
					"\nmessage.\n"
				);
			}
		} else {
			ds.cntrl.alternate = 1;

			if(ds.cntrl.blink) {
				ds.cntrl.blink = 0;
				if(!quiet) {
					fprintf(
						stderr,
						"Alternate messages "
						"override blinking\n"
					);
				}
			}
		}
		strchkcpy(ds.message1, argv[optind]);
		strchkcpy(ds.message2, argv[optind+1]);
		pathname = argv[optind+2];
	} else if(optind + 1 < argc) {
		if(ds.cntrl.type == TAPE_MSGTYPE_UNLOAD_LOAD) {
			fprintf(stderr, "Reload message type requires "
					"two messages.\n");
			exit(1);
		} else if(ds.cntrl.type == TAPE_MSGTYPE_LOAD) {
			strchkcpy(ds.message2, argv[optind]);
		}
		strchkcpy(ds.message1, argv[optind]);
		pathname = argv[optind+1];
	} else {
		fprintf(stderr, "%s", help_text);
		exit(1);
	}

	/* check whether specified device node is tape */
	if (is_not_tape(pathname))
		exit(EXIT_MISUSE);

	/* open device                                 */
	fd = open_tape(pathname);

	ret = ioctl(fd, TAPE390_DISPLAY, &ds);
	if (ret != 0)
		fprintf(stderr, "TAPE390_DISPLAY failed\n");

	close(fd);

	return ret;
}

