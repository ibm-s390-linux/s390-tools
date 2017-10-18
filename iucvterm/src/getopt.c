/*
 * iucvtty / iucvconn - IUCV Terminal Applications
 *
 * Processing of command line arguments
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/zt_common.h"

#include "iucvterm/config.h"
#include "iucvterm/functions.h"
#include "iucvterm/gettext.h"

static const char iucvtty_usage[] = N_(
"Usage: %s [-h|--help] [-v|--version]\n"
"       %s [-a <regex>] <terminal id>  [-- <login program> [<args>]]\n\n"
"Options:\n"
"  -h, --help           Print this help, then exit.\n"
"  -v, --version        Print version information, then exit.\n"
"  -a, --allow-from     Permit connections from particular z/VM guests only.\n"
"                       A z/VM guest is permitted if regex matches its name.\n"
);

static const char iucvconn_usage[] = N_(
"Usage: %s [-h|--help] [-v|--version]\n"
"       %s [-e esc] [-s <file>] <vm guest> <terminal id>\n\n"
"Options:\n"
"  -h, --help           Print this help, then exit.\n"
"  -v, --version        Print version information, then exit.\n"
"  -s, --sessionlog     Write terminal session to file.\n"
"  -e, --escape-char    Escape character (can be one of: A-Y, ], ^ or _)\n"
"                       Characters C, D, Q, S, Z and [ are not allowed.\n"
);

static const struct option iucvterm_long_opts[] = {
	{ "help",	  no_argument, NULL, 'h' },
	{ "version",	  no_argument, NULL, 'v' },
	{ "allow-from",	  required_argument, NULL, 'a' },
	{ "sessionlog",   required_argument, NULL, 's' },
	{ "escape-char",  required_argument, NULL, 'e' },
	{  NULL,	  no_argument, NULL,  0  }
};

struct tool_info {
	char		name[10];
	char		optstring[10];
	const char	*usage;
	unsigned char	reqNonOpts;
};

/* program specific command line settings */
static const struct tool_info iucv_tool[2] = {
	{	.name = "iucvtty",
		.optstring = "-hva:",
		.usage = iucvtty_usage,
		.reqNonOpts = 1,
	},
	{	.name = "iucvconn",
		.optstring = "-hvs:e:",
		.usage = iucvconn_usage,
		.reqNonOpts = 2,
	}
};


static void __noreturn usage_exit(const struct tool_info *prg, int is_error,
				  const char *msg)
{
	if (msg != NULL)
		fprintf(stderr, _("%s: %s\n"), prg->name, msg);
	fprintf(stderr, _(prg->usage), prg->name, prg->name);
	exit(is_error ? 1 : 0);	/* rc=1 .. invalid args */
}

static void __noreturn version_exit(const struct tool_info *prg)
{
	printf(_("%s: IUCV Terminal Applications, version %s\n"),
		prg->name, RELEASE_STRING);
	printf(_("Copyright IBM Corp. 2008, 2017\n"));
	exit(0);
}

static void cpy_or_exit(char *dest, const char *src, size_t size,
			const struct tool_info *prg, const char *param)
{
	if (strlen(src) >= size){
		fprintf(stderr,
			_("%s: %s exceeds the maximum of %zu characters\n"),
			prg->name, param, size - 1);
		exit(1);
	}
	strncpy(dest, src, size);
	dest[size - 1] = 0;
}

static void set_esc_or_exit(const struct tool_info *prg,
	                    const char val, unsigned char *esc)
{
	unsigned char upval = toupper(val);

	/* range of valid escape keys: A-Z [ \ ] ^ _ */
	if (upval < 'A' || upval > '_')
		usage_exit(prg, 1, _("The specified character is not a "
				     "valid escape character"));

	switch (upval) {
	case 'C':	/* interrupt (ISIG) */
	case 'D':	/* EoF / EoT */
	case 'Q':	/* XON */
	case 'S':	/* XOFF */
	case 'Z':	/* suspend (shell) */
	case '[':	/* ESC */
		usage_exit(prg, 1, _("The specified character is not a "
				     "valid escape character"));
	default:
		*esc = upval ^ 0100;	/* see ascii(7) */
		break;
	}
}


void parse_options(enum iucvterm_prg prg, struct iucvterm_cfg *config,
		   int argc, char **argv)
{
	int c;
	int index;
	int nonOpts = 0;

	config->cmd_parms = NULL;
	config->sessionlog = NULL;
	config->esc_char = '_' ^ 0100;		/* Ctrl-_ (0x1f) */
	config->flags = 0;

	while (1) {
		index = -1;
		c = getopt_long(argc, argv, iucv_tool[prg].optstring,
				iucvterm_long_opts, &index);
		if (c == -1)
			break;

		switch (c) {
		case 1:
			if (nonOpts >= iucv_tool[prg].reqNonOpts) {
				usage_exit(&iucv_tool[prg], 1, NULL);
				break;
			}
			switch (nonOpts) {
			case 0:
				if (prg == PROG_IUCV_CONN)
					cpy_or_exit(config->host, optarg,
						    sizeof(config->host),
						    &iucv_tool[prg],
						    _("<vm guest>"));
				else
					cpy_or_exit(config->service, optarg,
						    sizeof(config->service),
						    &iucv_tool[prg],
						    _("<terminal id>"));
				break;
			case 1:
				cpy_or_exit(config->service, optarg,
					    sizeof(config->service),
					    &iucv_tool[prg],
					    _("<terminal id>"));
				break;
			default:
				usage_exit(&iucv_tool[prg], 1, NULL);
				break;
			}
			++nonOpts;
			break;
		case 'a':/* max 80 */
			cpy_or_exit(config->client_re, optarg,
				    sizeof(config->client_re),
				    &iucv_tool[prg], _("<regex>"));
			if (is_regex_valid(config->client_re))
				exit(1);
			config->flags |= CFG_F_CHKCLNT;
			break;
		case 'e':
			switch (strlen(optarg)) {
			case 1:
				set_esc_or_exit(&iucv_tool[prg], optarg[0],
					        &config->esc_char);
				break;
			case 4:
				if (memcmp(optarg, "none", 4) == 0) {
					config->esc_char = 0;
					break;
				}
				/* fall through */
			default:
				usage_exit(&iucv_tool[prg], 1,
					   _("The escape character must be a "
					     "single character or 'none'"));
			}
			break;
		case 's':
			config->sessionlog = optarg;
			break;
		case 'h':
			usage_exit(&iucv_tool[prg], 0, NULL);
		case 'v':
			version_exit(&iucv_tool[prg]);
		case '?':
			printf(_("Try '%s --help' for more information.\n"),
				iucv_tool[prg].name);
			exit(1);
			break;
		}
	}

	if (optind < argc)	/* save additional parameters */
		config->cmd_parms = argv + optind;

	if (nonOpts < iucv_tool[prg].reqNonOpts)	/* not enough args */
		usage_exit(&iucv_tool[prg], 1,
			_("The command does not have enough arguments"));
}
