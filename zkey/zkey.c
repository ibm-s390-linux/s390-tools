/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_panic.h"
#include "lib/util_prg.h"
#include "lib/zt_common.h"

#include "misc.h"
#include "pkey.h"

/*
 * Program configuration
 */
const struct util_prg prg = {
	.desc = "Generate, re-encipher, and validate secure AES keys",
	.command_args = "COMMAND SECURE-KEY-FILE",
	.args = "",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2017,
			.pub_last = 2017,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Available commands
 */
#define COMMAND_GENERATE	"generate"
#define COMMAND_REENCIPHER	"reencipher"
#define COMMAND_VALIDATE	"validate"

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_GENERATE,
	},
	{
		.option = {"xts", 0, NULL, 'x'},
		.desc = "Generate a secure AES key for the XTS cipher mode",
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "keybits", required_argument, NULL, 'k'},
		.argument = "SIZE",
		.desc = "Size of the AES key to be generated in bits. "
			"Valid sizes are 128, 192, and 256 bits. Secure keys "
			"for use with the XTS cipher mode can only use keys "
			" of 128 or 256 bits. Default is 256 bits",
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "clearkey", required_argument, NULL, 'c'},
		.argument = "CLEAR-KEY-FILE",
		.desc = "Name of a file containing the clear AES key in "
			"binary. If option --keybits/-k is omitted, then the "
			"size of the CLEAR-KEY-FILE determines the size "
			"of the AES key. If option --keybits/-k is specified, "
			"then the size of the CLEAR-KEY-FILE must match the "
			"specified key size. Valid file sizes are 16, 24, or "
			"32 bytes, and 32, or 64 bytes for keys to be used "
			"with XTS mode ciphers",
		.command = COMMAND_GENERATE,
	},
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = { "output", required_argument, NULL, 'f'},
		.argument = "OUTPUT-FILE",
		.desc = "Name of the output file to which the re-enciphered "
			"secure key is written. If this option is omitted, "
			"then the re-enciphered secure key will be replaced "
			"in the SECURE-KEY-FILE",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"to-new", 0, NULL, 'n'},
		.desc = "Re-enciphers a secure AES key that is currently "
			"enciphered with the master key in the CURRENT "
			"register with the master key in the NEW register",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"from-old", 0, NULL, 'o'},
		.desc = "Re-enciphers a secure AES key that is currently "
			"enciphered with the master key in the OLD register "
			"with the master key in the CURRENT register",
		.command = COMMAND_REENCIPHER,
	},
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "COMMON OPTIONS"
	},
	{
		.option = {"verbose", 0, NULL, 'V'},
		.desc = "Print additional information messages during processing",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#define ZKEY_COMMAND_STR_LEN	80

/*
 * Table of supported commands
 */
struct zkey_command {
	char *command;
	unsigned int abbrev_len;
	int (*function)(const char *keyfile);
	int need_cca_library;
	int need_pkey_device;
	char *short_desc;
	char *long_desc;
	int has_options;
};

static int command_generate(const char *keyfile);
static int command_reencipher(const char *keyfile);
static int command_validate(const char *keyfile);

static struct zkey_command zkey_commands[] = {
	{
		.command = COMMAND_GENERATE,
		.abbrev_len = 3,
		.function = command_generate,
		.need_pkey_device = 1,
		.short_desc = "Generate a secure AES key",
		.long_desc = "Generate a secure AES key either by "
			     "random or from a specified clear key",
		.has_options = 1,
	},
	{
		.command = COMMAND_REENCIPHER,
		.abbrev_len = 2,
		.function = command_reencipher,
		.need_cca_library = 1,
		.need_pkey_device = 1,
		.short_desc = "Re-encipher an existing secure AES key",
		.long_desc = "Re-encipher an existing secure AES "
			     "key with another CCA master key",
		.has_options = 1,
	},
	{
		.command = COMMAND_VALIDATE,
		.abbrev_len = 3,
		.function = command_validate,
		.need_pkey_device = 1,
		.short_desc = "Validate an existing secure AES key",
		.long_desc = "Validate an existing secure AES key and print "
			     "information about the key",
	},
	{ .command = NULL }
};

#define pr_verbose(fmt...)	if (g.verbose) \
					warnx(fmt)

static void print_usage_command(const struct zkey_command *command)
{
	char command_str[ZKEY_COMMAND_STR_LEN];
	unsigned int i;

	strncpy(command_str, command->command, sizeof(command_str) - 1);
	for (i = 0; i < command->abbrev_len; i++)
		command_str[i] = toupper(command_str[i]);

	printf("Usage: %s %s SECURE-KEY-FILE",
	       program_invocation_short_name, command_str);
	printf(" [OPTIONS]");
	if (prg.args)
		printf(" %s", prg.args);
	printf("\n\n");
	util_print_indented(command->long_desc, 0);

	if (command->has_options)
		printf("\n");
}

static void print_usage_command_list(void)
{
	struct zkey_command *cmd = zkey_commands;
	char command_str[ZKEY_COMMAND_STR_LEN];
	unsigned int i;

	util_prg_print_help();

	printf("COMMANDS\n");
	while (cmd->command) {
		strcpy(command_str, cmd->command);
		for (i = 0; i < cmd->abbrev_len; i++)
			command_str[i] = toupper(command_str[i]);
		printf("  %s\t%s\n", command_str, cmd->short_desc);
		cmd++;
	}
	printf("\n");
}

/*
 * --help printout
 */
static void print_help(const struct zkey_command *command)
{
	/* Print usage */
	if (!command)
		print_usage_command_list();
	else
		print_usage_command(command);

	/* Print parameter help */
	util_opt_print_help();

	if (!command) {
		printf("\n");
		printf("For more information use '%s COMMAND --help'.\n",
			program_invocation_short_name);
	}
}

/*
 * Global variables for program options
 */
static struct zkey_globals {
	char *clearkeyfile;
	char *outputfile;
	int xts;
	int verbose;
	long int keybits;
	int tonew;
	int fromold;
	void *lib_csulcca;
	t_CSNBKTC dll_CSNBKTC;
	int pkey_fd;
} g = {
	.pkey_fd = -1,
};

/*
 * Command handler for 'generate with clear key'
 *
 * Generate a secure key from the specified clear key.
 */
static int command_generate_clear(const char *keyfile)
{
	int rc;

	rc = generate_secure_key_clear(g.pkey_fd, keyfile,
				       g.keybits, g.xts,
				       g.clearkeyfile,
				       AUTOSELECT, AUTOSELECT,
				       g.verbose);
	if (rc != 0)
		rc = EXIT_FAILURE;
	return rc;
}

/*
 * Command handler for 'generate by random'.
 *
 * Generate a secure key by random using the pkey kernel module.
 */
static int command_generate_random(const char *keyfile)
{
	int rc;

	rc = generate_secure_key_random(g.pkey_fd, keyfile,
					g.keybits, g.xts,
					AUTOSELECT, AUTOSELECT,
					g.verbose);
	if (rc != 0)
		rc = EXIT_FAILURE;

	return rc;
}

/*
 * Command handler for 'generate'.
 *
 * Generate a new secure key either by random or from the specified clear key.
 */
static int command_generate(const char *keyfile)
{
	return g.clearkeyfile ? command_generate_clear(keyfile)
			      : command_generate_random(keyfile);
}


/*
 * Command handler for 'reencipher'.
 *
 * Re-encipher the specified secure key with the NEW or CURRENT CCA master key.
 */
static int command_reencipher(const char *keyfile)
{
	size_t secure_key_size;
	int rc, is_old_mk;
	u8 *secure_key;

	/* Read the secure key to be re-enciphered */
	secure_key = read_secure_key(keyfile, &secure_key_size, g.verbose);
	if (secure_key == NULL)
		return EXIT_FAILURE;

	rc = validate_secure_key(g.pkey_fd, secure_key, secure_key_size, NULL,
				 &is_old_mk, g.verbose);
	if (rc != 0) {
		warnx("The secure key in file '%s' is not valid", keyfile);
		rc = EXIT_FAILURE;
		goto out;
	}

	if (!g.fromold && !g.tonew) {
		/* Autodetect reencipher option */
		if (is_old_mk) {
			g.fromold = 1;
			util_print_indented("The secure key is currently "
					    "enciphered with the OLD CCA "
					    "master key and is being "
					    "re-enciphered with the CURRENT "
					    "CCA master key\n", 0);
		} else {
			g.tonew = 1;
			util_print_indented("The secure key is currently "
					    "enciphered with the CURRENT CCA "
					    "master key and is being "
					    "re-enciphered with the NEW CCA "
					    "master key\n", 0);
		}
	}

	/* Re-encipher the secure key */
	if (g.fromold) {
		if (!is_old_mk) {
			warnx("The secure key is already enciphered "
			      "with the CURRENT CCA master key");
			rc = EXIT_FAILURE;
			goto out;
		}

		pr_verbose("Secure key will be re-enciphered from OLD to the "
			   "CURRENT CCA master key");

		rc = key_token_change(g.dll_CSNBKTC,
				      secure_key, secure_key_size,
				      METHOD_OLD_TO_CURRENT,
				      g.verbose);
		if (rc != 0) {
			warnx("Re-encipher from OLD to CURRENT CCA "
			      "master key has failed");
			rc = EXIT_FAILURE;
			goto out;
		}
	}
	if (g.tonew) {
		pr_verbose("Secure key will be re-enciphered from CURRENT "
			   "to the NEW CCA master key");

		rc = key_token_change(g.dll_CSNBKTC,
				      secure_key, secure_key_size,
				      METHOD_CURRENT_TO_NEW, g.verbose);
		if (rc != 0) {
			warnx("Re-encipher from CURRENT to NEW CCA "
			      "master key has failed");
			rc = EXIT_FAILURE;
			goto out;
		}
	}

	pr_verbose("Secure key was re-enciphered successfully");

	/* Write the migrated secure key */
	rc = write_secure_key(g.outputfile ? g.outputfile : keyfile,
			      secure_key, secure_key_size, g.verbose);
	if (rc != 0)
		rc = EXIT_FAILURE;
out:
	free(secure_key);
	return rc;
}

/*
 * Command handler for 'validate'.
 *
 * Validates the specified secure key and prints out information about it.
 */
static int command_validate(const char *keyfile)
{
	size_t secure_key_size;
	size_t clear_key_size;
	u8 *secure_key;
	int is_old_mk;
	int rc;

	/* Read the secure key to be re-enciphered */
	secure_key = read_secure_key(keyfile, &secure_key_size, g.verbose);
	if (secure_key == NULL)
		return EXIT_FAILURE;

	rc = validate_secure_key(g.pkey_fd, secure_key, secure_key_size,
				 &clear_key_size, &is_old_mk, g.verbose);
	if (rc != 0) {
		warnx("The secure key in file '%s' is not valid", keyfile);
		rc = EXIT_FAILURE;
		goto out;
	}

	printf("Validation of secure key in file '%s':\n", keyfile);
	printf("  Status:          Valid\n");
	printf("  Secure key size: %lu bytes\n", secure_key_size);
	printf("  Clear key size:  %lu bits\n", clear_key_size);
	printf("  XTS type key:    %s\n",
	       secure_key_size > SECURE_KEY_SIZE ? "Yes" : "No");
	printf("  Encrypted with:  %s CCA master key\n",
	       is_old_mk ? "OLD" : "CURRENT");

out:
	free(secure_key);
	return rc;
}

static bool is_command(struct zkey_command *command, const char *str)
{
	char command_str[ZKEY_COMMAND_STR_LEN];
	size_t str_len = strlen(str);

	util_assert(sizeof(command_str) > strlen(command->command),
		    "Buffer 'command_str' too small for %s", command->command);
	if (str_len < command->abbrev_len)
		return false;
	if (str_len > strlen(command->command))
		return false;
	strncpy(command_str, command->command, str_len);
	if (strncasecmp(str, command_str, str_len) != 0)
		return false;

	return true;
}

/*
 * Find the command in the command table
 */
struct zkey_command *find_command(const char *command)
{
	struct zkey_command *cmd = zkey_commands;

	while (cmd->command) {
		if (is_command(cmd, command))
			return cmd;
		cmd++;
	}
	return NULL;
}

/*
 * Entry point
 */
int main(int argc, char *argv[])
{
	struct zkey_command *command = NULL;
	char *keyfile = NULL;
	int arg_count = argc;
	char **args = argv;
	char *endp;
	int rc, c;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	/* Get command if one is pspecified */
	if (argc >= 2 && strncmp(argv[1], "-", 1) != 0) {
		command = find_command(argv[1]);
		if (command == NULL) {
			misc_print_invalid_command(argv[1]);
			return EXIT_FAILURE;
		}

		arg_count = argc - 1;
		args = &argv[1];

		if (argc >= 3 && strncmp(argv[2], "-", 1) != 0) {
			keyfile = argv[2];
			arg_count = argc - 2;
			args = &argv[2];
		}
	}

	util_opt_set_command(command ? command->command : NULL);
	util_prg_set_command(command ? command->command : NULL);

	while (1) {
		c = util_opt_getopt_long(arg_count, args);
		if (c == -1)
			break;
		switch (c) {
		case 'x':
			g.xts = 1;
			break;
		case 'k':
			g.keybits = strtol(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.keybits <= 0 ||
			    (g.keybits == LONG_MAX && errno == ERANGE)) {
				warnx("Invalid value for '--keybits'|'-c': "
				      "'%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case 'c':
			g.clearkeyfile = optarg;
			break;
		case 'f':
			g.outputfile = optarg;
			break;
		case 'n':
			g.tonew = 1;
			break;
		case 'o':
			g.fromold = 1;
			break;
		case 'V':
			g.verbose = 1;
			break;
		case 'h':
			print_help(command);
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		default:
			util_opt_print_parse_error(c, args);
			return EXIT_FAILURE;
		}
	}

	if (optind < arg_count) {
		util_prg_print_arg_error(args[optind]);
		return EXIT_FAILURE;
	}

	if (command == NULL) {
		misc_print_missing_command();
		return EXIT_FAILURE;
	}

	if (keyfile == NULL) {
		misc_print_required_parm("SECURE-KEY-FILE");
		return EXIT_FAILURE;
	}

	if (command->need_cca_library) {
		rc = load_cca_library(&g.lib_csulcca, &g.dll_CSNBKTC,
				      g.verbose);
		if (rc != 0)
			goto out;
	}
	if (command->need_pkey_device) {
		g.pkey_fd = open_pkey_device(g.verbose);
		if (g.pkey_fd == -1)
			goto out;
	}

	umask(0077);

	rc = command->function(keyfile);

out:
	if (g.lib_csulcca)
		dlclose(g.lib_csulcca);
	if (g.pkey_fd >= 0)
		close(g.pkey_fd);
	return rc;
}
