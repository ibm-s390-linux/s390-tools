/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2017, 2018
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

#include "keystore.h"
#include "misc.h"
#include "pkey.h"

/*
 * Program configuration
 */
const struct util_prg prg = {
	.desc = "Manage secure AES keys",
	.command_args = "COMMAND [SECURE-KEY-FILE]",
	.args = "",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2017,
			.pub_last = 2018,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Global variables for program options
 */
static struct zkey_globals {
	char *pos_arg;
	char *clearkeyfile;
	char *outputfile;
	bool xts;
	bool verbose;
	long int keybits;
	bool tonew;
	bool fromold;
	bool complete;
	bool inplace;
	bool staged;
	char *name;
	char *description;
	char *volumes;
	char *apqns;
	long int sector_size;
	char *newname;
	bool run;
	bool force;
	void *lib_csulcca;
	t_CSNBKTC dll_CSNBKTC;
	int pkey_fd;
	struct keystore *keystore;
} g = {
	.pkey_fd = -1,
	.sector_size = -1,
};

/*
 * Available commands
 */
#define COMMAND_GENERATE	"generate"
#define COMMAND_REENCIPHER	"reencipher"
#define COMMAND_VALIDATE	"validate"
#define COMMAND_IMPORT		"import"
#define COMMAND_EXPORT		"export"
#define COMMAND_LIST		"list  "
#define COMMAND_REMOVE		"remove"
#define COMMAND_CHANGE		"change"
#define COMMAND_RENAME		"rename"
#define COMMAND_COPY		"copy  "
#define COMMAND_CRYPTTAB	"crypttab"
#define COMMAND_CRYPTSETUP	"cryptsetup"

#define ZKEY_COMMAND_MAX_LEN	10

#define ENVVAR_ZKEY_REPOSITORY	"ZKEY_REPOSITORY"
#define DEFAULT_KEYSTORE	"/etc/zkey/repository"

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	/***********************************************************/
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
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES key in the repository. If "
			"option --name/-N is specified, then the generated "
			"secure AES key is stored in the repository. Parameter "
			"SECURE-KEY-FILE is not used when option --name/-M is "
			"specified",
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "description", required_argument, NULL, 'd'},
		.argument = "DESCRIPTION",
		.desc = "Textual description of the secure AES key in the "
			"repository",
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME:DMNAME[,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the repository",
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "apqns", required_argument, NULL, 'a'},
		.argument = "CARD.DOMAIN[,...]",
		.desc = "Comma-separated pairs of crypto cards and domains "
			"that are associated with the secure AES key in the "
			"repository",
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "sector-size", required_argument, NULL, 'S'},
		.argument = "bytes",
		.desc = "The sector size used with dm-crypt. It must be a power "
			"of two and in range 512 - 4096 bytes. If this option "
			"is omitted, the system default sector size (512) is "
			"used",
		.command = COMMAND_GENERATE,
	},
	/***********************************************************/
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
		.option = {"complete", 0, NULL, 'p'},
		.desc = "Completes a pending re-enciphering of a secure AES "
			"key that was re-enciphered with the master key in the "
			"NEW register",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"in-place", 0, NULL, 'i'},
		.desc = "Forces an in-place re-enchipering of a secure AES key",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"staged", 0, NULL, 's'},
		.desc = "Forces a staged re-enchipering of a secure AES key",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES keys in the repository that "
			"are to be re-enciphered. You can use wild-cards to "
			"select the keys to re-encipher.",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = { "apqns", required_argument, NULL, 'a'},
		.argument = "CARD.DOMAIN[,...]",
		.desc = "Comma-separated pairs of crypto cards and domains "
			"that are associated with the secure AES key in the "
			"repository. Use this option to re-encipher all keys "
			"associated with specific crypto cards",
		.command = COMMAND_REENCIPHER,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_VALIDATE,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES keys in the repository that "
			"are to be validated. You can use wild-cards to select "
			"the keys to validate.",
		.command = COMMAND_VALIDATE,
	},
	{
		.option = { "apqns", required_argument, NULL, 'a'},
		.argument = "CARD.DOMAIN[,...]",
		.desc = "Comma-separated pairs of crypto cards and domains "
			"that are associated with the secure AES key in the "
			"repository. Use this option to validate all keys "
			"associated with specific crypto cards",
		.command = COMMAND_VALIDATE,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_IMPORT,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the imported secure AES key in the repository",
		.command = COMMAND_IMPORT,
	},
	{
		.option = { "description", required_argument, NULL, 'd'},
		.argument = "DESCRIPTION",
		.desc = "Textual description of the secure AES key in the "
			"repository",
		.command = COMMAND_IMPORT,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME:DMNAME[,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the repository",
		.command = COMMAND_IMPORT,
	},
	{
		.option = { "apqns", required_argument, NULL, 'a'},
		.argument = "CARD.DOMAIN[,...]",
		.desc = "Comma-separated pairs of crypto cards and domains "
			"that are associated with the secure AES key in the "
			"repository",
		.command = COMMAND_IMPORT,
	},
	{
		.option = { "sector-size", required_argument, NULL, 'S'},
		.argument = "512|4096",
		.desc = "The sector size used with dm-crypt. It must be power "
			"of two and in range 512 - 4096 bytes. If this option "
			"is omitted, the system default sector size (512) is "
			"used",
		.command = COMMAND_IMPORT,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_EXPORT,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES key in the repository that is "
			"to be exported",
		.command = COMMAND_EXPORT,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_LIST,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES keys in the repository that "
			"are to be listed. You can use wild-cards to select "
			"the keys to list.",
		.command = COMMAND_LIST,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME[:DMNAME][,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the repository. Use this option to list all keys "
			"associated with specific volumes. The device-mapper "
			"name (DMNAME) is optional. If specified, only those "
			"keys are listed where both, the volume and the device-"
			"mapper name matches",
		.command = COMMAND_LIST,
	},
	{
		.option = { "apqns", required_argument, NULL, 'a'},
		.argument = "CARD.DOMAIN[,...]",
		.desc = "Comma-separated pairs of crypto cards and domains "
			"that are associated with the secure AES key in the "
			"repository. Use this option to list all keys "
			"associated with specific crypto cards",
		.command = COMMAND_LIST,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_REMOVE,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES key in the repository that is "
			"to be removed",
		.command = COMMAND_REMOVE,
	},
	{
		.option = {"force", 0, NULL, 'F'},
		.desc = "Do not prompt for a confirmation when removing a key",
		.command = COMMAND_REMOVE,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_CHANGE,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES key in the repository that is "
			"to be changed",
		.command = COMMAND_CHANGE,
	},
	{
		.option = { "description", required_argument, NULL, 'd'},
		.argument = "DESCRIPTION",
		.desc = "Textual description of the secure AES key in the "
			"repository",
		.command = COMMAND_CHANGE,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "[+|-]VOLUME:DMNAME[,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the repository. To add pairs of volume and device-"
			"mapper names to the key specify '+VOLUME:DMNAME[,...]'. "
			"To remove pairs of volume and device-mapper names "
			"from the key specify '-VOLUME:DMNAME[,...]'",
		.command = COMMAND_CHANGE,
	},
	{
		.option = { "apqns", required_argument, NULL, 'a'},
		.argument = "[+|-]CARD.DOMAIN[,...]",
		.desc = "Comma-separated pairs of crypto cards and domains "
			"that are associated with the secure AES key in the "
			"repository. To add pairs of crypto cards and domains "
			"to the key specify '+CARD.DOMAIN[,...]'. To remove "
			"pairs of crypto cards and domains from the key "
			"specify '-CARD.DOMAIN[,...]'",
		.command = COMMAND_CHANGE,
	},
	{
		.option = { "sector-size", required_argument, NULL, 'S'},
		.argument = "0|512|4096",
		.desc = "The sector size used with dm-crypt. It must be power "
			"of two and in range 512 - 4096 bytes. If this option "
			"is omitted, the system default sector size (512) is "
			"used",
		.command = COMMAND_CHANGE,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_RENAME,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES key in the repository that is "
			"to be renamed",
		.command = COMMAND_RENAME,
	},
	{
		.option = { "new-name", required_argument, NULL, 'w'},
		.argument = "NEW-NAME",
		.desc = "New name of the secure AES key in the repository",
		.command = COMMAND_RENAME,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_COPY,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES key in the repository that is "
			"to be copied",
		.command = COMMAND_COPY,
	},
	{
		.option = { "new-name", required_argument, NULL, 'w'},
		.argument = "NEW-NAME",
		.desc = "New name of the secure AES key in the repository",
		.command = COMMAND_COPY,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME:DMNAME[,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the copied secure AES "
			"key in the repository. If option '--volumes/-l' is "
			"omitted, no volumes are associated with the copied "
			"key, because only one key can be associated to a "
			"specific volume.",
		.command = COMMAND_COPY,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_CRYPTTAB,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME[:DMNAME][,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the repository. Use this option to select the volumes "
			"for which a crypttab entry is to be generated. The "
			"device-mapper name (DMNAME) is optional. If specified, "
			"only those volumes are selected where both, the "
			"volume and the device-mapper name matches",
		.command = COMMAND_CRYPTTAB,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_CRYPTSETUP,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME[:DMNAME][,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the repository. Use this option to select the volumes "
			"for which a cryptsetup command is to be generated or "
			"run. The device-mapper name (DMNAME) is optional."
			" If specified, only those volumes are selected where "
			"both, the volume and the device-mapper name matches",
		.command = COMMAND_CRYPTSETUP,
	},
	{
		.option = {"run", 0, NULL, 'r'},
		.desc = "Runs the generated cryptsetup command",
		.command = COMMAND_CRYPTSETUP,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "COMMON OPTIONS"
	},
	{
		.option = {"verbose", 0, NULL, 'V'},
		.desc = "Print additional information messages during "
			"processing",
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
	int (*function)(void);
	int need_cca_library;
	int need_pkey_device;
	char *short_desc;
	char *long_desc;
	int has_options;
	char *pos_arg;
	int pos_arg_optional;
	char *pos_arg_alternate;
	char **arg_alternate_value;
	int need_keystore;
};

static int command_generate(void);
static int command_reencipher(void);
static int command_validate(void);
static int command_import(void);
static int command_export(void);
static int command_list(void);
static int command_remove(void);
static int command_change(void);
static int command_rename(void);
static int command_copy(void);
static int command_crypttab(void);
static int command_cryptsetup(void);

static struct zkey_command zkey_commands[] = {
	{
		.command = COMMAND_GENERATE,
		.abbrev_len = 3,
		.function = command_generate,
		.need_pkey_device = 1,
		.short_desc = "Generate a secure AES key",
		.long_desc = "Generate a secure AES key either by "
			     "random or from a specified clear key and store "
			     "it either into SECURE-KEY-FILE or into the "
			     "repository",
		.has_options = 1,
		.pos_arg = "[SECURE-KEY-FILE]",
		.pos_arg_optional = 1,
		.pos_arg_alternate = "--name/-N",
		.arg_alternate_value = &g.name,
	},
	{
		.command = COMMAND_REENCIPHER,
		.abbrev_len = 2,
		.function = command_reencipher,
		.need_cca_library = 1,
		.need_pkey_device = 1,
		.short_desc = "Re-encipher an existing secure AES key",
		.long_desc = "Re-encipher an existing secure AES "
			     "key that is either contained in SECURE-KEY-FILE "
			     "or is stored in the repository with another "
			     "CCA master key",
		.has_options = 1,
		.pos_arg = "[SECURE-KEY-FILE]",
		.pos_arg_optional = 1,
	},
	{
		.command = COMMAND_VALIDATE,
		.abbrev_len = 3,
		.function = command_validate,
		.need_pkey_device = 1,
		.short_desc = "Validate an existing secure AES key",
		.long_desc = "Validate an existing secure AES key that is "
			     "either contained in SECURE-KEY-FILE or is stored"
			     "in the repository and print information about "
			     "the key",
		.has_options = 1,
		.pos_arg = "[SECURE-KEY-FILE]",
		.pos_arg_optional = 1,
	},
	{
		.command = COMMAND_IMPORT,
		.abbrev_len = 2,
		.function = command_import,
		.short_desc = "Import a secure AES key",
		.long_desc = "Import a secure AES key from a file into the "
			     "repository",
		.has_options = 1,
		.pos_arg = "SECURE-KEY-FILE",
		.need_keystore = 1,
	},
	{
		.command = COMMAND_EXPORT,
		.abbrev_len = 2,
		.function = command_export,
		.short_desc = "Export a secure AES key",
		.long_desc = "Export a secure AES key from the repository to "
			     "a file",
		.has_options = 1,
		.pos_arg = "SECURE-KEY-FILE",
		.need_keystore = 1,
	},
	{
		.command = COMMAND_LIST,
		.abbrev_len = 2,
		.function = command_list,
		.short_desc = "List keys in the repository",
		.long_desc = "List secure AES key in the repository",
		.has_options = 1,
		.need_keystore = 1,
	},
	{
		.command = COMMAND_REMOVE,
		.abbrev_len = 3,
		.function = command_remove,
		.short_desc = "Remove a secure AES key",
		.long_desc = "Remove a secure AES key from the repository",
		.has_options = 1,
		.need_keystore = 1,
	},
	{
		.command = COMMAND_CHANGE,
		.abbrev_len = 2,
		.function = command_change,
		.short_desc = "Change a secure AES key",
		.long_desc = "Change the properties of a secure AES key in "
			     "the repository",
		.has_options = 1,
		.need_keystore = 1,
	},
	{
		.command = COMMAND_RENAME,
		.abbrev_len = 3,
		.function = command_rename,
		.short_desc = "Rename a secure AES key",
		.long_desc = "Rename a secure AES key in the repository",
		.has_options = 1,
		.need_keystore = 1,
	},
	{
		.command = COMMAND_COPY,
		.abbrev_len = 2,
		.function = command_copy,
		.short_desc = "Copy a secure AES key",
		.long_desc = "Copy a secure AES key in the repository",
		.has_options = 1,
		.need_keystore = 1,
	},
	{
		.command = COMMAND_CRYPTTAB,
		.abbrev_len = 6,
		.function = command_crypttab,
		.short_desc = "Generate crypttab entries",
		.long_desc = "Generate crypttab entries for selected volumes",
		.has_options = 1,
		.need_keystore = 1,
	},
	{
		.command = COMMAND_CRYPTSETUP,
		.abbrev_len = 6,
		.function = command_cryptsetup,
		.short_desc = "Generate or run cryptsetup commands",
		.long_desc = "Generate or run cryptsetup commands for "
			     "selected volumes",
		.has_options = 1,
		.need_keystore = 1,
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

	printf("Usage: %s %s",
	       program_invocation_short_name, command_str);
	if (command->pos_arg != NULL)
		printf(" %s", command->pos_arg);
	if (command->has_options)
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
		printf("  %-*s    %s\n", ZKEY_COMMAND_MAX_LEN, command_str,
		       cmd->short_desc);
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
 * Command handler for 'generate with clear key'
 *
 * Generate a secure key from the specified clear key.
 */
static int command_generate_clear(void)
{
	int rc;

	rc = generate_secure_key_clear(g.pkey_fd, g.pos_arg,
				       g.keybits, g.xts,
				       g.clearkeyfile,
				       AUTOSELECT, AUTOSELECT,
				       g.verbose);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'generate by random'.
 *
 * Generate a secure key by random using the pkey kernel module.
 */
static int command_generate_random(void)
{
	int rc;

	rc = generate_secure_key_random(g.pkey_fd, g.pos_arg,
					g.keybits, g.xts,
					AUTOSELECT, AUTOSELECT,
					g.verbose);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'generate in repository'.
 *
 * Generate a secure key and store it in the repository.
 */
static int command_generate_repository(void)
{
	int rc;

	if (g.sector_size < 0)
		g.sector_size = 0;

	rc = keystore_generate_key(g.keystore, g.name, g.description, g.volumes,
				   g.apqns, g.sector_size, g.keybits, g.xts,
				   g.clearkeyfile, g.pkey_fd);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}


/*
 * Command handler for 'generate'.
 *
 * Generate a new secure key either by random or from the specified clear key.
 */
static int command_generate(void)
{
	if (g.pos_arg != NULL && g.name != NULL) {
		warnx(" Option '--name|-N' is not valid for generating a key "
		      "outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.name != NULL)
		return command_generate_repository();
	if (g.pos_arg != NULL) {
		if (g.volumes != NULL) {
			warnx("Option '--volumes|-l' is not valid for "
			      "generating a key outside of the repository");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}
		if (g.apqns != NULL) {
			warnx("Option '--apqns|-a' is not valid for "
			      "generating a key outside of the repository");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}
		if (g.description != NULL) {
			warnx("Option '--description|-d' is not valid for "
			      "generating a key outside of the repository");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}

		return g.clearkeyfile ? command_generate_clear()
				      : command_generate_random();
	}

	return EXIT_FAILURE;
}


/*
 * Command handler for 'reencipher'.
 *
 * Re-encipher the specified secure key with the NEW or CURRENT CCA master key.
 */
static int command_reencipher_file(void)
{
	size_t secure_key_size;
	int rc, is_old_mk;
	u8 *secure_key;

	if (g.name != NULL) {
		warnx("Option '--name|-N' is not valid for "
		      "re-enciphering a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.apqns != NULL) {
		warnx("Option '--apqns|-a' is not valid for "
		      "re-enciphering a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.inplace) {
		warnx("Option '--in-place|-i' is not valid for "
		      "re-enciphering a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.staged) {
		warnx("Option '--staged|-s' is not valid for "
		      "re-enciphering a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.complete) {
		warnx("Option '--complete|-p' is not valid for "
		      "re-enciphering a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	/* Read the secure key to be re-enciphered */
	secure_key = read_secure_key(g.pos_arg, &secure_key_size, g.verbose);
	if (secure_key == NULL)
		return EXIT_FAILURE;

	rc = validate_secure_key(g.pkey_fd, secure_key, secure_key_size, NULL,
				 &is_old_mk, g.verbose);
	if (rc != 0) {
		warnx("The secure key in file '%s' is not valid", g.pos_arg);
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
	rc = write_secure_key(g.outputfile ? g.outputfile : g.pos_arg,
			      secure_key, secure_key_size, g.verbose);
	if (rc != 0)
		rc = EXIT_FAILURE;
out:
	free(secure_key);
	return rc;
}

/*
 * Command handler for 'reencipher in repository'.
 *
 * Re-encipher the specified secure key with the NEW or CURRENT CCA master key.
 */
static int command_reencipher_repository(void)
{
	int rc;

	if (g.outputfile) {
		warnx("Option '--output|-o' is not valid for "
		      "re-enciphering a key in the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.inplace && g.staged) {
		warnx("Either '--in-place|-i' or '--staged|-s' can be "
		      "specified, but not both");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.complete) {
		if (g.inplace) {
			warnx("Option '--in-place|-i' is not valid together "
			      "with '--complete|-p'");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}
		if (g.staged) {
			warnx("Option '--staged|-s' is not valid together "
			      "with '--complete|-p'");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}
	}

	rc = keystore_reencipher_key(g.keystore, g.name, g.apqns, g.fromold,
				     g.tonew, g.inplace, g.staged, g.complete,
				     g.pkey_fd, g.dll_CSNBKTC);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'reencipher'.
 *
 * Re-encipher the specified secure key with the NEW or CURRENT CCA master key.
 */
static int command_reencipher(void)
{
	if (g.pos_arg != NULL)
		return command_reencipher_file();
	else
		return command_reencipher_repository();

	return EXIT_FAILURE;
}

/*
 * Command handler for 'validate'.
 *
 * Validates the specified secure key and prints out information about it.
 */
static int command_validate_file(void)
{
	char vp[VERIFICATION_PATTERN_LEN];
	size_t secure_key_size;
	size_t clear_key_size;
	u8 *secure_key;
	int is_old_mk;
	int rc;

	if (g.name != NULL) {
		warnx("Option '--name|-N' is not valid for "
		      "validating a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.apqns != NULL) {
		warnx("Option '--apqns|-a' is not valid for "
		      "validating a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	/* Read the secure key to be re-enciphered */
	secure_key = read_secure_key(g.pos_arg, &secure_key_size, g.verbose);
	if (secure_key == NULL)
		return EXIT_FAILURE;

	rc = validate_secure_key(g.pkey_fd, secure_key, secure_key_size,
				 &clear_key_size, &is_old_mk, g.verbose);
	if (rc != 0) {
		warnx("The secure key in file '%s' is not valid", g.pos_arg);
		rc = EXIT_FAILURE;
		goto out;
	}

	rc = generate_key_verification_pattern((char *)secure_key,
					       secure_key_size, vp, sizeof(vp),
					       g.verbose);
	if (rc != 0) {
		warnx("Failed to generate the verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		rc = EXIT_FAILURE;
		goto out;
	}

	printf("Validation of secure key in file '%s':\n", g.pos_arg);
	printf("  Status:                Valid\n");
	printf("  Secure key size:       %lu bytes\n", secure_key_size);
	printf("  Clear key size:        %lu bits\n", clear_key_size);
	printf("  XTS type key:          %s\n",
	       secure_key_size > SECURE_KEY_SIZE ? "Yes" : "No");
	printf("  Enciphered with:       %s CCA master key\n",
	       is_old_mk ? "OLD" : "CURRENT");
	printf("  Verification pattern:  %.*s\n", VERIFICATION_PATTERN_LEN / 2,
	       vp);
	printf("                         %.*s\n", VERIFICATION_PATTERN_LEN / 2,
	       &vp[VERIFICATION_PATTERN_LEN / 2]);

out:
	free(secure_key);
	return rc;
}

/*
 * Command handler for 'validate in repository'.
 *
 * Validates the specified secure key and prints out information about it.
 */
static int command_validate_repository(void)
{
	int rc;

	rc = keystore_validate_key(g.keystore, g.name, g.apqns, g.pkey_fd);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'validate'.
 *
 * Validates the specified secure key and prints out information about it.
 */
static int command_validate(void)
{
	if (g.pos_arg != NULL)
		return command_validate_file();
	else
		return command_validate_repository();

	return EXIT_FAILURE;
}

/*
 * Command handler for 'import'.
 *
 * Imports a secure key from a file into the key repository.
 */
static int command_import(void)
{
	int rc;

	if (g.name == NULL) {
		misc_print_required_parm("--name/-N");
		return EXIT_FAILURE;
	}

	if (g.sector_size < 0)
		g.sector_size = 0;

	rc = keystore_import_key(g.keystore, g.name, g.description, g.volumes,
				 g.apqns, g.sector_size, g.pos_arg);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'export'.
 *
 * Exports a secure key from the repository to a file
 */
static int command_export(void)
{
	int rc;

	if (g.name == NULL) {
		misc_print_required_parm("--name/-N");
		return EXIT_FAILURE;
	}

	rc = keystore_export_key(g.keystore, g.name, g.pos_arg);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'list'.
 *
 * Lists keys stored in the repository
 */
static int command_list(void)
{
	int rc;

	rc = keystore_list_keys(g.keystore, g.name, g.volumes, g.apqns);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'remove'.
 *
 * Remove a key from the repository
 */
static int command_remove(void)
{
	int rc;

	if (g.name == NULL) {
		misc_print_required_parm("--name/-N");
		return EXIT_FAILURE;
	}

	rc = keystore_remove_key(g.keystore, g.name, g.force);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'change'.
 *
 * Changes the properties of a key in the repository
 */
static int command_change(void)
{
	int rc;

	if (g.name == NULL) {
		misc_print_required_parm("--name/-N");
		return EXIT_FAILURE;
	}

	rc = keystore_change_key(g.keystore, g.name, g.description, g.volumes,
				 g.apqns, g.sector_size);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'rname'.
 *
 * renames a key in the repository
 */
static int command_rename(void)
{
	int rc;

	if (g.name == NULL) {
		misc_print_required_parm("--name/-N");
		return EXIT_FAILURE;
	}
	if (g.newname == NULL) {
		misc_print_required_parm("--new-name/-w");
		return EXIT_FAILURE;
	}

	rc = keystore_rename_key(g.keystore, g.name, g.newname);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'copy'.
 *
 * Copies a key in the repository
 */
static int command_copy(void)
{
	int rc;

	if (g.name == NULL) {
		misc_print_required_parm("--name/-N");
		return EXIT_FAILURE;
	}
	if (g.newname == NULL) {
		misc_print_required_parm("--new-name/-w");
		return EXIT_FAILURE;
	}

	rc = keystore_copy_key(g.keystore, g.name, g.newname, g.volumes);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'crypttab'.
 *
 * Generates crypttab entries for selected volumes
 */
static int command_crypttab(void)
{
	int rc;

	rc = keystore_crypttab(g.keystore, g.volumes);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'cryptsetup'.
 *
 * Generates and runs cryptsetup commands for selected volumes
 */
static int command_cryptsetup(void)
{
	int rc;

	rc = keystore_cryptsetup(g.keystore, g.volumes, g.run);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/**
 * Opens the keystore. The keystore directory is either the
 * default directory or as specified in an environment variable
 */
static int open_keystore(void)
{
	char *directory;

	directory = getenv(ENVVAR_ZKEY_REPOSITORY);
	if (directory == NULL)
		directory = DEFAULT_KEYSTORE;

	g.keystore = keystore_new(directory, g.verbose);

	return g.keystore == NULL ? EXIT_FAILURE : EXIT_SUCCESS;
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
 * Check if positional arguments are specified as needed by the command
 */
static int check_positional_arg(struct zkey_command *command)
{
	if (command->pos_arg_optional) {
		if (g.pos_arg == NULL &&
		    command->arg_alternate_value != NULL &&
		    *command->arg_alternate_value == NULL) {
			misc_print_required_parms(command->pos_arg,
						  command->pos_arg_alternate);
			return EXIT_FAILURE;
		}
	} else {
		if (g.pos_arg == NULL) {
			misc_print_required_parm(command->pos_arg);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

/*
 * Entry point
 */
int main(int argc, char *argv[])
{
	struct zkey_command *command = NULL;
	int arg_count = argc;
	char **args = argv;
	char *endp;
	int rc, c;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	/* Get command if one is specified */
	if (argc >= 2 && strncmp(argv[1], "-", 1) != 0) {
		command = find_command(argv[1]);
		if (command == NULL) {
			misc_print_invalid_command(argv[1]);
			return EXIT_FAILURE;
		}

		arg_count = argc - 1;
		args = &argv[1];

		if (argc >= 3 && strncmp(argv[2], "-", 1) != 0) {
			g.pos_arg = argv[2];
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
		case 'p':
			g.complete = 1;
			break;
		case 'i':
			g.inplace = 1;
			break;
		case 's':
			g.staged = 1;
			break;
		case 'N':
			g.name = optarg;
			break;
		case 'd':
			g.description = optarg;
			break;
		case 'l':
			g.volumes = optarg;
			break;
		case 'a':
			g.apqns = optarg;
			break;
		case 'S':
			g.sector_size = strtol(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.sector_size < 0 ||
			    (g.sector_size == LONG_MAX && errno == ERANGE)) {
				warnx("Invalid value for '--sector-size'|'-S': "
				      "'%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case 'w':
			g.newname = optarg;
			break;
		case 'r':
			g.run = 1;
			break;
		case 'F':
			g.force = 1;
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

	if (command->pos_arg != NULL) {
		if (check_positional_arg(command) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}

	if (command->need_keystore || g.pos_arg == NULL) {
		rc = open_keystore();
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	if (command->need_cca_library) {
		rc = load_cca_library(&g.lib_csulcca, &g.dll_CSNBKTC,
				      g.verbose);
		if (rc != 0) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}
	if (command->need_pkey_device) {
		g.pkey_fd = open_pkey_device(g.verbose);
		if (g.pkey_fd == -1) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}

	umask(0077);

	rc = command->function();

out:
	if (g.lib_csulcca)
		dlclose(g.lib_csulcca);
	if (g.pkey_fd >= 0)
		close(g.pkey_fd);
	if (g.keystore)
		keystore_free(g.keystore);
	return rc;
}
