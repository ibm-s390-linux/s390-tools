/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2017, 2020
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

#include "cca.h"
#include "ep11.h"
#include "keystore.h"
#include "misc.h"
#include "pkey.h"
#include "utils.h"
#include "kms.h"

/*
 * Program configuration
 */
static const struct util_prg prg = {
	.desc = "Manage secure AES keys",
	.command_args = "COMMAND [SECURE-KEY-FILE]",
	.args = "",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2017,
			.pub_last = 2020,
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
	bool noapqncheck;
	bool novolcheck;
	long int sector_size;
	char *volume_type;
	char *newname;
	char *key_type;
	char *label;
	bool local;
	bool gen_passphrase;
	char *passphrase_file;
	bool remove_passphrase;
	bool kms_bound;
	bool run;
	bool batch_mode;
	char *keyfile;
	long long keyfile_offset;
	long long keyfile_size;
	long long tries;
	bool force;
	bool open;
	bool format;
	bool refresh_properties;
	struct ext_lib lib;
	struct cca_lib cca;
	struct ep11_lib ep11;
	int pkey_fd;
	struct keystore *keystore;
	struct kms_info kms_info;
	int first_kms_option;
	struct kms_option *kms_options;
	size_t num_kms_options;
} g = {
	.pkey_fd = -1,
	.sector_size = -1,
	.lib.cca = &g.cca,
	.lib.ep11 = &g.ep11,
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
#define COMMAND_CONVERT		"convert"
#define COMMAND_KMS		"kms"
#define COMMAND_KMS_PLUGINS	"plugins"
#define COMMAND_KMS_BIND	"bind"
#define COMMAND_KMS_UNBIND	"unbind"
#define COMMAND_KMS_INFO	"info"
#define COMMAND_KMS_CONFIGURE	"configure"
#define COMMAND_KMS_REENCIPHER	"reencipher"
#define COMMAND_KMS_LIST	"list"
#define COMMAND_KMS_IMPORT	"import"
#define COMMAND_KMS_REFRESH	"refresh"

#define OPT_COMMAND_PLACEHOLDER	"PLACEHOLDER"

#define OPT_PLACEHOLDER					\
{							\
	.option = { "", 0, NULL, ' ' },			\
	.desc = OPT_COMMAND_PLACEHOLDER,		\
	.command = OPT_COMMAND_PLACEHOLDER,		\
}

#define ZKEY_COMMAND_MAX_LEN	10

#define ENVVAR_ZKEY_REPOSITORY	"ZKEY_REPOSITORY"
#define DEFAULT_KEYSTORE	"/etc/zkey/repository"

#define OPT_CRYPTSETUP_KEYFILE		256
#define OPT_CRYPTSETUP_KEYFILE_OFFSET	257
#define OPT_CRYPTSETUP_KEYFILE_SIZE	258
#define OPT_CRYPTSETUP_TRIES		259
#define OPT_CRYPTSETUP_OPEN		260
#define OPT_CRYPTSETUP_FORMAT		261
#define OPT_NO_APQN_CHECK		262
#define OPT_NO_VOLUME_CHECK		263
#define OPT_REFRESH_PROPERTIES		264
#define OPT_GEN_DUMMY_PASSPHRASE	265
#define OPT_SET_DUMMY_PASSPHRASE	266
#define OPT_REMOVE_DUMMY_PASSPHRASE	267

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
			"SECURE-KEY-FILE is not used when option --name/-N is "
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
		.option = {"no-apqn-check", 0, NULL, OPT_NO_APQN_CHECK},
		.desc = "Do not check if the specified APQN(s) are available. "
			"Use this option to associate APQN(s) with a secure "
			"AES key that are currently not available.",
		.command = COMMAND_GENERATE,
		.flags = UTIL_OPT_FLAG_NOSHORT,
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
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'. When this option is omitted, "
			"the default is 'luks2'",
		.command = COMMAND_GENERATE,
	},
#endif
	{
		.option = { "key-type", required_argument, NULL, 'K'},
		.argument = "type",
		.desc = "The type of the key. Possible values are '"
			KEY_TYPE_CCA_AESDATA"', '"KEY_TYPE_CCA_AESCIPHER"' "
			"and '"KEY_TYPE_EP11_AES"'. When this option is "
			"omitted, the default is '"KEY_TYPE_CCA_AESDATA"'",
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "local", 0, NULL, 'L'},
		.desc = "Generate the key locally. This is the default when no "
			"KMS plugin is bound to the repository. If the "
			"repository is bound to a KMS plugin, then keys are "
			"generated by the KMS per default.",
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "gen-dummy-passphrase", 0, NULL,
						OPT_GEN_DUMMY_PASSPHRASE},
		.desc = "Generate a dummy passphrase and associate it with the "
			"secure AES key used to encrypt LUKS2 volume(s). The "
			"LUKS2 passphrase is of less or no relevance for the "
			"security of the volume(s), when an secure AES key is "
			"used to encrypt the volume(s), and can therefore be "
			"stored insecurely inside the secure key repository.",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.command = COMMAND_GENERATE,
	},
	{
		.option = { "set-dummy-passphrase", required_argument, NULL,
						OPT_SET_DUMMY_PASSPHRASE},
		.argument = "passphrase-file",
		.desc = "Set a dummy passphrase to be associated with the "
			"secure AES key used to encrypt LUKS2 volume(s). The "
			"LUKS2 passphrase is of less or no relevance for the "
			"security of the volume(s), when an secure AES key is "
			"used to encrypt the volume(s), and can therefore be "
			"stored insecurely inside the secure key repository.",
		.flags = UTIL_OPT_FLAG_NOSHORT,
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
		.desc = "Completes a staged re-enciphering. Use this option "
			"after the new master key has been set (made "
			"active)",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"in-place", 0, NULL, 'i'},
		.desc = "Forces an in-place re-enchipering of a secure AES "
			"key. Re-enciphering from OLD to CURRENT is performed "
			"in-place per default",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"staged", 0, NULL, 's'},
		.desc = "Forces that the re-enciphering of a secure AES key is "
			"performed in staged mode. Re-enciphering from CURRENT "
			"to NEW is performed in staged mode per default",
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
	{
		.option = {"no-apqn-check", 0, NULL, OPT_NO_APQN_CHECK},
		.desc = "Do not check if the associated APQN(s) are available",
		.command = COMMAND_VALIDATE,
		.flags = UTIL_OPT_FLAG_NOSHORT,
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
		.option = {"no-apqn-check", 0, NULL, OPT_NO_APQN_CHECK},
		.desc = "Do not check if the specified APQN(s) are available. "
			"Use this option to associate APQN(s) with a secure "
			"AES key that are currently not available.",
		.command = COMMAND_IMPORT,
		.flags = UTIL_OPT_FLAG_NOSHORT,
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
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'. When this option is omitted, "
			"the default is 'luks2'",
		.command = COMMAND_IMPORT,
	},
#endif
	{
		.option = { "gen-dummy-passphrase", 0, NULL,
						OPT_GEN_DUMMY_PASSPHRASE},
		.desc = "Generate a dummy passphrase and associate it with the "
			"secure AES key used to encrypt LUKS2 volume(s). The "
			"LUKS2 passphrase is of less or no relevance for the "
			"security of the volume(s), when an secure AES key is "
			"used to encrypt the volume(s), and can therefore be "
			"stored insecurely inside the secure key repository.",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.command = COMMAND_IMPORT,
	},
	{
		.option = { "set-dummy-passphrase", required_argument, NULL,
						OPT_SET_DUMMY_PASSPHRASE},
		.argument = "passphrase-file",
		.desc = "Set a dummy passphrase to be associated with the "
			"secure AES key used to encrypt LUKS2 volume(s). The "
			"LUKS2 passphrase is of less or no relevance for the "
			"security of the volume(s), when an secure AES key is "
			"used to encrypt the volume(s), and can therefore be "
			"stored insecurely inside the secure key repository.",
		.flags = UTIL_OPT_FLAG_NOSHORT,
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
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'. Use this option to list all "
			"keys with the specified volumes type.",
		.command = COMMAND_LIST,
	},
#endif
	{
		.option = { "key-type", required_argument, NULL, 'K'},
		.argument = "type",
		.desc = "The type of the key. Possible values are '"
			KEY_TYPE_CCA_AESDATA"', '"KEY_TYPE_CCA_AESCIPHER"' "
			"and '"KEY_TYPE_EP11_AES"'. Use this option to list "
			"all keys with the specified key type.",
		.command = COMMAND_LIST,
	},
	{
		.option = { "local", 0, NULL, 'L'},
		.desc = "List local keys only. Local keys are not bound to a "
			"KMS plugin.",
		.command = COMMAND_LIST,
	},
	{
		.option = { "kms-bound", 0, NULL, 'M'},
		.desc = "List KMS-bound keys only. KMS-bound keys are bound to "
			"a KMS plugin.",
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
		.option = {"no-apqn-check", 0, NULL, OPT_NO_APQN_CHECK},
		.desc = "Do not check if the specified APQN(s) are available. "
			"Use this option to associate APQN(s) with a secure "
			"AES key that are currently not available.",
		.command = COMMAND_CHANGE,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "sector-size", required_argument, NULL, 'S'},
		.argument = "0|512|4096",
		.desc = "The sector size used with dm-crypt. It must be power "
			"of two and in range 512 - 4096 bytes. Specify 0 to "
			"use the system default sector size (512)",
		.command = COMMAND_CHANGE,
	},
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'",
		.command = COMMAND_CHANGE,
	},
#endif
	{
		.option = { "gen-dummy-passphrase", 0, NULL,
						OPT_GEN_DUMMY_PASSPHRASE},
		.desc = "Generate a dummy passphrase and associate it with the "
			"secure AES key used to encrypt LUKS2 volume(s). The "
			"LUKS2 passphrase is of less or no relevance for the "
			"security of the volume(s), when an secure AES key is "
			"used to encrypt the volume(s), and can therefore be "
			"stored insecurely inside the secure key repository.",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.command = COMMAND_CHANGE,
	},
	{
		.option = { "set-dummy-passphrase", required_argument, NULL,
						OPT_SET_DUMMY_PASSPHRASE},
		.argument = "passphrase-file",
		.desc = "Set a dummy passphrase to be associated with the "
			"secure AES key used to encrypt LUKS2 volume(s). The "
			"LUKS2 passphrase is of less or no relevance for the "
			"security of the volume(s), when an secure AES key is "
			"used to encrypt the volume(s), and can therefore be "
			"stored insecurely inside the secure key repository.",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.command = COMMAND_CHANGE,
	},
	{
		.option = { "remove-dummy-passphrase", 0, NULL,
						OPT_REMOVE_DUMMY_PASSPHRASE},
		.desc = "Remove an associated dummy passphrase used with LUKS2 "
			"volume(s).",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.command = COMMAND_CHANGE,
	},
	{
		.option = {"force", 0, NULL, 'F'},
		.desc = "Do not prompt for a confirmation when removing an "
			"associated dummy passphrase",
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
	{
		.option = { "local", 0, NULL, 'L'},
		.desc = "Copy the key to a local key. This is the default when "
			"no KMS plugin is bound to the repository. If the "
			"repository is bound to a KMS plugin, then keys are "
			"bound to the KMS per default, and KMS-bound key can "
			"only be copied to local keys.",
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
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'. Use this option to select "
			"the keys by its volume type for which a crypttab "
			"entry is to be generated",
		.command = COMMAND_CRYPTTAB,
	},
	{
		.option = {"key-file", required_argument, NULL,
			   OPT_CRYPTSETUP_KEYFILE},
		.argument = "FILE-NAME",
		.desc = "Read the passphrase from the specified file. "
			"The specified file is passed to the generated "
			"crypttab entry for LUKS2 volumes",
		.command = COMMAND_CRYPTTAB,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {"keyfile-offset", required_argument, NULL,
			   OPT_CRYPTSETUP_KEYFILE_OFFSET},
		.argument = "BYTES",
		.desc = "Specifies the number of bytes to skip in the file "
			"specified with option '--key-file'. "
			"The specified offset is passed to the generated "
			"crypttab entry for LUKS2 volumes. Not all "
			"distributions support the 'keyfile-offset' option in "
			"crypttab entries",
		.command = COMMAND_CRYPTTAB,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {"keyfile-size", required_argument, NULL,
			   OPT_CRYPTSETUP_KEYFILE_SIZE},
		.argument = "BYTES",
		.desc = "Specifies the number of bytes to read from the file "
			"specified with option '--key-file'. "
			"The specified size is passed to the generated "
			"crypttab entry for LUKS2 volumes. Not all "
			"distributions support the 'keyfile-size' option in "
			"crypttab entries",
		.command = COMMAND_CRYPTTAB,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {"tries", required_argument, NULL,
			   OPT_CRYPTSETUP_TRIES},
		.argument = "NUMBER",
		.desc = "Specifies how often the interactive input of the "
			"passphrase can be retried. "
			"The specified number is passed to the generated "
			"crypttab entry for LUKS2 volumes",
		.command = COMMAND_CRYPTTAB,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
#endif
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
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'. Use this option to select "
			"the keys by its volume type for which a crypttab "
			"entry is to be generated",
		.command = COMMAND_CRYPTSETUP,
	},
#endif
	{
		.option = {"run", 0, NULL, 'r'},
		.desc = "Runs the generated cryptsetup command",
		.command = COMMAND_CRYPTSETUP,
	},
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = {"key-file", required_argument, NULL,
			   OPT_CRYPTSETUP_KEYFILE},
		.argument = "FILE-NAME",
		.desc = "Read the passphrase from the specified file. "
			"This option is passed to the generated command(s) for "
			"LUKS2 volumes",
		.command = COMMAND_CRYPTSETUP,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {"keyfile-offset", required_argument, NULL,
			   OPT_CRYPTSETUP_KEYFILE_OFFSET},
		.argument = "BYTES",
		.desc = "Specifies the number of bytes to skip in the file "
			"specified with option '--key-file'. "
			"This option is passed to the generated command(s) for "
			"LUKS2 volumes",
		.command = COMMAND_CRYPTSETUP,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {"keyfile-size", required_argument, NULL,
			   OPT_CRYPTSETUP_KEYFILE_SIZE},
		.argument = "BYTES",
		.desc = "Specifies the number of bytes to read from the file "
			"specified with option '--key-file'. "
			"This option is passed to the generated command(s) for "
			"LUKS2 volumes",
		.command = COMMAND_CRYPTSETUP,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {"tries", required_argument, NULL,
			   OPT_CRYPTSETUP_TRIES},
		.argument = "NUMBER",
		.desc = "Specifies how often the interactive input of the "
			"passphrase can be retried. "
			"This option is passed to the generated command(s) for "
			"LUKS2 volumes",
		.command = COMMAND_CRYPTSETUP,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
#endif
	{
		.option = {"batch-mode", 0, NULL, 'q'},
		.desc = "Suppresses cryptsetup confirmation questions. "
			"This option is passed to the generated cryptsetup "
			"command(s)",
		.command = COMMAND_CRYPTSETUP,
	},
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = {"open", 0, NULL, OPT_CRYPTSETUP_OPEN},
		.desc = "Generates luksOpen or plainOpen commands. For the "
			"plain volume type, this is the default",
		.command = COMMAND_CRYPTSETUP,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {"format", 0, NULL, OPT_CRYPTSETUP_FORMAT},
		.desc = "Generates luksFormat commands. For the LUKS2 volume "
			"type, this is the default. If specified for the "
			"plain volume type, then no command is generated",
		.command = COMMAND_CRYPTSETUP,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
#endif
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_CONVERT,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES key in the repository that is "
			"to be converted",
		.command = COMMAND_CONVERT,
	},
	{
		.option = { "key-type", required_argument, NULL, 'K'},
		.argument = "type",
		.desc = "The type of the key to convert the secure key to. "
			"Possible values are '"KEY_TYPE_CCA_AESCIPHER"'. ",
		.command = COMMAND_CONVERT,
	},
	{
		.option = {"no-apqn-check", 0, NULL, OPT_NO_APQN_CHECK},
		.desc = "Do not check if the associated APQN(s) are available",
		.command = COMMAND_CONVERT,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {"force", 0, NULL, 'F'},
		.desc = "Do not prompt for a confirmation when converting a "
			"key",
		.command = COMMAND_CONVERT,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_KMS " " COMMAND_KMS_CONFIGURE,
	},
	{
		.option = { "apqns", required_argument, NULL, 'a'},
		.argument = "[+|-]CARD.DOMAIN[,...]",
		.desc = "Comma-separated pairs of crypto cards and domains "
			"that are associated with the key management system "
			"(KMS) plugin that the repository is bound to, and all "
			"keys generated with the KMS. To add pairs of crypto "
			"cards and domains to the key, specify "
			"'+CARD.DOMAIN[,...]'. To remove pairs of crypto cards "
			"and domains from the key specify '-CARD.DOMAIN[,...]'",
		.command = COMMAND_KMS " " COMMAND_KMS_CONFIGURE,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_KMS " " COMMAND_KMS_REENCIPHER,
	},
	{
		.option = {"to-new", 0, NULL, 'n'},
		.desc = "Re-enciphers KMS plugin internal secure keys that are "
			"currently enciphered with the master key in the "
			"CURRENT register with the master key in the NEW "
			"register.",
		.command = COMMAND_KMS " " COMMAND_KMS_REENCIPHER,
	},
	{
		.option = {"from-old", 0, NULL, 'o'},
		.desc = "Re-enciphers KMS plugin internal secure keys that are "
			"currently enciphered with the master key in the OLD "
			"register with the master key in the CURRENT register.",
		.command = COMMAND_KMS " " COMMAND_KMS_REENCIPHER,
	},
	{
		.option = {"complete", 0, NULL, 'p'},
		.desc = "Completes a staged re-enciphering. Use this option "
			"after the new master key has been set (made "
			"active).",
		.command = COMMAND_KMS " " COMMAND_KMS_REENCIPHER,
	},
	{
		.option = {"in-place", 0, NULL, 'i'},
		.desc = "Forces an in-place re-enchipering of the KMS plugin "
			"internal secure keys. Re-enciphering from OLD to "
			"CURRENT is performed in-place per default.",
		.command = COMMAND_KMS " " COMMAND_KMS_REENCIPHER,
	},
	{
		.option = {"staged", 0, NULL, 's'},
		.desc = "Forces that the re-enciphering of the KMS plugin "
			"internal secure keys is performed in staged mode. "
			"Re-enciphering from CURRENT to NEW is performed in "
			"staged mode per default.",
		.command = COMMAND_KMS " " COMMAND_KMS_REENCIPHER,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_KMS " " COMMAND_KMS_LIST,
	},
	{
		.option = { "label", required_argument, NULL, 'B'},
		.argument = "LABEL",
		.desc = "Label of the secure AES keys as known by the KMS that "
			"are to be listed. You can use wildcards to select "
			"the keys to be listed.",
		.command = COMMAND_KMS " " COMMAND_KMS_LIST,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES keys as known by zkey that "
			"are to be listed. You can use wildcards to select "
			"the keys to be listed.",
		.command = COMMAND_KMS " " COMMAND_KMS_LIST,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME[:DMNAME][,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the KMS. Use this option to list all keys "
			"associated with specific volumes. The device-mapper "
			"name (DMNAME) is optional. If specified, only those "
			"keys are listed where both, the volume and the device-"
			"mapper name matches.",
		.command = COMMAND_KMS " " COMMAND_KMS_LIST,
	},
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'. Use this option to list all "
			"keys with the specified volumes type.",
			.command = COMMAND_KMS " " COMMAND_KMS_LIST,
	},
#endif
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_KMS " " COMMAND_KMS_IMPORT,
	},
	{
		.option = { "label", required_argument, NULL, 'B'},
		.argument = "LABEL",
		.desc = "Label of the secure AES keys as known by the KMS that "
			"are to be imported. You can use wildcards to select "
			"the keys to be imported.",
		.command = COMMAND_KMS " " COMMAND_KMS_IMPORT,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES keys as known by zkey that "
			"are to be imported. You can use wildcards to select "
			"the keys to be imported.",
		.command = COMMAND_KMS " " COMMAND_KMS_IMPORT,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME[:DMNAME][,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the KMS. Use this option to import all keys "
			"associated with specific volumes. The device-mapper "
			"name (DMNAME) is optional. If specified, only those "
			"keys are listed where both, the volume and the device-"
			"mapper name matches.",
		.command = COMMAND_KMS " " COMMAND_KMS_IMPORT,
	},
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'. Use this option to import "
			"all keys with the specified volumes type.",
		.command = COMMAND_KMS " " COMMAND_KMS_IMPORT,
	},
#endif
	{
		.option = {"batch-mode", 0, NULL, 'q'},
		.desc = "Suppresses alternate name questions. When importing a "
			"key with a name that already exists in the "
			"repository, do not prompt for an alternate name, but "
			"skip the import of the duplicate key.",
		.command = COMMAND_KMS " " COMMAND_KMS_IMPORT,
	},
	{
		.option = {"no-volume-check", 0, NULL, OPT_NO_VOLUME_CHECK},
		.desc = "Do not check if the volume(s) associated with the "
			"secure key(s) to be imported are available, or are "
			"already associated with other secure keys.",
		.command = COMMAND_KMS " " COMMAND_KMS_IMPORT,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_KMS " " COMMAND_KMS_REFRESH,
	},
	{
		.option = { "name", required_argument, NULL, 'N'},
		.argument = "NAME",
		.desc = "Name of the secure AES keys in the repository that "
			"are to be refreshed. You can use wildcards to select "
			"the keys to be refreshed.",
		.command = COMMAND_KMS " " COMMAND_KMS_REFRESH,
	},
	{
		.option = { "volumes", required_argument, NULL, 'l'},
		.argument = "VOLUME[:DMNAME][,...]",
		.desc = "Comma-separated pairs of volume and device-mapper "
			"names that are associated with the secure AES key in "
			"the repository. Use this option to refresh all keys "
			"associated with specific volumes. The device-mapper "
			"name (DMNAME) is optional. If specified, only those "
			"keys are refreshed where both, the volume and the "
			"device-mapper name matches",
		.command = COMMAND_KMS " " COMMAND_KMS_REFRESH,
	},
#ifdef HAVE_LUKS2_SUPPORT
	{
		.option = { "volume-type", required_argument, NULL, 't'},
		.argument = "type",
		.desc = "The type of the associated volume(s). Possible values "
			"are 'plain' and 'luks2'. Use this option to refresh "
			"all keys with the specified volumes type.",
		.command = COMMAND_KMS " " COMMAND_KMS_REFRESH,
	},
#endif
	{
		.option = { "key-type", required_argument, NULL, 'K'},
		.argument = "type",
		.desc = "The type of the key. Possible values are '"
			KEY_TYPE_CCA_AESDATA"', '"KEY_TYPE_CCA_AESCIPHER"' "
			"and '"KEY_TYPE_EP11_AES"'. Use this option to refresh "
			"all keys with the specified key type.",
		.command = COMMAND_KMS " " COMMAND_KMS_REFRESH,
	},
	{
		.option = {"refresh-properties", 0, NULL, 'P'},
		.desc = "Also refresh the properties of the secure AES key "
			"and update them with the values from the KMS.",
		.command = COMMAND_KMS " " COMMAND_KMS_REFRESH,
	},
	{
		.option = {"no-volume-check", 0, NULL, OPT_NO_VOLUME_CHECK},
		.desc = "Do not check if the volume(s) associated with the "
			"secure key(s) to be refreshed are available, or are "
			"already associated with other secure keys.",
		.command = COMMAND_KMS " " COMMAND_KMS_REFRESH,
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	/***********************************************************/
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
	OPT_PLACEHOLDER,
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
	int need_ep11_library;
	int need_pkey_device;
	char *short_desc;
	char *long_desc;
	int has_options;
	char *pos_arg;
	int pos_arg_optional;
	char *pos_arg_alternate;
	char **arg_alternate_value;
	int need_keystore;
	int use_kms_plugin;
	char *kms_plugin_opts_cmd;
	int need_kms_login;
	struct zkey_command *sub_commands;
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
static int command_convert(void);
static int command_kms_plugins(void);
static int command_kms_bind(void);
static int command_kms_unbind(void);
static int command_kms_info(void);
static int command_kms_configure(void);
static int command_kms_reencipher(void);
static int command_kms_list(void);
static int command_kms_import(void);
static int command_kms_refresh(void);

static struct zkey_command zkey_kms_commands[] = {
	{
		.command = COMMAND_KMS_PLUGINS,
		.abbrev_len = 2,
		.function = command_kms_plugins,
		.short_desc = "Lists key management system plugins",
		.long_desc = "Lists available key management system (KMS) "
			     "plugins.",
		.has_options = 1,
	},
	{
		.command = COMMAND_KMS_BIND,
		.abbrev_len = 2,
		.function = command_kms_bind,
		.short_desc = "Binds the repository to a key management system "
			      "plugin",
		.long_desc = "Binds the repository to the specified key "
			     "management system (KMS) plugin.",
		.need_keystore = 1,
		.has_options = 1,
		.pos_arg = "[KMS-PLUGIN]",
	},
	{
		.command = COMMAND_KMS_UNBIND,
		.abbrev_len = 3,
		.function = command_kms_unbind,
		.short_desc = "Unbinds the repository from a key management "
			      "system plugin",
		.long_desc = "Unbinds the repository from the current key "
			     "management system (KMS) plugin, and turns all "
			     "KMS-bound keys into local keys",
		.need_keystore = 1,
		.has_options = 1,
		.use_kms_plugin = 1,
	},
	{
		.command = COMMAND_KMS_INFO,
		.abbrev_len = 2,
		.function = command_kms_info,
		.short_desc = "Displays information about a key management "
			      "system plugin",
		.long_desc = "Displays information about the current key "
			     "management system (KMS) plugin",
		.need_keystore = 1,
		.has_options = 1,
		.use_kms_plugin = 1,
	},
	{
		.command = COMMAND_KMS_CONFIGURE,
		.abbrev_len = 3,
		.function = command_kms_configure,
		.short_desc = "Configures a key management system plugin",
		.long_desc = "Configures or re-configures the current key "
			     "management system (KMS) plugin",
		.need_keystore = 1,
		.has_options = 1,
		.use_kms_plugin = 1,
		.kms_plugin_opts_cmd = KMS_COMMAND_CONFIGURE,
	},
	{
		.command = COMMAND_KMS_REENCIPHER,
		.abbrev_len = 2,
		.function = command_kms_reencipher,
		.short_desc = "Re-enciphers secure keys used by a key "
			      "management system plugin",
		.long_desc = "Re-enciphers secure keys internally used by a "
			     "key management system (KMS) plugin",
		.need_keystore = 1,
		.has_options = 1,
		.use_kms_plugin = 1,
		.kms_plugin_opts_cmd = KMS_COMMAND_REENCIPHER,
	},
	{
		.command = COMMAND_KMS_LIST,
		.abbrev_len = 2,
		.function = command_kms_list,
		.short_desc = "Lists secure keys managed by a key management "
			      "system",
		.long_desc = "Lists secure keys managed by a key management "
			     "system (KMS)",
		.need_keystore = 1,
		.has_options = 1,
		.use_kms_plugin = 1,
		.need_kms_login = 1,
		.kms_plugin_opts_cmd = KMS_COMMAND_LIST,
	},
	{
		.command = COMMAND_KMS_IMPORT,
		.abbrev_len = 2,
		.function = command_kms_import,
		.short_desc = "Imports secure keys managed by a key management "
			      "system",
		.long_desc = "Imports secure keys managed by a key management "
			     "system (KMS) into the repository",
		.need_keystore = 1,
		.has_options = 1,
		.use_kms_plugin = 1,
		.need_kms_login = 1,
		.kms_plugin_opts_cmd = KMS_COMMAND_LIST_IMPORT,
	},
	{
		.command = COMMAND_KMS_REFRESH,
		.abbrev_len = 3,
		.function = command_kms_refresh,
		.short_desc = "Refreshes secure keys that are bound to a key "
			      "management system",
		.long_desc = "Refreshes secure keys that are bound to a key "
			      "management system (KMS)",
		.need_keystore = 1,
		.has_options = 1,
		.use_kms_plugin = 1,
		.need_kms_login = 1,
	},
	{ .command = NULL }
};

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
		.use_kms_plugin = 1,
		.kms_plugin_opts_cmd = KMS_COMMAND_GENERATE,
	},
	{
		.command = COMMAND_REENCIPHER,
		.abbrev_len = 2,
		.function = command_reencipher,
		/* Will load the CCA or EP11 library on demand */
		.need_pkey_device = 1,
		.short_desc = "Re-encipher an existing secure AES key",
		.long_desc = "Re-encipher an existing secure AES "
			     "key that is either contained in SECURE-KEY-FILE "
			     "or is stored in the repository with another "
			     "master key",
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
			     "either contained in SECURE-KEY-FILE or is stored "
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
		.use_kms_plugin = 1,
		.kms_plugin_opts_cmd = KMS_COMMAND_REMOVE,
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
		.use_kms_plugin = 1,
	},
	{
		.command = COMMAND_RENAME,
		.abbrev_len = 3,
		.function = command_rename,
		.short_desc = "Rename a secure AES key",
		.long_desc = "Rename a secure AES key in the repository",
		.has_options = 1,
		.need_keystore = 1,
		.use_kms_plugin = 1,
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
	{
		.command = COMMAND_CONVERT,
		.abbrev_len = 3,
		.function = command_convert,
		.need_cca_library = 1,
		.need_pkey_device = 1,
		.short_desc = "Convert a secure AES key",
		.long_desc = "Convert an existing secure AES key that is "
			     "either contained in SECURE-KEY-FILE or is stored "
			     "in the repository from one key type to another "
			     "type.",
		.has_options = 1,
		.pos_arg = "[SECURE-KEY-FILE]",
		.pos_arg_optional = 1,
	},
	{
		.command = COMMAND_KMS,
		.abbrev_len = 2,
		.short_desc = "key management system (KMS) support",
		.long_desc = "Provides subcommands for key management system "
			     "(KMS) support.",
		.has_options = 1,
		.sub_commands = zkey_kms_commands,
	},
	{ .command = NULL }
};

#define pr_verbose(fmt...)	if (g.verbose) \
					warnx(fmt)

static void print_usage_sub_command_list(const struct zkey_command *sub_command)
{
	struct zkey_command *sub_cmd = (struct zkey_command *)sub_command;
	char command_str[ZKEY_COMMAND_STR_LEN];
	unsigned int i;

	printf("SUBCOMMANDS\n");
	while (sub_cmd->command) {
		strcpy(command_str, sub_cmd->command);
		for (i = 0; i < sub_cmd->abbrev_len; i++)
			command_str[i] =
				toupper(command_str[i]);
		printf("  %-*s    %s\n", ZKEY_COMMAND_MAX_LEN,
		       command_str, sub_cmd->short_desc);
		sub_cmd++;
	}
}

static void print_usage_command(const struct zkey_command *command,
				const struct zkey_command *sub_command)
{
	char sub_command_str[ZKEY_COMMAND_STR_LEN];
	char command_str[ZKEY_COMMAND_STR_LEN];
	const struct zkey_command *cmd;
	unsigned int i;

	strncpy(command_str, command->command, sizeof(command_str) - 1);
	for (i = 0; i < command->abbrev_len; i++)
		command_str[i] = toupper(command_str[i]);

	if (sub_command != NULL) {
		strncpy(sub_command_str, sub_command->command,
			sizeof(sub_command_str) - 1);
		for (i = 0; i < sub_command->abbrev_len; i++)
			sub_command_str[i] = toupper(sub_command_str[i]);

		printf("Usage: %s %s %s", program_invocation_short_name,
		       command_str, sub_command_str);
	} else {
		printf("Usage: %s %s", program_invocation_short_name,
		       command_str);
		if (command->sub_commands != NULL)
			printf(" SUBCOMMAND");
	}

	cmd = sub_command != NULL ? sub_command : command;

	if (cmd->pos_arg != NULL)
		printf(" %s", cmd->pos_arg);
	if (cmd->has_options)
		printf(" [OPTIONS]");

	if (prg.args)
		printf(" %s", prg.args);
	printf("\n\n");
	util_print_indented(cmd->long_desc, 0);

	if (cmd->has_options)
		printf("\n");

	if (sub_command == NULL && command->sub_commands != NULL)
		print_usage_sub_command_list(command->sub_commands);
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
static void print_help(const struct zkey_command *command,
		       const struct zkey_command *sub_command)
{
	/* Print usage */
	if (command == NULL)
		print_usage_command_list();
	else
		print_usage_command(command, sub_command);

	/* Print parameter help */
	util_opt_print_help();

	if (command == NULL) {
		printf("\n");
		printf("For more information use '%s COMMAND --help'.\n",
			program_invocation_short_name);
	} else if (command->sub_commands != NULL && sub_command == NULL) {
		printf("\n");
		printf("For more information use '%s %s SUBCOMMAND --help'.\n",
			program_invocation_short_name, command->command);
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
				       g.clearkeyfile, g.key_type,
				       NULL, g.verbose);

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
					g.keybits, g.xts, g.key_type,
					NULL, g.verbose);

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

	if (g.gen_passphrase && g.passphrase_file != NULL) {
		warnx("Either '--gen-dummy-passphrase' or "
		      "'--set-dummy-passphrase' can be specified, but not "
		      "both");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	if (g.kms_info.plugin_lib != NULL && !g.local) {
		if (g.apqns != NULL) {
			warnx("Option '--apqns|-a' is not valid for "
			      "generating a key in a KMS-bound repository");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}

		if (g.clearkeyfile != NULL) {
			warnx("Option '----clearkey|-c' is not valid for "
			      "generating a key in a KMS-bound repository, "
			      "unless option '--local|-L' is also specified");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}

		rc = perform_kms_login(&g.kms_info, g.verbose);
		if (rc != 0)
			rc = EXIT_FAILURE;

		rc = keystore_generate_key_kms(g.keystore, g.name,
					       g.description, g.volumes,
					       g.sector_size, g.keybits, g.xts,
					       g.volume_type, g.key_type,
					       g.gen_passphrase,
					       g.passphrase_file,
					       g.kms_options,
					       g.num_kms_options);
		goto out;
	}

	if (g.key_type == NULL)
		g.key_type = KEY_TYPE_CCA_AESDATA;

	rc = keystore_generate_key(g.keystore, g.name, g.description, g.volumes,
				   g.apqns, g.noapqncheck, g.sector_size,
				   g.keybits, g.xts, g.clearkeyfile,
				   g.volume_type, g.key_type, g.gen_passphrase,
				   g.passphrase_file, g.pkey_fd);

out:
	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}


/*
 * Command handler for 'generate'.
 *
 * Generate a new secure key either by random or from the specified clear key.
 */
static int command_generate(void)
{
	int rc;

	if (g.pos_arg != NULL && g.name != NULL) {
		warnx(" Option '--name|-N' is not valid for generating a key "
		      "outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.apqns == NULL && g.noapqncheck) {
		warnx("Option '--no-apqn-check' is only valid together with "
		      "the '--apqns|-a' option");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.name != NULL)
		return command_generate_repository();
	if (g.key_type == NULL)
		g.key_type = KEY_TYPE_CCA_AESDATA;
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
		if (g.noapqncheck) {
			warnx("Option '--no-apqn-check' is not valid for "
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
		if (g.local) {
			warnx("Option '--local|-L' is not valid for "
			      "generating a key outside of the repository");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}
		if (g.gen_passphrase) {
			warnx("Option '--gen-dummy-passphrase' is not valid "
			      "for generating a key outside of the repository");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}
		if (g.passphrase_file != NULL) {
			warnx("Option '--sen-dummy-passphrase' is not valid "
			      "for generating a key outside of the repository");
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}

		rc = cross_check_apqns(NULL, NULL,
				get_min_card_level_for_keytype(g.key_type),
				get_min_fw_version_for_keytype(g.key_type),
				get_card_type_for_keytype(g.key_type),
				true, g.verbose);
		if (rc == -EINVAL)
			return EXIT_FAILURE;
		if (rc != 0 && rc != -ENOTSUP) {
			warnx("Your master key setup is improper");
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
	bool selected;

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
				 &is_old_mk, NULL, g.verbose);
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
					    "enciphered with the OLD "
					    "master key and is being "
					    "re-enciphered with the CURRENT "
					    "master key\n", 0);
		} else {
			g.tonew = 1;
			util_print_indented("The secure key is currently "
					    "enciphered with the CURRENT "
					    "master key and is being "
					    "re-enciphered with the NEW "
					    "master key\n", 0);
		}
	}

	/* Re-encipher the secure key */
	if (g.fromold) {
		if (!is_old_mk) {
			warnx("The secure key is already enciphered "
			      "with the CURRENT master key");
			rc = EXIT_FAILURE;
			goto out;
		}

		pr_verbose("Secure key will be re-enciphered from OLD to the "
			   "CURRENT master key");

		rc = reencipher_secure_key(&g.lib, secure_key, secure_key_size,
					   NULL, REENCIPHER_OLD_TO_CURRENT,
					   &selected, g.verbose);
		if (rc != 0) {
			if (rc == -ENODEV) {
				warnx("No APQN found that is suitable for "
				      "re-enciphering the secure AES volume "
				      "key");
			} else {
				warnx("Re-encipher from OLD to CURRENT "
				      "master key has failed\n");
				if (!selected &&
				    !is_ep11_aes_key(secure_key,
						     secure_key_size))
					print_msg_for_cca_envvars(
							"secure AES key");
			}
			rc = EXIT_FAILURE;
			goto out;
		}
	}
	if (g.tonew) {
		pr_verbose("Secure key will be re-enciphered from CURRENT "
			   "to the NEW master key");

		rc = reencipher_secure_key(&g.lib, secure_key, secure_key_size,
					   NULL, REENCIPHER_CURRENT_TO_NEW,
					   &selected, g.verbose);
		if (rc != 0) {
			if (rc == -ENODEV) {
				warnx("No APQN found that is suitable for "
				      "re-enciphering the secure AES volume "
				      "key and has the NEW master key loaded");
			} else {
				warnx("Re-encipher from CURRENT to NEW "
				      "master key has failed\n");
				if (!selected &&
				    !is_ep11_aes_key(secure_key,
						     secure_key_size))
					print_msg_for_cca_envvars(
							"secure AES key");
			}
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
 * Re-encipher the specified secure key with the NEW or CURRENT master key.
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
				     g.pkey_fd, &g.lib);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'reencipher'.
 *
 * Re-encipher the specified secure key with the NEW or CURRENT master key.
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
	const char *key_type;
	u8 mkvp[MKVP_LENGTH];
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
	if (g.noapqncheck) {
		warnx("Option '--no-apqn-check' is not valid for "
		      "validating a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	/* Read the secure key to be re-enciphered */
	secure_key = read_secure_key(g.pos_arg, &secure_key_size, g.verbose);
	if (secure_key == NULL)
		return EXIT_FAILURE;

	rc = validate_secure_key(g.pkey_fd, secure_key, secure_key_size,
				 &clear_key_size, &is_old_mk, NULL, g.verbose);
	if (rc != 0) {
		warnx("The secure key in file '%s' is not valid", g.pos_arg);
		rc = EXIT_FAILURE;
		goto out;
	}

	rc = generate_key_verification_pattern(secure_key,
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

	rc = get_master_key_verification_pattern(secure_key, secure_key_size,
						 mkvp, g.verbose);
	if (rc != 0) {
		warnx("Failed to get the master key verification pattern: %s",
		      strerror(-rc));
		rc = EXIT_FAILURE;
		goto out;
	}

	key_type = get_key_type(secure_key, secure_key_size);

	printf("Validation of secure key in file '%s':\n", g.pos_arg);
	printf("  Status:                Valid\n");
	printf("  Secure key size:       %lu bytes\n", secure_key_size);
	printf("  Key type:              %s\n", key_type);
	printf("  Clear key size:        %lu bits\n", clear_key_size);
	printf("  XTS type key:          %s\n",
	       is_xts_key(secure_key, secure_key_size) ? "Yes" : "No");
	printf("  Enciphered with:       %s master key (MKVP: %s)\n",
	       is_old_mk ? "OLD" : "CURRENT",
	       printable_mkvp(get_card_type_for_keytype(key_type), mkvp));
	printf("  Verification pattern:  %.*s\n", VERIFICATION_PATTERN_LEN / 2,
	       vp);
	printf("                         %.*s\n", VERIFICATION_PATTERN_LEN / 2,
	       &vp[VERIFICATION_PATTERN_LEN / 2]);

	rc = cross_check_apqns(NULL, mkvp,
			       get_min_card_level_for_keytype(key_type),
			       get_min_fw_version_for_keytype(key_type),
			       get_card_type_for_keytype(key_type),
			       true, g.verbose);
	if (rc == -EINVAL)
		return EXIT_FAILURE;
	if (rc != 0 && rc != -ENOTSUP) {
		warnx("Your master key setup is improper");
		rc = EXIT_FAILURE;
		goto out;
	}

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

	rc = keystore_validate_key(g.keystore, g.name, g.apqns, g.noapqncheck,
				   g.pkey_fd);

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

	if (g.apqns == NULL && g.noapqncheck) {
		warnx("Option '--no-apqn-check' is only valid together with "
		      "the '--apqns|-a' option");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.gen_passphrase && g.passphrase_file != NULL) {
		warnx("Either '--gen-dummy-passphrase' or "
		      "'--set-dummy-passphrase' can be specified, but not "
		      "both");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}


	rc = keystore_import_key(g.keystore, g.name, g.description, g.volumes,
				 g.apqns, g.noapqncheck, g.sector_size,
				 g.pos_arg, g.volume_type, g.gen_passphrase,
				 g.passphrase_file, &g.lib);

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

	if (g.local && g.kms_bound) {
		warnx("Either '--local|-L' or '--kms-bound|-M' can be "
		      "specified, but not both");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	rc = keystore_list_keys(g.keystore, g.name, g.volumes, g.apqns,
				g.volume_type, g.key_type, g.local,
				g.kms_bound);

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

	rc = keystore_remove_key(g.keystore, g.name, g.force, g.kms_options,
				 g.num_kms_options);

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
	if (g.apqns == NULL && g.noapqncheck) {
		warnx("Option '--no-apqn-check' is only valid together with "
		      "the '--apqns|-a' option");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.gen_passphrase && g.passphrase_file != NULL) {
		warnx("Either '--gen-dummy-passphrase' or "
		      "'--set-dummy-passphrase' can be specified, but not "
		      "both");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.gen_passphrase && g.remove_passphrase) {
		warnx("Either '--gen-dummy-passphrase' or "
		      "'--remove-dummy-passphrase' can be specified, but not "
		      "both");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.passphrase_file != NULL && g.remove_passphrase) {
		warnx("Either '--set-dummy-passphrase' or "
		      "'--remove-dummy-passphrase' can be specified, but not "
		      "both");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.force && !g.remove_passphrase) {
		warnx("Option '--force|-F' is only valid together with "
		      "the '--remove-dummy-passphrase' option");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	rc = keystore_change_key(g.keystore, g.name, g.description, g.volumes,
				 g.apqns, g.noapqncheck, g.sector_size,
				 g.volume_type, g.gen_passphrase,
				 g.passphrase_file, g.remove_passphrase,
				 g.force);

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

	rc = keystore_copy_key(g.keystore, g.name, g.newname, g.volumes,
			       g.local);

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

	rc = keystore_crypttab(g.keystore, g.volumes, g.volume_type, g.keyfile,
			       g.keyfile_offset, g.keyfile_size, g.tries);

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

	if (g.open && g.format) {
		warnx("Either '--open' or '--format' can be specified, but "
		      "not both");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	rc = keystore_cryptsetup(g.keystore, g.volumes, g.run, g.volume_type,
				 g.keyfile, g.keyfile_offset, g.keyfile_size,
				 g.tries, g.batch_mode, g.open, g.format);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'convert'.
 *
 * Converts secure keys from one key type to another
 */
static int command_convert_file(void)
{
	u8 output_key[2 * MAX_SECURE_KEY_SIZE];
	unsigned int output_key_size;
	size_t secure_key_size;
	u8 mkvp[MKVP_LENGTH];
	int rc, is_old_mk;
	int selected = 1;
	u8 *secure_key;
	int min_level;

	if (g.name != NULL) {
		warnx("Option '--name|-N' is not valid for "
		      "re-enciphering a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	if (g.noapqncheck) {
		warnx("Option '--no-apqn-check' is not valid for "
		      "converting a key outside of the repository");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	min_level = get_min_card_level_for_keytype(g.key_type);
	if (min_level < 0) {
		warnx("Invalid key-type specified: %s", g.key_type);
		return EXIT_FAILURE;
	}

	rc = cross_check_apqns(NULL, NULL, min_level,
			       get_min_fw_version_for_keytype(g.key_type),
			       get_card_type_for_keytype(g.key_type),
			       true, g.verbose);
	if (rc == -EINVAL)
		return EXIT_FAILURE;
	if (rc != 0 && rc != -ENOTSUP) {
		warnx("Your master key setup is improper");
		return EXIT_FAILURE;
	}

	/* Read the secure key to be re-enciphered */
	secure_key = read_secure_key(g.pos_arg, &secure_key_size, g.verbose);
	if (secure_key == NULL)
		return EXIT_FAILURE;

	rc = validate_secure_key(g.pkey_fd, secure_key, secure_key_size, NULL,
				 &is_old_mk, NULL, g.verbose);
	if (rc != 0) {
		warnx("The secure key in file '%s' is not valid", g.pos_arg);
		rc = EXIT_FAILURE;
		goto out;
	}

	rc = get_master_key_verification_pattern(secure_key, secure_key_size,
						 mkvp, g.verbose);
	if (rc != 0) {
		warnx("Failed to get the master key verification pattern: %s",
		      strerror(-rc));
		rc = EXIT_FAILURE;
		goto out;
	}

	if (strcasecmp(get_key_type(secure_key, secure_key_size),
		       g.key_type) == 0) {
		warnx("The secure key in file '%s' is already of type %s",
		      g.pos_arg, get_key_type(secure_key, secure_key_size));
		rc = EXIT_FAILURE;
		goto out;
	}

	if (is_cca_aes_data_key(secure_key, secure_key_size)) {
		if (strcasecmp(g.key_type, KEY_TYPE_CCA_AESCIPHER) != 0) {
			warnx("The secure key in file '%s' can not be "
			      "converted into type %s", g.pos_arg, g.key_type);
			rc = EXIT_FAILURE;
			goto out;
		}
	} else if (is_cca_aes_cipher_key(secure_key, secure_key_size)) {
		warnx("The secure key in file '%s' is already of type %s",
		      g.pos_arg, KEY_TYPE_CCA_AESCIPHER);
		rc = EXIT_FAILURE;
		goto out;
	} else {
		warnx("The secure key in file '%s' has an unsupported key type",
		      g.pos_arg);
		rc = EXIT_FAILURE;
		goto out;
	}

	rc = select_cca_adapter_by_mkvp(&g.cca, mkvp, NULL,
					FLAG_SEL_CCA_MATCH_CUR_MKVP,
					g.verbose);
	if (rc == -ENOTSUP) {
		rc = 0;
		selected = 0;
	}
	if (rc != 0) {
		warnx("No APQN found that is suitable for "
		      "converting the secure AES key in file '%s'", g.pos_arg);
		rc = EXIT_FAILURE;
		goto out;
	}

	if (!g.force) {
		util_print_indented("ATTENTION: Converting a secure key is "
				    "irreversible, and might have an effect "
				    "on the volumes encrypted with it!", 0);
		printf("%s: Convert key in file '%s' [y/N]? ",
		       program_invocation_short_name, g.pos_arg);
		if (!prompt_for_yes(g.verbose)) {
			warnx("Operation aborted");
			rc = EXIT_FAILURE;
			goto out;
		}
	}

	memset(output_key, 0, sizeof(output_key));
	output_key_size = sizeof(output_key);
	rc = convert_aes_data_to_cipher_key(&g.cca, secure_key, secure_key_size,
					    output_key, &output_key_size,
					    g.verbose);
	if (rc != 0) {
		warnx("Converting the secure key from %s to %s has failed",
		      get_key_type(secure_key, secure_key_size), g.key_type);
		if (!selected)
			print_msg_for_cca_envvars("secure AES key");
		rc = EXIT_FAILURE;
		goto out;
	}

	rc = restrict_key_export(&g.cca, output_key, output_key_size,
				 g.verbose);
	if (rc != 0) {
		warnx("Export restricting the converted secure key has failed");
		if (!selected)
			print_msg_for_cca_envvars("secure AES key");
		rc = EXIT_FAILURE;
		goto out;
	}

	pr_verbose("Secure key was converted successfully");

	/* Write the converted secure key */
	rc = write_secure_key(g.outputfile ? g.outputfile : g.pos_arg,
			      output_key, output_key_size, g.verbose);
	if (rc != 0)
		rc = EXIT_FAILURE;
out:
	free(secure_key);
	return rc;
}

/*
 * Command handler for 'convert in repository'.
 *
 * Converts secure keys from one key type to another
 */
static int command_convert_repository(void)
{
	int rc;

	if (g.name == NULL) {
		misc_print_required_parm("--name/-N");
		return EXIT_FAILURE;
	}

	rc = keystore_convert_key(g.keystore, g.name, g.key_type, g.noapqncheck,
				  g.force, g.pkey_fd, &g.lib);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'convert'.
 *
 * Converts secure keys from one key type to another
 */
static int command_convert(void)
{
	if (g.key_type == NULL) {
		misc_print_required_parm("--key-type/-K");
		return EXIT_FAILURE;
	}
	if (strcasecmp(g.key_type, KEY_TYPE_CCA_AESCIPHER) != 0) {
		warnx("Secure keys can only be converted into key type %s",
		      KEY_TYPE_CCA_AESCIPHER);
		return EXIT_FAILURE;
	}

	if (g.pos_arg != NULL)
		return command_convert_file();
	else
		return command_convert_repository();

	return EXIT_SUCCESS;
}

/*
 * Command handler for 'kms plugins'.
 *
 * List KMS plugins
 */
static int command_kms_plugins(void)
{
	int rc;

	rc = list_kms_plugins(g.verbose);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'kms bind'.
 *
 * Bind repository to a KMS plugin
 */
static int command_kms_bind(void)
{
	int rc;

	rc = bind_kms_plugin(g.keystore, g.pos_arg, g.verbose);

	if (rc == 0)
		util_print_indented("The KMS plugin requires configuration, "
				    "run 'zkey kms configure [OPTIONS]' to "
				    "complete the KMS binding process", 0);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'kms unbind'.
 *
 * Unbind repository from a KMS plugin
 */
static int command_kms_unbind(void)
{
	char *msg;
	int rc;

	if (g.kms_info.plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		return EXIT_FAILURE;
	}

	util_asprintf(&msg, "%s: Unbind this repository from KMS plugin '%s' "
		     "and turn all KMS-bound keys into local keys [y/N]? ",
		     program_invocation_short_name, g.kms_info.plugin_name);
	util_print_indented(msg, 0);
	free(msg);
	if (!prompt_for_yes(g.verbose)) {
		warnx("Operation aborted");
		return EXIT_FAILURE;
	}

	rc = keystore_kms_keys_unbind(g.keystore);
	if (rc != 0) {
		warnx("Failed to turn KMS-bound keys into local keys: %s",
		      strerror(-rc));
		return EXIT_FAILURE;
	}

	rc = unbind_kms_plugin(&g.kms_info, g.keystore, g.verbose);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'kms info'.
 *
 * Prints information about a KMS plugin
 */
static int command_kms_info(void)
{
	int rc;

	if (g.kms_info.plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		return EXIT_FAILURE;
	}

	rc = print_kms_info(&g.kms_info);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'kms configure'.
 *
 * Configures or re-configures a KMS plugin
 */
static int command_kms_configure(void)
{
	int rc;

	if (g.kms_info.plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		return EXIT_FAILURE;
	}

	rc = configure_kms_plugin(g.keystore, g.apqns, g.kms_options,
				  g.num_kms_options, g.first_kms_option >= 0,
				  g.verbose);
	if (rc == -EAGAIN) {
		util_print_indented("The KMS plugin has accepted the "
				    "configuration so far, but requires further"
				    " configuration. Run 'zkey kms info' to "
				    "find out which KMS plugin settings still "
				    "require configuration, and run 'zkey kms "
				    "configure' again with the appropriate "
				    "options to complete the KMS "
				    "configuration process", 0);
		rc = 0;
	}

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'kms reencipher'.
 *
 * Reenciphers secure keys internally used by a KMS plugin
 */
static int command_kms_reencipher(void)
{
	int rc;

	if (g.kms_info.plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
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

	rc = reencipher_kms(&g.kms_info, g.fromold, g.tonew, g.inplace,
			   g.staged, g.complete, g.kms_options,
			   g.num_kms_options, g.verbose);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'kms list'.
 *
 * List secure keys managed by a KMS
 */
static int command_kms_list(void)
{
	int rc;

	if (g.kms_info.plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		return EXIT_FAILURE;
	}

	rc = list_kms_keys(&g.kms_info, g.label, g.name, g.volumes,
			   g.volume_type, g.kms_options, g.num_kms_options,
			   g.verbose);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'kms import'.
 *
 * Imports secure keys managed by a KMS
 */
static int command_kms_import(void)
{
	int rc;

	if (g.kms_info.plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		return EXIT_FAILURE;
	}

	rc = keystore_import_kms_keys(g.keystore, g.label, g.name, g.volumes,
				      g.volume_type, g.kms_options,
				      g.num_kms_options, g.batch_mode,
				      g.novolcheck);

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'kms refresh'.
 *
 * Refreshes secure keys managed by a KMS
 */
static int command_kms_refresh(void)
{
	int rc;

	if (g.kms_info.plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		return EXIT_FAILURE;
	}

	rc = keystore_refresh_kms_keys(g.keystore, g.name, g.volumes,
				       g.volume_type, g.key_type,
				       g.refresh_properties, g.novolcheck);

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

	g.keystore = keystore_new(directory, &g.kms_info, g.verbose);

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
static struct zkey_command *find_command(const struct zkey_command *commands,
				         const char *command)
{
	struct zkey_command *cmd = (struct zkey_command *)commands;

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
	char command_str[2 * ZKEY_COMMAND_STR_LEN + 2];
	struct zkey_command *sub_command = NULL;
	struct zkey_command *command = NULL;
	struct zkey_command *cmd = NULL;
	int arg_count = argc;
	char **args = argv;
	char *endp;
	int rc, c;

	util_prg_init(&prg);

	/* Get command and subcommand if one is specified */
	if (arg_count >= 2 && strncmp(args[1], "-", 1) != 0) {
		command = find_command(zkey_commands, args[1]);
		if (command == NULL) {
			misc_print_invalid_command(args[1]);
			return EXIT_FAILURE;
		}

		arg_count--;
		args = &args[1];

		if (arg_count >= 2 && strncmp(args[1], "-", 1) != 0 &&
		    command->sub_commands != NULL) {
			sub_command = find_command(command->sub_commands,
						   args[1]);
			if (sub_command == NULL) {
				misc_print_invalid_command(args[1]);
				return EXIT_FAILURE;
			}

			arg_count--;
			args = &args[1];
		}

		if (arg_count >= 2 && strncmp(args[1], "-", 1) != 0) {
			g.pos_arg = args[1];
			arg_count--;
			args = &args[1];
		}
	}

	if (sub_command != NULL) {
		snprintf(command_str, sizeof(command_str), "%s %s",
			 command->command, sub_command->command);
		util_prg_set_command(command_str);
		util_opt_set_command(command_str);
	} else {
		util_prg_set_command(command ? command->command : NULL);
		util_opt_set_command(command ? command->command : NULL);
	}

	if (sub_command != NULL && command->sub_commands != NULL)
		cmd = sub_command;
	else
		cmd = command;

	if (cmd != NULL && cmd->use_kms_plugin) {
		rc = check_for_kms_plugin(&g.kms_info, g.verbose);
		if (rc != 0)
			return EXIT_FAILURE;

		if (cmd->kms_plugin_opts_cmd) {
			rc = get_kms_options(&g.kms_info, opt_vec,
					     OPT_COMMAND_PLACEHOLDER,
					     cmd->kms_plugin_opts_cmd,
					     sub_command != NULL ?
						command_str : cmd->command,
					     &g.first_kms_option,
					     g.verbose);
			if (rc != 0)
				return EXIT_FAILURE;
		}
	}

	util_opt_init(opt_vec, NULL);

	while (1) {
		c = util_opt_getopt_long(arg_count, args);
		if (c == -1)
			break;

		if (cmd != NULL && cmd->kms_plugin_opts_cmd) {
			rc = handle_kms_option(&g.kms_info, opt_vec,
					       g.first_kms_option,
					       sub_command != NULL ?
						    command_str : cmd->command,
					       c, optarg, &g.kms_options,
					       &g.num_kms_options, g.verbose);
			if (rc != 0 && rc != -ENOENT) {
				warnx("Failed to process KMS plugin option: "
				      "'%c': %s", c, strerror(-rc));
				return EXIT_FAILURE;
			}

			if (rc == 0)
				continue;
		}

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
		case OPT_NO_APQN_CHECK:
			g.noapqncheck = 1;
			break;
		case OPT_NO_VOLUME_CHECK:
			g.novolcheck = 1;
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
#ifdef HAVE_LUKS2_SUPPORT
		case 't':
			g.volume_type = optarg;
			break;
#endif
		case 'w':
			g.newname = optarg;
			break;
		case 'r':
			g.run = 1;
			break;
		case 'K':
			g.key_type = optarg;
			break;
		case 'F':
			g.force = 1;
			break;
		case 'V':
			g.verbose = 1;
			break;
#ifdef HAVE_LUKS2_SUPPORT
		case OPT_CRYPTSETUP_KEYFILE:
			g.keyfile = optarg;
			break;
		case OPT_CRYPTSETUP_KEYFILE_OFFSET:
			g.keyfile_offset = strtoll(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.keyfile_offset < 0 ||
			    (g.keyfile_offset == LLONG_MAX &&
			     errno == ERANGE)) {
				warnx("Invalid value for '--keyfile-offset': "
				      "'%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case OPT_CRYPTSETUP_KEYFILE_SIZE:
			g.keyfile_size = strtoll(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.keyfile_size <= 0 ||
			    (g.keyfile_size == LLONG_MAX && errno == ERANGE)) {
				warnx("Invalid value for '--keyfile-size': "
				      "'%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case OPT_CRYPTSETUP_TRIES:
			g.tries = strtoll(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.tries <= 0 ||
			    (g.tries == LLONG_MAX && errno == ERANGE)) {
				warnx("Invalid value for '--tries': '%s'",
				      optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
#endif
		case 'q':
			g.batch_mode = 1;
			break;
#ifdef HAVE_LUKS2_SUPPORT
		case OPT_CRYPTSETUP_OPEN:
			g.open = 1;
			break;
		case OPT_CRYPTSETUP_FORMAT:
			g.format = 1;
			break;
#endif
		case 'L':
			g.local = 1;
			break;
		case 'M':
			g.kms_bound = 1;
			break;
		case 'B':
			g.label = optarg;
			break;
		case 'P':
			g.refresh_properties = 1;
			break;
		case OPT_GEN_DUMMY_PASSPHRASE:
			g.gen_passphrase = 1;
			break;
		case OPT_SET_DUMMY_PASSPHRASE:
			g.passphrase_file = optarg;
			break;
		case OPT_REMOVE_DUMMY_PASSPHRASE:
			g.remove_passphrase = 1;
			break;
		case 'h':
			print_help(command, sub_command);
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

	if (cmd == NULL) {
		misc_print_missing_command();
		return EXIT_FAILURE;
	}

	if (cmd->sub_commands != NULL) {
		misc_print_missing_sub_command();
		return EXIT_FAILURE;
	}

	if (cmd->pos_arg != NULL) {
		if (check_positional_arg(cmd) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}

	if (cmd->need_keystore ||
	    (cmd->pos_arg_optional && g.pos_arg == NULL)) {
		rc = open_keystore();
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	if (cmd->need_cca_library) {
		rc = load_cca_library(&g.cca, g.verbose);
		if (rc != 0) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}
	if (cmd->need_ep11_library) {
		rc = load_ep11_library(&g.ep11, g.verbose);
		if (rc != 0) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}
	if (cmd->need_pkey_device) {
		g.pkey_fd = open_pkey_device(g.verbose);
		if (g.pkey_fd == -1) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}

	if (g.kms_info.plugin_lib != NULL) {
		rc = init_kms_plugin(&g.kms_info, g.verbose);
		if (rc != 0) {
			rc = EXIT_FAILURE;
			goto out;
		}

		if (cmd->need_kms_login) {
			rc = perform_kms_login(&g.kms_info, g.verbose);
			if (rc != 0) {
				rc = EXIT_FAILURE;
				goto out;
			}
		}
	}

	umask(0077);

	rc = cmd->function();

out:
	free_kms_plugin(&g.kms_info);
	if (g.cca.lib_csulcca)
		dlclose(g.cca.lib_csulcca);
	if (g.ep11.lib_ep11)
		dlclose(g.ep11.lib_ep11);
	if (g.pkey_fd >= 0)
		close(g.pkey_fd);
	if (g.keystore)
		keystore_free(g.keystore);
	if (g.kms_options != NULL)
		free(g.kms_options);
	return rc;
}
