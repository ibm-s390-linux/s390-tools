/*
 * zkey-cryptsetup - Re-encipher or validate volume keys of volumes
 * encrypted with LUKS2 and the paes cipher.
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#define _LARGEFILE64_SOURCE

#include <ctype.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>

#include <libcryptsetup.h>
#include <json-c/json.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_panic.h"
#include "lib/util_prg.h"
#include "lib/zt_common.h"

#include "misc.h"
#include "pkey.h"
#include "cca.h"
#include "ep11.h"
#include "utils.h"

/* Detect if cryptsetup 2.1 or later is available */
#ifdef CRYPT_LOG_DEBUG_JSON
#define HAVE_CRYPT_KEYSLOT_GET_PBKDF
#endif

#define MAX_KEY_SIZE                (8 * 1024 * 1024)
#define MAX_PASSWORD_SIZE           512
#define KEYFILE_BUFLEN              4096
#define SEEK_BUFLEN                 4096

#define PAES_VP_TOKEN_NAME          "paes-verification-pattern"
#define PAES_VP_TOKEN_VP            "verification-pattern"

#define PAES_REENC_TOKEN_NAME       "paes-reencipher"
#define PAES_REENC_TOKEN_VP         "verification-pattern"
#define PAES_REENC_TOKEN_ORG_SLOT   "original-keyslot"
#define PAES_REENC_TOKEN_UNB_SLOT   "unbound-keyslot"

struct reencipher_token {
	char verification_pattern[VERIFICATION_PATTERN_LEN];
	unsigned int original_keyslot;
	unsigned int unbound_keyslot;
};

struct vp_token {
	char verification_pattern[VERIFICATION_PATTERN_LEN];
};

__attribute__ ((unused))
static void misc_print_required_parms(const char *parm_name1,
				      const char *parm_name2);

/*
 * Program configuration
 */
static const struct util_prg prg = {
	.desc = "Manage secure volume keys of volumes encrypted with LUKS2 and "
		"the 'paes' cipher",
	.command_args = "COMMAND DEVICE",
	.args = "",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2018,
			.pub_last = 2018,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Global variables for program options
 */
static struct zkey_cryptsetup_globals {
	char *pos_arg;
	char *keyfile;
	long long keyfile_offset;
	long long keyfile_size;
	long long tries;
	bool tonew;
	bool fromold;
	bool complete;
	bool inplace;
	bool staged;
	char *master_key_file;
	bool batch_mode;
	bool debug;
	bool verbose;
	struct ext_lib lib;
	struct cca_lib cca;
	struct ep11_lib ep11;
	int pkey_fd;
	struct crypt_device *cd;
} g = {
	.tries = 3,
	.pkey_fd = -1,
	.lib.cca = &g.cca,
	.lib.ep11 = &g.ep11,
};

/*
 * Available commands
 */
#define COMMAND_REENCIPHER	"reencipher"
#define COMMAND_VALIDATE	"validate"
#define COMMAND_SETVP		"setvp"
#define COMMAND_SETKEY		"setkey"

#define ZKEY_CRYPTSETUP_COMMAND_MAX_LEN	10

/*
 * These options are exactly the same as for the cryptsetup tool
 */
#define OPT_PASSPHRASE_ENTRY(cmd)					\
{									\
	.option = {"key-file", required_argument, NULL, 'd'},		\
	.argument = "FILE-NAME",					\
	.desc = "Read the passphrase from the specified file",		\
	.command = cmd,							\
},									\
{									\
	.option = {"keyfile-offset", required_argument, NULL, 'o'},	\
	.argument = "BYTES",						\
	.desc = "Specifies the number of bytes to skip in the file "	\
		"specified with option '--key-file'|'-d'",		\
	.command = cmd,							\
},									\
{									\
	.option = {"keyfile-size", required_argument, NULL, 'l'},	\
	.argument = "BYTES",						\
	.desc = "Specifies the number of bytes to read from the file "	\
		"specified with option '--key-file'|'-d'",		\
	.command = cmd,							\
},									\
{									\
	.option = {"tries", required_argument, NULL, 'T'},		\
	.argument = "NUMBER",						\
	.desc = "Specifies how often the interactive input of the "	\
		"passphrase can be retried",				\
	.command = cmd,							\
}

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"to-new", 0, NULL, 'N'},
		.desc = "Re-enciphers a secure volume key in the LUKS2 header "
			"that is currently enciphered with the master key in "
			"the CURRENT register with the master key in the NEW "
			"register",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"from-old", 0, NULL, 'O'},
		.desc = "Re-enciphers a secure volume key in the LUKS2 header "
			"that is currently enciphered with the master key in "
			"the OLD register with the master key in the CURRENT "
			"register",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"staged", 0, NULL, 's'},
		.desc = "Forces that the re-enciphering of a secure volume "
			"key in the LUKS2 header is performed in staged mode",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"in-place", 0, NULL, 'i'},
		.desc = "Forces an in-place re-enciphering of a secure volume "
			"key in the LUKS2 header",
		.command = COMMAND_REENCIPHER,
	},
	{
		.option = {"complete", 0, NULL, 'c'},
		.desc = "Completes a staged re-enciphering. Use this option "
			"after the new master key has been set (made "
			"active)",
		.command = COMMAND_REENCIPHER,
	},
	OPT_PASSPHRASE_ENTRY(COMMAND_REENCIPHER),
	{
		.option = {"batch-mode", 0, NULL, 'q'},
		.desc = "Suppresses all confirmation questions. Use with care!",
		.command = COMMAND_REENCIPHER,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_VALIDATE,
	},
	OPT_PASSPHRASE_ENTRY(COMMAND_VALIDATE),
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_SETVP,
	},
	OPT_PASSPHRASE_ENTRY(COMMAND_SETVP),
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
		.command = COMMAND_SETKEY,
	},
	{
		.option = {"master-key-file", required_argument, NULL, 'm'},
		.argument = "FILE-NAME",
		.desc = "Specifies the name of a file containing the secure "
			"AES key that is set as new volume key",
		.command = COMMAND_SETKEY,
	},
	OPT_PASSPHRASE_ENTRY(COMMAND_SETKEY),
	{
		.option = {"batch-mode", 0, NULL, 'q'},
		.desc = "Suppresses all confirmation questions. Use with care!",
		.command = COMMAND_SETKEY,
	},
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "COMMON OPTIONS"
	},
	{
		.option = {"debug", 0, NULL, 'D'},
		.desc = "Print additional debugging messages during "
			"processing",
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

#define ZKEY_CRYPTSETUP_COMMAND_STR_LEN	80

/*
 * Table of supported commands
 */
struct zkey_cryptsetup_command {
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
	int open_device;
};

static int command_reencipher(void);
static int command_validate(void);
static int command_setvp(void);
static int command_setkey(void);

static struct zkey_cryptsetup_command zkey_cryptsetup_commands[] = {
	{
		.command = COMMAND_REENCIPHER,
		.abbrev_len = 2,
		.function = command_reencipher,
		/* Will load the CCA or EP11 library on demand */
		.need_pkey_device = 1,
		.short_desc = "Re-encipher a secure volume key",
		.long_desc = "Re-encipher a secure volume key of a volume "
			     "encrypted with LUKS2 and the 'paes' cipher",
		.has_options = 1,
		.pos_arg = "DEVICE",
		.open_device = 1,
	},
	{
		.command = COMMAND_VALIDATE,
		.abbrev_len = 3,
		.function = command_validate,
		.need_pkey_device = 1,
		.short_desc = "Validate a secure volume key",
		.long_desc = "Validate a secure volume key of a volume "
			     "encrypted with LUKS2 and the 'paes' cipher",
		.has_options = 1,
		.pos_arg = "DEVICE",
		.open_device = 1,
	},
	{
		.command = COMMAND_SETVP,
		.abbrev_len = 4,
		.function = command_setvp,
		.need_pkey_device = 1,
		.short_desc = "Set a verification pattern of the secure volume "
			      "key",
		.long_desc = "Set a verification pattern of the secure AES "
			     "volume key of a volume encrypted with LUKS2 and "
			     "the 'paes' cipher",
		.has_options = 1,
		.pos_arg = "DEVICE",
		.open_device = 1,
	},
	{
		.command = COMMAND_SETKEY,
		.abbrev_len = 4,
		.function = command_setkey,
		.need_pkey_device = 1,
		.short_desc = "Set a new secure volume key",
		.long_desc = "Set a new secure AES volume key for a volume "
			     "encrypted with LUKS2 and the 'paes' cipher",
		.has_options = 1,
		.pos_arg = "DEVICE",
		.open_device = 1,
	},
	{ .command = NULL }
};

#define pr_verbose(fmt...)	do { \
					if (g.verbose) \
						warnx(fmt); \
				} while (0)

static volatile int quit;

/*
 * Signal handler for SIGINT and SIGTERM
 */
static void int_handler(int sig __attribute__((__unused__)))
{
	quit++;
}

/*
 * Install signal handler for SIGINT and SIGTERM
 */
static void set_int_handler(void)
{
	struct sigaction sigaction_open;

	pr_verbose("Installing SIGINT/SIGTERM handler");
	memset(&sigaction_open, 0, sizeof(struct sigaction));
	sigaction_open.sa_handler = int_handler;
	sigaction(SIGINT, &sigaction_open, NULL);
	sigaction(SIGTERM, &sigaction_open, NULL);
}

static void print_usage_command(const struct zkey_cryptsetup_command *command)
{
	char command_str[ZKEY_CRYPTSETUP_COMMAND_STR_LEN];
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
	struct zkey_cryptsetup_command *cmd = zkey_cryptsetup_commands;
	char command_str[ZKEY_CRYPTSETUP_COMMAND_STR_LEN];
	unsigned int i;

	util_prg_print_help();

	printf("COMMANDS\n");
	while (cmd->command) {
		strcpy(command_str, cmd->command);
		for (i = 0; i < cmd->abbrev_len; i++)
			command_str[i] = toupper(command_str[i]);
		printf("  %-*s    %s\n", ZKEY_CRYPTSETUP_COMMAND_MAX_LEN,
		       command_str, cmd->short_desc);
		cmd++;
	}
	printf("\n");
}

/*
 * --help printout
 */
static void print_help(const struct zkey_cryptsetup_command *command)
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
 * Log function called from libcryptsetup routines when debugging is enabled
 */
static void cryptsetup_log(int level, const char *msg,
			   void *usrptr __attribute__((unused)))
{
	switch (level) {
	case CRYPT_LOG_NORMAL:
		fputs(msg, stdout);
		break;
	case CRYPT_LOG_VERBOSE:
		if (g.verbose)
			fputs(msg, stdout);
		break;
	case CRYPT_LOG_ERROR:
		fprintf(stderr, "%s: %s", program_invocation_short_name, msg);
		break;
	case CRYPT_LOG_DEBUG:
		fprintf(stderr, "%s: # %s\n", program_invocation_short_name, msg);
		break;
#ifdef CRYPT_DEBUG_JSON
	case CRYPT_DEBUG_JSON:
		fprintf(stderr, "%s\n", msg);
		break;
#endif
	default:
		warnx("Internal error on logging class for msg: %s", msg);
		break;
	}
}

static void secure_free(void *area, size_t size)
{
	if (area == NULL)
		return;

	memset(area, 0, size);
	free(area);
}

/*
 * Seek a number of bytes in a file.
 *
 * A simple call to lseek(3) might not be possible for some inputs (e.g.
 * reading from a pipe), so this function instead reads of up to 4K bytes
 * at a time until the specified number of bytes. It returns -1 on read error
 * or when it reaches EOF before the requested number of bytes have been
 * discarded.
 */
static int keyfile_seek(int fd, size_t bytes)
{
	size_t next_read;
	ssize_t bytes_r;
	off64_t r;
	char *tmp;

	r = lseek64(fd, bytes, SEEK_CUR);
	if (r > 0)
		return 0;
	if (r < 0 && errno != ESPIPE)
		return -1;

	tmp = util_malloc(SEEK_BUFLEN);
	while (bytes > 0) {
		next_read = bytes > SEEK_BUFLEN ? SEEK_BUFLEN : (size_t)bytes;

		bytes_r = read(fd, tmp, next_read);
		if (bytes_r < 0) {
			if (errno == EINTR)
				continue;
			secure_free(tmp, SEEK_BUFLEN);
			return -1;
		}

		if (bytes_r == 0)
			break;

		bytes -= bytes_r;
	}

	secure_free(tmp, SEEK_BUFLEN);
	return bytes == 0 ? 0 : -1;
}

/*
 * Read data from fd into the specified buffer
 */
static ssize_t keyfile_read(int fd, void *buf, size_t length)
{
	size_t read_size = 0;
	ssize_t r;

	if (fd < 0 || buf == NULL)
		return -EINVAL;

	do {
		r = read(fd, buf, length - read_size);
		if (r == -1 && errno != EINTR)
			return r;
		if (r == 0)
			return (ssize_t)read_size;
		if (r > 0) {
			read_size += (size_t)r;
			buf = (char *)buf + r;
		}
	} while (read_size != length);

	return (ssize_t)length;
}

/*
 * Prompt for the password
 */
static int get_password_interactive(const char *prompt, char **pwd,
				    size_t *pwd_size)
{
	struct termios orig, tmp;
	int infd, outfd, rc = 0;
	char *pass;
	int num;

	pass = calloc(MAX_PASSWORD_SIZE + 1, 1);
	if (pass == NULL) {
		warnx("Out of memory while reading passphrase");
		return -ENOMEM;
	}

	infd = open("/dev/tty", O_RDWR);
	if (infd == -1) {
		infd = STDIN_FILENO;
		outfd = STDERR_FILENO;
	} else {
		outfd = infd;
	}

	if (prompt != NULL) {
		if (write(outfd, prompt, strlen(prompt)) < 0) {
			rc = -errno;
			warnx("Failed to write prompt: %s", strerror(-rc));
			goto out_err;
		}
	}

	rc = tcgetattr(infd, &orig);
	if (rc != 0) {
		rc = -errno;
		warnx("Failed to get terminal attributes: %s", strerror(-rc));
		goto out_err;
	}

	memcpy(&tmp, &orig, sizeof(tmp));
	tmp.c_lflag &= ~ECHO;

	rc = tcsetattr(infd, TCSAFLUSH, &tmp);
	if (rc != 0) {
		rc = -errno;
		warnx("Failed to set terminal attributes: %s", strerror(-rc));
		goto out_err;
	}

	quit = 0;
	num = read(infd, pass, MAX_PASSWORD_SIZE);
	if (num > 0)
		pass[num - 1] = '\0';
	else if (num == 0)
		*pass = '\0';

	if (quit) {
		printf("\n");
		num = -1;
		pr_verbose("Password entry aborted by user");
	}

	rc = tcsetattr(infd, TCSAFLUSH, &orig);
	if (rc != 0) {
		rc = -errno;
		warnx("Failed to set terminal attributes: %s", strerror(-rc));
		goto out_err;
	}

	if (num < 0) {
		warnx("Failed to read the password");
		rc = -EIO;
		goto out_err;
	}

	*pwd = pass;
	*pwd_size = strlen(pass);
	rc = 0;

out_err:
	if (rc != 0)
		secure_free(pass, MAX_PASSWORD_SIZE + 1);
	else
		rc = write(outfd, "\n", 1) == 1 ? 0 : -EIO;

	if (infd != STDIN_FILENO)
		close(infd);

	return rc;
}

/*
 * Read the password from the key file
 */
static int get_password_file(char **pwd, size_t *pwd_size, const char *key_file,
			     size_t keyfile_offset, size_t key_size,
			     int stop_at_eol)
{
	int unlimited_read = 0;
	size_t file_read_size;
	int regular_file = 0;
	int char_to_read = 0;
	size_t buflen = 0, i;
	int fd, rc, newline;
	char *pass = NULL;
	int char_read = 0;
	struct stat sb;

	fd = key_file ? open(key_file, O_RDONLY) : STDIN_FILENO;
	if (fd < 0) {
		rc = -errno;
		warnx("Failed to open key file '%s': %s", key_file,
		      strerror(-rc));
		return rc;
	}

	if (isatty(fd)) {
		warnx("Cannot read key file from a terminal");
		rc = -EINVAL;
		goto out_err;
	}

	if (key_size == 0) {
		key_size = MAX_KEY_SIZE + 1;
		unlimited_read = 1;
		buflen = KEYFILE_BUFLEN;
	} else
		buflen = key_size;

	if (key_file) {
		rc = stat(key_file, &sb);
		if (rc != 0) {
			warnx("Failed to stat key file '%s': %s", key_file,
			      strerror(-rc));
			goto out_err;
		}
		if (S_ISREG(sb.st_mode)) {
			regular_file = 1;
			file_read_size = sb.st_size;

			if (keyfile_offset > file_read_size) {
				warnx("Cannot seek to requested key file "
				      "offset %lu", keyfile_offset);
				goto out_err;
			}
			file_read_size -= keyfile_offset;

			if (file_read_size >= key_size)
				buflen = key_size;
			else if (file_read_size)
				buflen = file_read_size;
		}
	}

	pass = calloc(buflen, 1);
	if (pass == NULL) {
		warnx("Out of memory while reading passphrase");
		rc = -ENOMEM;
		goto out_err;
	}

	if (keyfile_offset && keyfile_seek(fd, keyfile_offset) < 0) {
		warnx("Cannot seek to requested key file offset %lu",
		       keyfile_offset);
		rc = -EIO;
		goto out_err;
	}

	for (i = 0, newline = 0; i < key_size; i += char_read) {
		if (i == buflen) {
			buflen += 4096;
			pass = realloc(pass, buflen);
			if (pass == NULL) {
				warnx("Out of memory while reading passphrase");
				rc = -ENOMEM;
				goto out_err;
			}
		}

		if (stop_at_eol)
			char_to_read = 1;
		else
			char_to_read = key_size < buflen ?
					key_size - i : buflen - i;

		char_read = keyfile_read(fd, &pass[i], char_to_read);
		if (char_read < 0) {
			warnx("Error reading passphrase");
			rc = -EPIPE;
			goto out_err;
		}

		if (char_read == 0)
			break;

		if (stop_at_eol && pass[i] == '\n') {
			newline = 1;
			pass[i] = '\0';
			break;
		}
	}

	if (!i && !regular_file && !newline) {
		warnx("Nothing read on input");
		rc = -EPIPE;
		goto out_err;
	}

	if (unlimited_read && i == key_size) {
		warnx("Maximum key size exceeded");
		rc = -EINVAL;
		goto out_err;
	}

	if (!unlimited_read && i != key_size) {
		warnx("Cannot read requested amount of data");
		rc = -EINVAL;
		goto out_err;
	}

	*pwd = pass;
	*pwd_size = i;
	rc = 0;

out_err:
	if (fd != STDIN_FILENO)
		close(fd);
	if (rc != 0)
		secure_free(pass, buflen);

	return rc;
}

/*
 * Check if the specfied file name denotes stdin
 */
static bool is_stdin(const char *file_name)
{
	if (file_name == NULL)
		return true;

	return strcmp(file_name, "-") ? false : true;
}

/*
 * Prompt for the password or read the password from the keyfile.
 */
static int get_password(const char *prompt, char **pwd, size_t *pwd_size,
			const char *key_file, size_t keyfile_offset,
			size_t keyfile_size)
{
	int rc;

	if (is_stdin(key_file)) {
		if (isatty(STDIN_FILENO)) {
			if (keyfile_offset) {
				warnx("Cannot use option --keyfile-offset with "
				      "terminal input");
				return -EINVAL;
			}
			if (keyfile_size) {
				warnx("Cannot use option --keyfile-size with "
				      "terminal input");
				return -EINVAL;
			}

			rc = get_password_interactive(prompt, pwd, pwd_size);
		} else {
			rc = get_password_file(pwd, pwd_size, NULL,
					       keyfile_offset, keyfile_size,
					       key_file == NULL);
		}
	} else {
		rc = get_password_file(pwd, pwd_size, key_file,
				       keyfile_offset, keyfile_size, 0);
	}

	return rc;
}
static int ensure_is_active_keylot(int keyslot)
{
	crypt_keyslot_info info;

	info = crypt_keyslot_status(g.cd, keyslot);
	if (info != CRYPT_SLOT_ACTIVE && info != CRYPT_SLOT_ACTIVE_LAST) {
		warnx("Keyslot %d is not a valid key slot", keyslot);
		return -EINVAL;
	}

	return 0;
}

static int ensure_is_unbound_keylot(int keyslot)
{
	crypt_keyslot_info info;

	info = crypt_keyslot_status(g.cd, keyslot);
	if (info != CRYPT_SLOT_UNBOUND) {
		warnx("Key slot %d is not an unbound key slot", keyslot);
		return -EINVAL;
	}

	return 0;
}

/*
 * Returns the token number of the token of the specified name if found,
 * -1 otherwise.
 */
static int find_token(struct crypt_device *cd, const char *name)
{
	crypt_token_info info;
	const char *type;
	int i;

	for (i = 0; ; i++) {
		info = crypt_token_status(cd, i, &type);
		if (info == CRYPT_TOKEN_INVALID)
			break;
		if (info == CRYPT_TOKEN_INACTIVE)
			continue;

		if (strcmp(type, name) != 0)
			continue;

		pr_verbose("'%s' token found at slot %d", name, i);
		return i;
	}

	pr_verbose("'%s' token not found", name);
	return -1;
}

/*
 * Validate the reencipher token
 */
static int validate_reencipher_token(struct reencipher_token *tok)
{
	int rc;

	rc = ensure_is_unbound_keylot(tok->unbound_keyslot);
	if (rc != 0)
		return rc;

	rc = ensure_is_active_keylot(tok->original_keyslot);
	if (rc != 0)
		return rc;

	pr_verbose("The re-encipher token has been validated");

	return 0;
}

static int get_token(struct crypt_device *cd, int token, json_object **obj)
{
	const char *json;
	int rc;

	if (obj == NULL)
		return -EINVAL;

	rc = crypt_token_json_get(cd, token, &json);
	if (rc < 0) {
		warnx("Failed to get re-encipher token %d: %s", token,
		       strerror(-rc));
		return -rc;
	}

	*obj = json_tokener_parse(json);
	if (*obj == NULL) {
		warnx("Failed to parse JSON");
		return -EINVAL;
	}

	return 0;
}

/*
 * Reads the re-encipher token from the LUKS2 header
 */
static int get_reencipher_token(struct crypt_device *cd, int token,
				struct reencipher_token *info, bool validate)
{
	json_object *jobj_org_keyslot = NULL;
	json_object *jobj_unb_keyslot = NULL;
	json_object *json_token = NULL;
	json_object *jobj_vp = NULL;
	const char *temp;
	int rc;

	rc = get_token(cd, token, &json_token);
	if (rc != 0)
		return rc;

	if (!json_object_object_get_ex(json_token, PAES_REENC_TOKEN_VP,
				       &jobj_vp)) {
		warnx("The re-encipher token is incomplete, '%s' is missing",
		      PAES_REENC_TOKEN_VP);
		rc = -EINVAL;
		goto out;
	}
	temp = json_object_get_string(jobj_vp);
	if (temp == NULL) {
		warnx("The re-encipher token is incomplete, '%s' is missing",
		      PAES_REENC_TOKEN_VP);
		rc = -EINVAL;
		goto out;
	}
	strncpy(info->verification_pattern, temp,
		sizeof(info->verification_pattern));
	info->verification_pattern[
			sizeof(info->verification_pattern) - 1] = '\0';

	if (!json_object_object_get_ex(json_token, PAES_REENC_TOKEN_ORG_SLOT,
				       &jobj_org_keyslot)) {
		warnx("The re-encipher token is incomplete, '%s' is missing",
		      PAES_REENC_TOKEN_ORG_SLOT);
		rc = -EINVAL;
		goto out;
	}
	errno = 0;
	info->original_keyslot = json_object_get_int64(jobj_org_keyslot);
	if (errno != 0) {
		warnx("The re-encipher token is incomplete, '%s' is missing",
		      PAES_REENC_TOKEN_ORG_SLOT);
		rc = -EINVAL;
		goto out;
	}

	if (!json_object_object_get_ex(json_token, PAES_REENC_TOKEN_UNB_SLOT,
				      &jobj_unb_keyslot)) {
		warnx("The re-encipher token is incomplete, '%s' is missing",
		      PAES_REENC_TOKEN_UNB_SLOT);
		rc = -EINVAL;
		goto out;
	}
	errno = 0;
	info->unbound_keyslot = json_object_get_int64(jobj_unb_keyslot);
	if (errno != 0) {
		warnx("The re-encipher token is incomplete, '%s' is missing",
		      PAES_REENC_TOKEN_UNB_SLOT);
		rc = -EINVAL;
		goto out;
	}

	pr_verbose("Re-encipher token: original-keyslot: %d, unbound-keyslot: "
		   "%d, verification-pattern: %s", info->original_keyslot,
		   info->unbound_keyslot, info->verification_pattern);

	rc = 0;

	if (validate)
		rc = validate_reencipher_token(info);

out:
	if (json_token != NULL)
		json_object_put(json_token);

	return rc;
}

/*
 * Writes the re-encipher token to the LUKS2 header
 */
static int put_reencipher_token(struct crypt_device *cd, int token,
				struct reencipher_token *info)
{
	json_object *jobj, *jobj_keyslots;
	char temp[20];
	int rc;

	pr_verbose("Re-encipher token: original-keyslot: %d, unbound-keyslot: "
		   "%d, verification-pattern: %s", info->original_keyslot,
		   info->unbound_keyslot, info->verification_pattern);

	jobj = json_object_new_object();
	json_object_object_add(jobj, "type",
			       json_object_new_string(PAES_REENC_TOKEN_NAME));

	jobj_keyslots = json_object_new_array();
	sprintf(temp, "%d", info->unbound_keyslot);
	json_object_array_add(jobj_keyslots, json_object_new_string(temp));
	json_object_object_add(jobj, "keyslots", jobj_keyslots);

	json_object_object_add(jobj, PAES_REENC_TOKEN_VP,
			       json_object_new_string(
					info->verification_pattern));
	json_object_object_add(jobj, PAES_REENC_TOKEN_ORG_SLOT,
			       json_object_new_int64(info->original_keyslot));
	json_object_object_add(jobj, PAES_REENC_TOKEN_UNB_SLOT,
			       json_object_new_int64(info->unbound_keyslot));

	rc = crypt_token_json_set(cd, token >= 0 ? token : CRYPT_ANY_TOKEN,
				  json_object_to_json_string_ext(jobj,
						  JSON_C_TO_STRING_PLAIN));

	if (rc < 0)
		warnx("Failed to add the re-encipher token to device "
		      "'%s': %s", g.pos_arg, strerror(-rc));
	else
		pr_verbose("Re-encipher token put to token slot %d",
			   rc);

	json_object_put(jobj);

	return rc;
}


/*
 * Reads the verification pattern token from the LUKS2 header
 */
static int get_vp_token(struct crypt_device *cd, int token,
			struct vp_token *info)
{
	json_object *json_token = NULL;
	json_object *jobj_vp = NULL;
	const char *temp;
	int rc;

	rc = get_token(cd, token, &json_token);
	if (rc != 0)
		return rc;

	if (!json_object_object_get_ex(json_token, PAES_VP_TOKEN_VP,
				       &jobj_vp)) {
		warnx("The verification-pattern token is incomplete, '%s' is "
		      "missing", PAES_VP_TOKEN_VP);
		rc = -EINVAL;
		goto out;
	}
	temp = json_object_get_string(jobj_vp);
	if (temp == NULL) {
		warnx("The verification-pattern token is incomplete, '%s' is "
		      "missing", PAES_VP_TOKEN_VP);
		rc = -EINVAL;
		goto out;
	}
	strncpy(info->verification_pattern, temp,
		sizeof(info->verification_pattern));
	info->verification_pattern[
			sizeof(info->verification_pattern) - 1] = '\0';

	pr_verbose("Verification-pattern: %s", info->verification_pattern);

out:
	if (json_token != NULL)
		json_object_put(json_token);

	return rc;
}

/*
 * Writes the verification pattern token to the LUKS2 header
 */
static int put_vp_token(struct crypt_device *cd, int token,
			struct vp_token *info)
{
	json_object *jobj, *jobj_keyslots;
	int rc;

	pr_verbose("Verification-pattern: %s", info->verification_pattern);

	jobj = json_object_new_object();
	json_object_object_add(jobj, "type",
			       json_object_new_string(PAES_VP_TOKEN_NAME));

	jobj_keyslots = json_object_new_array();
	json_object_object_add(jobj, "keyslots", jobj_keyslots);

	json_object_object_add(jobj, PAES_VP_TOKEN_VP,
			       json_object_new_string(
					info->verification_pattern));

	rc = crypt_token_json_set(cd, token >= 0 ? token : CRYPT_ANY_TOKEN,
				  json_object_to_json_string_ext(jobj,
						  JSON_C_TO_STRING_PLAIN));

	if (rc < 0)
		warnx("Failed to add the verification-pattern token to device "
		      "'%s': %s", g.pos_arg, strerror(-rc));
	else
		pr_verbose("Verification-pattern token put to token slot %d",
			   rc);

	json_object_put(jobj);

	return rc;
}

/*
 * Open the LUKS2 device
 */
static int open_device(const char *device, struct crypt_device **cd)
{
	const struct crypt_pbkdf_type pbkdf2 = {
		.type = CRYPT_KDF_PBKDF2,
		.hash = "sha256",
		.time_ms = 2000,
	};
	struct crypt_device *cdev = NULL;
	int rc;

	rc = crypt_init(&cdev, device);
	if (rc != 0) {
		warnx("Failed to open device '%s': %s", device, strerror(-rc));
		goto out;
	}

	crypt_set_log_callback(cdev, cryptsetup_log, NULL);

	rc = crypt_load(cdev, CRYPT_LUKS, NULL);
	if (rc != 0) {
		warnx("Failed to load the header from device '%s': %s", device,
		      strerror(-rc));
		goto out;
	}

	if (strcmp(crypt_get_type(cdev), CRYPT_LUKS2) != 0) {
		warnx("Device '%s' is not a LUKS2 device", device);
		rc = -EINVAL;
		goto out;
	}

	if (strcmp(crypt_get_cipher(cdev), "paes") != 0) {
		warnx("Device '%s' is not encrypted using the 'paes' cipher",
		      device);
		rc = -EINVAL;
		goto out;
	}

	/*
	 * Set PBKDF2 as default key derivation function. LUKS2 uses
	 * Argon2i as default, but this might cause out-of-memory errors when
	 * multiple LUKS2 volumes are opened automatically via /etc/crypttab
	 */
	rc = crypt_set_pbkdf_type(cdev, &pbkdf2);
	if (rc != 0) {
		warnx("Failed to set the PBKDF for device '%s': %s",
		      device, strerror(-rc));
		goto out;
	}

	*cd = cdev;

out:
	if (rc != 0) {
		if (cdev != NULL)
			crypt_free(cdev);
		*cd = NULL;
	}

	return rc;
}

/*
 * Prompts for yes or no. Returns true if 'y' or 'yes' was entered.
 */
static bool _prompt_for_yes(void)
{
	char str[20];

	if (g.batch_mode) {
		printf("(yes implied because '--batch-mode' | '-q' option is "
		       "specified)\n");
		return true;
	}

	if (fgets(str, sizeof(str), stdin) == NULL)
		return false;

	if (str[strlen(str) - 1] == '\n')
		str[strlen(str) - 1] = '\0';
	pr_verbose("Prompt reply: '%s'", str);
	if (strcasecmp(str, "y") == 0 || strcasecmp(str, "yes") == 0)
		return true;

	return false;
}

/*
 * Cleans up a left over re-encipher token and associated unbound keyslot
 */
static int cleanup_reencipher_token(int token)
{
	struct reencipher_token tok;
	int rc;

	rc = get_reencipher_token(g.cd, token, &tok, false);
	if (rc == 0) {
		if (ensure_is_unbound_keylot(tok.unbound_keyslot) == 0) {
			rc = crypt_keyslot_destroy(g.cd, tok.unbound_keyslot);
			if (rc != 0)
				pr_verbose("Failed to destroy unbound key slot "
					   "%d: %s", tok.unbound_keyslot,
					   strerror(-rc));
			else
				pr_verbose("Successfully destroyed unbound key "
					   "slot %d",  tok.unbound_keyslot);
		} else {
			pr_verbose("Key slot %d is not in unbound state, it is "
				   "not destroyed", tok.unbound_keyslot);
		}
	} else {
		pr_verbose("Failed to get re-encipher token (ignored): %s",
			   strerror(-rc));
	}

	rc = crypt_token_json_set(g.cd, token, NULL);
	if (rc < 0)
		warnx("Failed to remove the re-encipher token: %s",
		      strerror(-rc));
	else
		pr_verbose("Successfully removed re-encipher token %d", token);

	return rc;
}

/*
 * Activates an unbound key slot and removes the previous key slots
 */
static int activate_unbound_keyslot(int token, int keyslot, const char *key,
				    size_t keysize, char *password,
				    size_t password_len, char *complete_msg)
{
	crypt_keyslot_info info;
	int rc, i, n;

	rc = crypt_keyslot_add_by_key(g.cd, keyslot, key, keysize, password,
				      password_len, CRYPT_VOLUME_KEY_SET);
	if (rc < 0) {
		warnx("Failed to activate the unbound key slot %d: %s", keyslot,
		      strerror(-rc));
		return rc;
	}

	pr_verbose("Unbound key slot %d activated, it is now key slot %d",
		   keyslot, rc);
	keyslot = rc;

	if (token >= 0) {
		rc = crypt_token_json_set(g.cd, token, NULL);
		if (rc < 0) {
			warnx("Failed remove the re-encipher token %d: %s",
			      token, strerror(-rc));
			return rc;
		}
	}

	if (complete_msg != NULL)
		util_print_indented(complete_msg, 0);
	util_print_indented("All key slots containing the old volume key are "
			    "now in unbound state. Do you want to remove "
			    "these key slots [y/N]?", 0);

	if (!_prompt_for_yes())
		return 0;

	for (i = 0, n = 0; ; i++) {
		if (i == keyslot)
			continue;

		info = crypt_keyslot_status(g.cd, i);
		if (info == CRYPT_SLOT_INVALID)
			break;
		if (info <= CRYPT_SLOT_ACTIVE_LAST)
			continue;

		pr_verbose("Removing now unbound key slot %d", i);
		rc = crypt_keyslot_destroy(g.cd, i);
		if (rc < 0) {
			warnx("Failed to remove previous key slot %d: %s", i,
			      strerror(-rc));
		}

		n++;
	}

	if (n > 1) {
		util_print_indented("\nWARNING:  Before re-enciphering, the "
				    "volume's LUKS header had multiple active "
				    "key slots with the same key, but different "
				    "passwords. Use 'cryptsetup luksAddKey' if "
				    "you need more than one key slot.", 0);
	}

	return rc;
}

static int check_keysize_and_cipher_mode(const u8 *key, size_t keysize)
{
	if (keysize < MIN_SECURE_KEY_SIZE ||
	    keysize > 2 * MAX_SECURE_KEY_SIZE) {
		warnx("Invalid volume key size");
		return -EINVAL;
	}

	if (strncmp(crypt_get_cipher_mode(g.cd), "xts", 3) == 0) {
		if (keysize < 2 * MIN_SECURE_KEY_SIZE ||
		    (key != NULL && !is_xts_key(key, keysize))) {
			warnx("The volume key size %lu is not valid for the "
			      "cipher mode '%s'", keysize,
			      crypt_get_cipher_mode(g.cd));
			return -EINVAL;
		}
	} else {
		if (keysize > MAX_SECURE_KEY_SIZE ||
		    (key != NULL && is_xts_key(key, keysize))) {
			warnx("The volume key size %lu is not valid for the "
			      "cipher mode '%s'", keysize,
			      crypt_get_cipher_mode(g.cd));
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * Open a keyslot and get a secure key from a key slot. Optionally returns the
 * key and password used to unlock the keyslot. You can either open a specific
 * key slot, or let it choose based on the password (keyslot=CRYPT_ANY_SLOT).
 */
static int open_keyslot(int keyslot, char **key, size_t *keysize,
			    char **password, size_t *password_len,
			    const char *prompt)
{
#ifdef HAVE_CRYPT_KEYSLOT_GET_PBKDF
	struct crypt_pbkdf_type pbkdf;
#endif
	char *vkey = NULL;
	char *pw = NULL;
	long long tries;
	size_t vkeysize;
	size_t pw_len;
	int rc;

	vkeysize = crypt_get_volume_key_size(g.cd);
	pr_verbose("Volume key size: %lu", vkeysize);

	rc = check_keysize_and_cipher_mode(NULL, vkeysize);
	if (rc != 0)
		return rc;

	vkey = malloc(vkeysize);
	if (vkey == NULL) {
		warnx("Out of memory while allocating a buffer for the volume "
		      "key");
		return -ENOMEM;
	}

	tries = (is_stdin(g.keyfile) && isatty(STDIN_FILENO)) ? g.tries : 1;
	do {
		if (pw != NULL) {
			secure_free(pw, pw_len);
			pw = NULL;
		}

		rc = get_password(prompt, &pw, &pw_len, g.keyfile,
				  g.keyfile_offset, g.keyfile_size);
		if (rc != 0)
			goto out;

		rc = crypt_volume_key_get(g.cd, keyslot, vkey, &vkeysize,
					  pw, pw_len);

		if (rc == -EPERM || rc == -ENOENT)
			warnx("No key available with this passphrase");


	} while ((rc == -EPERM || rc == -ENOENT) && (--tries > 0));

	if (rc < 0) {
		warnx("Failed to get volume key of device '%s': "
		      "%s", g.pos_arg, strerror(-rc));
		goto out;
	}

	keyslot = rc;
	pr_verbose("Volume key obtained from key slot %d", keyslot);

#ifdef HAVE_CRYPT_KEYSLOT_GET_PBKDF
	/*
	 * Get PBKDF of the key slot that was opened, and use its PBKDF for
	 * new key slots.
	 */
	memset(&pbkdf, 0, sizeof(pbkdf));
	rc = crypt_keyslot_get_pbkdf(g.cd, keyslot, &pbkdf);
	if (rc != 0) {
		warnx("Failed to get the PBKDF for key slot %d: %s",
		      keyslot, strerror(-rc));
		goto out;
	}

	/* Reuse already benchmarked number of iterations */
	pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;

	rc = crypt_set_pbkdf_type(g.cd, &pbkdf);
	if (rc != 0) {
		warnx("Failed to set the PBKDF for new key slots: %s",
		      strerror(-rc));
		goto out;
	}
#endif

	if (key != NULL)
		*key = vkey;
	else
		secure_free(vkey, vkeysize);
	vkey = NULL;
	if (keysize != NULL)
		*keysize = vkeysize;
	if (password != NULL)
		*password = pw;
	else
		secure_free(pw, pw_len);
	pw = NULL;
	if (password_len != NULL)
		*password_len = pw_len;

	rc = keyslot;

out:
	secure_free(vkey, vkeysize);
	secure_free(pw, pw_len);

	return rc;
}


/*
 * Validate and get a secure key from a key slot. Optionally returns the key
 * and password used to unlock the keyslot. You can either validate a specific
 * key slot, or let it choose based on the password (keyslot=CRYPT_ANY_SLOT).
 */
static int validate_keyslot(int keyslot, char **key, size_t *keysize,
			    char **password, size_t *password_len,
			    int *is_old_mk, size_t *clear_keysize,
			    const char *prompt, const char *invalid_msg)
{
	size_t vkeysize = 0;
	char *vkey = NULL;
	int rc, is_old;

	rc = open_keyslot(keyslot, &vkey, &vkeysize, password, password_len,
			  prompt);
	if (rc < 0)
		return rc;

	keyslot = rc;

	rc = validate_secure_key(g.pkey_fd, (u8 *)vkey, vkeysize, clear_keysize,
				 &is_old, NULL, g.verbose);
	if (rc != 0) {
		if (invalid_msg != NULL)
			warnx("%s", invalid_msg);
		else
			warnx("The secure volume key of device '%s' is not "
			      "valid", g.pos_arg);
		rc = -EINVAL;
		goto out;
	}
	pr_verbose("Volume key is currently enciphered with %s master key",
		   is_old ? "OLD" : "CURRENT");

	if (key != NULL)
		*key = vkey;
	else
		secure_free(vkey, vkeysize);
	vkey = NULL;
	if (keysize != NULL)
		*keysize = vkeysize;
	if (is_old_mk != NULL)
		*is_old_mk = is_old;

	rc = keyslot;

out:
	secure_free(vkey, vkeysize);

	return rc;
}

/*
 * Prepares for a re-enciphering of a secure volume key. Dependent on the
 * options specified by the user and the state of the volume key, it starts
 * a staged re-enciphering or performs an in-place re-enciphering.
 */
static int reencipher_prepare(int token)
{
	struct reencipher_token reenc_tok;
	struct vp_token vp_tok;
	char *password = NULL;
	size_t password_len;
	char *key = NULL;
	size_t keysize;
	int is_old_mk;
	bool selected;
	char *prompt;
	char *msg;
	int rc;

	if (token >= 0) {
		util_asprintf(&msg, "Staged volume key re-enciphering is "
			      "already initiated for device '%s'. Do you want to "
			      "cancel the pending re-enciphering and start a "
			      "new re-enciphering process [y/N]?", g.pos_arg);
		util_print_indented(msg, 0);
		free(msg);

		if (!_prompt_for_yes()) {
			warnx("Device '%s' is left unchanged", g.pos_arg);
			return -ECANCELED;
		}

		rc = cleanup_reencipher_token(token);
		if (rc < 0)
			return rc;
	}

	util_asprintf(&prompt, "Enter passphrase for '%s': ", g.pos_arg);
	rc = validate_keyslot(CRYPT_ANY_SLOT, &key, &keysize, &password,
			      &password_len, &is_old_mk, NULL, prompt, NULL);
	free(prompt);
	if (rc < 0)
		goto out;

	reenc_tok.original_keyslot = rc;

	rc = ensure_is_active_keylot(reenc_tok.original_keyslot);
	if (rc != 0)
		goto out;

	rc = generate_key_verification_pattern((u8 *)key, keysize,
					       reenc_tok.verification_pattern,
					 sizeof(reenc_tok.verification_pattern),
					       g.verbose);
	if (rc != 0) {
		warnx("Failed to generate the verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		goto out;
	}

	memcpy(vp_tok.verification_pattern, reenc_tok.verification_pattern,
	       sizeof(vp_tok.verification_pattern));
	token = find_token(g.cd, PAES_VP_TOKEN_NAME);
	rc = put_vp_token(g.cd, token, &vp_tok);
	if (rc < 0)
		goto out;

	if (!g.fromold && !g.tonew) {
		/* Autodetect reencipher mode */
		if (is_old_mk) {
			g.fromold = 1;
			util_asprintf(&msg, "The secure volume key of device "
				      "'%s' is enciphered with the OLD "
				      "master key and is being re-enciphered "
				      "with the CURRENT master key.",
				      g.pos_arg);
			util_print_indented(msg, 0);
			free(msg);
		} else {
			g.tonew = 1;
			util_asprintf(&msg, "The secure volume key of device "
				      "'%s' is enciphered with the CURRENT "
				      "master key and is being re-enciphered "
				      "with the NEW master key.",
				      g.pos_arg);
			util_print_indented(msg, 0);
			free(msg);
		}
	}

	if (g.fromold) {
		rc = reencipher_secure_key(&g.lib, (u8 *)key, keysize,
					   NULL, REENCIPHER_OLD_TO_CURRENT,
					   &selected, g.verbose);
		if (rc != 0) {
			if (rc == -ENODEV) {
				warnx("No APQN found that is suitable for "
				      "re-enciphering the secure AES volume "
				      "key from the OLD to the CURRENT master "
				      "key.");
			} else {
				warnx("Failed to re-encipher the secure volume "
				      "key for device '%s'\n", g.pos_arg);
				if (!selected &&
				    !is_ep11_aes_key((u8 *)key, keysize))
					print_msg_for_cca_envvars(
						"secure AES volume key");
				rc = -EINVAL;
			}
			goto out;
		}
	}

	if (g.tonew) {
		rc = reencipher_secure_key(&g.lib, (u8 *)key, keysize,
					   NULL, REENCIPHER_CURRENT_TO_NEW,
					   &selected, g.verbose);
		if (rc != 0) {
			if (rc == -ENODEV) {
				warnx("No APQN found that is suitable for "
				      "re-enciphering the secure AES volume "
				      "key from the CURRENT to the NEW master "
				      "key.");
			} else {
				warnx("Failed to re-encipher the secure volume "
				      "key for device '%s'\n", g.pos_arg);
				if (!selected &&
				    !is_ep11_aes_key((u8 *)key, keysize))
					print_msg_for_cca_envvars(
						"secure AES volume key");
				rc = -EINVAL;
			}
			goto out;
		}
	}

	rc = crypt_keyslot_add_by_key(g.cd, CRYPT_ANY_SLOT, key, keysize,
				      password, password_len,
				      CRYPT_VOLUME_KEY_NO_SEGMENT);
	if (rc < 0) {
		warnx("Failed to add an unbound key slot to device '%s': %s",
		      g.pos_arg, strerror(-rc));
		goto out;
	}

	reenc_tok.unbound_keyslot = rc;
	pr_verbose("Re-enciphered volume key added to unbound key slot %d",
			   reenc_tok.unbound_keyslot);

	rc = ensure_is_unbound_keylot(reenc_tok.unbound_keyslot);
	if (rc != 0)
		goto out;

	if ((!is_old_mk && g.inplace) ||
	    (is_old_mk && !g.staged)) {
		if (!g.inplace)
			printf("An in-place re-enciphering is performed.\n");

		util_asprintf(&msg, "Re-enciphering has completed "
			      "successfully for device '%s'", g.pos_arg);
		rc = activate_unbound_keyslot(-1, reenc_tok.unbound_keyslot,
					      key, keysize, password,
					      password_len, msg);
		free(msg);
		goto out;
	}

	rc = put_reencipher_token(g.cd, CRYPT_ANY_TOKEN, &reenc_tok);
	if (rc < 0)
		goto out;
	rc = 0;

	util_asprintf(&msg, "Staged re-enciphering is initiated for "
		      "device '%s'. After the NEW master key has been set "
		      "to become the CURRENT master key, run 'zkey-cryptsetup "
		      "reencipher' with option '--complete' to complete the "
		      "re-enciphering process.", g.pos_arg,
		      program_invocation_short_name);
	util_print_indented(msg, 0);
	free(msg);

out:
	secure_free(password, password_len);
	secure_free(key, keysize);

	return rc;
}

/*
 * Completes a staged re-enciphering.
 */
static int reencipher_complete(int token)
{
	char vp[VERIFICATION_PATTERN_LEN];
	struct reencipher_token tok;
	char *password = NULL;
	size_t password_len;
	char *key = NULL;
	size_t keysize;
	int is_old_mk;
	bool selected;
	char *prompt;
	char *msg;
	int rc;

	rc = get_reencipher_token(g.cd, token, &tok, true);
	if (rc != 0) {
		warnx("Failed to get the re-encipher token from device '%s': "
		      "%s", g.pos_arg, strerror(-rc));
		return rc;
	}

	util_asprintf(&msg, "The re-enciphered secure volume key for "
		      "device '%s' is not valid.\nThe new master key might "
		      "yet have to be set as the CURRENT master key.",
		      g.pos_arg);
	util_asprintf(&prompt, "Enter passphrase for key slot %d of '%s': ",
		      tok.original_keyslot, g.pos_arg);
	rc = validate_keyslot(tok.unbound_keyslot, &key, &keysize, &password,
			      &password_len, &is_old_mk, NULL, prompt, msg);
	free(msg);
	free(prompt);
	if (rc < 0)
		goto out;

	rc = ensure_is_unbound_keylot(rc);
	if (rc != 0)
		goto out;

	if (is_old_mk) {
		util_asprintf(&msg, "The re-enciphered secure volume key "
			      "of device '%s' is enciphered with the "
			      "master key from the OLD master key register. "
			      "The master key might have changed again, "
			      "before the previous volume key re-enciphering "
			      "was completed.\n"
			      "Do you want to re-encipher the secure key with "
			      "the master key in the CURRENT master key "
			      "register [y/N]?", g.pos_arg);
		util_print_indented(msg, 0);
		free(msg);

		if (!_prompt_for_yes()) {
			warnx("Re-enciphering was aborted");
			rc = -ECANCELED;
			goto out;
		}

		rc = reencipher_secure_key(&g.lib, (u8 *)key, keysize,
					   NULL, REENCIPHER_OLD_TO_CURRENT,
					   &selected, g.verbose);
		if (rc != 0) {
			if (rc == -ENODEV) {
				warnx("No APQN found that is suitable for "
				      "re-enciphering the secure AES volume "
				      "key from the OLD to the CURRENT master "
				      "key.");
			} else {
				warnx("Failed to re-encipher the secure volume "
				      "key for device '%s'\n", g.pos_arg);
				if (!selected &&
				    !is_ep11_aes_key((u8 *)key, keysize))
					print_msg_for_cca_envvars(
						"secure AES volume key");
				rc = -EINVAL;
			}
			goto out;
		}

		rc = crypt_keyslot_destroy(g.cd, tok.unbound_keyslot);
		if (rc < 0) {
			warnx("Failed to remove unbound key slot %d: %s",
			      tok.unbound_keyslot, strerror(-rc));
		}

		rc = crypt_keyslot_add_by_key(g.cd, CRYPT_ANY_SLOT, key,
					      keysize, password, password_len,
					      CRYPT_VOLUME_KEY_NO_SEGMENT);
		if (rc < 0) {
			warnx("Failed to add an unbound key slot to device "
			      "'%s': %s", g.pos_arg, strerror(-rc));
			goto out;
		}

		tok.unbound_keyslot = rc;
		pr_verbose("Re-enciphered volume key added to unbound key "
			   "slot %d", tok.unbound_keyslot);

	}

	rc = generate_key_verification_pattern((u8 *)key, keysize, vp,
					       sizeof(vp), g.verbose);
	if (rc != 0) {
		warnx("Failed to generate the verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		goto out;
	}

	if (strcmp(tok.verification_pattern, vp) != 0) {
		warnx("The verification patterns of the new and old volume "
		      "keys do not match");
		rc = -EINVAL;
		goto out;
	}

	util_asprintf(&msg, "Re-enciphering has completed successfully for "
		      "device '%s'.", g.pos_arg);
	rc = activate_unbound_keyslot(token, tok.unbound_keyslot, key, keysize,
				      password, password_len, msg);
	free(msg);

out:
	secure_free(password, password_len);
	secure_free(key, keysize);

	return rc;
}


/*
 * Command handler for 'reencipher'.
 *
 * Re-encipher a volume key of a volume encrypted with LUKS2 and the
 * 'paes' cipher
 */
static int command_reencipher(void)
{
	int token;
	int rc;

	if (g.inplace && g.staged) {
		warnx("Options '--in-place|-i' and '--staged|-s' are "
		      "mutual exclusive");
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

	token = find_token(g.cd, PAES_REENC_TOKEN_NAME);

	if (token < 0 && g.complete) {
		warnx("Staged volume key re-enciphering is not pending for "
		      "device '%s'", g.pos_arg);
		return EXIT_FAILURE;
	}

	if (token < 0 || g.staged || g.inplace)
		rc = reencipher_prepare(token);
	else
		rc = reencipher_complete(token);

	return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void print_verification_pattern(const char *vp)
{
	printf("  Verification pattern:  %.*s\n", VERIFICATION_PATTERN_LEN / 2,
	       vp);
	printf("                         %.*s\n", VERIFICATION_PATTERN_LEN / 2,
	       &vp[VERIFICATION_PATTERN_LEN / 2]);
}

/*
 * Command handler for 'validate'.
 *
 * Validate a volume key of a volume encrypted with LUKS2 and the
 * 'paes' cipher
 */
static int command_validate(void)
{
	int reenc_pending = 0, vp_tok_avail = 0, is_valid = 0, is_old_mk = 0;
	struct reencipher_token reenc_tok;
	struct vp_token vp_tok;
	const char *key_type;
	u8 mkvp[MKVP_LENGTH];
	size_t clear_keysize;
	size_t keysize = 0;
	char *key = NULL;
	char *prompt;
	char *msg;
	int token;
	int rc;

	util_asprintf(&prompt, "Enter passphrase for '%s': ", g.pos_arg);
	rc = open_keyslot(CRYPT_ANY_SLOT, &key, &keysize, NULL, NULL, prompt);
	free(prompt);
	if (rc < 0)
		goto out;

	rc = ensure_is_active_keylot(rc);
	if (rc != 0)
		goto out;

	rc = validate_secure_key(g.pkey_fd, (u8 *)key, keysize, &clear_keysize,
				 &is_old_mk, NULL, g.verbose);
	is_valid = (rc == 0);

	token = find_token(g.cd, PAES_REENC_TOKEN_NAME);
	if (token >= 0) {
		rc = get_reencipher_token(g.cd, token, &reenc_tok, true);
		if (rc == 0)
			reenc_pending = 1;
	}

	token = find_token(g.cd, PAES_VP_TOKEN_NAME);
	if (token >= 0) {
		rc = get_vp_token(g.cd, token, &vp_tok);
		if (rc == 0)
			vp_tok_avail = 1;
	}

	rc = get_master_key_verification_pattern((u8 *)key, keysize,
						 mkvp, g.verbose);
	if (rc != 0) {
		warnx("Failed to get the master key verification pattern: %s",
		      strerror(-rc));
		goto out;
	}

	key_type = get_key_type((u8 *)key, keysize);

	printf("Validation of secure volume key of device '%s':\n", g.pos_arg);
	printf("  Status:                %s\n", is_valid ? "Valid" : "Invalid");
	printf("  Secure key size:       %lu bytes\n", keysize);
	printf("  XTS type key:          %s\n",
	       is_xts_key((u8 *)key, keysize) ? "Yes" : "No");
	printf("  Key type:              %s\n", key_type);
	if (is_valid) {
		printf("  Clear key size:        %lu bits\n", clear_keysize);
		printf("  Enciphered with:       %s master key (MKVP: "
		       "%s)\n", is_old_mk ? "OLD" : "CURRENT",
		       printable_mkvp(get_card_type_for_keytype(key_type),
				      mkvp));
	} else {
		printf("  Clear key size:        (unknown)\n");
		printf("  Enciphered with:       (unknown, MKVP: %s)\n",
		       printable_mkvp(get_card_type_for_keytype(key_type),
				      mkvp));
	}
	if (vp_tok_avail)
		print_verification_pattern(vp_tok.verification_pattern);
	else if (reenc_pending)
		print_verification_pattern(reenc_tok.verification_pattern);
	else
		printf("  Verification pattern:  Not available\n");


	if (reenc_pending)
		printf("  Volume key re-enciphering is pending\n");

	if (!is_valid)
		printf("\nATTENTION: The secure volume key is not valid.\n");

	if (is_old_mk)
		util_print_indented("\nWARNING: The secure volume key is "
				    "currently enciphered with the OLD "
				    "master key. To mitigate the danger of "
				    "data loss re-encipher the volume key with "
				    "the CURRENT master key.", 0);

	if (is_valid && !vp_tok_avail) {
		util_asprintf(&msg, "\nWARNING: The volume key cannot be "
			      "identified because the key verification pattern "
			      "token is not available in the LUKS2 header. Use "
			      "the '%s setvp' command to set the token.",
			      program_invocation_short_name);
		util_print_indented(msg, 0);
		free(msg);
	}

	rc = is_valid ? 0 : -EINVAL;

out:
	secure_free(key, keysize);

	return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'setvp'.
 *
 * Set the verification pattern token to allow identification of the key
 */
static int command_setvp(void)
{
	struct vp_token vp_tok;
	size_t keysize = 0;
	char *key = NULL;
	char *prompt;
	int token;
	int rc;

	util_asprintf(&prompt, "Enter passphrase for '%s': ", g.pos_arg);
	rc = validate_keyslot(CRYPT_ANY_SLOT, &key, &keysize, NULL, NULL,
			      NULL, NULL, prompt, NULL);
	free(prompt);
	if (rc < 0)
		goto out;

	rc = ensure_is_active_keylot(rc);
	if (rc != 0)
		goto out;

	token = find_token(g.cd, PAES_VP_TOKEN_NAME);

	rc = generate_key_verification_pattern((const u8 *)key, keysize,
					       vp_tok.verification_pattern,
					    sizeof(vp_tok.verification_pattern),
					       g.verbose);
	if (rc != 0) {
		warnx("Failed to generate the verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		goto out;
	}

	rc = put_vp_token(g.cd, token, &vp_tok);
	if (rc < 0)
		goto out;

	rc = 0;

out:
	secure_free(key, keysize);

	return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Command handler for 'setkey'.
 *
 * Set a new volume key to allow to recover from an invalid volume key
 */
static int command_setkey(void)
{
	char vp[VERIFICATION_PATTERN_LEN];
	size_t password_len = 0;
	struct vp_token vp_tok;
	size_t newkey_size = 0;
	char *password = NULL;
	size_t keysize = 0;
	u8 *newkey = NULL;
	char *key = NULL;
	int is_old_mk;
	char *prompt;
	int keyslot;
	char *msg;
	int token;
	int rc;

	if (g.master_key_file == NULL) {
		misc_print_required_parm("--master-key-file/-m");
		return EXIT_FAILURE;
	}

	newkey = read_secure_key(g.master_key_file, &newkey_size, g.verbose);
	if (newkey == NULL)
		return EXIT_FAILURE;

	rc = check_keysize_and_cipher_mode(newkey, newkey_size);
	if (rc != 0)
		goto out;

	rc = validate_secure_key(g.pkey_fd, newkey, newkey_size, NULL,
				 &is_old_mk, NULL, g.verbose);
	if (rc != 0) {
		warnx("The secure key in file '%s' is not valid",
		      g.master_key_file);
		goto out;
	}

	if (is_old_mk) {
		util_asprintf(&msg, "The secure key in file '%s' is "
			      "enciphered with the master key in the OLD "
			      "master key register. Do you want to set this "
			      "key as the new volume key anyway [y/N]?",
			      g.master_key_file);
		util_print_indented(msg, 0);
		free(msg);

		if (!_prompt_for_yes()) {
			warnx("Device '%s' is left unchanged", g.pos_arg);
			rc = -EINVAL;
			goto out;
		}
	}

	util_asprintf(&prompt, "Enter passphrase for '%s': ", g.pos_arg);
	rc = open_keyslot(CRYPT_ANY_SLOT, &key, &keysize, &password,
			  &password_len, prompt);
	free(prompt);
	if (rc < 0)
		goto out;

	if (keysize == newkey_size && memcmp(newkey, key, keysize) == 0) {
		warnx("The secure key in file '%s' is equal to the current "
		      "volume key, setkey is ignored", g.master_key_file);
		rc = 0;
		goto out;
	}

	rc = generate_key_verification_pattern(newkey, newkey_size, vp,
					       sizeof(vp), g.verbose);
	if (rc != 0) {
		warnx("Failed to generate the verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		goto out;
	}

	token = find_token(g.cd, PAES_VP_TOKEN_NAME);
	if (token >= 0) {
		rc = get_vp_token(g.cd, token, &vp_tok);
		if (rc < 0) {
			warnx("Failed to get the verification pattern token: "
			      "%s", strerror(-rc));
			goto out;
		}

		if (strcmp(vp_tok.verification_pattern, vp) != 0) {
			warnx("The verification patterns of the new and old "
			      "volume keys do not match");
			rc = -EINVAL;
			goto out;
		}
	} else {
		util_asprintf(&msg, "ATTENTION: The key validation pattern "
			      "token is not available in the LUKS2 header. "
			      "Thus, the new volume key cannot be confirmed to "
			      "be correct. You will lose all data on the "
			      "volume if you set the wrong volume key!\n"
			      "Are you sure that the key in file '%s' is the "
			      "correct volume key for volume '%s' [y/N]?",
			      g.master_key_file, g.pos_arg);
		util_print_indented(msg, 0);
		free(msg);

		if (!_prompt_for_yes()) {
			warnx("Device '%s' is left unchanged", g.pos_arg);
			rc = -EINVAL;
			goto out;
		}
	}

	rc = crypt_keyslot_add_by_key(g.cd, CRYPT_ANY_SLOT, (char *)newkey,
				      newkey_size, password, password_len,
				      CRYPT_VOLUME_KEY_NO_SEGMENT);
	if (rc < 0) {
		warnx("Failed to add an unbound key slot to device '%s': %s",
		      g.pos_arg, strerror(-rc));
		goto out;
	}
	keyslot = rc;

	rc = ensure_is_unbound_keylot(keyslot);
	if (rc != 0)
		goto out;

	pr_verbose("New volume key added to unbound key slot %d", keyslot);

	util_asprintf(&msg, "The volume key has been successfully set for "
		      "device '%s'", g.pos_arg);
	rc = activate_unbound_keyslot(-1, keyslot, (char *)newkey, newkey_size,
				      password, password_len, msg);
	free(msg);
	if (rc < 0)
		goto out;

	memcpy(vp_tok.verification_pattern, vp,
	       sizeof(vp_tok.verification_pattern));
	rc = put_vp_token(g.cd, token, &vp_tok);
	if (rc < 0)
		goto out;

	rc = 0;

out:
	secure_free(password, password_len);
	secure_free(newkey, newkey_size);
	secure_free(key, keysize);

	return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}


static bool is_command(struct zkey_cryptsetup_command *command, const char *str)
{
	char command_str[ZKEY_CRYPTSETUP_COMMAND_STR_LEN];
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
static struct zkey_cryptsetup_command *find_command(const char *command)
{
	struct zkey_cryptsetup_command *cmd = zkey_cryptsetup_commands;

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
	struct zkey_cryptsetup_command *command = NULL;
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
		case 'N':
			g.tonew = 1;
			break;
		case 'O':
			g.fromold = 1;
			break;
		case 'c':
			g.complete = 1;
			break;
		case 'i':
			g.inplace = 1;
			break;
		case 's':
			g.staged = 1;
			break;
		case 'd':
			g.keyfile = optarg;
			break;
		case 'o':
			g.keyfile_offset = strtoll(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.keyfile_offset < 0 ||
			    (g.keyfile_offset == LLONG_MAX &&
			     errno == ERANGE)) {
				warnx("Invalid value for '--keyfile-offset'|"
				      "'-o': '%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case 'l':
			g.keyfile_size = strtoll(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.keyfile_size <= 0 ||
			    (g.keyfile_size == LLONG_MAX && errno == ERANGE)) {
				warnx("Invalid value for '--keyfile-size'|"
				      "'-l': '%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case 'T':
			g.tries = strtoll(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.tries <= 0 ||
			    (g.tries == LLONG_MAX && errno == ERANGE)) {
				warnx("Invalid value for '--tries'|'-T': '%s'",
				      optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case 'm':
			g.master_key_file = optarg;
			break;
		case 'q':
			g.batch_mode = true;
			break;
		case 'D':
			g.debug = true;
			g.verbose = true;
			break;
		case 'V':
			g.verbose = true;
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

	if (command->need_cca_library) {
		rc = load_cca_library(&g.cca, g.verbose);
		if (rc != 0) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}
	if (command->need_ep11_library) {
		rc = load_ep11_library(&g.ep11, g.verbose);
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

	crypt_set_log_callback(NULL, cryptsetup_log, NULL);
	if (g.debug)
#ifdef CRYPT_DEBUG_JSON
		crypt_set_debug_level(CRYPT_DEBUG_JSON);
#else
		crypt_set_debug_level(CRYPT_DEBUG_ALL);
#endif

	if (command->open_device) {
		if (g.pos_arg == NULL) {
			misc_print_required_parm(command->pos_arg);
			rc = EXIT_FAILURE;
			goto out;
		}

		rc = open_device(g.pos_arg, &g.cd);
		if (rc != 0) {
			g.cd = NULL;
			rc = EXIT_FAILURE;
			goto out;
		}
	}

	set_int_handler();

	rc = command->function();

out:
	if (g.cca.lib_csulcca)
		dlclose(g.cca.lib_csulcca);
	if (g.pkey_fd >= 0)
		close(g.pkey_fd);
	if (g.cd)
		crypt_free(g.cd);
	return rc;
}
