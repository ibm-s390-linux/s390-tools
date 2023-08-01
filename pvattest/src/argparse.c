/*
 * Definitions used for parsing arguments.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "argparse.h"
#include "log.h"
#include "common.h"

#define DEFAULT_OUTPUT_FILE_NAME "attest.bin"
#define DEFAULT_OPTION_PHKH_IMG FALSE
#define DEFAULT_OPTION_PHKH_ATT FALSE
#define DEFAULT_OPTION_NO_VERIFY FALSE
#define DEFAULT_OPTION_ONLINE TRUE
#define DEFAULT_OPTION_NONCE TRUE

static pvattest_config_t pvattest_config = {
	.general = {
		.log_level = PVATTEST_LOG_LVL_DEFAULT,
	},
	.create = {
		.output_path = NULL,
		.host_key_document_paths = NULL,
		.crl_paths = NULL,
		.root_ca_path = NULL,
		.certificate_paths = NULL,
		.arp_key_out_path = NULL,
		.phkh_img = DEFAULT_OPTION_PHKH_IMG,
		.phkh_att = DEFAULT_OPTION_PHKH_ATT,
		.online = DEFAULT_OPTION_ONLINE,
		.use_nonce = DEFAULT_OPTION_NONCE,
		.paf = 0,
		.x_aad_size = -1,
	},
	.perform = {
		.output_path = NULL,
		.input_path = NULL,
	},
	.verify = {
		.input_path = NULL,
		.output_path = NULL,
		.hdr_path = NULL,
		.arp_key_in_path = NULL,
		.output_fmt = VERIFY_FMT_YAML,
	},
};
typedef gboolean (*verify_options_fn_t)(GError **);

static gboolean check_for_non_null(const void *ptr, const char *msg, GError **error)
{
	if (!ptr) {
		g_set_error(error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG, "%s", msg);
		return FALSE;
	}
	return TRUE;
}

static gboolean _check_for_invalid_path(const char *path, gboolean must_exist, GError **error)
{
	int cached_errno = 0;

	g_assert(path);

	if (must_exist) {
		if (access(path, F_OK | R_OK) != 0)
			cached_errno = errno;
	}
	if (cached_errno) {
		g_set_error(error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG, "Cannot access '%s': %s",
			    path, g_strerror(cached_errno));
		return FALSE;
	}
	return TRUE;
}

static gboolean check_for_optional_invalid_path(const char *path, gboolean must_exist,
						GError **error)
{
	if (!path)
		return TRUE;
	return _check_for_invalid_path(path, must_exist, error);
}

static gboolean check_for_invalid_path(const char *path, gboolean must_exist, const char *null_msg,
				       GError **error)
{
	if (!check_for_non_null(path, null_msg, error))
		return FALSE;
	return _check_for_invalid_path(path, must_exist, error);
}

static gboolean _check_file_list(char **path_list, gboolean must_exist, GError **error)
{
	char *path = NULL;
	for (char **path_it = path_list; path_it != NULL && *path_it != NULL; path_it++) {
		path = *path_it;
		if (!_check_for_invalid_path(path, must_exist, error))
			return FALSE;
	}
	return TRUE;
}

static gboolean check_optional_file_list(char **path_list, gboolean must_exist, GError **error)
{
	if (!path_list)
		return TRUE;
	return _check_file_list(path_list, must_exist, error);
}

static gboolean check_file_list(char **path_list, gboolean must_exist, const char *null_msg,
				GError **error)
{
	if (!check_for_non_null(path_list, null_msg, error))
		return FALSE;
	return _check_file_list(path_list, must_exist, error);
}

static gboolean hex_str_toull(const char *nptr, uint64_t *dst, GError **error)
{
	uint64_t value;
	gchar *end;

	g_assert(dst);

	if (!g_str_is_ascii(nptr)) {
		g_set_error(
			error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG,
			_("Invalid value: '%s'. A hexadecimal value is required, for example '0xcfe'"),
			nptr);
		return FALSE;
	}

	value = g_ascii_strtoull(nptr, &end, 16);
	if ((value == G_MAXUINT64 && errno == ERANGE) || (end && *end != '\0')) {
		g_set_error(
			error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG,
			_("Invalid value: '%s'. A hexadecimal value is required, for example '0xcfe'"),
			nptr);
		return FALSE;
	}
	*dst = value;
	return TRUE;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

/************************* SHARED OPTIONS *************************************/
/* NOTE REQUIRED */
#define _entry_host_key_document(__arg_data, __indent)                                             \
	{                                                                                          \
		.long_name = "host-key-document", .short_name = 'k', .flags = G_OPTION_FLAG_NONE,  \
		.arg = G_OPTION_ARG_FILENAME_ARRAY, .arg_data = __arg_data,                        \
		.description =                                                                     \
			"FILE specifies a host-key document. At least one is required.\n" __indent \
			"Specify this option multiple times to enable the request for\n" __indent  \
			"more than one host.\n",                                                   \
		.arg_description = "FILE",                                                         \
	}

/* NOTE REQUIRED */
#define _entry_certs(__arg_data, __indent)                                                  \
	{                                                                                   \
		.long_name = "cert", .short_name = 'C', .flags = G_OPTION_FLAG_NONE,        \
		.arg = G_OPTION_ARG_FILENAME_ARRAY, .arg_data = __arg_data,                 \
		.description = "FILE contains a certificate that is used to\n" __indent     \
			       "establish a chain of trust for the verification\n" __indent \
			       "of the host-key documents. The IBM Z signing\n" __indent    \
			       "key and intermediate CA certificate (signed\n" __indent     \
			       "by the root CA) are required.\n",                           \
		.arg_description = "FILE",                                                  \
	}

/* NOTE REQUIRED */
#define _entry_crls(__arg_data, __indent)                                                   \
	{                                                                                   \
		.long_name = "crl", .short_name = 0, .flags = G_OPTION_FLAG_NONE,           \
		.arg = G_OPTION_ARG_FILENAME_ARRAY, .arg_data = __arg_data,                 \
		.description = "FILE contains a certificate revocation list (optional).\n", \
		.arg_description = "FILE",                                                  \
	}

/* NOTE REQUIRED */
#define _entry_root_ca(__arg_data, __indent)                                              \
	{                                                                                 \
		.long_name = "root-ca", .short_name = 0, .flags = G_OPTION_FLAG_NONE,     \
		.arg = G_OPTION_ARG_FILENAME_ARRAY, .arg_data = __arg_data,               \
		.description = "Use FILE as the trusted root CA instead the\n" __indent   \
			       "root CAs that are installed on the system (optional).\n", \
		.arg_description = "FILE",                                                \
	}

/* NOTE REQUIRED */
#define _entry_guest_hdr(__arg_data, __indent)                                            \
	{                                                                                 \
		.long_name = "hdr", .short_name = 0, .flags = G_OPTION_FLAG_NONE,         \
		.arg = G_OPTION_ARG_FILENAME, .arg_data = __arg_data,                     \
		.description = "FILE specifies the header of the guest image.\n" __indent \
			       "Exactly one is required.\n",                              \
		.arg_description = "FILE",                                                \
	}

/* NOTE REQUIRED */
#define _entry_input(__arg_data, __additional_text, __indent)                          \
	{                                                                              \
		.long_name = "input", .short_name = 'i', .flags = G_OPTION_FLAG_NONE,  \
		.arg = G_OPTION_ARG_FILENAME, .arg_data = __arg_data,                  \
		.description = "FILE specifies the " __additional_text " as input.\n", \
		.arg_description = "FILE",                                             \
	}

/* NOTE REQUIRED */
#define _entry_output(__arg_data, __additional_text, __indent)                              \
	{                                                                                   \
		.long_name = "output", .short_name = 'o', .flags = G_OPTION_FLAG_NONE,      \
		.arg = G_OPTION_ARG_FILENAME, .arg_data = __arg_data,                       \
		.description = "FILE specifies the output for the " __additional_text "\n", \
		.arg_description = "FILE",                                                  \
	}

/* NOTE REQUIRED */
#define _entry_att_prot_key_save(__arg_data, __indent)                                           \
	{                                                                                        \
		.long_name = "arpk", .short_name = 'a', .flags = G_OPTION_FLAG_NONE,             \
		.arg = G_OPTION_ARG_FILENAME, .arg_data = __arg_data,                            \
		.description =                                                                   \
			"Save the protection key as GCM-AES256 key in FILE\n" __indent           \
			"Do not publish this key, otherwise your attestation is compromised.\n", \
		.arg_description = "FILE",                                                       \
	}

/* NOTE REQUIRED */
#define _entry_att_prot_key_load(__arg_data, __indent)                                        \
	{                                                                                     \
		.long_name = "arpk", .short_name = 'a', .flags = G_OPTION_FLAG_NONE,          \
		.arg = G_OPTION_ARG_FILENAME, .arg_data = __arg_data,                         \
		.description = "Use FILE to specify the GCM-AES256 key to decrypt\n" __indent \
			       "the attestation request.\n" __indent                          \
			       "Delete this key after verification.\n",                       \
		.arg_description = "FILE",                                                    \
	}

#define _entry_phkh_img(__arg_data, __indent)                                            \
	{                                                                                \
		.long_name = "x-phkh-img", .short_name = 0, .flags = G_OPTION_FLAG_NONE, \
		.arg = G_OPTION_ARG_NONE, .arg_data = __arg_data,                        \
		.description = "Add the public host key hash of the\n" __indent          \
			       "image header used to decrypt\n" __indent                 \
			       "the secure guest to the measurement. (optional)\n"       \
	}

#define _entry_phkh_att(__arg_data, __indent)                                             \
	{                                                                                 \
		.long_name = "x-phkh-att", .short_name = 0, .flags = G_OPTION_FLAG_NONE,  \
		.arg = G_OPTION_ARG_NONE, .arg_data = __arg_data,                         \
		.description = "Add the public host key hash of the\n" __indent           \
			       "attestation header used to decrypt\n" __indent            \
			       "the attestation request to the measurement. (optional)\n" \
	}

#define _entry_no_verify(__arg_data, __indent)                                          \
	{                                                                               \
		.long_name = "no-verify", .short_name = 0, .flags = G_OPTION_FLAG_NONE, \
		.arg = G_OPTION_ARG_NONE, .arg_data = __arg_data,                       \
		.description = "Disable the host-key document verification.\n" __indent \
			       "(optional)\n",                                          \
	}

#define _entry_offline_maps_to_online(__arg_data, __indent)                              \
	{                                                                                \
		.long_name = "offline", .short_name = 0, .flags = G_OPTION_FLAG_REVERSE, \
		.arg = G_OPTION_ARG_NONE, .arg_data = __arg_data,                        \
		.description = "Don't download CRLs. (optional)\n",                      \
	}

#define _entry_verbose(__indent)                                                          \
	{                                                                                 \
		.long_name = "verbose", .short_name = 'V', .flags = G_OPTION_FLAG_NO_ARG, \
		.arg = G_OPTION_ARG_CALLBACK, .arg_data = &increase_log_lvl,              \
		.description = "Provide more detailed output. (optional)\n",              \
		.arg_description = NULL,                                                  \
	}

#define _entry_x_paf(__arg_data, __indent)                                             \
	{                                                                              \
		.long_name = "x-paf", .short_name = 0, .flags = G_OPTION_FLAG_NONE,    \
		.arg = G_OPTION_ARG_CALLBACK, .arg_data = __arg_data,                  \
		.description = "Specify the Plain text Attestation Flags\n" __indent   \
			       "as a hexadecimal value. Flags that change\n" __indent  \
			       "the paf (--phkh-*) take precedence over\n" __indent    \
			       "this flag.\n" __indent                                 \
			       "Setting the nonce paf is not allowed here.\n" __indent \
			       "(optional, default 0x0)\n",                            \
		.arg_description = "HEX",                                              \
	}

#define _entry_x_no_nonce(__arg_data, __indent)                                             \
	{                                                                                   \
		.long_name = "x-no-nonce", .short_name = 0, .flags = G_OPTION_FLAG_REVERSE, \
		.arg = G_OPTION_ARG_NONE, .arg_data = __arg_data,                           \
		.description = "Do not use a nonce in the request.\n" __indent              \
			       "(optional, not recommended)\n"                              \
	}

#define _entry_x_aad_size(__arg_data, __indent)                                                   \
	{                                                                                         \
		.long_name = "x-add-size", .short_name = 0, .flags = G_OPTION_FLAG_NONE,          \
		.arg = G_OPTION_ARG_INT, .arg_data = __arg_data,                                  \
		.description = "Specify the size of the additional area\n" __indent               \
			       "Overwrite every flag that changes\n" __indent                     \
			       "this size implicitly. No verification is performed!\n" __indent   \
			       "Ignored if negative.\n" __indent "(optional, default ignored)\n", \
		.arg_description = "INT"                                                          \
	}

#define _entry_x_user_data(__arg_data, __indent)                                                  \
	{                                                                                         \
		.long_name = "x-user-data", .short_name = 0, .flags = G_OPTION_FLAG_NONE,         \
		.arg = G_OPTION_ARG_FILENAME, .arg_data = __arg_data,                             \
		.description = "Use FILE to specify the user data.\n", .arg_description = "FILE", \
	}

#define _entry__verify_format(__indent)                                                            \
	{                                                                                          \
		.long_name = "format", .short_name = 0, .flags = G_OPTION_FLAG_NONE,               \
		.arg = G_OPTION_ARG_CALLBACK, .arg_data = &set_verify_output_format,               \
		.description = "Define the output format.\n" __indent                              \
			       "Defaults to 'yaml'. (possible values: 'yaml')\n",                  \
		.arg_description = "FORMAT",                                                       \
	}

static gboolean increase_log_lvl(G_GNUC_UNUSED const char *option_name,
				 G_GNUC_UNUSED const char *value, G_GNUC_UNUSED void *data,
				 G_GNUC_UNUSED GError **error)
{
	pvattest_log_increase_log_lvl(&pvattest_config.general.log_level);
	return TRUE;
}

static gboolean set_verify_output_format(const char *option_name, const char *value,
					 G_GNUC_UNUSED void *data, GError **error)
{
	if (!g_strcmp0(value, "yaml")) {
		pvattest_config.verify.output_fmt = VERIFY_FMT_YAML;
	} else {
		g_set_error(error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
			    _("Found value '%s' for option '%s', but only 'yaml' is allowed."),
			    value, option_name);
		return FALSE;
	}
	return TRUE;
}

static gboolean create_set_paf(G_GNUC_UNUSED const char *option_name, const char *value,
			       G_GNUC_UNUSED void *data, GError **error)
{
	return hex_str_toull(value, &pvattest_config.create.paf, error);
}

/***************************** GENERAL OPTIONS ********************************/
static gboolean print_version = FALSE;

static GOptionEntry general_options[] = {
	{
		.long_name = "version",
		.short_name = 'v',
		.flags = G_OPTION_FLAG_NONE,
		.arg = G_OPTION_ARG_NONE,
		.arg_data = &print_version,
		.description = "Print the version and exit.\n",
		.arg_description = NULL,
	},
	_entry_verbose(""),
	{ NULL },
};

/************************* CREATE ATTESTATION OPTIONS *************************/
#define create_indent "                                   "

static GOptionEntry create_options[] = {
	_entry_host_key_document(&pvattest_config.create.host_key_document_paths, create_indent),
	_entry_certs(&pvattest_config.create.certificate_paths, create_indent),
	_entry_crls(&pvattest_config.create.crl_paths, create_indent),
	_entry_root_ca(&pvattest_config.create.root_ca_path, create_indent),
	_entry_output(&pvattest_config.create.output_path, "attestation request", create_indent),
	_entry_att_prot_key_save(&pvattest_config.create.arp_key_out_path, create_indent),

	_entry_no_verify(&pvattest_config.create.no_verify, create_indent),
	_entry_offline_maps_to_online(&pvattest_config.create.online, create_indent),
	_entry_verbose(create_indent),
	{ NULL }
};

static GOptionEntry experimental_create_options[] = {
	_entry_x_no_nonce(&pvattest_config.create.use_nonce, create_indent),
	_entry_x_paf(&create_set_paf, create_indent),
	_entry_x_aad_size(&pvattest_config.create.x_aad_size, create_indent),
	_entry_phkh_img(&pvattest_config.create.phkh_img, create_indent),
	_entry_phkh_att(&pvattest_config.create.phkh_att, create_indent),
	{ NULL }
};

static gboolean verify_create(GError **error)
{
	if (!check_file_list(pvattest_config.create.host_key_document_paths, TRUE,
			     _("Specify --host-key-document at least once."), error))
		return FALSE;
	if (!pvattest_config.create.no_verify) {
		if (!check_file_list(
			    pvattest_config.create.certificate_paths, TRUE,
			    _("Either specify the IBM Z signing key and"
			      " intermediate CA certificate\nby using the '--cert' option, or"
			      " use the '--no-verify' flag to disable the\nhost-key document"
			      " verification completely (at your own risk).\n"
			      "Only use this option in test environments or if"
			      " you trust the unverified document."),
			    error))
			return FALSE;
	}
	if (!check_for_invalid_path(pvattest_config.create.arp_key_out_path, FALSE,
				    _("Missing argument for --arpk."), error))
		return FALSE;
	if (!check_for_invalid_path(pvattest_config.create.output_path, FALSE,
				    _("Missing argument for --output."), error))
		return FALSE;
	if (!check_optional_file_list(pvattest_config.create.crl_paths, TRUE, error))
		return FALSE;
	if (!check_for_optional_invalid_path(pvattest_config.create.root_ca_path, TRUE, error))
		return FALSE;
	return TRUE;
};

/************************* MEASUREMENT OPTIONS ********************************/
#define perform_indent "                            "

static GOptionEntry perform_options[] = {
	_entry_input(&pvattest_config.perform.input_path, "attestation request", perform_indent),
	_entry_output(&pvattest_config.perform.output_path, "attestation result", perform_indent),
	_entry_verbose(perform_indent),
	{ NULL },
};

static GOptionEntry experimental_perform_options[] = {
	_entry_x_user_data(&pvattest_config.perform.user_data_path, perform_indent),
	{ NULL },
};

static gboolean verify_perform(GError **error)
{
	if (!check_for_invalid_path(pvattest_config.perform.input_path, TRUE,
				    _("Missing argument for --input."), error))
		return FALSE;
	if (!check_for_invalid_path(pvattest_config.perform.output_path, FALSE,
				    _("Missing argument for --output."), error))
		return FALSE;
	if (!check_for_optional_invalid_path(pvattest_config.perform.user_data_path, TRUE, error))
		return FALSE;
	return TRUE;
}

/************************* VERIFY OPTIONS ************************************/
#define verify_indent "                        "

static GOptionEntry verify_options[] = {
	_entry_input(&pvattest_config.verify.input_path, "attestation result", verify_indent),
	_entry_output(&pvattest_config.verify.output_path,
		      "verification result.\n" verify_indent "(optional)", verify_indent),
	_entry_guest_hdr(&pvattest_config.verify.hdr_path, verify_indent),
	_entry_att_prot_key_load(&pvattest_config.verify.arp_key_in_path, verify_indent),
	_entry_verbose(verify_indent),
	_entry__verify_format(verify_indent),
	{ NULL },
};

static gboolean verify_verify(GError **error)
{
	if (!check_for_invalid_path(pvattest_config.verify.input_path, TRUE,
				    _("Missing argument for --input."), error))
		return FALSE;
	if (!check_for_invalid_path(pvattest_config.verify.hdr_path, TRUE,
				    _("Missing argument for --hdr."), error))
		return FALSE;
	if (!check_for_invalid_path(pvattest_config.verify.arp_key_in_path, TRUE,
				    _("Missing argument for --arpk."), error))
		return FALSE;
	return TRUE;
}

/************************** OPTIONS END ***************************************/

#pragma GCC diagnostic pop

static char summary[] =
	"\n"
	"Create, perform, and verify attestation measurements for IBM Secure Execution guest"
	" systems.\n"
	"\n"
	"COMMANDS\n"
	"  create    On a trusted system, creates an attestation request.\n"
	"  perform   On the SE-guest to be attested, sends the attestation request\n"
	"            to the Ultravisor and receives the answer.\n"
#ifndef PVATTEST_COMPILE_PERFORM
	"            (not supported on this platform)\n"
#endif /* PVATTEST_COMPILE_PERFORM */

	"  verify    On a trusted system, compares the one from your trusted system.\n"
	"            If they differ, the Secure Execution guest might not be compromised\n"
	"\n"
	"Use '" GETTEXT_PACKAGE " [COMMAND] -h' to get detailed help\n";
static char create_summary[] =
	"Create attestation measurement requests to attest an\n"
	"IBM Secure Execution guest. Only build attestation requests in a trusted\n"
	"environment such as your Workstation.\n"
	"To avoid compromising the attestation do not publish the\n"
	"protection key and delete it after verification.\n"
	"Every 'create' will generate a new, random protection key.\n";
static char perform_summary[] =
#ifndef PVATTEST_COMPILE_PERFORM
	"This system does NOT support 'perform'.\n"
#endif /* PVATTEST_COMPILE_PERFORM */
	"Perform a measurement of this IBM Secure Execution guest using '/dev/uv'.\n";
static char verify_summary[] =
	"Verify that a previously generated attestation measurement of an\n"
	"IBM Secure Execution guest yielded the expected results.\n"
	"Verify attestation requests only in a trusted environment, such as your workstation.";

static void print_version_and_exit(void)
{
	printf("%s version %s\n", GETTEXT_PACKAGE, RELEASE_STRING);
	printf("%s\n", COPYRIGHT_NOTICE);
	exit(EXIT_SUCCESS);
}

static GOptionContext *create_ctx(GOptionEntry *options, GOptionEntry *experimental_options,
				  const char *param_name, const char *opt_summary)
{
	GOptionContext *ret = g_option_context_new(param_name);
	GOptionGroup *x_group = NULL;
	g_option_context_add_main_entries(ret, options, NULL);
	g_option_context_set_summary(ret, opt_summary);
	if (experimental_options) {
		x_group = g_option_group_new(
			"experimental",
			"Experimental Options; Do not use in a production environment",
			"Show experimental options", NULL, NULL);
		g_option_group_add_entries(x_group, experimental_options);
		g_option_context_add_group(ret, x_group);
	}
	return ret;
}

enum pvattest_command pvattest_parse(int *argc, char **argvp[], pvattest_config_t **config,
				     GError **error)
{
	g_autoptr(GOptionContext) main_context = NULL, subc_context = NULL;
	char **argv = *argvp;
	enum pvattest_command subc = PVATTEST_SUBC_INVALID;
	verify_options_fn_t verify_options_fn = NULL;

	pv_wrapped_g_assert(argc);
	pv_wrapped_g_assert(argvp);
	pv_wrapped_g_assert(config);

	/*
	 * First parse until the first non dash argument. This must be one of the commands.
	 * (strict POSIX parsing)
	 */
	main_context = g_option_context_new(
		"COMMAND [OPTIONS] - create, perform, and verify attestation measurements");
	g_option_context_set_strict_posix(main_context, TRUE);
	g_option_context_add_main_entries(main_context, general_options, NULL);
	g_option_context_set_summary(main_context, summary);

	if (!g_option_context_parse(main_context, argc, argvp, error))
		return PVATTEST_SUBC_INVALID;
	if (print_version)
		print_version_and_exit();

	/*
	 * Parse depending on the specified command
	 */
	else if (g_strcmp0(argv[1], PVATTEST_SUBC_STR_CREATE) == 0) {
		subc_context =
			create_ctx(create_options, experimental_create_options,
				   "create [OPTIONS] - create an attestation measurement request",
				   create_summary);
		subc = PVATTEST_SUBC_CREATE;
		verify_options_fn = &verify_create;
	} else if (g_strcmp0(argv[1], PVATTEST_SUBC_STR_PERFORM) == 0) {
		subc_context =
			create_ctx(perform_options, experimental_perform_options,
				   "perform [OPTIONS] - perform an attestation measurement request",
				   perform_summary);
		subc = PVATTEST_SUBC_PERFORM;
		verify_options_fn = &verify_perform;
#ifndef PVATTEST_COMPILE_PERFORM
		g_set_error(error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARG,
			    _("This system does not support the 'perform' command."));
		return PVATTEST_SUBC_INVALID;
#endif /* PVATTEST_COMPILE_PERFORM */
	} else if (g_strcmp0(argv[1], PVATTEST_SUBC_STR_VERIFY) == 0) {
		subc_context = create_ctx(verify_options, NULL,
					  "verify [OPTIONS] - verify an attestation measurement",
					  verify_summary);
		subc = PVATTEST_SUBC_VERIFY;
		verify_options_fn = &verify_verify;
	} else {
		if (argv[1])
			g_set_error(error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARGV,
				    _("Invalid command specified: %s."), argv[1]);
		else
			g_set_error(error, PVATTEST_ERROR, PVATTEST_ERR_INV_ARGV,
				    _("No command specified."));
		return PVATTEST_SUBC_INVALID;
	}
	g_assert(verify_options_fn);

	if (!g_option_context_parse(subc_context, argc, argvp, error))
		return PVATTEST_SUBC_INVALID;

	if (!verify_options_fn(error))
		return PVATTEST_SUBC_INVALID;

	*config = &pvattest_config;
	return subc;
}

static void pvattest_parse_clear_create_config(pvattest_create_config_t *config)
{
	if (!config)
		return;
	g_strfreev(config->host_key_document_paths);
	g_strfreev(config->certificate_paths);
	g_free(config->arp_key_out_path);
	g_free(config->output_path);
}

static void pvattest_parse_clear_perform_config(pvattest_perform_config_t *config)
{
	if (!config)
		return;
	g_free(config->input_path);
	g_free(config->output_path);
}

static void pvattest_parse_clear_verify_config(pvattest_verify_config_t *config)
{
	if (!config)
		return;
	g_free(config->input_path);
	g_free(config->output_path);
	g_free(config->hdr_path);
	g_free(config->arp_key_in_path);
}

void pvattest_parse_clear_config(pvattest_config_t *config)
{
	if (!config)
		return;
	pvattest_parse_clear_create_config(&config->create);
	pvattest_parse_clear_perform_config(&config->perform);
	pvattest_parse_clear_verify_config(&config->verify);
}
