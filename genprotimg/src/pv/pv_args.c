/*
 * PV arguments related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <glib.h>
#include <glib/gprintf.h>

#include "common.h"

#include "pv_comp.h"
#include "pv_error.h"
#include "pv_args.h"

static gchar summary[] =
	"Use genprotimg to create a protected virtualization kernel image file,\n"
	"which can be loaded using zipl or QEMU. For all certificates, revocation\n"
	"lists, and host-key documents, both the PEM and DER input formats are\n"
	"supported.";

static gint pv_arg_compare(gconstpointer arg_1, gconstpointer arg_2)
{
	g_assert(arg_1);
	g_assert(arg_2);

	PvComponentType a = ((PvArg *)arg_1)->type;
	PvComponentType b = ((PvArg *)arg_2)->type;

	if (a < b)
		return -1;
	if (a == b)
		return 0;
	return 1;
}

static gint pv_arg_has_type(gconstpointer arg, gconstpointer type)
{
	const PvArg *c = arg;
	const PvComponentType *t = type;

	g_assert(arg);

	if (c->type == *t)
		return 0;
	if (c->type < *t)
		return -1;
	return 1;
}

static gint pv_args_set_defaults(PvArgs *args, GError **err G_GNUC_UNUSED)
{
	if (!args->psw_addr)
		args->psw_addr =
			g_strdup_printf("0x%lx", DEFAULT_INITIAL_PSW_ADDR);

	return 0;
}

static gint pv_args_validate_options(PvArgs *args, GError **err)
{
	PvComponentType KERNEL = PV_COMP_TYPE_KERNEL;

	if (args->unused_values->len > 0) {
		g_autofree gchar *unused = NULL;

		for (gsize i = args->unused_values->len; i > 0; i--) {
			g_autofree gchar *tmp = unused;

			unused = g_strjoin(" ", g_ptr_array_index(args->unused_values, i - 1),
					   tmp,
					   NULL);
		}

		g_set_error(err, PV_PARSE_ERROR, PR_PARSE_ERROR_INVALID_ARGUMENT,
			    _("Unrecognized arguments: '%s'.\nUse 'genprotimg --help' for more information"),
			    unused);
		return -1;
	}

	if (!args->output_path) {
		g_set_error(err, PV_PARSE_ERROR, PR_PARSE_ERROR_MISSING_ARGUMENT,
			    _("Option '--output' is required.\nUse 'genprotimg --help' for more information"));
		return -1;
	}

	if (!g_slist_find_custom(args->comps, &KERNEL, pv_arg_has_type)) {
		g_set_error(err, PV_PARSE_ERROR, PR_PARSE_ERROR_MISSING_ARGUMENT,
			    _("Option '--image' is required.\nUse 'genprotimg --help' for more information"));
		return -1;
	}

	if (!args->host_keys || g_strv_length(args->host_keys) == 0) {
		g_set_error(err, PV_PARSE_ERROR, PR_PARSE_ERROR_MISSING_ARGUMENT,
			    _("Option '--host-key-document' is required.\nUse 'genprotimg --help' for more information"));
		return -1;
	}

	if (!args->no_verify &&
	    (!args->untrusted_cert_paths ||
	     g_strv_length(args->untrusted_cert_paths) == 0)) {
		g_set_error(
			err, PV_PARSE_ERROR, PR_PARSE_ERROR_MISSING_ARGUMENT,
			_("Either specify the IBM Z signing key and (DigiCert) intermediate CA certificate\n"
			  "by using the '--cert' option, or use the '--no-verify' flag to disable the\n"
			  "host-key document verification completely (at your own risk)."));
		return -1;
	}

	return 0;
}

static gboolean cb_add_component(const gchar *option, const gchar *value,
				 PvArgs *args, GError **err)
{
	PvArg *comp = NULL;
	gint type = -1;

	if (g_str_equal(option, "-i") || g_str_equal(option, "--image"))
		type = PV_COMP_TYPE_KERNEL;
	if (g_str_equal(option, "-r") || g_str_equal(option, "--ramdisk"))
		type = PV_COMP_TYPE_INITRD;
	if (g_str_equal(option, "-p") || g_str_equal(option, "--parmfile"))
		type = PV_COMP_TYPE_CMDLINE;

	if (type < 0) {
		g_set_error(err, PV_PARSE_ERROR, PV_PARSE_ERROR_SYNTAX,
			    _("Invalid option '%s': "), option);
		return FALSE;
	}

	if (g_slist_find_custom(args->comps, &type, pv_arg_has_type)) {
		g_set_error(err, PV_PARSE_ERROR, PV_PARSE_ERROR_SYNTAX,
			    _("Multiple values for option '%s'"), option);
		return FALSE;
	}

	comp = pv_arg_new((PvComponentType)type, value);
	args->comps = g_slist_insert_sorted(args->comps, comp, pv_arg_compare);
	return TRUE;
}

static gboolean cb_set_string_option(const gchar *option, const gchar *value,
				     PvArgs *args, GError **err)
{
	gchar **args_option = NULL;

	if (g_str_equal(option, "--root-ca"))
		args_option = &args->root_ca_path;
	if (g_str_equal(option, "-o") || g_str_equal(option, "--output"))
		args_option = &args->output_path;
	if (g_str_equal(option, "--x-comp-key"))
		args_option = &args->xts_key_path;
	if (g_str_equal(option, "--x-comm-key"))
		args_option = &args->cust_comm_key_path;
	if (g_str_equal(option, "--x-header-key"))
		args_option = &args->cust_root_key_path;
	if (g_str_equal(option, "--x-pcf"))
		args_option = &args->pcf;
	if (g_str_equal(option, "--x-psw"))
		args_option = &args->psw_addr;
	if (g_str_equal(option, "--x-scf"))
		args_option = &args->scf;

	if (!args_option) {
		g_set_error(err, PV_PARSE_ERROR, PV_PARSE_ERROR_SYNTAX,
			    _("Invalid option '%s': "), option);
		return FALSE;
	}

	if (*args_option) {
		g_set_error(err, PV_PARSE_ERROR, PV_PARSE_ERROR_SYNTAX,
			    _("Multiple values for option '%s'"), option);
		return FALSE;
	}

	*args_option = g_strdup(value);
	return TRUE;
}

static gboolean cb_set_log_level(const gchar *option G_GNUC_UNUSED,
				 const gchar *value G_GNUC_UNUSED, PvArgs *args,
				 GError **err G_GNUC_UNUSED)
{
	args->log_level++;
	return TRUE;
}

static gboolean cb_remaining_values(const gchar *option G_GNUC_UNUSED,
				    const gchar *value, PvArgs *args,
				    GError **err G_GNUC_UNUSED)
{
	g_ptr_array_add(args->unused_values, g_strdup(value));
	return TRUE;
}

#define INDENT "                                   "

gint pv_args_parse_options(PvArgs *args, gint *argc, gchar **argv[],
			   GError **err)
{
	g_autoptr(GOptionContext) context = NULL;
	gboolean print_version = FALSE;
	GOptionGroup *group, *x_group;

	g_autofree gchar *psw_desc = g_strdup_printf(
		_("Load from the specified hexadecimal ADDRESS.\n" INDENT
		  "Optional; default: '0x%lx'."),
		DEFAULT_INITIAL_PSW_ADDR);
	GOptionEntry entries[] = {
		{ .long_name = "host-key-document",
		  .short_name = 'k',
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_FILENAME_ARRAY,
		  .arg_data = &args->host_keys,
		  .description =
			_("FILE specifies a host-key document. At least\n" INDENT
			  "one is required."),
		  .arg_description = _("FILE") },
		{ .long_name = "cert",
		  .short_name = 'C',
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_FILENAME_ARRAY,
		  .arg_data = &args->untrusted_cert_paths,
		  .description = _(
			  "FILE contains a certificate that is used to\n" INDENT
			  "establish a chain of trust for the verification\n" INDENT
			  "of the host-key documents. The IBM Z signing\n" INDENT
			  "key and intermediate CA certificate (signed\n" INDENT
			  "by the root CA) are required."),
		  .arg_description = _("FILE") },
		{ .long_name = "output",
		  .short_name = 'o',
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_string_option,
		  .description = _("Set FILE as the output file."),
		  .arg_description = _("FILE") },
		{ .long_name = "image",
		  .short_name = 'i',
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_add_component,
		  .description = _("Use IMAGE as the Linux kernel image."),
		  .arg_description = _("IMAGE") },
		{ .long_name = "ramdisk",
		  .short_name = 'r',
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_add_component,
		  .description = _("Use RAMDISK as the initial RAM disk\n" INDENT
				   "(optional)."),
		  .arg_description = _("RAMDISK") },
		{ .long_name = "parmfile",
		  .short_name = 'p',
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_add_component,
		  .description = _("Use the kernel parameters stored in PARMFILE\n" INDENT
				   "(optional)."),
		  .arg_description = _("PARMFILE") },
		{ .long_name = "crl",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_FILENAME_ARRAY,
		  .arg_data = &args->crl_paths,
		  .description = _(
			  "FILE contains a certificate revocation list\n" INDENT
			  "(optional)."),
		  .arg_description = _("FILE") },
		{ .long_name = "offline",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_NONE,
		  .arg_data = &args->offline,
		  .description = _("Don't download CRLs (optional)."),
		  .arg_description = NULL },
		{ .long_name = "root-ca",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_string_option,
		  .description = _(
			  "Set FILE as the trusted root CA and don't use the\n" INDENT
			  "root CAs that are installed on the system (optional)."),
		  .arg_description = _("FILE") },
		{ .long_name = "no-verify",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_NONE,
		  .arg_data = &args->no_verify,
		  .description = _("Disable the host-key document verification\n" INDENT
				   "(optional)."),
		  .arg_description = NULL },
		{ .long_name = "verbose",
		  .short_name = 'V',
		  .flags = G_OPTION_FLAG_NO_ARG,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_log_level,
		  .description = _("Provide more detailed output (optional)."),
		  .arg_description = NULL },
		{ .long_name = "version",
		  .short_name = 'v',
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_NONE,
		  .arg_data = &print_version,
		  .description = _("Print the version and exit."),
		  .arg_description = NULL },
		{ .long_name = G_OPTION_REMAINING,
		  .short_name = 0,
		  .flags = 0,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_remaining_values,
		  .description = NULL,
		  .arg_description = NULL },
		{ 0 },
	};

	GOptionEntry x_entries[] = {
		{ .long_name = "x-comm-key",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_string_option,
		  .description = _(
			  "Use FILE as the customer communication key.\n" INDENT
			  "Optional; default: auto-generated."),
		  .arg_description = _("FILE") },
		{ .long_name = "x-comp-key",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_string_option,
		  .description = _(
			  "Use FILE as the AES 256-bit XTS key\n" INDENT
			  "that is used for the component encryption.\n" INDENT
			  "Optional; default: auto-generated."),
		  .arg_description = _("FILE") },
		{ .long_name = "x-header-key",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_string_option,
		  .description = _(
			  "Use FILE as the AES 256-bit GCM header key\n" INDENT
			  "that protects the PV header.\n" INDENT
			  "Optional; default: auto-generated."),
		  .arg_description = _("FILE") },
		{ .long_name = "x-pcf",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_string_option,
		  .description =
			  _("Specify the plaintext control flags\n" INDENT
			    "as a hexadecimal value.\n" INDENT
			    "Optional; default: '0x0'."),
		  .arg_description = _("VALUE") },
		{ .long_name = "x-psw",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_string_option,
		  .description = psw_desc,
		  .arg_description = _("ADDRESS") },
		{ .long_name = "x-scf",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = cb_set_string_option,
		  .description = _("Specify the secret control flags\n" INDENT
				   "as a hexadecimal value.\n" INDENT
				   "Optional; default: '0x0'."),
		  .arg_description = _("VALUE") },
		{ 0 },
	};

	context = g_option_context_new(
		_("- Create a protected virtualization image"));
	g_option_context_set_summary(context, _(summary));
	group = g_option_group_new(GETTEXT_PACKAGE, _("Application Options:"),
				   _("Show help options"), args, NULL);
	g_option_group_add_entries(group, entries);
	g_option_context_set_main_group(context, group);

	x_group = g_option_group_new("experimental", _("Experimental Options:"),
				     _("Show experimental options"), args, NULL);
	g_option_group_add_entries(x_group, x_entries);
	g_option_context_add_group(context, x_group);
	if (!g_option_context_parse(context, argc, argv, err))
		return -1;

	if (print_version) {
		g_printf(_("%s version %s\n"), tool_name, RELEASE_STRING);
		g_printf("%s\n", copyright_notice);
		exit(EXIT_SUCCESS);
	}

	if (pv_args_set_defaults(args, err) < 0)
		return -1;

	return pv_args_validate_options(args, err);
}

PvArgs *pv_args_new(void)
{
	g_autoptr(PvArgs) args = g_new0(PvArgs, 1);

	args->unused_values = g_ptr_array_new_with_free_func(g_free);
	return g_steal_pointer(&args);
}

void pv_args_free(PvArgs *args)
{
	if (!args)
		return;

	g_free(args->pcf);
	g_free(args->scf);
	g_free(args->psw_addr);
	g_free(args->cust_root_key_path);
	g_free(args->cust_comm_key_path);
	g_free(args->gcm_iv_path);
	g_free(args->root_ca_path);
	g_strfreev(args->crl_paths);
	g_strfreev(args->untrusted_cert_paths);
	g_strfreev(args->host_keys);
	g_free(args->xts_key_path);
	g_slist_free_full(args->comps, (GDestroyNotify)pv_arg_free);
	g_ptr_array_free(args->unused_values, TRUE);
	g_free(args->output_path);
	g_free(args->tmp_dir);
	g_free(args);
}

void pv_arg_free(PvArg *arg)
{
	if (!arg)
		return;

	g_free(arg->path);
	g_free(arg);
}
PvArg *pv_arg_new(PvComponentType type, const gchar *path)
{
	g_autoptr(PvArg) ret = g_new0(struct pv_arg, 1);

	ret->type = type;
	ret->path = g_strdup(path);
	return g_steal_pointer(&ret);
}
