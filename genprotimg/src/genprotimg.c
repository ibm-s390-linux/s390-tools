/*
 * genprotimg - build relocatable secure images
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gtypes.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>

#include "common.h"
#include "pv/pv_args.h"
#include "pv/pv_image.h"
#include "utils/crypto.h"
#include "utils/curl.h"

enum {
	LOG_LEVEL_CRITICAL = 0,
	LOG_LEVEL_INFO = 1,
	LOG_LEVEL_DEBUG = 2,
};

static gint log_level = LOG_LEVEL_CRITICAL;
static gchar *tmp_dir;

static void rmdir_recursive(gchar *dir_path, GError **err)
{
	const gchar *file = NULL;
	g_autoptr(GDir) d = NULL;

	if (!dir_path)
		return;

	d = g_dir_open(dir_path, 0, err);
	if (!d) {
		g_set_error(err, G_FILE_ERROR,
			    (gint)g_file_error_from_errno(errno),
			    _("Failed to open directory '%s': %s"), dir_path,
			    g_strerror(errno));
		return;
	}

	while ((file = g_dir_read_name(d)) != NULL) {
		g_autofree gchar *file_path =
			g_build_filename(dir_path, file, NULL);
		/* ignore error */
		(void)g_unlink(file_path);
	}

	if (g_rmdir(dir_path) != 0) {
		g_set_error(err, G_FILE_ERROR,
			    (gint)g_file_error_from_errno(errno),
			    _("Failed to remove directory '%s': %s"), dir_path,
			    g_strerror(errno));
		return;
	}
}

static void sig_term_handler(int signal G_GNUC_UNUSED)
{
	rmdir_recursive(tmp_dir, NULL);
	exit(EXIT_FAILURE);
}

static void log_handler_cb(const gchar *log_domain G_GNUC_UNUSED,
			   GLogLevelFlags level, const gchar *message,
			   gpointer user_data G_GNUC_UNUSED)
{
	const gchar *prefix = "";

	/* filter out messages depending on debugging level */
	if ((level & G_LOG_LEVEL_DEBUG) && log_level < LOG_LEVEL_DEBUG)
		return;

	if ((level & G_LOG_LEVEL_INFO) && log_level < LOG_LEVEL_INFO)
		return;

	if (level & G_LOG_LEVEL_WARNING)
		prefix = "WARNING: ";

	if (level & G_LOG_LEVEL_ERROR)
		prefix = "ERROR: ";

	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_ERROR))
		g_printerr("%s%s\n", prefix, message);
	else
		g_print("%s%s\n", prefix, message);
}

static void setup_prgname(const gchar *name)
{
	g_set_prgname(name);
	g_set_application_name(_(name));
}

static void setup_handler(const gint *signals, const gsize signals_n)
{
	/* set up logging handler */
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL |
				  G_LOG_FLAG_RECURSION,
			  log_handler_cb, NULL);

	/* set signal handler */
	for (gsize i = 0; i < signals_n; i++)
		signal(signals[i], sig_term_handler);
}

static void remove_signal_handler(const gint *signals, const gsize signals_n)
{
	for (gsize i = 0; i < signals_n; i++)
		signal(signals[i], SIG_DFL);
}

static void __attribute__((constructor)) __init(void);
static void __attribute__((destructor)) __cleanup(void);
gint main(gint argc, gchar *argv[])
{
	g_autoptr(PvArgs) args = pv_args_new();
	gint signals[] = { SIGINT, SIGTERM };
	g_autoptr(PvImage) img = NULL;
	gint ret = EXIT_FAILURE;
	GError *err = NULL;

	setlocale(LC_CTYPE, "");
	setup_prgname(tool_name);
	setup_handler(signals, G_N_ELEMENTS(signals));

	if (pv_args_parse_options(args, &argc, &argv, &err) < 0)
		goto error;

	/* set new log level */
	log_level = args->log_level;

	/* if the user has not specified a temporary directory let's
	 * create one
	 */
	if (!args->tmp_dir) {
		tmp_dir = g_dir_make_tmp("genprotimg-XXXXXX", &err);
		if (!tmp_dir)
			goto error;
		args->tmp_dir = g_strdup(tmp_dir);
	}

	/* allocate and initialize ``pv_img`` data structure */
	img = pv_img_new(args, GENPROTIMG_STAGE3A_PATH, &err);
	if (!img)
		goto error;

	/* add user components: `args->comps` must be sorted by the
	 * component type => by memory address
	 */
	for (GSList *iterator = args->comps; iterator; iterator = iterator->next) {
		const PvArg *arg = iterator->data;

		if (pv_img_add_component(img, arg, &err) < 0)
			goto error;
	}

	if (pv_img_finalize(img, GENPROTIMG_STAGE3B_PATH, &err) < 0)
		goto error;

	if (pv_img_write(img, args->output_path, &err) < 0)
		goto error;

	ret = EXIT_SUCCESS;

error:
	if (err) {
		fputs(err->message, stderr);
		fputc('\n', stderr);
		g_clear_error(&err);
	}
	rmdir_recursive(tmp_dir, NULL);
	remove_signal_handler(signals, G_N_ELEMENTS(signals));
	g_free(tmp_dir);
	g_clear_pointer(&img, pv_img_free);
	g_clear_pointer(&args, pv_args_free);
	exit(ret);
}

static void __init(void)
{
	pv_crypto_init();
	if (curl_init() != 0)
		g_abort();
}

static void __cleanup(void)
{
	curl_cleanup();
	pv_crypto_cleanup();
}
