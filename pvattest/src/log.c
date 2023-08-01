/*
 * Functions used for logging.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <stdio.h>
#include <stdarg.h>

#include "types.h"
#include "common.h"
#include "log.h"

void pvattest_log_increase_log_lvl(int *log_lvl)
{
	if (*log_lvl >= PVATTEST_LOG_LVL_MAX)
		return;
	*log_lvl = *log_lvl << 1;
}

void pvattest_log_error(const char *format, ...)
{
	va_list argp;

	va_start(argp, format);
	g_logv(NULL, PVATTEST_LOG_LVL_ERROR, format, argp);
	va_end(argp);
}

void pvattest_log_warning(const char *format, ...)
{
	va_list argp;

	va_start(argp, format);
	g_logv(NULL, PVATTEST_LOG_LVL_WARNING, format, argp);
	va_end(argp);
}

void pvattest_log_info(const char *format, ...)
{
	va_list argp;

	va_start(argp, format);
	g_logv(NULL, PVATTEST_LOG_LVL_INFO, format, argp);
	va_end(argp);
}

void pvattest_log_debug(const char *format, ...)
{
	va_list argp;

	va_start(argp, format);
	g_logv(NULL, PVATTEST_LOG_LVL_DEBUG, format, argp);
	va_end(argp);
}

static void _log_print(FILE *stream, const char *prefix, const char *message, const char *postfix)
{
	g_autofree char *prefix_empty = NULL, *new_msg = NULL;
	size_t prefix_len = strlen(prefix);
	char **message_v;

	if (!prefix || prefix_len == 0) {
		printf("%s%s", message, postfix);
		return;
	}

	message_v = g_strsplit(message, "\n", 0);
	prefix_empty = g_malloc0(prefix_len + 2);

	snprintf(prefix_empty, prefix_len + 2, "\n%*c\b", (int)prefix_len, ' ');
	new_msg = g_strjoinv(prefix_empty, message_v);

	fprintf(stream, "%s%s%s", prefix, new_msg, postfix);

	g_strfreev(message_v);
}

static void _log_logger(GLogLevelFlags level, const char *message, int log_level,
			gboolean use_prefix, const char *postfix)
{
	const char *prefix = "";

	/* filter out messages depending on debugging level */
	if ((level & PVATTEST_LOG_LVL_DEBUG) && log_level < PVATTEST_LOG_LVL_DEBUG)
		return;

	if ((level & PVATTEST_LOG_LVL_INFO) && log_level < PVATTEST_LOG_LVL_INFO)
		return;

	if (use_prefix && level & (G_LOG_LEVEL_WARNING | PVATTEST_LOG_LVL_WARNING))
		prefix = _("WARNING: ");

	if (use_prefix && level & (G_LOG_LEVEL_ERROR | PVATTEST_LOG_LVL_ERROR))
		prefix = _("ERROR: ");

	if (use_prefix && level & (G_LOG_LEVEL_DEBUG | PVATTEST_LOG_LVL_DEBUG))
		prefix = _("DEBUG: ");

	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_ERROR | PVATTEST_LOG_LVL_WARNING |
		     PVATTEST_LOG_LVL_ERROR))
		_log_print(stderr, prefix, message, postfix);
	else
		_log_print(stdout, prefix, message, postfix);
}

/**
 * prefixes type. and adds a "\n" ad the end.
 */
void pvattest_log_default_logger(const char *log_domain G_GNUC_UNUSED, GLogLevelFlags level,
				 const char *message, void *user_data)
{
	int log_level = *(int *)user_data;

	_log_logger(level, message, log_level, TRUE, "\n");
}

/*
 * writes message as it is if log level is high enough.
 */
void pvattest_log_plain_logger(const char *log_domain G_GNUC_UNUSED, GLogLevelFlags level,
			       const char *message, void *user_data)
{
	int log_level = *(int *)user_data;

	_log_logger(level, message, log_level, FALSE, "");
}

void pvattest_log_bytes(const void *data, size_t size, size_t width, const char *prefix,
			gboolean beautify, GLogLevelFlags log_lvl)
{
	const uint8_t *data_b = data;

	pv_wrapped_g_assert(data);

	if (beautify)
		g_log(PVATTEST_BYTES_LOG_DOMAIN, log_lvl, "%s0x0000  ", prefix);
	else
		g_log(PVATTEST_BYTES_LOG_DOMAIN, log_lvl, "%s", prefix);
	for (size_t i = 0; i < size; i++) {
		g_log(PVATTEST_BYTES_LOG_DOMAIN, log_lvl, "%02x", data_b[i]);
		if (i % 2 == 1 && beautify)
			g_log(PVATTEST_BYTES_LOG_DOMAIN, log_lvl, " ");
		if (i == size - 1)
			break;
		if (i % width == width - 1) {
			if (beautify)
				g_log(PVATTEST_BYTES_LOG_DOMAIN, log_lvl, "\n%s0x%04lx  ", prefix,
				      i + 1);
			else
				g_log(PVATTEST_BYTES_LOG_DOMAIN, log_lvl, "\n%s", prefix);
		}
	}
	g_log(PVATTEST_BYTES_LOG_DOMAIN, log_lvl, "\n");
}

void pvattest_hexdump(FILE *stream, GBytes *bytes, const size_t width, const char *prefix,
		      const gboolean beautify)
{
	const uint8_t *data;
	size_t size;

	pv_wrapped_g_assert(bytes);
	pv_wrapped_g_assert(stream);

	data = g_bytes_get_data(bytes, &size);
	pv_wrapped_g_assert(data);

	if (beautify)
		fprintf(stream, "%s0x0000  ", prefix);
	else
		fprintf(stream, "%s", prefix);
	for (size_t i = 0; i < size; i++) {
		fprintf(stream, "%02x", data[i]);
		if (i % 2 == 1 && beautify)
			fprintf(stream, " ");
		if (i == size - 1)
			break;
		if (width == 0)
			continue;
		if (i % width == width - 1) {
			if (beautify)
				fprintf(stream, "\n%s0x%04lx  ", prefix, i + 1);
			else
				fprintf(stream, "\n%s", prefix);
		}
	}
}

void pvattest_log_GError(const char *info, GError *error)
{
	pv_wrapped_g_assert(info);

	if (!error)
		return;

	pvattest_log_error("%s:\n%s", info, error->message);
}
