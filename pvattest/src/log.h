/*
 * Definitions used for logging.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef PVATTEST_LOG_H
#define PVATTEST_LOG_H
/* Must be included before any other header */
#include "config.h"

#include "libpv/glib-helper.h"
#include "libpv/macros.h"

#define PVATTEST_LOG_LVL_TOOL_ALL (1 << (G_LOG_LEVEL_USER_SHIFT))
#define PVATTEST_LOG_LVL_ERROR (1 << (G_LOG_LEVEL_USER_SHIFT))
#define PVATTEST_LOG_LVL_WARNING (1 << (G_LOG_LEVEL_USER_SHIFT + 1))
#define PVATTEST_LOG_LVL_INFO (1 << (G_LOG_LEVEL_USER_SHIFT + 2))
#define PVATTEST_LOG_LVL_DEBUG (1 << (G_LOG_LEVEL_USER_SHIFT + 3))

#define PVATTEST_LOG_LVL_DEFAULT PVATTEST_LOG_LVL_WARNING
#define PVATTEST_LOG_LVL_MAX PVATTEST_LOG_LVL_DEBUG

#define PVATTEST_HEXDUMP_LOG_DOMAIN "pvattest_hdump"

void pvattest_log_increase_log_lvl(int *log_lvl);
void pvattest_log_error(const char *format, ...);
void pvattest_log_warning(const char *format, ...);
void pvattest_log_info(const char *format, ...);
void pvattest_log_debug(const char *format, ...);

/** pvattest_log_default_logger:
 *
 * A #GLogFunc implementation.
 * Prefixes log level and adds a "\n" ad the end.
 */
void pvattest_log_default_logger(const char *log_domain, GLogLevelFlags level, const char *message,
				 void *user_data);
/* pvattest_log_plain_logger:
 *
 * A #GLogFunc implementation.
 * Writes message as it is if log level is high enough.
 */
void pvattest_log_plain_logger(const char *log_domain, GLogLevelFlags level, const char *message,
			       void *user_data);
#define dhexdump(v, s)                                                            \
	{                                                                         \
		pvattest_log_debug("%s (%li byte):", #v, s);                      \
		hexdump(v, s, 16L, "    ", PVATTEST_LOG_LVL_DEBUG);               \
		g_log(PVATTEST_HEXDUMP_LOG_DOMAIN, PVATTEST_LOG_LVL_DEBUG, "\n"); \
	}
#define gbhexdump(v)                                                                 \
	{                                                                            \
		pvattest_log_debug("%s:(%li byte):", #v, g_bytes_get_size(v));       \
		hexdump(g_bytes_get_data(v, NULL), g_bytes_get_size(v), 16L, "    ", \
			PVATTEST_LOG_LVL_DEBUG);                                     \
		g_log(PVATTEST_HEXDUMP_LOG_DOMAIN, PVATTEST_LOG_LVL_DEBUG, "\n");    \
	}
void hexdump(const void *data, size_t size, size_t len, const char *prefix, GLogLevelFlags log_lvl)
	PV_NONNULL(1);
void printf_hexdump(const void *data, size_t size, size_t len, const char *prefix, FILE *stream)
	PV_NONNULL(1, 5);
void pvattest_log_GError(const char *info, GError *error) PV_NONNULL(1);

#endif /* PVATTEST_LOG_H */
