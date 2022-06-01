/*
 * Definitions for the pvattest exchange format to send attestation requests and responses between
 * machines. The "exchange format" is a simple file format to send labeled binary blobs between
 * pvattest instances on different machines. All sizes, etc are in big endian.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef PVATTEST_EXCHANGE_FORMAT_H
#define PVATTEST_EXCHANGE_FORMAT_H
/* Must be included before any other header */
#include "config.h"

#include "libpv/glib-helper.h"

#include "types.h"
#include "common.h"

/* Similar to linux/arch/s390x/include/uapi/uvdevice.h as this part needs to be
 * architecture independent.
 */
#define PVATTEST_UID_SIZE 0x10UL
#define PVATTEST_USER_DATA_MAX_SIZE 0x100UL
#define PVATTEST_ARCB_MAX_SIZE 0x100000
#define PVATTEST_MEASUREMENT_MAX_SIZE 0x8000
#define PVATTEST_ADDITIONAL_MAX_SIZE 0x8000

#define PVATTEST_EXCHANGE_V_INVALID 0
#define PVATTEST_EXCHANGE_VERSION_1_00 0x0100

typedef struct _exchange_format_v1_hdr exchange_format_v1_hdr_t;
typedef struct _exchange_format_ctx exchange_format_ctx_t;

/**
 * exchange_ctx_new:
 *
 * @version: Format version. Currently, only version 1 supported.
 * @serialized_arcb: ARCB as #GBytes
 * @req_measurement_size: Measurement size the given ARCB needs.
 * @req_measurement_size: Additional Data size the given ARCB needs.
 * @error: GError. *error will != NULL if error occurs.
 *
 * Returns: (nullable) (transfer full): new, empty exchange format context
 *
 */
exchange_format_ctx_t *exchange_ctx_new(const uint32_t version, GBytes *serialized_arcb,
					const uint32_t req_measurement_size,
					const uint32_t req_additional_size, GError **error)
	PV_NONNULL(2);

/**
 * exchange_ctx_from_file:
 *
 * @filename: name of the file to be loaded
 * @error: GError. *error will != NULL if error occurs.
 *
 * Loads all blobs from file and caches them in the context structure.
 *
 * Returns: (nullable) (transfer full): exchange format context filled with data from file
 *
 */
exchange_format_ctx_t *exchange_ctx_from_file(const char *filename, GError **error) PV_NONNULL(1);
void clear_free_exchange_ctx(exchange_format_ctx_t *ctx);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(exchange_format_ctx_t, clear_free_exchange_ctx)

/**
 * exchange_set_serialized_arcb:
 *
 * @ctx: exchange format context
 * @serialized_arcb: blob to add.
 *
 * Adds blob to the exchange format. Unreferences old data if already set.
 */
void exchange_set_serialized_arcb(exchange_format_ctx_t *ctx, GBytes *serialized_arcb)
	PV_NONNULL(1, 2);

/**
 * exchange_set_measurement:
 *
 * @ctx: exchange format context
 * @measurement: blob to add.
 *
 * Adds blob to the exchange format. Unreferences old data if already set.
 */
void exchange_set_measurement(exchange_format_ctx_t *ctx, GBytes *measurement) PV_NONNULL(1, 2);

/**
 * exchange_set_additional_data:
 *
 * @ctx: exchange format context
 * @additional_data: blob to add.
 *
 * Adds blob to the exchange format. Unreferences old data if already set.
 */
void exchange_set_additional_data(exchange_format_ctx_t *ctx, GBytes *additional_data)
	PV_NONNULL(1, 2);

/**
 * exchange_set_user_data:
 *
 * @ctx: exchange format context
 * @user_data: blob to add.
 *
 * Adds blob to the exchange format. Unreferences old data if already set.
 */
void exchange_set_user_data(exchange_format_ctx_t *ctx, GBytes *user_data) PV_NONNULL(1, 2);

/**
 * exchange_set_config_uid:
 *
 * @ctx: exchange format context
 * @config_uid: blob to add.
 *
 * Adds blob to the exchange format. Unreferences old data if already set.
 */
void exchange_set_config_uid(exchange_format_ctx_t *ctx, GBytes *config_uid) PV_NONNULL(1, 2);

GBytes *exchange_get_serialized_arcb(const exchange_format_ctx_t *ctx) PV_NONNULL(1);
GBytes *exchange_get_measurement(const exchange_format_ctx_t *ctx) PV_NONNULL(1);
GBytes *exchange_get_additional_data(const exchange_format_ctx_t *ctx) PV_NONNULL(1);
GBytes *exchange_get_user_data(const exchange_format_ctx_t *ctx) PV_NONNULL(1);
GBytes *exchange_get_config_uid(const exchange_format_ctx_t *ctx) PV_NONNULL(1);

uint32_t exchange_get_requested_measurement_size(const exchange_format_ctx_t *ctx) PV_NONNULL(1);
uint32_t exchange_get_requested_additional_data_size(const exchange_format_ctx_t *ctx)
	PV_NONNULL(1);

/**
 * exchange_write_to_file:
 *
 * @ctx: exchange format context
 * @filename: name of the file to be loaded
 * @error: GError. *error will != NULL if error occours.
 *
 * Takes all Data in the context and writes them into a file.
 * Places the exchange format header before the data.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */
int exchange_write_to_file(const exchange_format_ctx_t *ctx, const char *filename, GError **error)
	PV_NONNULL(1, 2);

/**
 * exchange_info_print:
 *
 * @ctx: exchange format context
 * @print_data: TRUE: print present data + label names
 *              FALSE: just print label names of present data
 * @stream: FILE* stream to print data
 *
 * Prints the content of @ctx to @stream.
 */
void exchange_info_print(const exchange_format_ctx_t *ctx, const gboolean print_data, FILE *stream)
	PV_NONNULL(1, 3);

#define EXCHANGE_FORMAT_ERROR g_quark_from_static_string("pv-exchange-format_error-quark")
typedef enum {
	EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
	EXCHANGE_FORMAT_ERROR_UNSUPPORTED_VERSION,
	EXCHANGE_FORMAT_ERROR_WRITE,
	EXCHANGE_FORMAT_ERROR_UNSUPPORTED_FILE_TYPE,
} exchange_error_e;

#endif /* PVATTEST_EXCHANGE_FORMAT_H */
