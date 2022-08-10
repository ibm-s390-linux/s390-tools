/*
 * Functions for the pvattest exchange format to send attestation requests and responses between
 * machines .
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"

#include "exchange_format.h"
#include "log.h"

struct exchange_shared_hdr {
	be64_t magic;
	be32_t version;
	be32_t size;
} __packed;

/*
 * If size == 0
 * 	offset ignored.
 * 	(part does not exist)
 * if offset >0 and <0x50 -> invalid format
 * if offset == 0 and size > 0 no data saved, however the request will need this amount of memory to
 * 	succeed.
 * 	Only makes sense for measurement and additional data. This however, is not enforced.
 */
struct entry {
	be32_t size;
	be32_t offset;
} __packed;
G_STATIC_ASSERT(sizeof(struct entry) == 8);

struct _exchange_format_v1_hdr {
	be64_t magic;
	be32_t version;
	be32_t size;
	uint64_t reserved;
	struct entry serialized_arcb;
	struct entry measurement;
	struct entry additional_data;
	struct entry user_data;
	struct entry config_uid;
} __packed;
G_STATIC_ASSERT(sizeof(exchange_format_v1_hdr_t) == 0x40);

struct _exchange_format_ctx {
	uint32_t version;
	uint32_t req_meas_size;
	uint32_t req_add_size;
	GBytes *serialized_arcb;
	GBytes *measurement;
	GBytes *additional_data;
	GBytes *user_data;
	GBytes *config_uid;
};

/* Use a byte array to avoid any byteorder issues while checking */

#define PVATTEST_EXCHANGE_MAGIC 0x7076617474657374 /* pvattest */
static const uint8_t exchange_magic[] = { 0x70, 0x76, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74 };

exchange_format_ctx_t *exchange_ctx_new(uint32_t version, GBytes *serialized_arcb,
					uint32_t req_measurement_size, uint32_t req_additional_size,
					GError **error)
{
	g_autoptr(exchange_format_ctx_t) ctx = NULL;

	pv_wrapped_g_assert(serialized_arcb);

	if (version != PVATTEST_EXCHANGE_VERSION_1_00) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR, EXCHANGE_FORMAT_ERROR_UNSUPPORTED_VERSION,
			    _("'%d' unsupported version."), version);
		return NULL;
	}

	ctx = g_malloc0(sizeof(*ctx));
	ctx->version = version;

	exchange_set_serialized_arcb(ctx, serialized_arcb);
	ctx->req_meas_size = req_measurement_size;
	ctx->req_add_size = req_additional_size;

	return g_steal_pointer(&ctx);
}

static GBytes *get_content(GBytes *file_content, const struct entry *entry, const size_t max_size,
			   GError **error)
{
	uint64_t size = GUINT32_FROM_BE(entry->size);
	uint64_t offset = GUINT32_FROM_BE(entry->offset);
	size_t file_size = 0;
	const uint8_t *file_content_u8 = g_bytes_get_data(file_content, &file_size);

	if (size == 0 || offset == 0)
		return NULL;

	if (offset < sizeof(exchange_format_v1_hdr_t) || offset + size > file_size ||
	    size > max_size) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR, EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    _("Input file is not in a valid format."));
		return NULL;
	}
	return g_bytes_new(file_content_u8 + offset, size);
}

static gboolean check_format(const struct exchange_shared_hdr *hdr)
{
	if (memcmp(exchange_magic, &hdr->magic, sizeof(exchange_magic)) == 0)
		return TRUE;
	return FALSE;
}

exchange_format_ctx_t *exchange_ctx_from_file(const char *filename, GError **error)
{
	g_autoptr(exchange_format_ctx_t) ctx = g_malloc0(sizeof(*ctx));
	const struct exchange_shared_hdr *hdr = NULL;
	const exchange_format_v1_hdr_t *hdr_v1 = NULL;
	g_autoptr(GBytes) file_content = NULL;
	size_t config_uid_size = 0;
	size_t file_size;

	pv_wrapped_g_assert(filename);

	file_content = pv_file_get_content_as_g_bytes(filename, error);
	if (!file_content)
		return NULL;
	hdr = (const struct exchange_shared_hdr *)g_bytes_get_data(file_content, &file_size);

	if (file_size < sizeof(*hdr) || !check_format(hdr)) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR, EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    _("'%s' is not in a valid format."), filename);
		return NULL;
	}

	if (GUINT32_FROM_BE(hdr->version) != PVATTEST_EXCHANGE_VERSION_1_00) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR, EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    _("The version (%#x) of '%s' is not supported"),
			    GUINT32_FROM_BE(hdr->version), filename);
		return NULL;
	}

	/* get the header */
	if (file_size < sizeof(exchange_format_v1_hdr_t)) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR, EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    _("'%s' is not in a valid format."), filename);
		return NULL;
	}
	hdr_v1 = (const exchange_format_v1_hdr_t *)hdr;

	/* get entries if present */
	ctx->serialized_arcb =
		get_content(file_content, &hdr_v1->serialized_arcb, PVATTEST_ARCB_MAX_SIZE, error);
	if (*error)
		return NULL;
	ctx->measurement = get_content(file_content, &hdr_v1->measurement,
				       PVATTEST_MEASUREMENT_MAX_SIZE, error);
	if (*error)
		return NULL;
	ctx->additional_data = get_content(file_content, &hdr_v1->additional_data,
					   PVATTEST_ADDITIONAL_MAX_SIZE, error);
	if (*error)
		return NULL;
	ctx->user_data =
		get_content(file_content, &hdr_v1->user_data, PVATTEST_USER_DATA_MAX_SIZE, error);
	if (*error)
		return NULL;
	ctx->config_uid = get_content(file_content, &hdr_v1->config_uid, PVATTEST_UID_SIZE, error);
	if (*error)
		return NULL;

	if (ctx->config_uid)
		config_uid_size = g_bytes_get_size(ctx->config_uid);

	if (config_uid_size != PVATTEST_UID_SIZE && config_uid_size != 0) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR, EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			    _("'%s' is not in a valid format."), filename);
		return NULL;
	}
	ctx->req_meas_size = GUINT32_FROM_BE(hdr_v1->measurement.size);
	ctx->req_add_size = GUINT32_FROM_BE(hdr_v1->additional_data.size);
	ctx->version = GUINT32_TO_BE(hdr->version);

	return g_steal_pointer(&ctx);
}

void clear_free_exchange_ctx(exchange_format_ctx_t *ctx)
{
	if (!ctx)
		return;

	if (ctx->serialized_arcb)
		g_bytes_unref(ctx->serialized_arcb);
	if (ctx->measurement)
		g_bytes_unref(ctx->measurement);
	if (ctx->additional_data)
		g_bytes_unref(ctx->additional_data);
	if (ctx->user_data)
		g_bytes_unref(ctx->user_data);
	if (ctx->config_uid)
		g_bytes_unref(ctx->config_uid);

	g_free(ctx);
}

void exchange_set_serialized_arcb(exchange_format_ctx_t *ctx, GBytes *serialized_arcb)
{
	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(serialized_arcb);

	g_bytes_ref(serialized_arcb);
	g_bytes_unref(ctx->serialized_arcb);
	ctx->serialized_arcb = serialized_arcb;
}

void exchange_set_measurement(exchange_format_ctx_t *ctx, GBytes *measurement)
{
	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(measurement);

	g_bytes_ref(measurement);
	g_bytes_unref(ctx->measurement);
	ctx->measurement = measurement;
}

void exchange_set_additional_data(exchange_format_ctx_t *ctx, GBytes *additional_data)
{
	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(additional_data);

	g_bytes_ref(additional_data);
	g_bytes_unref(ctx->additional_data);
	ctx->additional_data = additional_data;
}

void exchange_set_user_data(exchange_format_ctx_t *ctx, GBytes *user_data)
{
	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(user_data);

	g_bytes_ref(user_data);
	g_bytes_unref(ctx->user_data);
	ctx->user_data = user_data;
}

void exchange_set_config_uid(exchange_format_ctx_t *ctx, GBytes *config_uid)
{
	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(config_uid);

	g_bytes_ref(config_uid);
	g_bytes_unref(ctx->config_uid);
	ctx->config_uid = config_uid;
}

static GBytes *gbytes_ref0(GBytes *bytes)
{
	if (!bytes)
		return NULL;
	return g_bytes_ref(bytes);
}

GBytes *exchange_get_serialized_arcb(const exchange_format_ctx_t *ctx)
{
	pv_wrapped_g_assert(ctx);

	return gbytes_ref0(ctx->serialized_arcb);
}

GBytes *exchange_get_measurement(const exchange_format_ctx_t *ctx)
{
	pv_wrapped_g_assert(ctx);

	return gbytes_ref0(ctx->measurement);
}

GBytes *exchange_get_additional_data(const exchange_format_ctx_t *ctx)
{
	pv_wrapped_g_assert(ctx);

	return gbytes_ref0(ctx->additional_data);
}

GBytes *exchange_get_user_data(const exchange_format_ctx_t *ctx)
{
	pv_wrapped_g_assert(ctx);

	return gbytes_ref0(ctx->user_data);
}

GBytes *exchange_get_config_uid(const exchange_format_ctx_t *ctx)
{
	pv_wrapped_g_assert(ctx);

	return gbytes_ref0(ctx->config_uid);
}

uint32_t exchange_get_requested_measurement_size(const exchange_format_ctx_t *ctx)
{
	pv_wrapped_g_assert(ctx);

	return ctx->req_meas_size;
}

uint32_t exchange_get_requested_additional_data_size(const exchange_format_ctx_t *ctx)
{
	pv_wrapped_g_assert(ctx);

	return ctx->req_add_size;
}

static struct entry add_g_bytes(GBytes *bytes, FILE *file, GError **error)
{
	struct entry result = {};
	long offset;
	size_t size;
	const void *data = g_bytes_get_data(bytes, &size);

	g_assert(size <= G_MAXUINT32);

	offset = pv_file_tell(file, error);
	g_assert(offset <= G_MAXUINT32);
	if (offset < 0)
		return result;

	result.offset = GUINT32_TO_BE((uint32_t)offset);
	result.size = GUINT32_TO_BE((uint32_t)size);
	pv_file_write(file, data, size, error);
	return result;
}

int exchange_write_to_file(const exchange_format_ctx_t *ctx, const char *filename, GError **error)
{
	exchange_format_v1_hdr_t hdr = {
		.magic = GUINT64_TO_BE(PVATTEST_EXCHANGE_MAGIC),
		.version = GUINT32_TO_BE(ctx->version),
	};
	size_t file_size = sizeof(hdr);
	g_autoptr(FILE) file = NULL;
	struct stat file_stat;
	long actual_file_size;
	size_t tmp_size;

	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(filename);

	file = pv_file_open(filename, "w", error);
	if (!file)
		return -1;

	if (fstat(fileno(file), &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
		g_set_error(error, EXCHANGE_FORMAT_ERROR,
			    EXCHANGE_FORMAT_ERROR_UNSUPPORTED_FILE_TYPE,
			    "Only regular files are supported: '%s'", filename);
		return -1;
	}

	if (pv_file_seek(file, sizeof(exchange_format_v1_hdr_t), SEEK_SET, error))
		return -1;

	if (ctx->serialized_arcb) {
		hdr.serialized_arcb = add_g_bytes(ctx->serialized_arcb, file, error);
		if (*error)
			return -1;
		file_size += g_bytes_get_size(ctx->serialized_arcb);
	}
	if (ctx->measurement) {
		hdr.measurement = add_g_bytes(ctx->measurement, file, error);
		if (*error)
			return -1;
		file_size += g_bytes_get_size(ctx->measurement);
	} else {
		hdr.measurement.size = GUINT32_TO_BE(ctx->req_meas_size);
	}

	if (ctx->additional_data) {
		hdr.additional_data = add_g_bytes(ctx->additional_data, file, error);
		if (*error)
			return -1;
		file_size += g_bytes_get_size(ctx->additional_data);
	} else {
		hdr.additional_data.size = GUINT32_TO_BE(ctx->req_add_size);
	}

	if (ctx->user_data) {
		tmp_size = g_bytes_get_size(ctx->user_data);
		g_assert(tmp_size <= PVATTEST_USER_DATA_MAX_SIZE);
		tmp_size = MIN(tmp_size, PVATTEST_USER_DATA_MAX_SIZE); /* should be a noop */
		hdr.user_data = add_g_bytes(ctx->user_data, file, error);
		if (*error)
			return -1;
		file_size += g_bytes_get_size(ctx->user_data);
	}
	if (ctx->config_uid) {
		tmp_size = g_bytes_get_size(ctx->config_uid);
		g_assert(tmp_size == PVATTEST_UID_SIZE);
		tmp_size = MIN(tmp_size, PVATTEST_UID_SIZE); /* should be a noop */
		hdr.config_uid = add_g_bytes(ctx->config_uid, file, error);
		if (*error)
			return -1;
		file_size += g_bytes_get_size(ctx->config_uid);
	}

	/*
	 * This case should never happen. It could be seen as a programming error as:
	 * ARCB is restricted by kernel (and this tool) to be max 1M, Additional+meas to max 8pages
	 * userdata to 256B and config uid to 16b this is way less than 4G.
	 *
	 * However, lets be conservative and trow an error instead of an assertion.
	 */
	if (file_size > UINT32_MAX) {
		g_set_error(
			error, EXCHANGE_FORMAT_ERROR, EXCHANGE_FORMAT_ERROR_INVALID_FORMAT,
			"The exchange file format cannot handle this much data in one blob. (%#lx bytes)",
			file_size);
		return -1;
	}
	hdr.size = GUINT32_TO_BE((uint32_t)file_size);
	if (pv_file_seek(file, 0, SEEK_SET, error) != 0)
		return -1;
	if (sizeof(hdr) != pv_file_write(file, &hdr, sizeof(hdr), error))
		return -1;
	if (pv_file_seek(file, 0, SEEK_END, error) != 0)
		return -1;
	actual_file_size = pv_file_tell(file, error);
	if (actual_file_size < 0)
		return -1;
	if (actual_file_size != (uint32_t)file_size) {
		g_set_error(
			error, EXCHANGE_FORMAT_ERROR, EXCHANGE_FORMAT_ERROR_WRITE,
			"The exchange file size doesn't match the expectations: %ld bytes != %lu bytes",
			actual_file_size, file_size);
		return -1;
	}

	return 0;
}

static void print_entry(const char *name, GBytes *data, const gboolean print_data, FILE *stream)
{
	if (!data)
		return;
	fprintf(stream, _("%s (%#lx bytes)"), name, g_bytes_get_size(data));
	if (print_data) {
		fprintf(stream, ":\n");
		pvattest_hexdump(g_bytes_get_data(data, NULL), g_bytes_get_size(data), 16, "      ",
				 stream);
	}
	fprintf(stream, "\n");
}

void exchange_info_print(const exchange_format_ctx_t *ctx, const gboolean print_data, FILE *stream)
{
	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(stream);

	fprintf(stream, _("Version: %#x\n"), ctx->version);
	fprintf(stream, _("Sections:\n"));
	print_entry(_("  ARCB"), ctx->serialized_arcb, print_data, stream);
	print_entry(_("  Measurement"), ctx->measurement, print_data, stream);
	print_entry(_("  Additional Data"), ctx->additional_data, print_data, stream);
	print_entry(_("  User Data"), ctx->user_data, print_data, stream);
	print_entry(_("  Config UID"), ctx->config_uid, print_data, stream);
	if (!ctx->measurement)
		fprintf(stream, _("Required measurement size: %#x\n"), ctx->req_meas_size);
	if (!ctx->additional_data)
		fprintf(stream, _("Required additional data size: %#x\n"), ctx->req_add_size);
}
