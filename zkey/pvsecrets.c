/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_rec.h"

#include "pvsecrets.h"

struct pvsecret_type_info {
	u16 type;
	const char *name;
	bool zkey_usage;
};

static const struct pvsecret_type_info pvsecret_type_info[] = {
	{ .type = UV_SECRET_TYPE_NULL, .name = "NULL",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_AP_ASSOCIATION, .name = "AP-ASSOCIATION",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_PLAIN_TEXT, .name = "PLAIN-TEXT",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_AES_128, .name = "AES-128",
	  .zkey_usage = true },
	{ .type = UV_SECRET_TYPE_AES_192, .name = "AES-192",
	  .zkey_usage = true },
	{ .type = UV_SECRET_TYPE_AES_256, .name = "AES-256",
	  .zkey_usage = true },
	{ .type = UV_SECRET_TYPE_AES_XTS_128, .name = "AES-XTS-128",
	  .zkey_usage = true },
	{ .type = UV_SECRET_TYPE_AES_XTS_256, .name = "AES-XTS-256",
	  .zkey_usage = true },
	{ .type = UV_SECRET_TYPE_HMAC_SHA_256, .name = "HMAC-SHA-256",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_HMAC_SHA_512, .name = "HMAC-SHA-512",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_ECDSA_P256, .name = "ECDSA-P256",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_ECDSA_P384, .name = "ECDSA-P384",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_ECDSA_P521, .name = "ECDSA-P521",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_EDDSA_ED25519, .name = "EDDSA-ED25519",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_EDDSA_ED448, .name = "EDDSA-ED448",
	  .zkey_usage = false },
	{ .type = UV_SECRET_TYPE_INVALID, }
};

#define PVSECRETS_REC_ID		"Secret ID"
#define PVSECRETS_REC_TYPE		"Type"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

/**
 * Opens the ultravisor device and returns its file descriptor.
 * This only succeeds when running in a secure execution guest.
 * A failure of this function indicates that it is not running in a secure
 * execution guest.
 *
 * @param verbose            if true, verbose messages are printed
 *
 * @returns the file descriptor or -1 to indicate an error
 */
int uv_open_device(bool verbose)
{
	unsigned int pvguest = 0, max_retr_secrets = 0;
	char *path = NULL;
	int uv_fd, err;

	uv_fd = open(UVDEVICE, O_RDWR);
	if (uv_fd < 0) {
		err = errno;
		warnx("File '%s:' %s\n", UVDEVICE, strerror(errno));
		if (err == EACCES)
			warnx("Only the 'root' user is allowed to perform "
			      "this command");
		else
			warnx("Ensure that you are running in a secure "
			      "execution guest, and that the 'uvdevice' "
			      "kernel module is loaded.");
		return -1;
	}

	path = util_path_sysfs(SYSFS_UV);
	if (util_file_read_ui(&pvguest, 10, SYSFS_UV_PV_GUEST, path) != 0 ||
	    pvguest != 1) {
		warnx("You are not running in a secure execution guest.");
		goto error;
	}

	if (util_file_read_ui(&max_retr_secrets, 10, SYSFS_UV_MAX_SECRETS,
			      path) != 0 ||
	    max_retr_secrets == 0) {
		warnx("The ultravisor device is at a too old version, or "
		      "the ultravisor does not support retrievable secrets.");
		goto error;
	}
	free(path);

	pr_verbose(verbose, "Device '%s' has been opened successfully",
		   UVDEVICE);
	return uv_fd;

error:
	free(path);
	close(uv_fd);

	return -1;
}

/**
 * Retrieves a list of secrets from the ultravisor. Calls the supplied callback
 * function for each secret found.
 *
 * @param uv_fd              the file descriptor of the ultravisor device
 * @param cb                 the callback function
 * @param cb_private         private data to pass to the callback function
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int uv_list_secrets(int uv_fd, int (*cb)(u16 idx, u16 type, u32 len,
						const u8 id[UV_SECRET_ID_LEN],
						void *cb_private),
			   void *cb_private, bool verbose)
{
	struct uvio_list_secrets *list;
	struct uvio_ioctl_cb io;
	unsigned int i;
	int rc;

	util_assert(uv_fd != -1, "Internal error: uv_fd is -1");
	util_assert(cb != NULL, "Internal error: cb is NULL");

	list = util_zalloc(UVIO_LIST_SECRETS_MAX_LEN);

	memset(&io, 0, sizeof(io));
	io.argument_addr = list;
	io.argument_len = UVIO_LIST_SECRETS_MAX_LEN;

	rc = ioctl(uv_fd, UVIO_IOCTL_LIST_SECRETS, &io);
	if (rc != 0) {
		rc = -errno;

		pr_verbose(verbose, "ioctl UVIO_IOCTL_LIST_SECRETS: %s",
			   strerror(-rc));

		if (rc == -ENOTTY || rc == -EINVAL)
			warnx("The ultravisor device is at a too old version");

		goto out;
	}

	if (io.uv_rc != UVIO_RC_SUCCESS) {
		pr_verbose(verbose, "ioctl UVIO_IOCTL_LIST_SECRETS' uv_rc: %u",
			   io.uv_rc);
		rc = -EIO;
		goto out;
	}

	pr_verbose(verbose, "Number of secrets: %u", list->num_secrets_stored);

	for (i = 0; i < list->num_secrets_stored &&
		    i < ARRAY_SIZE(list->secret_entries); i++) {
		if (list->secret_entries[i].secret_type <=
						UV_SECRET_TYPE_AP_ASSOCIATION)
			continue;

		rc = cb(list->secret_entries[i].secret_idx,
			list->secret_entries[i].secret_type,
			list->secret_entries[i].secret_len,
			list->secret_entries[i].secret_id,
			cb_private);
		if (rc != 0)
			break;
	}

out:
	free(list);

	return rc;
}

/**
 * Returns true if the secret type is supported by zkey
 *
 * @param type               the secret type
 *
 * @returns true if the type is supported, false otherwise
 */
static bool is_pvsecret_type_supported(u16 type)
{
	unsigned int i;

	for (i = 0; pvsecret_type_info[i].type != UV_SECRET_TYPE_INVALID; i++) {
		if (pvsecret_type_info[i].type == type)
			return pvsecret_type_info[i].zkey_usage;
	}

	return false;
}

/**
 * Returns the secret type name for the specified secret type
 *
 * @param type               the secret type
 *
 * @returns a constant string containing the type name
 */
static const char *get_pvsecret_type_name(u16 type)
{
	unsigned int i;

	for (i = 0; pvsecret_type_info[i].type != UV_SECRET_TYPE_INVALID; i++) {
		if (pvsecret_type_info[i].type == type)
			return pvsecret_type_info[i].name;
	}

	return "[UNKNOWN]";
}

/**
 * Returns the secret type for the specified type name
 *
 * @param name               the secret type name
 *
 * @returns the secret type or UV_SECRET_TYPE_INVALID if unknown.
 */
static u16 get_pvsecret_type_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; pvsecret_type_info[i].type != UV_SECRET_TYPE_INVALID; i++) {
		if (strcasecmp(pvsecret_type_info[i].name, name) == 0)
			return pvsecret_type_info[i].type;
	}

	return UV_SECRET_TYPE_INVALID;
}

/**
 * Parses a 32 byte hex string into a 32 byte binary secret ID
 *
 * @param id_str          the hex string to parse
 * @param id              the output buffer to store the secret ID
 *
 * @returns 0 for success or a negative errno in case of an error
 */
static int parse_secret_id_str(const char *id_str,
			       unsigned char id[UV_SECRET_ID_LEN])
{
	char hex[3] = { 0 };
	unsigned long val;
	unsigned int i;
	char *endptr;

	util_assert(id_str != NULL, "Internal error: id_str is NULL");
	util_assert(id != NULL, "Internal error: id is NULL");

	if (strncasecmp(id_str, "0x", 2) == 0)
		id_str += 2;

	if (strlen(id_str) != UV_SECRET_ID_LEN * 2)
		return -EINVAL;

	for (i = 0; i < UV_SECRET_ID_LEN; i++) {
		hex[0] = id_str[i * 2];
		hex[1] = id_str[i * 2 + 1];

		errno = 0;
		val = strtoul(hex, &endptr, 16);
		if (errno != 0 || *endptr != '\0' || val > 0xff)
			return -EINVAL;

		id[i] = val;
	}

	return 0;
}

/**
 * Get the 32 byte binary secret ID from the secret name by calculating the
 * SHA-256 has from the name.
 *
 * @param name            the name of the secret
 * @param id              the output buffer to store the secret ID
 *
 * @returns 0 for success or a negative errno in case of an error
 */
static int get_secret_id_from_name(const char *name,
				   unsigned char id[UV_SECRET_ID_LEN])
{
	util_assert(name != NULL, "Internal error: id_str is NULL");
	util_assert(id != NULL, "Internal error: id is NULL");
	util_assert(UV_SECRET_ID_LEN == SHA256_DIGEST_LENGTH,
		    "Internal error: UV_SECRET_ID_LEN != SHA256_DIGEST_LENGTH");

	if (SHA256((const unsigned char *)name, strlen(name), id) != id)
		return -EIO;

	return 0;
}

/**
 * Gets the binary 32 byte secret id from either a hex string or a secret name.
 *
 * @param hex                the secret id as hex string. Can be NULL.
 * @param name               the secret name. Can be NULL. If the id
 *                           parameter is non-NULL, then this parameter is
 *                           ignored.
 * @param id                 Output: the 32 byte binary secret id.
 * @param id_str             Output: the secret id in printable ascii chars
 *                           form, if name is non-NULL and the name length is
 *                           less than UV_SECRET_ID_LEN.
 *
 * @returns 0 on success, a negative errno in case of an error.
 * If neither the hex string nor the secret name is specified, 1 is returned,
 * and the id parameter is not modified.
 */
static int get_secret_id_from_hex_or_name(const char *hex, const char *name,
					  unsigned char id[UV_SECRET_ID_LEN],
					  char id_name[UV_SECRET_ID_LEN])
{
	int rc;

	util_assert(id != NULL, "Internal error: id is NULL");

	if (hex != NULL) {
		rc = parse_secret_id_str(hex, id);
		if (rc != 0) {
			warnx("Invalid pvsecret id specified: '%s'", hex);
			return rc;
		}

		return 0;
	}

	if (name != NULL) {
		rc = get_secret_id_from_name(name, id);
		if (rc != 0) {
			warnx("Failed to get the ID from pvsecret name: '%s'",
			      name);
			return rc;
		}

		if (strlen(name) < UV_SECRET_ID_LEN) {
			strncpy(id_name, name, UV_SECRET_ID_LEN);
			id_name[UV_SECRET_ID_LEN - 1] = '\0';
		}

		return 0;
	}

	return 1;
}

/**
 * Checks if the secret id is printable. To be printable, all characters up to
 * the first zero byte must be printable. All bytes after the first zero byte
 * must be all zero. There must be at least one zero byte as the very last byte
 * of the id.
 *
 * @param id                 the ID of the secret
 * @param name               Output: the id in the printable form and enclosed
 *                           in single quotes if the id is printable. The max
 *                           length of the name buffer is UV_SECRET_ID_LEN + 2:
 *                           A starting quote, up to UV_SECRET_ID_LEN-1 chars,
 *                           an ending quote and a zero termination byte.
 *
 * @returns true if the id is printable, false otherwise.
 */
static bool is_printable_name(const u8 id[UV_SECRET_ID_LEN],
			      char name[UV_SECRET_ID_LEN + 2])
{
	bool end_found = false, printable_name = false;
	unsigned int i;

	name[0] = '\'';
	for (i = 0; i < UV_SECRET_ID_LEN; i++) {
		if (!end_found) {
			if (id[i] == '\0') {
				name[1 + i] = '\'';
				end_found = true;
			} else if (isprint(id[i])) {
				name[1 + i] = id[i];
				printable_name = true;
			} else {
				printable_name = false;
				end_found = true;
			}
		} else if (id[i] != '\0') {
			printable_name = false;
		}
	}
	if (!end_found)
		printable_name = false;

	return printable_name;
}

struct list_secrets_data {
	struct util_rec *rec;
	bool all;
	bool hex;
	u16 type_filter;
	bool id_filter;
	char name[UV_SECRET_ID_LEN];
	unsigned char id[UV_SECRET_ID_LEN];
	unsigned int matched;
};

/**
 * Callback used with pvsecrets_list function. Called for each secret.
 *
 * @param idx                the index of the secret
 * @param type               the type of the secret
 * @param id                 the ID of the secret
 * @param cb_private         callback private data
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int pvsecrets_list_cb(u16 UNUSED(idx), u16 type, u32 UNUSED(len),
			     const u8 id[UV_SECRET_ID_LEN], void *cb_private)
{
	struct list_secrets_data *list_data = cb_private;
	char name[2 + UV_SECRET_ID_LEN] = { 0 };
	char hex[2 * UV_SECRET_ID_LEN + 1] = { 0 };
	unsigned int i;

	if (!list_data->all && !is_pvsecret_type_supported(type))
		return 0;

	if (list_data->type_filter != 0 && type != list_data->type_filter)
		return 0;

	if (list_data->id_filter &&
	    memcmp(id, list_data->name, UV_SECRET_ID_LEN) != 0 &&
	    memcmp(id, list_data->id, UV_SECRET_ID_LEN) != 0)
		return 0;

	for (i = 0; i < UV_SECRET_ID_LEN; i++)
		sprintf(&hex[i * 2], "%02x", id[i]);

	if (!list_data->hex && is_printable_name(id, name))
		util_rec_set(list_data->rec, PVSECRETS_REC_ID, name);
	else
		util_rec_set(list_data->rec, PVSECRETS_REC_ID, hex);
	util_rec_set(list_data->rec, PVSECRETS_REC_TYPE,
		     get_pvsecret_type_name(type));

	if (list_data->matched == 0)
		util_rec_print_hdr(list_data->rec);

	util_rec_print(list_data->rec);

	list_data->matched++;

	return 0;
}

/**
 * Lists protected virtualization secrets.
 *
 * @param uv_fd              the file descriptor of the ultravisor device
 * @param all                if true, all secret types are listed
 * @param hex                if true, list the secret ID in hex, even if the
 *                           secret ID would be printable
 * @param type_filter        only display secrets of the specified secret type.
 *                           Can be NULL.
 * @param secret_id          the secret id to list. Can be NULL.
 * @param secret_name        the secret name to list. Can be NULL. If the id
 *                           parameter is non-NULL, then this parameter is
 *                           ignored.
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int pvsecrets_list(int uv_fd, bool all, bool hex, const char *type_filter,
		   const char *secret_id, const char *secret_name,
		   bool verbose)
{
	struct list_secrets_data list_data = { 0 };
	int rc;

	util_assert(uv_fd != -1, "Internal error: uv_fd is -1");

	list_data.all = all;
	list_data.hex = hex;
	list_data.type_filter = UV_SECRET_TYPE_INVALID;

	if (type_filter != NULL) {
		list_data.type_filter = get_pvsecret_type_by_name(type_filter);
		if (list_data.type_filter == UV_SECRET_TYPE_INVALID) {
			warnx("Invalid pvsecret type specified: %s",
			      type_filter);
			return -EINVAL;
		}
	}

	if (secret_id != NULL || secret_name != NULL) {
		rc = get_secret_id_from_hex_or_name(secret_id, secret_name,
						    list_data.id,
						    list_data.name);
		if (rc < 0)
			return rc;

		list_data.id_filter = true;
	}

	list_data.rec = util_rec_new_wide("-");
	util_rec_def(list_data.rec, PVSECRETS_REC_ID, UTIL_REC_ALIGN_LEFT,
		     UV_SECRET_ID_LEN * 2, PVSECRETS_REC_ID);
	util_rec_def(list_data.rec, PVSECRETS_REC_TYPE, UTIL_REC_ALIGN_LEFT,
		     12, PVSECRETS_REC_TYPE);

	rc = uv_list_secrets(uv_fd, pvsecrets_list_cb, &list_data, verbose);
	if (rc != 0) {
		warnx("Failed to list protected virtualization secrets: %s",
		      strerror(-rc));
	}

	util_rec_free(list_data.rec);

	if (list_data.matched == 0)
		rc = -ENOENT;

	return rc;
}
