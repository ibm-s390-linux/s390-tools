/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * TAR file generation
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <string.h>

#include "buffer.h"
#include "idcache.h"
#include "misc.h"
#include "tar.h"

#define LONGLINK	"././@LongLink"
#define TYPE_LONGLINK	'K'
#define TYPE_LONGNAME	'L'

#define BLOCKSIZE	512

/* Basic TAR header */
struct tar_header {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
};

/* Store the octal value of @value to at most @len bytes at @dest */
static void set_octal(char *dest, size_t len, unsigned long value)
{
	int i;

	dest[len - 1] = 0;
	for (i = len - 2; i >= 0; i--) {
		dest[i] = '0' + (value & 7);
		value >>= 3;
	}
}

/* Store time @value to at most @len bytes at @dest */
static void set_time(char *dest, size_t len, time_t value)
{
	time_t max = (1ULL << (3 * (len - 1))) - 1;

	if (value >= 0 && value <= max) {
		set_octal(dest, len, value);
		return;
	}

	for (; len > 0; len--) {
		dest[len - 1] = value & 0xff;
		value >>= 8;
	}

	dest[0] |= 0x80;
}

#define SET_FIELD(obj, name, value) \
	set_octal((obj)->name, sizeof((obj)->name), (unsigned long) (value))
#define SET_TIME_FIELD(obj, name, value) \
	set_time((obj)->name, sizeof((obj)->name), (time_t) (value))
#define SET_STR_FIELD(obj, name, value) \
	util_strlcpy((obj)->name, (value), sizeof((obj)->name))

/* Initialize the tar file @header with the provided data */
static void init_header(struct tar_header *header, const char *filename,
			const char *link, size_t len, struct stat *stat,
			char type)
{
	unsigned int i, checksum;
	unsigned char *c;

	memset(header, 0, sizeof(*header));

	/* Fill in header fields */
	SET_STR_FIELD(header, name, filename);
	if (link)
		SET_STR_FIELD(header, linkname, link);
	SET_FIELD(header, size, len);
	if (stat) {
		SET_FIELD(header, mode, stat->st_mode & 07777);
		SET_FIELD(header, uid, stat->st_uid);
		SET_FIELD(header, gid, stat->st_gid);
		SET_TIME_FIELD(header, mtime, stat->st_mtime);
		uid_to_name(stat->st_uid, header->uname, sizeof(header->uname));
		gid_to_name(stat->st_gid, header->gname, sizeof(header->gname));
	} else {
		SET_FIELD(header, mode, 0644);
		SET_FIELD(header, uid, 0);
		SET_FIELD(header, gid, 0);
		SET_TIME_FIELD(header, mtime, 0);
		uid_to_name(0, header->uname, sizeof(header->uname));
		gid_to_name(0, header->gname, sizeof(header->gname));
	}
	header->typeflag = type;
	memcpy(header->magic, "ustar ", sizeof(header->magic));
	memcpy(header->version, " ", sizeof(header->version));

	/* Calculate checksum */
	memset(header->chksum, ' ', sizeof(header->chksum));
	checksum = 0;
	c = (unsigned char *) header;
	for (i = 0; i < sizeof(*header); i++)
		checksum += c[i];
	snprintf(header->chksum, 7, "%06o", checksum);
}

/* Emit zero bytes via @emit_cb to pad @len to a multiple of BLOCKSIZE */
static int emit_padding(emit_cb_t emit_cb, void *data, size_t len)
{
	size_t pad = BLOCKSIZE - len % BLOCKSIZE;
	char zeroes[BLOCKSIZE];

	if (len % BLOCKSIZE > 0) {
		memset(zeroes, 0, BLOCKSIZE);
		return emit_cb(data, zeroes, pad);
	}

	return 0;
}

/* Emit @len bytes at @addr via @emit_cb and pad data to BLOCKSIZE with zero
 * bytes */
static int emit_data(emit_cb_t emit_cb, void *data, void *addr, size_t len)
{
	int rc;

	if (len == 0)
		return 0;

	rc = emit_cb(data, addr, len);
	if (rc)
		return rc;
	return emit_padding(emit_cb, data, len);
}

/* Emit a tar header via @emit_cb */
static int emit_header(emit_cb_t emit_cb, void *data, char *filename,
		       char *link, size_t len, struct stat *stat, char type)
{
	struct tar_header header;
	size_t namelen = strlen(filename);
	size_t linklen;
	int rc;

	/* /proc can contain unreadable links which causes tar to complain
	 * during extract - use a dummy value to handle this more gracefully */
	if (link && !*link)
		link = " ";

	linklen = link ? strlen(link) : 0;
	if (linklen > sizeof(header.linkname)) {
		rc = emit_header(emit_cb, data, LONGLINK, NULL, linklen + 1,
				 NULL, TYPE_LONGLINK);
		if (rc)
			return rc;
		rc = emit_data(emit_cb, data, link, linklen + 1);
		if (rc)
			return rc;
	}
	if (namelen > sizeof(header.name)) {
		rc = emit_header(emit_cb, data, LONGLINK, NULL, namelen + 1,
				 NULL, TYPE_LONGNAME);
		if (rc)
			return rc;
		rc = emit_data(emit_cb, data, filename, namelen + 1);
		if (rc)
			return rc;
	}

	init_header(&header, filename, link, len, stat, type);
	return emit_data(emit_cb, data, &header, sizeof(header));
}

struct emit_content_cb_data {
	emit_cb_t emit_cb;
	void *data;
	size_t len;
	int rc;
};

/* Callback for emitting a single chunk of data of a buffer */
static int emit_content_cb(void *data, void *addr, size_t len)
{
	struct emit_content_cb_data *cb_data = data;

	if (len > cb_data->len)
		len = cb_data->len;
	cb_data->len -= len;

	cb_data->rc = cb_data->emit_cb(cb_data->data, addr, len);

	if (cb_data->rc || cb_data->len == 0)
		return 1;

	return 0;
}

/* Emit at most @len bytes of contents of @buffer via @emit_cb and pad output
 * to BLOCKSIZE with zero bytes */
static int emit_content(emit_cb_t emit_cb, void *data, struct buffer *buffer,
			size_t len)
{
	struct emit_content_cb_data cb_data;

	cb_data.emit_cb = emit_cb;
	cb_data.data = data;
	cb_data.len = len;
	cb_data.rc = 0;
	buffer_iterate(buffer, emit_content_cb, &cb_data);
	if (cb_data.rc)
		return cb_data.rc;

	return emit_padding(emit_cb, data, buffer->total);
}

/* Convert file meta data and content specified as @content into a
 * stream of bytes that is reported via the @emit_cb callback. @data is
 * passed through to the callback for arbitrary use. */
int tar_emit_file_from_buffer(char *filename, char *link, size_t len,
			      struct stat *stat, char type,
			      struct buffer *content, emit_cb_t emit_cb,
			      void *data)
{
	int rc;

	DBG("emit tar file=%s type=%d len=%zu", filename, type, len);
	rc = emit_header(emit_cb, data, filename, link, len, stat, type);
	if (rc)
		return rc;
	if (content)
		rc = emit_content(emit_cb, data, content, len);

	return rc;
}

/* Convert file meta data and content specified as @addr and @len into a
 * stream of bytes that is reported via the @emit_cb callback. @data is
 * passed through to the callback for arbitrary use. */
int tar_emit_file_from_data(char *filename, char *link, size_t len,
			    struct stat *stat, char type, void *addr,
			    emit_cb_t emit_cb, void *data)
{
	int rc;

	DBG("emit tar file=%s type=%d len=%zu", filename, type, len);
	rc = emit_header(emit_cb, data, filename, link, len, stat, type);
	if (rc)
		return rc;
	if (addr)
		rc = emit_data(emit_cb, data, addr, len);

	return rc;
}
