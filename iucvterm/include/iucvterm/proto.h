/*
 * iucvtty / iucvconn - IUCV Terminal Applications
 *
 * Structure and function definitions for the IUCV terminal message protocol
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef __IUCVTTY_PROTO_H_
#define __IUCVTTY_PROTO_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_base.h"

/* Standard macros      */
#ifndef offsetof
#	define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

/* Packet version magic */
#define MSG_VERSION		0x02
/* Message types */
#define MSG_TYPE_ERROR		0x01	/* Error message. */
#define MSG_TYPE_TERMENV	0x02	/* Terminal environment variable. */
#define MSG_TYPE_TERMIOS	0x04	/* Terminal IO struct update. */
#define MSG_TYPE_WINSIZE	0x08	/* Terminal window size update. */
#define MSG_TYPE_DATA		0x10	/* Terminal data. */


struct iucvtty_msg {
	uint8_t		version;	/* Message version */
	uint8_t		type;		/* Message type */
	uint16_t	datalen;	/* Number of bytes in payload */
	uint8_t		data[];		/* Payload buffer */
} __attribute__((packed));
#define MSG_DATA_OFFSET		(offsetof(struct iucvtty_msg, data))
#define msg_size(m)		(MSG_DATA_OFFSET + (m)->datalen)

/**
 * msg_cpy_from() - Copy data to message
 * @msg:	IUCV terminal message
 * @src:	Pointer to source data buffer
 * @len:	Length of source data buffer
 *
 * Copies @len bytes from @src to the message data buffer. The caller must
 * ensure not to overwrite the message data buffer.
 * Finally, the message datalen is set to @len
 */
static inline void msg_cpy_from(struct iucvtty_msg *msg, const void *src,
				  size_t len)
{
	memcpy(msg->data, src, len);
	msg->datalen = len;
}

/**
 * msg_cpy_to() - Copy data from a message
 * @msg:	IUCV terminal message
 * @dst:	Destination buffer
 * @len:	Destination buffer length.
 *
 * Copies up to min(@len, message datalen) number of bytes from the IUCV
 * terminal message to the destination buffer.
 */
static inline void msg_cpy_to(const struct iucvtty_msg *msg, void *dst,
				size_t len)
{
	memcpy(dst, msg->data, MIN(msg->datalen, len));
}

/**
 * msg_alloc() - Allocates a new iucv terminal message.
 * @type:	Message type
 * @size:	Message data size
 *
 * The function allocates a new iucv terminal message with the given data size
 * @size. (The total message size is @size plus MSG_DATA_OFFSET.)
 * The new message is initialized with the specific @type.
 */
static inline struct iucvtty_msg *msg_alloc(uint8_t type, uint16_t size)
{
	struct iucvtty_msg *m;

	m = malloc(size + MSG_DATA_OFFSET);
	if (m != NULL) {
		m->version = MSG_VERSION;
		m->type    = type;
		m->datalen = size;
	}
	return m;
}

/**
 * msg_free() - free an allocated iucv tty message
 */
static inline void msg_free(struct iucvtty_msg *m)
{
	free(m);
}

#endif /* __IUCVTTY_PROTO_H_ */
