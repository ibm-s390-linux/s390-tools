/*
 * test_functions - Test program for the IUCV Terminal Applications
 *
 * Test program for the common functions used by the
 * IUCV Terminal Applications
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termio.h>
#include <unistd.h>

#include "iucvterm/functions.h"
#include "iucvterm/proto.h"
#include "test.h"


#define BUF_SIZE	256


static int __testReadWriteMessage(int[2]);
static int __testReadWriteMessage_chunks(int[2]);
static int __testReadWriteMessage_nochunks(int[2]);
static int __testTransmitData(int[2]);
static int __testTermEnvVar(int[2]);
static int __testWinsize(int[2]);
static int __testCopyData(int[2]);


int main(void)
{
	int sockv[2];

	__socketpair(sockv);

	assert(!__testReadWriteMessage(sockv));
	assert(!__testReadWriteMessage_chunks(sockv));
	assert(!__testReadWriteMessage_nochunks(sockv));
	assert(!__testTermEnvVar(sockv));
	assert(!__testWinsize(sockv));
	assert(!__testCopyData(sockv));
	assert(!__testTransmitData(sockv));

	close(sockv[0]);
	close(sockv[1]);

	return 0;
}


static int __testReadWriteMessage_chunks(int sv[2])
{
	struct iucvtty_msg *msg[2];
	char data[] = "Hallo\0test1\0test2\0test3\0test4\0test5\0test6\0test7\0test8";
	size_t chunk;
	int i;

	/* setup msg to be sent */
	msg[0] = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);
	msg[1] = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);

	/* send msg */
	msg_cpy_from(msg[0], data, sizeof(data));
	if (iucvtty_write_msg(sv[0], msg[0]))
		return 1;

	/* read msg */
	chunk = 0;
	for (i = 0; i < 9; i++) {
		if (iucvtty_read_msg(sv[1], msg[1], 6 + MSG_DATA_OFFSET, &chunk))
			return 2;
		assert(msg[1]->datalen == 6);
		assert(0 == memcmp(msg[1]->data, data + (i * 6), msg[1]->datalen));
		/*
		printf("chunk=%i datalen=%u data='%s'\n",
			chunk, msg[1]->datalen, msg[1]->data);
		*/
	}
	assert(chunk == 0);

	msg_free(msg[0]);
	msg_free(msg[1]);

	return 0;
}

static int __testReadWriteMessage_nochunks(int sv[2])
{
	struct iucvtty_msg *msg[2];
	char data[] = "Hallo\0test1\0test2\0test3\0test4\0test5\0test6\0test7\0test8";
	int i;
	size_t residual = 0;

	/* setup msg to be sent */
	msg[0] = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);
	msg[1] = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);

	/* send and read msg .. with chunks disabled.
	 * The iucvtty_read_msg() shall ignore any data more than the given
	 * length. */
	i = 7;
	while (i--) {
		msg_cpy_from(msg[0], data, sizeof(data));
		if (iucvtty_write_msg(sv[0], msg[0]))
			return 1;

		/* read msg */
		if (iucvtty_read_msg(sv[1], msg[1], 6 + MSG_DATA_OFFSET, &residual))
			return 2;
		assert(0 == memcmp(msg[1]->data, data, msg[1]->datalen));
		iucvtty_skip_msg_residual(sv[1], &residual);
		assert(0 == residual);
		/*printf("datalen=%u data='%s'\n",
			msg[1]->datalen, msg[1]->data);*/
	}

	msg_free(msg[0]);
	msg_free(msg[1]);

	return 0;
}

static int __testReadWriteMessage(int sv[2])
{
	struct iucvtty_msg *msg[2];
	char data[10] = "Hallo";
	size_t chunk = 0;

	/* setup msg to be sent */
	msg[0] = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);
	msg[1] = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);

	/* send msg */
	msg_cpy_from(msg[0], data, sizeof(data));
	if (iucvtty_write_msg(sv[0], msg[0]))
		return 1;

	/* read msg */
	if (iucvtty_read_msg(sv[1], msg[1], BUF_SIZE, &chunk))
		return 2;
	iucvtty_skip_msg_residual(sv[1], &chunk);

	/* compare msg */
	if (__msgcmp(msg[0], msg[1]))
		return 3;

	msg_free(msg[0]);
	msg_free(msg[1]);

	return 0;
}

static int __testTransmitData(int sv[2])
{
	struct iucvtty_msg *msg;
	char data[] = "Vah __testTransmitData hai.";
	size_t chunk = 0;


	/* I. write something to sv[0]
	 * II. tx_data: read from sv[1], write to sv[0]
	 * III. read iucvtty_msg from sv[1]
	 */
	assert(sizeof(data) == write(sv[0], data, sizeof(data)));
	msg = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);
	assert(0 == iucvtty_tx_data(sv[0], sv[1], msg, BUF_SIZE));
	assert(0 == iucvtty_read_msg(sv[1], msg, BUF_SIZE, &chunk));
	assert(MSG_TYPE_DATA == msg->type);
	assert(sizeof(data) == msg->datalen);
	assert(0 == memcmp(&data, msg->data, msg->datalen));

	msg_free(msg);
	return 0;
}

static int __testTermEnvVar(int sv[2])
{
#define __BUF_SIZE 81
	char term[__BUF_SIZE] = "my_default_term";
	char buf[__BUF_SIZE];
	char *orig_term = getenv("TERM");

	/* I. */
	if (orig_term != NULL) {
		assert(0 == iucvtty_tx_termenv(sv[0], NULL));
		assert(0 == iucvtty_rx_termenv(sv[1], buf, __BUF_SIZE));
		assert(0 == strncmp(orig_term, buf,
				    MIN(__BUF_SIZE, strlen(orig_term))));
	}

	unsetenv("TERM");	/* clear term */

	/* II. */
	assert(0 == iucvtty_tx_termenv(sv[0], term));
	assert(0 == iucvtty_rx_termenv(sv[1], buf, __BUF_SIZE));
	assert(0 == strncmp(buf, term, __BUF_SIZE));

	/* III. */
	assert(0 == iucvtty_tx_termenv(sv[0], NULL));
	assert(0 == iucvtty_rx_termenv(sv[1], buf, __BUF_SIZE));
	assert(0 == strncmp("", buf, 1));

	setenv("TERM", orig_term, 1);	/* restore original term */
	return 0;
#undef __BUF_SIZE
}

static int __testWinsize(int sv[2])
{
	struct iucvtty_msg *msg;
	struct winsize winsz;
	size_t chunk = 0;

	msg = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);
	assert(0 == ioctl(STDIN_FILENO, TIOCGWINSZ, &winsz));
	assert(0 == iucvtty_tx_winsize(sv[0], STDIN_FILENO));
	assert(0 == iucvtty_read_msg(sv[1], msg, BUF_SIZE, &chunk));
	assert(MSG_TYPE_WINSIZE == msg->type);
	assert(sizeof(struct winsize) == msg->datalen);
	assert(0 == memcmp(&winsz, msg->data, msg->datalen));

	msg_free(msg);
	return 0;
}

static int __testCopyData(int sv[2])
{
	struct iucvtty_msg *msg;
	char data[] = "palim palim";
	char buf[BUF_SIZE];

	msg = msg_alloc(MSG_TYPE_DATA, BUF_SIZE);
	msg_cpy_from(msg, data, sizeof(data));
	assert(0 == iucvtty_copy_data(sv[0], msg));
	assert(sizeof(data) == read(sv[1], &buf, BUF_SIZE));
	assert(0 == memcmp(data, buf, sizeof(data)));

	msg_free(msg);
	return 0;
}
