/*
 * iucvtty / iucvconn - IUCV Terminal Applications
 *
 * Common functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "af_iucv.h"
#include "iucvterm/config.h"
#include "iucvterm/functions.h"
#include "iucvterm/gettext.h"
#include "iucvterm/proto.h"


/* Global program component for iucv terminal tools */
#define PRG_COMPONENT		"iucvterm"


/**
 * __write() - Write data
 * @fd:		File descriptor
 * @buf:	Pointer to data buffer
 * @len:	Buffer length
 *
 * Write @len number of bytes from the buffer @buf to the file
 * descriptor @fd. The routines handles EINTR and partially writes.
 * Returns the error code from the underlying write(2) syscall.
 */
ssize_t __write(int fd, const void *buf, size_t len)
{
	ssize_t rc;
	size_t  written = 0;

	while (written < len) {
		rc = write(fd, buf + written, len - written);
		if (rc == -1 && errno == EINTR)
			continue;
		if (rc <= 0)
			return rc;
		written += rc;
	}
	return written;
}

#ifdef __DEBUG__
static void __dump_msg(int fd, const struct iucvtty_msg *m, char dir)
{
	write_session_info("%c: (fd=%d) MSG: ver=%02x type=%02x datalen=%u\n",
			   dir, fd, m->version, m->type, (uint16_t) m->datalen);
}
#endif


/**
 * iucvtty_socket() - Creates and return an IUCV socket
 * @sai:	AF_IUCV socket address structure
 * @host:	z/VM guest name
 * @service:	Terminal name passed as additional data to @host after connect
 *
 * This function sets up the struct sockaddr_iucv with the specified
 * VM guest virtual machine and terminal information.
 * Finally, it returns an AF_IUCV socket.
 */
int iucvtty_socket(struct sockaddr_iucv *sai,
		   const char *host, const char *service)
{
	char temp[9];

	memset(sai, 0, sizeof(struct sockaddr_iucv));
	sai->siucv_family = AF_IUCV;

	if (host != NULL) {
		snprintf(temp, 9, "%-8s", host);
		memcpy(sai->siucv_user_id, temp, 8);
	} else
		memset(sai->siucv_user_id, ' ', 8);

	if (service != NULL) {
		snprintf(temp, 9, "%-8s", service);
		memcpy(sai->siucv_name, temp, 8);
	} else
		memset(sai->siucv_name, ' ', 8);

	return socket(PF_IUCV, SOCK_STREAM, 0);
}

/**
 * iucvtty_tx_termenv() - Send terminal environment variable
 * @dest:	File descriptor to output data
 * @dflt:	TERM environment string ('\0' terminated)
 *
 * Copy terminal environment variable to destination @dest.
 */
int iucvtty_tx_termenv(int dest, char *dflt)
{
	struct iucvtty_msg *msg;
	char *term = getenv("TERM");
	size_t len;
	int rc;

	if (term == NULL && dflt != NULL)
		term = dflt;

	len = 0;
	if (term != NULL)
		len = 1 + strlen(term);

	/* Note: The server console tool waits for terminal environment
	 *       information: the message is sent even if it is empty */
	msg = msg_alloc(MSG_TYPE_TERMENV, len);
	if (msg == NULL)
		return -1;
	msg_cpy_from(msg, term, len);
	rc = iucvtty_write_msg(dest, msg);
	msg_free(msg);

	return rc;
}

/**
 * iucvtty_rx_termenv() - Receive terminal environment variable
 * @fd:		File descriptor to read data from
 * @buf:	Buffer to store the terminal environment variable
 * @len:	Size of buffer @buf
 */
int iucvtty_rx_termenv(int fd, void *buf, size_t len)
{
	int rc;
	size_t skip;
	struct iucvtty_msg *msg = msg_alloc(MSG_TYPE_TERMENV, len);

	if (msg == NULL)
		return -1;
	skip = 0;
	rc = iucvtty_read_msg(fd, msg, msg_size(msg), &skip);
	iucvtty_skip_msg_residual(fd, &skip);
	if (!rc) {
		if (msg->datalen == 0)
			memset(buf, 0, MIN(1u, len));
		else
			msg_cpy_to(msg, buf, len);
	}
	msg_free(msg);
	return rc;
}

/**
 * iucvtty_tx_data() - Send terminal data
 * @from:	File descriptor to read data from
 * @msg:	Pointer to iucv tty message buffer
 * @len:	Size of message buffer
 *
 * This routine reads data from file descriptor @from and stores them in
 * a data array of the specified iucv tty message @msg. It reads up to
 * @len - MSG_DATA_OFFSET bytes from fd @from.
 */
int iucvtty_read_data(int from, struct iucvtty_msg *msg, size_t len)
{
	ssize_t r;

	r = read(from, msg->data, len - MSG_DATA_OFFSET);
	if (r == -1 && errno == EINTR)	/* REVIEW: loop if EINTR ? */
		r = read(from, msg->data, len - MSG_DATA_OFFSET);
	if (r <= 0)
		return -1;
	msg->version = MSG_VERSION;
	msg->type    = MSG_TYPE_DATA;
	msg->datalen = (uint16_t) r;

	return 0;
}

/**
 * iucvtty_tx_data() - Send terminal data
 * @dest:	File descriptor to send data to
 * @from:	File descriptor to read data from
 * @msg:	Pointer to iucv tty message buffer
 * @len:	Size of message buffer
 *
 * This routine reads data from file descriptor @from and stores them in
 * a data array of the specified iucv tty message @msg. It reads up to
 * @len - MSG_DATA_OFFSET bytes from fd @from.
 * Finally, the iucv tty message written to file descriptor @dest.
 */
int iucvtty_tx_data(int dest, int from, struct iucvtty_msg *msg, size_t len)
{
	if (iucvtty_read_data(from, msg, len))
		return -1;
	if (iucvtty_write_msg(dest, msg))
		return -1;
	return 0;
}

/**
 * iucvtty_tx_winsize() - Send terminal window size information.
 * @dest:	Destination
 * @from:	Terminal file descriptor to request winsize
 *
 * Sends the terminal window size from terminal file descriptor
 * @from to the destination @dest.
 * If the window size is not retrieved, the routine will not fail.
 * The routine fails if there is a problem sending the window size
 * to @dest. The return codes are specified by iucvtty_write_msg().
 */
int iucvtty_tx_winsize(int dest, int from)
{
	int rc;
	struct iucvtty_msg *msg = msg_alloc(MSG_TYPE_WINSIZE,
					      sizeof(struct winsize));
	if (msg == NULL)
		return -1;
	rc = 0;
	if (ioctl(from, TIOCGWINSZ, msg->data) > -1)
		rc = iucvtty_write_msg(dest, msg);
	msg_free(msg);

	return rc;
}

/**
 * iucvtty_tx_error() - Send an error code
 * @dest:	Destination
 * @errCode:	Error code
 */
int iucvtty_tx_error(int dest, uint32_t errCode)
{
	struct iucvtty_msg *msg;
	int rc;

	msg = msg_alloc(MSG_TYPE_ERROR, sizeof(errCode));
	if (msg == NULL)
		return -1;
	msg_cpy_from(msg, &errCode, sizeof(errCode));
	rc = iucvtty_write_msg(dest, msg);
	msg_free(msg);
	return rc;
}

/**
 * iucvtty_copy_data() - Copy IUCV message data
 * @dest:	Destination to copy data to
 * @msg:	IUCV message
 */
int iucvtty_copy_data(int dest, struct iucvtty_msg *msg)
{
	if (__write(dest, msg->data, msg->datalen) <= 0)
		return -1;
	return 0;
}

/**
 * iucvtty_skip_msg_residual() - Skip (receive & forget) count number of bytes
 * @fd:		File descriptor
 * @residual:	Residual of an iucv tty message received by iucvtty_read_msg()
 *
 * See iucvtty_read_msg() for an explanation when to use this routine.
 * Note: The @residual parameter shall not be NULL.
 */
void iucvtty_skip_msg_residual(int fd, size_t *residual)
{
	char b;
	size_t  i;

	if (*residual <= 0)
		return;
	for (i = 0; i < *residual; i++)
		if (read(fd, &b, 1) <= 0)
			break;
	*residual = 0;
}

/**
 * iucvtty_read_msg() - Read/Receive an IUCV message
 * @fd:		File descriptor to read from
 * @msg:	Pointer to IUCV message buffer
 * @len:	IUCV message data len
 * @residual:	Status to be used by next call
 *
 * The function reads up to @len bytes from file descriptor @fd.
 * If the received message is larger than @len bytes, the @residual value
 * is set to the number of bytes remaining.
 * The function shall then be re-called to create a new message and receive
 * the next chunk of size @residual; or the remaining characters must be
 * skipped using the iucvtty_skip_msg() routine.
 * Note: The @len parameter shall be greater than MSG_DATA_OFFSET.
 *       The @residual parameter shall not be NULL.
 */
int iucvtty_read_msg(int fd, struct iucvtty_msg *msg,
		     size_t len, size_t *residual)
{
	int rc;
	ssize_t r;		/* number of bytes read from fd */

	if (*residual)
		len = MIN(len - MSG_DATA_OFFSET, *residual);

	while (1) {
		if (*residual) {
			r = read(fd, msg->data, len);
			if (r > 0)
				msg->datalen = r;
		} else
			r = read(fd, msg, len);

		if (r == -1 && errno == EINTR)
			continue;
		if (r <= 0) {
			rc = -1;
			goto out_read_error;
		}

		break;	/* exit loop for a successful read */
	}
#ifdef __DEBUG__
	if (!*residual)
		__dump_msg(fd, msg, 'R');
#endif

	/* (re)calculate next chunk */
	if (*residual)
		*residual -= msg->datalen;
	else
		if (msg->datalen > (r - MSG_DATA_OFFSET)) {
			/* calculate pending msg data and update datalen */
			*residual = msg->datalen - (r - MSG_DATA_OFFSET);
			msg->datalen = r - MSG_DATA_OFFSET;
		}

	/* check for a sane message */
	if (msg->version != MSG_VERSION) {
		fprintf(stderr, _("%s: %s\n"),
			PRG_COMPONENT, _("The version of the received data "
					 "message is not supported\n"));
		rc = -2;
		goto out_read_error;
	}

	rc = 0;
out_read_error:
	return rc;
}

/**
 * iucvtty_write_msg() - Write/Send IUCV message
 * @fd:		File descriptor
 * @msg:	Pointer to IUCV message
 */
int iucvtty_write_msg(int fd, struct iucvtty_msg *msg)
{
	msg->version = MSG_VERSION;

	if (__write(fd, msg, msg_size(msg)) <= 0)
		return -1;

#ifdef __DEBUG__
	__dump_msg(fd, msg, 'S');
#endif
	return 0;
}


/**
 * iucv_msg_error() - Reports an IUCV message error
 * @comp:	Program component
 * @errnum:	IUCV message error code
 */
void iucv_msg_error(const char *comp, uint32_t errnum)
{
	const char *translated;

	switch (errnum) {
	case ERR_FORK:
		translated = _("Creating a new process to run the "
				"login program failed");
		break;
	case ERR_CANNOT_EXEC_LOGIN:
		translated = _("Running the login program failed");
		break;
	case ERR_SETUP_LOGIN_TTY:
		translated = _("Setting up a terminal for user login failed");
		break;
	case ERR_NOT_AUTHORIZED:
		translated = _("The z/VM guest virtual machine is not "
				"permitted to connect");
		break;
	default:
		translated = _("The specified error code is not known");
		break;
	}
	fprintf(stderr, "%s: %s (%s=%" PRIu32 ")\r\n",
		comp, translated, _("error code"), errnum);
}

/**
 * program_error() - Report an program/syscall error.
 * @comp:	Program component name
 * @d:		Error message, subject to gettext translation
 */
void program_error(const char *comp, const char *d)
{
	fprintf(stderr, _("%s: %s: %s\n"), comp, _(d), strerror(errno));
}


/**
 * __regerror - Report an error from a previous regex api call
 * @error:	Error code
 * @re:		Reference to the used regular expression
 */
static inline void __regerror(int error, const regex_t *re)
{
	char errbuf[81];

	regerror(error, re, errbuf, 81);
	fprintf(stderr, _("The regular expression has an error: %s\n"), errbuf);
	return;
}

/**
 * is_regex_valid() - Check if the specified regex is syntactically correct.
 * @re:		String representation of the regular expression
 *
 * Returns zero on success, otherwise -1.
 */
int is_regex_valid(const char *re)
{
	regex_t regex;
	int rc;

	if (re == NULL)
		return -1;
	rc = regcomp(&regex, re, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if (rc) {
		__regerror(rc, &regex);
		rc = -1;
	}
	regfree(&regex);

	return rc;
}

/**
 * strmatch() - Match a string using a regular expression
 * @str:	String to match
 * @re:		Regular expression
 *
 * Returns zero on success, -1 on error or if @str is NULL; and
 * 1 if the regular expression did not match the string.
 */
int strmatch(const char *str, const char *re)
{
	regex_t regex;
	regmatch_t pmatch[1];
	size_t nmatch = 0;
	int rc;

	if (re == NULL)
		return -1;

	rc = regcomp(&regex, re, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if (rc) {
		__regerror(rc, &regex);
		regfree(&regex);
		return -1;
	}

	rc = regexec(&regex, str, nmatch, pmatch, 0);
	if (rc == REG_NOMATCH)
		rc = 1;

	regfree(&regex);
	return rc;
}

/**
 * is_client_allowed() - Check if the client is allowed to connect.
 * @client:	Client name
 * @cfg:	Pointer to the IUCV terminal configuration structure
 *
 * The return code is identical to strmatch().  If client checking is
 * disabled, the function returns zero.
 */
int is_client_allowed(const char *client, const struct iucvterm_cfg *cfg)
{
	if (!CFG_CHKCLNT(cfg))
		return 0;

	return strmatch(client, cfg->client_re);
}

/**
 * userid_cpy() - Copy z/VM user ID and skip trailing spaces.
 * @dest:	Destination buffer
 * @userid:	z/VM user ID
 */
void userid_cpy(char dest[9], const char userid[8])
{
	ssize_t pos;

	/* find pos of last character (pos 0..7) or -1 if user ID is empty */
	for (pos = 7; pos >= 0; pos--)
		if (userid[pos] != ' ')
			break;

	if (pos >= 0)
		memcpy(dest, userid, pos + 1);
	dest[pos + 1] = '\0';
}
