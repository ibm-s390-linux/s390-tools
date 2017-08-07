/*
 * iucvconn - Application that establishes a terminal connection over IUCV
 *
 * Core application
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

#include "lib/util_base.h"

#include "iucvterm/config.h"
#include "iucvterm/functions.h"
#include "iucvterm/gettext.h"

#define SYSLOG_IDENT		"iucvconn"
#define PRG_COMPONENT		SYSLOG_IDENT
#define DEFAULT_TERM		"linux"

#define AUDIT(f, ...)		do { \
					syslog(LOG_INFO, (f), __VA_ARGS__); \
					write_session_info((f), __VA_ARGS__); \
				} while (0);

/* escape mode actions */
enum esc_action_t {
	DISCONNECT,		/* Disconnect from terminal   */
	RESIZE,			/* Force terminal resizing    */
	SEND,			/* Send data (default action) */
	IGNORE,			/* Ignore escape character   */
};


static volatile sig_atomic_t resize_tty;
static struct termios ios_orig;		/* store original termio settings */


/**
 * sig_handler() - Signal handler
 * @sig:	Signal number
 */
static void sig_handler(int sig)
{
	switch (sig) {
	case SIGWINCH:
		resize_tty = sig;
		break;

	case SIGTERM:
		tcsetattr(STDIN_FILENO, TCSANOW, &ios_orig);
		close_session_log();
		_exit(0);
		break;
	}
}

/**
 * get_msg_char() - Returns single character from message
 * @msg:	The IUCV terminal message
 *
 * Returns the (single) character of an IUCV terminal message
 * if @msg is of type MSG_TYPE_DATA and contains a single character
 * (datalen == 1). Otherwise the routine returns zero.
 */
static unsigned char get_msg_char(const struct iucvtty_msg *msg)
{
	if (msg->type != MSG_TYPE_DATA || msg->datalen != 1)
		return 0;

	return msg->data[0];
}

/**
 * is_esc_char() - Check message for escape character
 * @msg:	The IUCV terminal message
 * @esc:	The escape character
 *
 * Returns 1 if @msg contains the escape character @esc only; otherwise the
 * function returns 0.
 */
static int is_esc_char(const struct iucvtty_msg *msg, unsigned char esc)
{
	if (!esc)
		return 0;

	return (get_msg_char(msg) == esc) ? 1 : 0;
}

/**
 * get_action() - Returns the action from an escaped character
 * @msg:	The IUCV terminal message
 * @esc:	The escape character
 *
 * Returns the appropriate action of the escaped character.
 * The action is derived from the single character stored in the IUCV terminal
 * message @msg. If the escape character is recognized, SEND is returned for
 * sending the "escaped" escape character to the terminal.
 *
 * If it contains multiple characters, the default SEND action is used to
 * indicate that the escape mode is done and to force sending the complete data
 * characters (e.g. entered by copy & paste).
 *
 * NOTE: This routine must be called in "escape mode".
 */
static enum esc_action_t get_action(const struct iucvtty_msg *msg,
				    unsigned char esc)
{
	if (is_esc_char(msg, esc))
		return SEND;

	switch (get_msg_char(msg)) {
	case   0:
		return SEND;
	case '.':
	case 'd':
		return DISCONNECT;
	case 'r':
		return RESIZE;
	default:
		return IGNORE;
	}
}

/**
 * iucvtty_worker() - Handle server connection
 * @terminal:	IUCV TTY server file descriptor
 */
static int iucvtty_worker(int terminal, const struct iucvterm_cfg *cfg)
{
	struct iucvtty_msg *msg;
	fd_set set;
	size_t chunk;
	int in_esc_mode;
	enum esc_action_t action;

	/* setup buffers */
	msg = malloc(MSG_BUFFER_SIZE);
	if (msg == NULL) {
		print_error("Allocating memory for the data buffer failed");
		return -1;
	}

	/* multiplex i/o between login program and socket */
	chunk = 0;
	in_esc_mode = 0;	/* escape mode state */
	action = SEND;
	while (1) {
		if (resize_tty) {
			iucvtty_tx_winsize(terminal, STDIN_FILENO);
			resize_tty = 0;	/* clear signal flag */
		}

		FD_ZERO(&set);
		FD_SET(terminal, &set);
		FD_SET(STDIN_FILENO, &set);

		if (select(MAX(STDIN_FILENO, terminal) + 1, &set,
			   NULL, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (FD_ISSET(terminal, &set)) {
			if (iucvtty_read_msg(terminal, msg,
					     MSG_BUFFER_SIZE, &chunk))
				break;

			switch (msg->type) {
			case MSG_TYPE_DATA:
				iucvtty_copy_data(STDOUT_FILENO, msg);
				write_session_log(msg->data, msg->datalen);
				break;
			case MSG_TYPE_ERROR:
				iucvtty_error(msg);
				break;
			}
		}

		if (FD_ISSET(STDIN_FILENO, &set)) {
			if (iucvtty_read_data(STDIN_FILENO, msg,
					      MSG_BUFFER_SIZE))
				break;

			if (in_esc_mode) {
				in_esc_mode = 0;	/* reset */
				action = get_action(msg, cfg->esc_char);
			} else {
				if (is_esc_char(msg, cfg->esc_char)) {
					in_esc_mode = 1;
					action = IGNORE;
				} else
					action = SEND;
			}

			/* handle escape mode */
			switch (action) {
			case SEND:	/* non-escape mode (default) */
				if (iucvtty_write_msg(terminal, msg))
					goto out_worker_loop;
				break;

			case DISCONNECT:/* disconnect  */
				goto out_worker_loop;

			case RESIZE: 	/* force terminal resize */
				iucvtty_tx_winsize(terminal, STDIN_FILENO);
				break;

			case IGNORE:
				break;
			}
		}
	}

out_worker_loop:
	free(msg);
	return 0;
}

/**
 * main() - IUCV CONN program startup
 */
int main(int argc, char *argv[])
{
	int			rc;
	int 			server;
	struct sockaddr_iucv	addr;
	struct termios		ios;
	struct sigaction	sigact;
	struct passwd		*passwd;
	struct iucvterm_cfg	conf;


	/* gettext initialization */
	gettext_init();

	/* parse command line options */
	parse_options(PROG_IUCV_CONN, &conf, argc, argv);

	/* open session audit log */
	if (conf.sessionlog != NULL)
		if (open_session_log(conf.sessionlog)) {
			print_error("Creating the terminal session "
				    "log files failed");
			return 1;
		}

	/* open socket and connect to server */
	server = iucvtty_socket(&addr, conf.host, conf.service);
	if (server == -1) {
		print_error((errno == EAFNOSUPPORT)
			    ? N_("The AF_IUCV address family is not available")
			    : N_("Creating the AF_IUCV socket failed"));
		return 1;
	}

	/* syslog */
	openlog(SYSLOG_IDENT, LOG_PID, LOG_AUTHPRIV);

	/* get user information for syslog */
	passwd = getpwuid(geteuid());

	if (connect(server, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		switch (errno) {
		case EAGAIN:
			print_error("The new connection would exceed the "
				    "maximum number of IUCV connections");
			break;
		case ENETUNREACH:
			print_error("The target z/VM guest virtual machine "
				    "is not logged on");
			break;
		case EACCES:
			print_error("The IUCV authorizations do not permit "
				    "connecting to the target z/VM guest");
			break;
		default:
			print_error("Connecting to the z/VM guest virtual "
				    "machine failed");
			break;
		}
		AUDIT("Connection to %s/%s failed for user %s (uid=%i)",
			conf.host, conf.service,
			(passwd != NULL) ? passwd->pw_name : "n/a", geteuid());
		rc = 2;
		goto return_on_error;
	}
	AUDIT("Established connection to %s/%s for user %s (uid=%i)",
		conf.host, conf.service,
		(passwd != NULL) ? passwd->pw_name : "n/a", geteuid());

	/* send client parameters */
	iucvtty_tx_termenv(server, DEFAULT_TERM);
	iucvtty_tx_winsize(server, STDIN_FILENO);

	/* register signal handler */
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;
	sigact.sa_handler = sig_handler;
	sigaction(SIGWINCH, &sigact, NULL);
	sigaction(SIGTERM,  &sigact, NULL);

	/* modify terminal settings */
	if (tcgetattr(STDIN_FILENO, &ios_orig)) {
		print_error("Getting the terminal I/O settings failed");
		rc = 3;
		goto return_on_error;
	}
	memcpy(&ios, &ios_orig, sizeof(ios));

	/* put terminal into raw mode */
	cfmakeraw(&ios);
	/* NOTE: If the TTY driver (ldisc) runs in TTY_DRIVER_REAL_RAW,
	 *       we need to do the input character processing here;
	 *       that means to translate CR into CR + NL (ICRNL).
	 * Define TTY_REAL_RAW in for that case. */
#ifdef TTY_REAL_RAW
	ios.c_iflag |= ICRNL;			/* | IGNPAR | IGNBRK; */
#endif
	tcflush(STDIN_FILENO, TCIOFLUSH);
	if (tcsetattr(STDIN_FILENO, TCSANOW, &ios)) {
		print_error("Modifying the terminal I/O settings failed");
		rc = 4;
		goto return_on_error;
	}

	iucvtty_worker(server, &conf);

	tcsetattr(STDIN_FILENO, TCSANOW, &ios_orig);

	rc = 0;
return_on_error:
	close(server);
	closelog();
	close_session_log();

	return rc;
}
