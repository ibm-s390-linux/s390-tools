/*
 * iucvtty - Application that provides a full-screen terminal for iucvconn
 *
 * Core application
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <utmp.h>

#include "lib/util_base.h"

#include "af_iucv.h"
#include "iucvterm/config.h"
#include "iucvterm/functions.h"
#include "iucvterm/gettext.h"

#define SYSLOG_IDENT		"iucvtty"
#define PRG_COMPONENT           SYSLOG_IDENT
#define TERM_BUFSIZE		256
#define TERM_DEFAULT		"linux"


static volatile sig_atomic_t sig_shutdown;


/**
 * sig_handler() - Signal handler
 * @sig:	Signal number.
 */
static void sig_handler(int sig)
{
	sig_shutdown = sig;
}

/**
 * exec_login_prog() - execute a login program
 * @cmd:	Path to the (login) program executable
 */
static int exec_login_prog(char *cmd[])
{
	int rc;

	if (cmd != NULL)
		rc = execv(cmd[0], cmd);
	else
		rc = execl("/bin/login", "/bin/login", (char *) NULL);
	return rc;
}

/**
 * iucvtty_worker() - Handle an incoming client connection
 * @client:	Client file descriptor
 * @master:	PTY master file descriptor
 * @slave:	PTY slave file descriptor
 * @cfg:	IUCV TTY configuration structure.
 */
static int iucvtty_worker(int client, int master, int slave,
			  const struct iucvterm_cfg *cfg)
{
	int rc;
	struct iucvtty_msg *msg;
	pid_t child;
	fd_set set;
	size_t chunk;
	char term_env[TERM_BUFSIZE];


	/* flush pending terminal data */
	tcflush(master, TCIOFLUSH);

	/* read terminal parameters from client */
	if (iucvtty_rx_termenv(client, term_env, TERM_BUFSIZE))
		sprintf(term_env, TERM_DEFAULT);

	/* start login program */
	child = fork();
	if (child == -1) {
		print_error("Creating a new process to run the "
			    "login program failed");
		iucvtty_tx_error(client, ERR_FORK);
		return 1;	/* return from worker */
	}
	if (child == 0) {	/* child process */
		closelog();	/* close syslog */

		/* setup terminal */
		if (login_tty(slave)) {
			print_error("Setting up a terminal for user login failed");
			iucvtty_tx_error(client, ERR_SETUP_LOGIN_TTY);
			exit(2);
		}
		setenv("TERM", term_env, 1);
		if (exec_login_prog(cfg->cmd_parms)) {
			print_error("Running the login program failed");
			iucvtty_tx_error(client, ERR_CANNOT_EXEC_LOGIN);
		}
		exit(3);	/* we only reach here if exec has failed */
	}

	/* setup buffers */
	msg = malloc(MSG_BUFFER_SIZE);
	if (msg == NULL) {
		print_error("Allocating memory for the data buffer failed");
		rc = 2;
		goto out_kill_login;
	}

	/* multiplex i/o between login program and socket. */
	rc = 0;
	chunk = 0;
	while (!sig_shutdown) {
		FD_ZERO(&set);
		FD_SET(client, &set);
		FD_SET(master, &set);

		if (select(MAX(master, client) + 1, &set,
			   NULL, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (FD_ISSET(client, &set)) {
			if (iucvtty_read_msg(client, msg,
					     MSG_BUFFER_SIZE, &chunk))
				break;
			switch (msg->type) {
			case MSG_TYPE_DATA:
				iucvtty_copy_data(master, msg);
				break;
			case MSG_TYPE_WINSIZE:
				if (msg->datalen != sizeof(struct winsize))
					break;
				if (ioctl(master, TIOCSWINSZ,
					  (struct winsize *) msg->data))
					print_error("Resizing the terminal "
						    "window failed");
				break;
			case MSG_TYPE_TERMIOS:	/* ignored */
				break;
			case MSG_TYPE_ERROR:
				iucvtty_error(msg);
				break;
			}
		}

		if (FD_ISSET(master, &set))
			if (iucvtty_tx_data(client, master,
					    msg, MSG_BUFFER_SIZE))
				break;
	}
	free(msg);

out_kill_login:
	/* ensure the chld is terminated before calling waitpid:
	 * - in case a sigterm has been received,
	 * - or a sigchld from other than the chld
	 */
	kill(child, SIGKILL);	/* cause a sigchld */
	waitpid(child, NULL, 0);

	return rc;
}

/**
 * main() - IUCV TTY program startup
 */
int main(int argc, char *argv[])
{
	struct iucvterm_cfg	conf;		/* program configuration */
	struct sockaddr_iucv	saddr, caddr;	/* IUCV socket address info */
	char 			client_host[9];	/* client guest name */
	int 			server, client;	/* socket file descriptors */
	int 			master, slave;	/* pre-allocated PTY fds */
	struct sigaction	sigact;		/* signal handler */
	int 			rc;
	socklen_t		len;


	/* gettext initialization */
	gettext_init();

	/* parse command line arguments */
	parse_options(PROG_IUCV_TTY, &conf, argc, argv);

	/* create server socket... */
	server = iucvtty_socket(&saddr, NULL, conf.service);
	if (server == -1) {
		print_error((errno == EAFNOSUPPORT)
			    ? N_("The AF_IUCV address family is not available")
			    : N_("Creating the AF_IUCV socket failed"));
		return 1;
	}
	if (bind(server, (struct sockaddr *) &saddr, sizeof(saddr)) == -1) {
		print_error("Binding the AF_IUCV socket failed");
		close(server);
		return 1;
	}
	if (listen(server, 1) == -1) {
		print_error("Listening for incoming connections failed");
		close(server);
		return 1;
	}

	/* pre-allocate PTY master/slave file descriptors */
	if (openpty(&master, &slave, NULL, NULL, NULL)) {
		print_error("Opening a new PTY master/slave device pair failed");
		close(server);
		return 1;
	}

	/* set close-on-exec for file descriptors */
	fcntl(master, F_SETFD, FD_CLOEXEC);
	fcntl(server, F_SETFD, FD_CLOEXEC);

	/* syslog */
	openlog(SYSLOG_IDENT, LOG_PID, LOG_AUTHPRIV);
	syslog(LOG_INFO, "Listening on terminal ID: %s, using pts device: %s",
		conf.service, ttyname(slave));

	rc = 0;
	len = sizeof(struct sockaddr_iucv);
	/* accept a new client connection */
	client = accept(server, (struct sockaddr *) &caddr, &len);
	if (client == -1) {
		print_error("An incoming connection could not be accepted");
		rc = 2;
		goto exit_on_error;
	}

	/* check if client is allowed to connect */
	userid_cpy(client_host, caddr.siucv_user_id);
	if (is_client_allowed(client_host, &conf)) {
		iucvtty_tx_error(client, ERR_NOT_AUTHORIZED);
		syslog(LOG_WARNING, "Rejected client connection from %s; "
				    "Client is not allowed to connect.",
				    client_host);
		rc = 3;

	} else { /* client is allowed to connect */
		syslog(LOG_INFO, "Accepted client connection from %s",
			client_host);
		/* set close-on-exec for client socket */
		fcntl(client, F_SETFD, FD_CLOEXEC);
		/* close server socket */
		close(server);

		/* setup signal handler to notify shutdown signal */
		sigemptyset(&sigact.sa_mask);
		sigact.sa_flags = SA_RESTART;
		sigact.sa_handler = sig_handler;
		if (sigaction(SIGCHLD, &sigact, NULL)
			|| sigaction(SIGTERM, &sigact, NULL)
			|| sigaction(SIGINT,  &sigact, NULL)
			|| sigaction(SIGPIPE, &sigact, NULL)) {
			print_error("Registering a signal handler failed");
			rc = 4;
			goto exit_on_error;
		}

		/* handle client terminal connection */
		rc = iucvtty_worker(client, master, slave, &conf);
	}

	close(client);

exit_on_error:
	close(slave);
	close(master);
	closelog();

	return rc;
}
