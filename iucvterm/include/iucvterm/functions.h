/*
 * iucvtty / iucvconn - IUCV Terminal Applications
 *
 * Definition of common functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef __FUNCTIONS_H_
#define __FUNCTIONS_H_

#include <unistd.h>

#include "af_iucv.h"
#include "inttypes.h"
#include "iucvterm/config.h"
#include "iucvterm/proto.h"

/* Message buffer: message header + 4096 bytes of data */
#define MSG_BUFFER_SIZE		(MSG_DATA_OFFSET + (4096))

/* Error macros */
#define print_error(s)		program_error(PRG_COMPONENT, (s))
#define iucvtty_error(m)					\
	do {							\
		uint32_t *err = (uint32_t *) (m)->data;		\
		iucv_msg_error(PRG_COMPONENT, *err);		\
	} while (0);

/* Error codes */
/* Unable to fork new process */
#define ERR_FORK			105
/* Cannot execute login program  */
#define ERR_CANNOT_EXEC_LOGIN		106
/* Cannot set up terminal as a login terminal */
#define ERR_SETUP_LOGIN_TTY		107
/* Client (vm guest) is not authorized */
#define ERR_NOT_AUTHORIZED		110


extern int iucvtty_handle_req(int);

extern int iucvtty_socket(struct sockaddr_iucv *,
			  const char *, const char *);

extern int iucvtty_tx_termenv(int, char *);
extern int iucvtty_rx_termenv(int, void *, size_t);
extern int iucvtty_tx_winsize(int, int);
extern int iucvtty_tx_data(int, int, struct iucvtty_msg *, size_t);
extern int iucvtty_tx_error(int, uint32_t);
extern int iucvtty_copy_data(int, struct iucvtty_msg *);
extern int iucvtty_read_data(int, struct iucvtty_msg *, size_t);

extern int iucvtty_read_msg(int, struct iucvtty_msg *, size_t, size_t *);
extern int iucvtty_write_msg(int, struct iucvtty_msg *);
extern void iucvtty_skip_msg_residual(int, size_t *);

extern ssize_t __write(int, const void*, size_t);

extern int strmatch(const char *, const char *);
extern int is_regex_valid(const char *);
extern int is_client_allowed(const char *, const struct iucvterm_cfg *);
extern void userid_cpy(char [8], const char [8]);

extern void iucv_msg_error(const char *, uint32_t);
extern void program_error(const char *, const char *);

/* Audit/session log */
extern int open_session_log(const char *);
extern ssize_t write_session_log(const void*, size_t);
extern void write_session_info(const char *, ...);
extern void close_session_log(void);

#endif /* __FUNCTIONS_H_ */
