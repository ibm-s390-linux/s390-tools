/*
 * iucvtty / iucvconn - IUCV Terminal Applications
 *
 * Configuration structure and command line processing function
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef __IUCVTTY_CONFIG_H_
#define __IUCVTTY_CONFIG_H_

enum iucvterm_prg {
	PROG_IUCV_TTY  = 0,
	PROG_IUCV_CONN = 1,
};

struct iucvterm_cfg {
	char		client_re[129];	/* Regexp to match incoming clients  */
	char		host[9];	/* IUCV target host name  */
	char		service[9];	/* IUCV service name  */
	char		**cmd_parms;	/* ptr to commandline parms  */
	char		*sessionlog;	/* ptr to session log file path  */
	unsigned char	esc_char;	/* Escape character  */
	unsigned int	flags;		/* Configuration flags  */
};

/* configuration flags */
#define CFG_F_CHKCLNT		0x0001	/* Check for permitted clients */

/* configuration macros */
#define CFG_CHKCLNT(c)		((c)->flags & CFG_F_CHKCLNT)


extern void parse_options(enum iucvterm_prg, struct iucvterm_cfg *,
			  int, char **);

#endif /* __IUCVTTY_CONFIG_H_ */
