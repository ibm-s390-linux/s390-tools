/*
 * tape_390 - Common functions
 *
 * Copyright IBM Corp. 2006, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _TAPE390_COMMON_H
#define _TAPE390_COMMON_H

#define ERRMSG(x...) {fflush(stdout);fprintf(stderr,x);}
#define ERRMSG_EXIT(ec,x...) do {fflush(stdout);fprintf(stderr,x);exit(ec);} while(0)
#define EXIT_MISUSE 1

extern int is_not_tape(char *); 
extern int open_tape(char *);
extern void set_prog_name(char *);
extern char *prog_name;

#endif
