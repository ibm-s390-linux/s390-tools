/*
 * Miscellaneous definitions
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MISC_H
#define MISC_H

/* Program exit codes. */
enum exit_code_t {
	EXIT_OK		= 0, /* Program finished successfully */
	EXIT_USAGE	= 1, /* Usage error */
	EXIT_RUNTIME	= 2, /* Run-time error */
};

#endif /* MISC_H */
