/*
 * Defines for CPU Measurement Facility Characteristics
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DEFINES_H
#define	DEFINES_H

#define	PERF_SFB_SIZE	"/sys/module/kernel/parameters/cpum_sfb_size"
#define	PERF_PATH	"/sys/bus/event_source/devices/"
#define	PERF_SF		"cpum_sf"
#define	PERF_CF		"cpum_cf"

static inline void linux_error(const char *message)
{
	fprintf(stderr, "Error: %s: %s\n", message, strerror(errno));
}

#endif
