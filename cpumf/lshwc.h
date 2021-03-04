/* Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/*
 * CPU Measurement counter facility application for device driver.
 *
 * Ioctl system call definitions.
 */

#ifndef LSHWC_H
#define LSHWC_H

#include <sys/ioctl.h>

enum {
	S390_HWCTR_BASIC = 0x2,		/* BASIC counter set */
	S390_HWCTR_USER = 0x4,		/* Problem-State Counter Set */
	S390_HWCTR_CRYPTO = 0x8,	/* Crypto-Activity Counter Set */
	S390_HWCTR_EXT = 0x1,		/* Extended Counter Set */
	S390_HWCTR_MT_DIAG = 0x20,	/* MT-diagnostic Counter Set */
	S390_HWCTR_ALL = S390_HWCTR_BASIC | S390_HWCTR_USER |
				S390_HWCTR_CRYPTO | S390_HWCTR_EXT |
				S390_HWCTR_MT_DIAG
};

/* The ioctl(..., S390_HWCTR_READ, ...) is the only subcommand which returns
 * data. It requires member data_bytes to be positive and indicates the
 * maximum amount of data available to store counter set data. The other
 * ioctl() subcommands do not use this member and it should be set to zero.
 *
 * The cpuset data is flattened using the following scheme, stored in member
 * data:
 *
 * 0x0       0x8   0xc       0x10   0x14      0x18  0x20  0x28         0xU-1
 * +---------+-----+---------+-----+---------+-----+-----+------+------+
 * | no_cpus | cpu | no_sets | set | no_cnts | cv1 | cv2 | .... | cv_n |
 * +---------+-----+---------+-----+---------+-----+-----+------+------+
 *
 *                           0xU   0xU+4     0xU+8 0xU+10             0xV-1
 *                           +-----+---------+-----+-----+------+------+
 *                           | set | no_cnts | cv1 | cv2 | .... | cv_n |
 *                           +-----+---------+-----+-----+------+------+
 *
 *           0xV   0xV+4     0xV+8 0xV+c
 *           +-----+---------+-----+---------+-----+-----+------+------+
 *           | cpu | no_sets | set | no_cnts | cv1 | cv2 | .... | cv_n |
 *           +-----+---------+-----+---------+-----+-----+------+------+
 *
 * U and V denote arbitrary hexadezimal addresses.
 * In fact the first int represents the number of CPUs data was extracted
 * from. This is followed by CPU number and number of counter sets extracted.
 * Both are two integer values. This is followed by the set number and number
 * of counters extracted. Both are two integer values. This is followed by
 * the counter values, each element is eight bytes in size.
 */

struct s390_hwctr_start {		/* Set CPUs to operate on */
	__u64 version;			/* Version of interface */
	__u64 data_bytes;		/* # of bytes required */
	__u64 cpumask_len;		/* Length of CPU mask in bytes */
	__u64 *cpumask;			/* Pointer to CPU mask */
	__u64 counter_sets;		/* Bit mask of counter set to get */
};

struct s390_hwctr_setdata {		/* Counter set data */
	__u32 set;			/* Counter set number */
	__u32 no_cnts;			/* # of counters stored in cv[] */
	__u64 cv[0];			/* Counter values (variable length) */
};

struct s390_hwctr_cpudata {		/* Counter set data per CPU */
	__u32 cpu_nr;			/* Counter set number */
	__u32 no_sets;			/* # of counters sets in data[] */
	struct s390_hwctr_setdata data[0];
};

struct s390_hwctr_read {		/* Structure to get all ctr sets */
	__u64 no_cpus;			/* Total # of CPUs data taken from */
	struct s390_hwctr_cpudata data[0];
};

#define S390_HWCTR_MAGIC	'C'	/* Random magic # for ioctls */
#define	S390_HWCTR_START	_IOWR(S390_HWCTR_MAGIC, 1, struct s390_hwctr_start)
#define	S390_HWCTR_STOP		_IO(S390_HWCTR_MAGIC, 2)
#define	S390_HWCTR_READ		_IOWR(S390_HWCTR_MAGIC, 3, struct s390_hwctr_read)

#define	S390_HWCTR_START_VERSION	1	/* Version # s390_hwctr_start */
#define	S390_HWCTR_DEVICE	"/dev/hwctr"	/* Device name */
#endif
