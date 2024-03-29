/*
 * cpacfstats - display and maintain CPACF perf counters
 *
 * common function prototypes and definitions
 *
 * Copyright IBM Corp. 2015, 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CPACFSTATS_H
#define CPACFSTATS_H

#include "lib/zt_common.h"

#define COPYRIGHT "Copyright IBM Corp. 2015, 2022"

#define DEFAULT_SEND_TIMEOUT  (30 * 1000)
#define DEFAULT_RECV_TIMEOUT  (30 * 1000)

/*
 * Number of PAI counters for user space.  This excludes PCKMO since
 * this instruction is privileged.
 */
#define NUM_PAI_USER     143
/* Number of PAI counters for kernel space.  Contains all counters. */
#define NUM_PAI_KERNEL   156

int eprint(const char *format, ...);

/*
 * Counter names
 * ALL_COUNTER specifies the number of physical counters.  Virtual
 * counters might be added afterwards.  NUM_COUNTER is the last
 * managed counter (i.e., a counter that can be activated, reset,
 * deactivated).
 */
enum ctr_e {
	DES_FUNCTIONS = 0,
	AES_FUNCTIONS,
	SHA_FUNCTIONS,
	PRNG_FUNCTIONS,
	ECC_FUNCTIONS,
	ALL_COUNTER,
	PAI_USER,
	PAI_KERNEL,
	NUM_COUNTER,
	HOTPLUG_DETECTED = 0xffff
};

enum type_e {
	QUERY = 0,
	ANSWER
};

enum cmd_e {
	PRINT = 0,
	ENABLE,
	DISABLE,
	RESET
};

enum state_e {
	DISABLED = 0,
	ENABLED,
	UNSUPPORTED
};

/*
 * query send from client to daemon
 * Consist of:
 * enum counter
 * enum command
 */
struct msg_query {
	uint32_t m_ctr;
	uint32_t m_cmd;
} __packed;

/*
 * answer send from daemon to client
 * Consist of:
 * enum counter or PAI counter number if following PAI_USER or PAI_KERNEL
 * status code: < 0 error, 0 disabled, > 0 enabled
 * counter value
 */
struct msg_answer {
	uint32_t m_ctr;
	int32_t  m_state;
	uint64_t m_value;
} __packed;

/* stats_sock.c */

#define SERVER 1
#define CLIENT 2

#define BACKLOG 10

#define SOCKET_FILE "/run/cpacfstatsd_socket"
#define PID_FILE    "/run/cpacfstatsd.pid"

#define CPACFSTATS_GROUP "cpacfstats"

struct msg_header {
	uint32_t m_ver;
	uint32_t m_type;
} __packed;

struct msg {
	struct msg_header head;
	union {
		struct msg_query  query;
		struct msg_answer answer;
	};
} __packed;

int open_socket(int mode);
int send_msg(int sfd, struct msg *m, int timeout);
int recv_msg(int sfd, struct msg *m, int timeout);

/* perf_crypto.c */

int  perf_init(void);
void perf_stop(void);
void perf_close(void);
int  perf_enable_ctr(enum ctr_e ctr);
int  perf_disable_ctr(enum ctr_e ctr);
int  perf_reset_ctr(enum ctr_e ctr, uint64_t *value);
int  perf_read_ctr(enum ctr_e ctr, uint64_t *value);
int  perf_ecc_supported(void);
int  perf_ctr_state(enum ctr_e ctr);
int  perf_read_pai_ctr(unsigned int ctrnum, int user, uint64_t *value);

#endif
