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
 * Number of PAI counters. Contains all counters regardless of kernel or user
 * space
 */
#define MAX_NUM_PAI 		156

/*
 * This is the sysfs directory from which cpacfstatsd daemon application loads
 * the available PAI counters
 */
#define SYSFS_PAI_COUNTER		"/sys/bus/event_source/devices/pai_crypto/events/"

/*
 * Note that this is the first kernel only counter in the 1-based list of the
 * architecture and NOT from the 0-based list in the cpacfstats code!
 */
#define FIRST_KERNEL_ONLY_COUNTER		144

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

enum counter_type {
	SUPPRESS_COUNTER = 0,
	KERNEL_AND_USER_COUNTER,
	KERNEL_ONLY_COUNTER,
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

int  perf_init(unsigned int *supported_counters);
void perf_stop(void);
void perf_close(void);
int  perf_enable_ctr(enum ctr_e ctr, unsigned int *supported_counters);
int  perf_disable_ctr(enum ctr_e ctr, unsigned int *supported_counters);
int  perf_reset_ctr(enum ctr_e ctr, uint64_t *value, unsigned int
					*supported_counters);
int  perf_read_ctr(enum ctr_e ctr, uint64_t *value, unsigned int
				   *supported_counters);
int  perf_ecc_supported(void);
int  perf_ctr_state(enum ctr_e ctr);
int  perf_read_pai_ctr(unsigned int ctrnum, int user, uint64_t *value);

/* cpacfstats_common.c */

enum counter_type is_user_space(unsigned int ctr);
const char *get_ctr_name(unsigned int ctr);
unsigned int get_num_user_space_ctrs(void);

#endif
