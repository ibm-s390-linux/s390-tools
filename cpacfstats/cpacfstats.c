/*
 * cpacfstats - display and maintain CPACF perf counters
 *
 * cpacfstats client implementation
 *
 * Copyright IBM Corp. 2015, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <getopt.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "cpacfstats.h"


static const char *const name = "cpacfstats";

static const char *const usage =
	"Usage: %s [OPTIONS [COUNTER]]\n"
	"\n"
	"Enable, disable, reset and read CPACF Crypto Activity Counters\n"
	"Use OPTIONS described below:\n"
	"\n"
	"\t-h, --help                Print this help, then exit\n"
	"\t-v, --version             Print version information, then exit\n"
	"\t-e, --enable  [counter]   Enable one or all counters\n"
	"\t-d, --disable [counter]   Disable one or all counters\n"
	"\t-r, --reset   [counter]   Reset one or all counter values\n"
	"\t-p, --print   [counter]   Print one or all counter values\n"
	"\tcounter can be: 'aes' 'des' 'rng' 'sha' 'ecc' or 'all'\n";

static const char *const counter_str[] = {
	[DES_FUNCTIONS]  = "des",
	[AES_FUNCTIONS]  = "aes",
	[SHA_FUNCTIONS]  = "sha",
	[PRNG_FUNCTIONS] = "rng",
	[ECC_FUNCTIONS] = "ecc",
	[ALL_COUNTER]    = "all"
};


static int send_query(int s, enum cmd_e cmd, enum ctr_e ctr)
{
	struct msg m;

	memset(&m, 0, sizeof(m));

	m.head.m_ver = VERSION;
	m.head.m_type = QUERY;
	m.query.m_ctr = ctr;
	m.query.m_cmd = cmd;

	return send_msg(s, &m);
}


static int recv_answer(int s, int *ctr, int *state, uint64_t *value)
{
	struct msg m;
	int rc;

	rc = recv_msg(s, &m);
	if (rc == 0) {
		if (m.head.m_ver != VERSION) {
			eprint("Received msg with wrong version %d != %d\n",
			       m.head.m_ver, VERSION);
			return -1;
		}
		if (m.head.m_type != ANSWER) {
			eprint("Received msg with wrong type %d != %d\n",
			       m.head.m_type, ANSWER);
			return -1;
		}
		*ctr = m.answer.m_ctr;
		*state = m.answer.m_state;
		*value = m.answer.m_value;
	}

	return rc;
}


static void print_answer(int ctr, int state, uint64_t value)
{
	if (state < 0)
		printf(" %s counter: error state %d\n",
		       counter_str[ctr], state);
	else if (state == DISABLED)
		printf(" %s counter: disabled\n", counter_str[ctr]);
	else if (state == UNSUPPORTED)
		printf(" %s counter: unsupported\n", counter_str[ctr]);
	else
		printf(" %s counter: %"PRIu64"\n", counter_str[ctr], value);
}


int eprint(const char *format, ...)
{
	char buf[1024];
	va_list vargs;
	int i, n;

	i = snprintf(buf, sizeof(buf), "%s: ", name);
	va_start(vargs, format);
	n = vsnprintf(buf+i, sizeof(buf)-i, format, vargs);
	va_end(vargs);

	if (n > 0)
		fputs(buf, stderr);

	return n;
}


int main(int argc, char *argv[])
{
	enum ctr_e ctr = ALL_COUNTER;
	enum cmd_e cmd = PRINT;
	int i, j, s, state;
	uint64_t value;

	if (argc > 1) {
		int opt, idx = 0;
		const struct option long_opts[] = {
			{ "help", 0, NULL, 'h' },
			{ "version", 0, NULL, 'v' },
			{ "enable", 0, NULL, 'e' },
			{ "disable", 0, NULL, 'd' },
			{ "reset", 0, NULL, 'r' },
			{ "print", 0, NULL, 'p' },
			{ NULL, 0, NULL, 0 } };
		while (1) {
			opt = getopt_long(argc, argv,
					  "hvedrp", long_opts, &idx);
			if (opt == -1)
				break; /* no more arguments */
			switch (opt) {
			case 'h':
				printf(usage, name);
				exit(0);
				break;
			case 'v':
				printf("%s: Linux on System z CPACF Crypto Activity Counters Client\n"
				       "Version %s\n%s\n",
				       name, RELEASE_STRING, COPYRIGHT);
				exit(0);
				break;
			case 'e':
				cmd = ENABLE;
				break;
			case 'd':
				cmd = DISABLE;
				break;
			case 'r':
				cmd = RESET;
				break;
			case 'p':
				cmd = PRINT;
				break;
			default:
				eprint("Invalid argument, try -h or --help for more information\n");
				exit(1);
				break;
			}
		}
		/* there may be an optional counter argument */
		if (optind > 0 && optind < argc) {
			for (i = 0; i <= ALL_COUNTER; i++)
				if (strcmp(argv[optind], counter_str[i]) == 0)
					break;
			if (i > ALL_COUNTER) {
				eprint("Unknown counter '%s'\n", argv[optind]);
				exit(1);
			}
			ctr = (enum ctr_e) i;
		}
	}

	/* try to open and connect socket to the cpacfstatsd daemon */
	s = open_socket(CLIENT);
	if (s < 0) {
		eprint("Can't connect to daemon\n");
		exit(1);
	}

	/* send query */
	if (send_query(s, cmd, ctr) != 0) {
		eprint("Error on sending query message to daemon\n");
		close(s);
		exit(1);
	}

	if (ctr == ALL_COUNTER) {
		for (i = 0; i < ALL_COUNTER; i++) {
			/* receive answer */
			if (recv_answer(s, &j, &state, &value) != 0) {
				eprint("Error on receiving answer message from daemon\n");
				exit(1);
			}
			if (state < 0) {
				eprint("Received bad status code %d from daemon\n",
				       state);
				close(s);
				exit(1);
			}
			print_answer(j, state, value);
		}
	} else {
		/* receive answer */
		if (recv_answer(s, &j, &state, &value) != 0) {
			eprint("Error on receiving answer message from daemon\n");
			close(s);
			exit(1);
		}
		if (state < 0) {
			eprint("Received bad status code %d from daemon\n",
			       state);
			close(s);
			exit(1);
		}
		print_answer(j, state, value);
	}

	/* close connection */
	close(s);

	return 0;
}
