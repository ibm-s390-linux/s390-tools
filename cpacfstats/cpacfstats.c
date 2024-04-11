/*
 * cpacfstats - display and maintain CPACF perf counters
 *
 * cpacfstats client implementation
 *
 * Copyright IBM Corp. 2015, 2022
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
	"\t-n, --nonzero             Print all PAI counters\n"
	"\t-j, --json                Print all counter values in JSON format\n"
	"\tcounter can be: 'aes' 'des' 'rng' 'sha' 'ecc'\n"
	"\t                'pai_user' 'pai_kernel' or 'all'\n";

static const char *const counter_str[] = {
	[DES_FUNCTIONS]  = "des",
	[AES_FUNCTIONS]  = "aes",
	[SHA_FUNCTIONS]  = "sha",
	[PRNG_FUNCTIONS] = "rng",
	[ECC_FUNCTIONS]  = "ecc",
	[ALL_COUNTER]    = "all",
	[PAI_USER]       = "pai_user",
	[PAI_KERNEL]     = "pai_kernel"
};


static int paiprintnonzero;


static int send_query(int s, enum cmd_e cmd, enum ctr_e ctr)
{
	struct msg m;

	memset(&m, 0, sizeof(m));

	m.head.m_ver = VERSION;
	m.head.m_type = QUERY;
	m.query.m_ctr = ctr;
	m.query.m_cmd = cmd;

	return send_msg(s, &m, 0);
}


static int recv_answer(int s, int *ctr, int *state, uint64_t *value)
{
	struct msg m;
	int rc;

	rc = recv_msg(s, &m, 0);
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


static void printjsonsep(void)
{
	static const char *jsonsep = "";

	fputs(jsonsep, stdout);
	jsonsep = ",";
}


static void json_print_virtual_counter_answer(int s, int ctr,
					      int state, uint64_t value)
{
	int paictr = 0, paistate = 0, ec;
	uint64_t i, paivalue = 0;
	unsigned int maxnum;
	const char *space;

	switch (ctr) {
	case HOTPLUG_DETECTED:
		printjsonsep();
		printf("{\"counter\":\"hotplug detected\",");
		if (state < 0)
			printf("\"error\":%d}", state);
		else
			printf("\"value\":%d}", !!value);
		return;
	case PAI_USER:
		maxnum = get_num_user_space_ctrs();
		space = "user";
		break;
	case PAI_KERNEL:
		maxnum = MAX_NUM_PAI;
		space = "kernel";
		break;
	default:
		return;
	}
	/* Here, we have validated the PAI counter retrieved, but not
	 * yet printed. */
	if (state != ENABLED)
		return;
	if (value > maxnum) {
		eprint("Incompatible versions detected!\n");
		eprint("Expected %lu counter space for %s, but got %lu\n",
			maxnum, space, value);
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < value; ++i) {
		ec = recv_answer(s, &paictr, &paistate, &paivalue);
		if (ec < 0 || paistate < 0) {
			eprint("Error on receiving answer message from daemon\n");
			/* No more data for this virtual event after error. */
			return;
		}
		if (paictr > MAX_NUM_PAI) {
			eprint("Pai counter number too big: %d\n", paictr);
		} else {
			printjsonsep();
			printf("{\"counter\":\"%s\",\"space\":\"%s\",\"counterid\":%d,",
				get_ctr_name(paictr), space, paictr + 1);
			if (paistate < 0) {
				printf("\"error\":%d}", paistate);
				/* Protocol does not send further counters. */
				return;
			}
			printf("\"value\":%lu}", paivalue);
		}
	}
}


static void print_virtual_counter_answer(int s,
					 int ctr, int state, uint64_t value)
{
	static const char *const states[] = {
		[DISABLED]    = "disabled",
		[ENABLED]     = "enabled",
		[UNSUPPORTED] = "unsupported"
	};
	int paictr = 0, paistate = 0, ec;
	uint64_t i, paivalue = 0;
	unsigned int maxnum;
	const char *ctrstr;

	switch (ctr) {
	case HOTPLUG_DETECTED:
		if (state >= 0 && value > 0)
			printf(" hotplug detected\n");
		return;
	case PAI_USER:
		maxnum = get_num_user_space_ctrs();
		ctrstr = "pai_user";
		break;
	case PAI_KERNEL:
		maxnum = MAX_NUM_PAI;
		ctrstr = "pai_kernel";
		break;
	default:
		return;
	}
	/* Here, we have validated the PAI counter retrieved, but not
	 * yet printed. */
	if (state < 0 || state > UNSUPPORTED) {
		printf(" %11s: error state %d\n", ctrstr, state);
		/* No details follow if counter in error state. */
		return;
	}
	printf(" %-11s: %s\n", ctrstr, states[state]);
	if (state != ENABLED)
		return;
	if (value > maxnum) {
		eprint("Incompatible versions detected!\n");
		eprint("Expected %lu counters for %s, but got %lu\n",
		       maxnum, ctrstr, value);
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < value; ++i) {
		ec = recv_answer(s, &paictr, &paistate, &paivalue);
		if (ec < 0 || paistate < 0) {
			eprint("Error on receiving answer message from daemon\n");
			/* No more data for this virtual event after error. */
			return;
		}
		if (paictr > MAX_NUM_PAI)
			eprint("Pai counter number too big: %d\n", paictr);
		else if (!paiprintnonzero || paivalue > 0)
			printf("  (%3d) %-45s: %lu\n", paictr + 1,
			       get_ctr_name(paictr), paivalue);
	}
}

static void print_answer(int s, int ctr, int state, uint64_t value)
{
	if (ctr > ALL_COUNTER)
		print_virtual_counter_answer(s, ctr, state, value);
	else if (state < 0)
		printf(" %s counter: error state %d\n",
		       counter_str[ctr], state);
	else if (state == DISABLED)
		printf(" %s counter: disabled\n", counter_str[ctr]);
	else if (state == UNSUPPORTED)
		printf(" %s counter: unsupported\n", counter_str[ctr]);
	else
		printf(" %s counter: %lu\n", counter_str[ctr], value);
}


static void json_print_answer(int s, int ctr, int state, uint64_t value)
{
	if (ctr > ALL_COUNTER) {
		json_print_virtual_counter_answer(s, ctr, state, value);
	} else if (state < 0) {
		printjsonsep();
		printf("{\"counter\":\"%s\",", counter_str[ctr]);
		printf("\"error\":%d}\n", state);
	} else if (state == ENABLED) {
		printjsonsep();
		printf("{\"counter\":\"%s\",", counter_str[ctr]);
		printf("\"value\":%lu}", value);
	}
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
	int i, j, s, state, num, json = 0;
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
			{ "nonzero", 0, NULL, 'n' },
			{ "json", 0, NULL, 'j' },
			{ NULL, 0, NULL, 0 } };
		while (1) {
			opt = getopt_long(argc, argv,
					  "hvedrpnj", long_opts, &idx);
			if (opt == -1)
				break; /* no more arguments */
			switch (opt) {
			case 'h':
				printf(usage, name);
				return 0;
			case 'v':
				printf("%s: Linux on System z CPACF Crypto Activity Counters Client\n"
				       "Version %s\n%s\n",
				       name, RELEASE_STRING, COPYRIGHT);
				return 0;
			case 'e':
				cmd = ENABLE;
				json = 0;
				break;
			case 'd':
				cmd = DISABLE;
				json = 0;
				break;
			case 'r':
				cmd = RESET;
				break;
			case 'p':
				cmd = PRINT;
				json = 0;
				break;
			case 'n':
				paiprintnonzero = 1;
				break;
			case 'j':
				cmd = PRINT;
				json = 1;
				break;
			default:
				eprint("Invalid argument, try -h or --help for more information\n");
				return EXIT_FAILURE;
			}
		}
		/* there may be an optional counter argument */
		if (optind > 0 && optind < argc) {
			for (i = 0; i < NUM_COUNTER; i++)
				if (strcmp(argv[optind], counter_str[i]) == 0)
					break;
			if (i >= NUM_COUNTER) {
				eprint("Unknown counter '%s'\n", argv[optind]);
				return EXIT_FAILURE;
			}
			ctr = (enum ctr_e) i;
		}
	}
	if (json)
		ctr = ALL_COUNTER;

	/* try to open and connect socket to the cpacfstatsd daemon */
	s = open_socket(CLIENT);
	if (s < 0) {
		eprint("Can't connect to daemon\n");
		return EXIT_FAILURE;
	}

	/* send query */
	if (send_query(s, cmd, ctr) != 0) {
		eprint("Error on sending query message to daemon\n");
		close(s);
		return EXIT_FAILURE;
	}

	if (ctr == ALL_COUNTER) {
		/* The -1 is for ALL_COUNTER which is not sent, +1 for
		 * hotplug state. */
		num = NUM_COUNTER - 1 + 1;
	} else {
		/* +1 for hotplug state */
		num = 1 + 1;
	}
	if (json)
		putchar('[');
	for (i = 0; i < num; i++) {
		/* receive answer */
		if (recv_answer(s, &j, &state, &value) != 0) {
			eprint("Error on receiving answer message from daemon\n");
			return EXIT_FAILURE;
		}
		if (state < 0) {
			eprint("Received bad status code %d from daemon\n",
				state);
			close(s);
			return EXIT_FAILURE;
		}
		if (json)
			json_print_answer(s, j, state, value);
		else
			print_answer(s, j, state, value);
	}
	if (json)
		putchar(']');

	/* close connection */
	close(s);

	return 0;
}
