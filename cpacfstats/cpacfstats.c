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

/* Strings for the pai counter details.  Note that this is 0-based
 * while PoP is 1-based.
 */
static const char *const pai_str[] = {
	[  0] = "KM DES",
	[  1] = "KM 2key TDES",
	[  2] = "KM TDES",
	[  3] = "KM DES protected key",
	[  4] = "KM 2key TDES protected key",
	[  5] = "KM TDES protected key",
	[  6] = "KM AES 128bit",
	[  7] = "KM AES 192bit",
	[  8] = "KM AES 256bit",
	[  9] = "KM AES 128bit protected key",
	[ 10] = "KM AES 192bit protected key",
	[ 11] = "KM AES 256bit protected key",
	[ 12] = "KM AES-XTS 128bit",
	[ 13] = "KM AES-XTS 256bit",
	[ 14] = "KM AES-XTS 128bit protected key",
	[ 15] = "KM AES-XTS 256bit protected key",
	[ 16] = "KMC DES",
	[ 17] = "KMC 2key TDES",
	[ 18] = "KMC TDES",
	[ 19] = "KMC DES protected key",
	[ 20] = "KMC 2key TDES protected key",
	[ 21] = "KMC TDES protected key",
	[ 22] = "KMC AES 128bit",
	[ 23] = "KMC AES 192bit",
	[ 24] = "KMC AES 256bit",
	[ 25] = "KMC AES 128bit protected key",
	[ 26] = "KMC AES 192bit protected key",
	[ 27] = "KMC AES 256bit protected key",
	[ 28] = "KMC PRNG",
	[ 29] = "KMA AES 128bit",
	[ 30] = "KMA AES 192bit",
	[ 31] = "KMA AES 256bit",
	[ 32] = "KMA AES 128bit protected key",
	[ 33] = "KMA AES 192bit protected key",
	[ 34] = "KMA AES 256bit protected key",
	[ 35] = "KMF DES",
	[ 36] = "KMF 2key TDES",
	[ 37] = "KMF TDES",
	[ 38] = "KMF DES protected key",
	[ 39] = "KMF 2key TDES protected key",
	[ 40] = "KMF TDES protected key",
	[ 41] = "KMF AES 128bit",
	[ 42] = "KMF AES 192bit",
	[ 43] = "KMF AES 256bit",
	[ 44] = "KMF AES 128bit protected key",
	[ 45] = "KMF AES 192bit protected key",
	[ 46] = "KMF AES 256bit protected key",
	[ 47] = "KMCTR DES",
	[ 48] = "KMCTR 2key TDES",
	[ 49] = "KMCTR TDES",
	[ 50] = "KMCTR DES protected key",
	[ 51] = "KMCTR 2key TDES protected key",
	[ 52] = "KMCTR TDES protected key",
	[ 53] = "KMCTR AES 128bit",
	[ 54] = "KMCTR AES 192bit",
	[ 55] = "KMCTR AES 256bit",
	[ 56] = "KMCTR AES 128bit protected key",
	[ 57] = "KMCTR AES 192bit protected key",
	[ 58] = "KMCTR AES 256bit protected key",
	[ 59] = "KMO DES",
	[ 60] = "KMO 2key TDES",
	[ 61] = "KMO TDES",
	[ 62] = "KMO DES protected key",
	[ 63] = "KMO 2key TDES protected key",
	[ 64] = "KMO TDES protected key",
	[ 65] = "KMO AES 128bit",
	[ 66] = "KMO AES 192bit",
	[ 67] = "KMO AES 256bit",
	[ 68] = "KMO AES 128bit protected key",
	[ 69] = "KMO AES 192bit protected key",
	[ 70] = "KMO AES 256bit protected key",
	[ 71] = "KIMD SHA1",
	[ 72] = "KIMD SHA256",
	[ 73] = "KIMD SHA512",
	[ 74] = "KIMD SHA3-224",
	[ 75] = "KIMD SHA3-256",
	[ 76] = "KIMD SHA3-384",
	[ 77] = "KIMD SHA3-512",
	[ 78] = "KIMD SHAKE 128",
	[ 79] = "KIMD SHAKE 256",
	[ 80] = "KIMD GHASH",
	[ 81] = "KLMD SHA1",
	[ 82] = "KLMD SHA256",
	[ 83] = "KLMD SHA512",
	[ 84] = "KLMD SHA3-224",
	[ 85] = "KLMD SHA3-256",
	[ 86] = "KLMD SHA3-384",
	[ 87] = "KLMD SHA3-512",
	[ 88] = "KLMD SHAKE 128",
	[ 89] = "KLMD SHAKE 256",
	[ 90] = "KMAC DES",
	[ 91] = "KMAC 2key TDES",
	[ 92] = "KMAC TDES",
	[ 93] = "KMAC DES protected key",
	[ 94] = "KMAC 2key TDES protected key",
	[ 95] = "KMAC TDES protected key",
	[ 96] = "KMAC AES 128bit",
	[ 97] = "KMAC AES 192bit",
	[ 98] = "KMAC AES 256bit",
	[ 99] = "KMAC AES 128bit protected key",
	[100] = "KMAC AES 192bit protected key",
	[101] = "KMAC AES 256bit protected key",
	[102] = "PCC Last Block CMAC DES",
	[103] = "PCC Last Block CMAC 2key TDES",
	[104] = "PCC Last Block CMAC TDES",
	[105] = "PCC Last Block CMAC DES protected key",
	[106] = "PCC Last Block CMAC 2key TDES protected key",
	[107] = "PCC Last Block CMAC TDES protected key",
	[108] = "PCC Last Block CMAC AES 128bit",
	[109] = "PCC Last Block CMAC AES 192bit",
	[110] = "PCC Last Block CMAC AES 256bit",
	[111] = "PCC Last Block CMAC AES 128bit protected key",
	[112] = "PCC Last Block CMAC AES 192bit protected key",
	[113] = "PCC Last Block CMAC AES 256bit protected key",
	[114] = "PCC XTS Parameter AES 128bit",
	[115] = "PCC XTS Parameter AES 256bit",
	[116] = "PCC XTS Parameter AES 128bit protected key",
	[117] = "PCC XTS Parameter AES 256bit protected key",
	[118] = "PCC Scalar Mult P256",
	[119] = "PCC Scalar Mult P384",
	[120] = "PCC Scalar Mult P521",
	[121] = "PCC Scalar Mult Ed25519",
	[122] = "PCC Scalar Mult Ed448",
	[123] = "PCC Scalar Mult X25519",
	[124] = "PCC Scalar Mult X448",
	[125] = "PRNO SHA512 DRNG",
	[126] = "PRNO TRNG Query Ratio",
	[127] = "PRNO TRNG",
	[128] = "KDSA ECDSA Verify P256",
	[129] = "KDSA ECDSA Verify P384",
	[130] = "KDSA ECDSA Verify P521",
	[131] = "KDSA ECDSA Sign P256",
	[132] = "KDSA ECDSA Sign P384",
	[133] = "KDSA ECDSA Sign P521",
	[134] = "KDSA ECDSA Sign P256 protected key",
	[135] = "KDSA ECDSA Sign P384 protected key",
	[136] = "KDSA ECDSA Sign P521 protected key",
	[137] = "KDSA EdDSA Verify Ed25519",
	[138] = "KDSA EdDSA Verify Ed448",
	[139] = "KDSA EdDSA Sign Ed25519",
	[140] = "KDSA EdDSA Sign Ed448",
	[141] = "KDSA EdDSA Sign Ed25519 protected key",
	[142] = "KDSA EdDSA Sign Ed448 protected key",
	[143] = "PCKMO DES",
	[144] = "PCKMO 2key TDES",
	[145] = "PCMKO TDES",
	[146] = "PCKMO AES 128bit",
	[147] = "PCKMO AES 192bit",
	[148] = "PCMKO AES 256bit",
	[149] = "PCKMO ECC P256",
	[150] = "PCKMO ECC P384",
	[151] = "PCKMO ECC P521",
	[152] = "PCKMO ECC Ed25519",
	[153] = "PCKMO ECC Ed448",
	[154] = "Reserved 1",
	[155] = "Reserved 2"
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
	uint64_t i, paivalue = 0, maxnum;
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
		maxnum = NUM_PAI_USER;
		space = "user";
		break;
	case PAI_KERNEL:
		maxnum = NUM_PAI_KERNEL;
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
		eprint("Expected %"PRIu64" counter space for %s, but got %"PRIu64"\n",
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
		if (paictr > NUM_PAI_KERNEL) {
			eprint("Pai counter number too big: %d\n", paictr);
		} else {
			printjsonsep();
			printf("{\"counter\":\"%s\",\"space\":\"%s\",\"counterid\":%d,",
				pai_str[paictr], space, paictr + 1);
			if (paistate < 0) {
				printf("\"error\":%d}", paistate);
				/* Protocol does not send further counters. */
				return;
			}
			printf("\"value\":%"PRIu64"}", paivalue);
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
	uint64_t i, paivalue = 0, maxnum;
	const char *ctrstr;

	switch (ctr) {
	case HOTPLUG_DETECTED:
		if (state >= 0 && value > 0)
			printf(" hotplug detected\n");
		return;
	case PAI_USER:
		maxnum = NUM_PAI_USER;
		ctrstr = "pai_user";
		break;
	case PAI_KERNEL:
		maxnum = NUM_PAI_KERNEL;
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
		eprint("Expected %"PRIu64" counters for %s, but got %"PRIu64"\n",
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
		if (paictr > NUM_PAI_KERNEL)
			eprint("Pai counter number too big: %d\n", paictr);
		else if (!paiprintnonzero || paivalue > 0)
			printf("  %-45s: %"PRIu64"\n", pai_str[paictr], paivalue);
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
		printf(" %s counter: %"PRIu64"\n", counter_str[ctr], value);
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
		printf("\"value\":%"PRIu64"}", value);
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
