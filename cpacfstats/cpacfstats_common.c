/* SPDX-License-Identifier: MIT */
/*
 * cpacfstats_common.c - shared code by daemon and client
 *
 * Copyright IBM Corp. 2024
 */

#include <stdint.h>
#include <stdlib.h>
#include "cpacfstats.h"

struct pai_counter {
	const char *str;
	const unsigned int counter_type;
};

/*
 * Strings for the pai counter details.
 * Integer indicating if kernel space is needed (0 for user, KERNEL_ONLY_COUNTER for kernel)
 * Note that this is 0-based while PoP is 1-based.
 *
 * When adding new items to this list add the counter number in the pai_idx
 * list in cpacfstatsd.c and increase the number of total counters in
 * cpacfstats.h.
 */
const struct pai_counter pai[] = {
	[  0] = {"KM DES", KERNEL_AND_USER_COUNTER},
	[  1] = {"KM 2key TDES", KERNEL_AND_USER_COUNTER},
	[  2] = {"KM TDES", KERNEL_AND_USER_COUNTER},
	[  3] = {"KM DES protected key", KERNEL_AND_USER_COUNTER},
	[  4] = {"KM 2key TDES protected key", KERNEL_AND_USER_COUNTER},
	[  5] = {"KM TDES protected key", KERNEL_AND_USER_COUNTER},
	[  6] = {"KM AES 128bit", KERNEL_AND_USER_COUNTER},
	[  7] = {"KM AES 192bit", KERNEL_AND_USER_COUNTER},
	[  8] = {"KM AES 256bit", KERNEL_AND_USER_COUNTER},
	[  9] = {"KM AES 128bit protected key", KERNEL_AND_USER_COUNTER},
	[ 10] = {"KM AES 192bit protected key", KERNEL_AND_USER_COUNTER},
	[ 11] = {"KM AES 256bit protected key", KERNEL_AND_USER_COUNTER},
	[ 12] = {"KM AES-XTS 128bit", KERNEL_AND_USER_COUNTER},
	[ 13] = {"KM AES-XTS 256bit", KERNEL_AND_USER_COUNTER},
	[ 14] = {"KM AES-XTS 128bit protected key", KERNEL_AND_USER_COUNTER},
	[ 15] = {"KM AES-XTS 256bit protected key", KERNEL_AND_USER_COUNTER},
	[ 16] = {"KMC DES", KERNEL_AND_USER_COUNTER},
	[ 17] = {"KMC 2key TDES", KERNEL_AND_USER_COUNTER},
	[ 18] = {"KMC TDES", KERNEL_AND_USER_COUNTER},
	[ 19] = {"KMC DES protected key", KERNEL_AND_USER_COUNTER},
	[ 20] = {"KMC 2key TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 21] = {"KMC TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 22] = {"KMC AES 128bit", KERNEL_AND_USER_COUNTER},
	[ 23] = {"KMC AES 192bit", KERNEL_AND_USER_COUNTER},
	[ 24] = {"KMC AES 256bit", KERNEL_AND_USER_COUNTER},
	[ 25] = {"KMC AES 128bit protected key", KERNEL_AND_USER_COUNTER},
	[ 26] = {"KMC AES 192bit protected key", KERNEL_AND_USER_COUNTER},
	[ 27] = {"KMC AES 256bit protected key", KERNEL_AND_USER_COUNTER},
	[ 28] = {"KMC PRNG", KERNEL_AND_USER_COUNTER},
	[ 29] = {"KMA AES 128bit", KERNEL_AND_USER_COUNTER},
	[ 30] = {"KMA AES 192bit", KERNEL_AND_USER_COUNTER},
	[ 31] = {"KMA AES 256bit", KERNEL_AND_USER_COUNTER},
	[ 32] = {"KMA AES 128bit protected key", KERNEL_AND_USER_COUNTER},
	[ 33] = {"KMA AES 192bit protected key", KERNEL_AND_USER_COUNTER},
	[ 34] = {"KMA AES 256bit protected key", KERNEL_AND_USER_COUNTER},
	[ 35] = {"KMF DES", KERNEL_AND_USER_COUNTER},
	[ 36] = {"KMF 2key TDES", KERNEL_AND_USER_COUNTER},
	[ 37] = {"KMF TDES", KERNEL_AND_USER_COUNTER},
	[ 38] = {"KMF DES protected key", KERNEL_AND_USER_COUNTER},
	[ 39] = {"KMF 2key TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 40] = {"KMF TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 41] = {"KMF AES 128bit", KERNEL_AND_USER_COUNTER},
	[ 42] = {"KMF AES 192bit", KERNEL_AND_USER_COUNTER},
	[ 43] = {"KMF AES 256bit", KERNEL_AND_USER_COUNTER},
	[ 44] = {"KMF AES 128bit protected key", KERNEL_AND_USER_COUNTER},
	[ 45] = {"KMF AES 192bit protected key", KERNEL_AND_USER_COUNTER},
	[ 46] = {"KMF AES 256bit protected key", KERNEL_AND_USER_COUNTER},
	[ 47] = {"KMCTR DES", KERNEL_AND_USER_COUNTER},
	[ 48] = {"KMCTR 2key TDES", KERNEL_AND_USER_COUNTER},
	[ 49] = {"KMCTR TDES", KERNEL_AND_USER_COUNTER},
	[ 50] = {"KMCTR DES protected key", KERNEL_AND_USER_COUNTER},
	[ 51] = {"KMCTR 2key TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 52] = {"KMCTR TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 53] = {"KMCTR AES 128bit", KERNEL_AND_USER_COUNTER},
	[ 54] = {"KMCTR AES 192bit", KERNEL_AND_USER_COUNTER},
	[ 55] = {"KMCTR AES 256bit", KERNEL_AND_USER_COUNTER},
	[ 56] = {"KMCTR AES 128bit protected key", KERNEL_AND_USER_COUNTER},
	[ 57] = {"KMCTR AES 192bit protected key", KERNEL_AND_USER_COUNTER},
	[ 58] = {"KMCTR AES 256bit protected key", KERNEL_AND_USER_COUNTER},
	[ 59] = {"KMO DES", KERNEL_AND_USER_COUNTER},
	[ 60] = {"KMO 2key TDES", KERNEL_AND_USER_COUNTER},
	[ 61] = {"KMO TDES", KERNEL_AND_USER_COUNTER},
	[ 62] = {"KMO DES protected key", KERNEL_AND_USER_COUNTER},
	[ 63] = {"KMO 2key TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 64] = {"KMO TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 65] = {"KMO AES 128bit", KERNEL_AND_USER_COUNTER},
	[ 66] = {"KMO AES 192bit", KERNEL_AND_USER_COUNTER},
	[ 67] = {"KMO AES 256bit", KERNEL_AND_USER_COUNTER},
	[ 68] = {"KMO AES 128bit protected key", KERNEL_AND_USER_COUNTER},
	[ 69] = {"KMO AES 192bit protected key", KERNEL_AND_USER_COUNTER},
	[ 70] = {"KMO AES 256bit protected key", KERNEL_AND_USER_COUNTER},
	[ 71] = {"KIMD SHA1", KERNEL_AND_USER_COUNTER},
	[ 72] = {"KIMD SHA256", KERNEL_AND_USER_COUNTER},
	[ 73] = {"KIMD SHA512", KERNEL_AND_USER_COUNTER},
	[ 74] = {"KIMD SHA3-224", KERNEL_AND_USER_COUNTER},
	[ 75] = {"KIMD SHA3-256", KERNEL_AND_USER_COUNTER},
	[ 76] = {"KIMD SHA3-384", KERNEL_AND_USER_COUNTER},
	[ 77] = {"KIMD SHA3-512", KERNEL_AND_USER_COUNTER},
	[ 78] = {"KIMD SHAKE 128", KERNEL_AND_USER_COUNTER},
	[ 79] = {"KIMD SHAKE 256", KERNEL_AND_USER_COUNTER},
	[ 80] = {"KIMD GHASH", KERNEL_AND_USER_COUNTER},
	[ 81] = {"KLMD SHA1", KERNEL_AND_USER_COUNTER},
	[ 82] = {"KLMD SHA256", KERNEL_AND_USER_COUNTER},
	[ 83] = {"KLMD SHA512", KERNEL_AND_USER_COUNTER},
	[ 84] = {"KLMD SHA3-224", KERNEL_AND_USER_COUNTER},
	[ 85] = {"KLMD SHA3-256", KERNEL_AND_USER_COUNTER},
	[ 86] = {"KLMD SHA3-384", KERNEL_AND_USER_COUNTER},
	[ 87] = {"KLMD SHA3-512", KERNEL_AND_USER_COUNTER},
	[ 88] = {"KLMD SHAKE 128", KERNEL_AND_USER_COUNTER},
	[ 89] = {"KLMD SHAKE 256", KERNEL_AND_USER_COUNTER},
	[ 90] = {"KMAC DES", KERNEL_AND_USER_COUNTER},
	[ 91] = {"KMAC 2key TDES", KERNEL_AND_USER_COUNTER},
	[ 92] = {"KMAC TDES", KERNEL_AND_USER_COUNTER},
	[ 93] = {"KMAC DES protected key", KERNEL_AND_USER_COUNTER},
	[ 94] = {"KMAC 2key TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 95] = {"KMAC TDES protected key", KERNEL_AND_USER_COUNTER},
	[ 96] = {"KMAC AES 128bit", KERNEL_AND_USER_COUNTER},
	[ 97] = {"KMAC AES 192bit", KERNEL_AND_USER_COUNTER},
	[ 98] = {"KMAC AES 256bit", KERNEL_AND_USER_COUNTER},
	[ 99] = {"KMAC AES 128bit protected key", KERNEL_AND_USER_COUNTER},
	[100] = {"KMAC AES 192bit protected key", KERNEL_AND_USER_COUNTER},
	[101] = {"KMAC AES 256bit protected key", KERNEL_AND_USER_COUNTER},
	[102] = {"PCC Last Block CMAC DES", KERNEL_AND_USER_COUNTER},
	[103] = {"PCC Last Block CMAC 2key TDES", KERNEL_AND_USER_COUNTER},
	[104] = {"PCC Last Block CMAC TDES", KERNEL_AND_USER_COUNTER},
	[105] = {"PCC Last Block CMAC DES protected key",
			 KERNEL_AND_USER_COUNTER},
	[106] = {"PCC Last Block CMAC 2key TDES protected key",
			 KERNEL_AND_USER_COUNTER},
	[107] = {"PCC Last Block CMAC TDES protected key",
			 KERNEL_AND_USER_COUNTER},
	[108] = {"PCC Last Block CMAC AES 128bit", KERNEL_AND_USER_COUNTER},
	[109] = {"PCC Last Block CMAC AES 192bit", KERNEL_AND_USER_COUNTER},
	[110] = {"PCC Last Block CMAC AES 256bit", KERNEL_AND_USER_COUNTER},
	[111] = {"PCC Last Block CMAC AES 128bit protected key",
			 KERNEL_AND_USER_COUNTER},
	[112] = {"PCC Last Block CMAC AES 192bit protected key",
			 KERNEL_AND_USER_COUNTER},
	[113] = {"PCC Last Block CMAC AES 256bit protected key",
			 KERNEL_AND_USER_COUNTER},
	[114] = {"PCC XTS Parameter AES 128bit", KERNEL_AND_USER_COUNTER},
	[115] = {"PCC XTS Parameter AES 256bit", KERNEL_AND_USER_COUNTER},
	[116] = {"PCC XTS Parameter AES 128bit protected key",
			 KERNEL_AND_USER_COUNTER},
	[117] = {"PCC XTS Parameter AES 256bit protected key",
			 KERNEL_AND_USER_COUNTER},
	[118] = {"PCC Scalar Mult P256", KERNEL_AND_USER_COUNTER},
	[119] = {"PCC Scalar Mult P384", KERNEL_AND_USER_COUNTER},
	[120] = {"PCC Scalar Mult P521", KERNEL_AND_USER_COUNTER},
	[121] = {"PCC Scalar Mult Ed25519", KERNEL_AND_USER_COUNTER},
	[122] = {"PCC Scalar Mult Ed448", KERNEL_AND_USER_COUNTER},
	[123] = {"PCC Scalar Mult X25519", KERNEL_AND_USER_COUNTER},
	[124] = {"PCC Scalar Mult X448", KERNEL_AND_USER_COUNTER},
	[125] = {"PRNO SHA512 DRNG", KERNEL_AND_USER_COUNTER},
	[126] = {"PRNO TRNG Query Ratio", KERNEL_AND_USER_COUNTER},
	[127] = {"PRNO TRNG", KERNEL_AND_USER_COUNTER},
	[128] = {"KDSA ECDSA Verify P256", KERNEL_AND_USER_COUNTER},
	[129] = {"KDSA ECDSA Verify P384", KERNEL_AND_USER_COUNTER},
	[130] = {"KDSA ECDSA Verify P521", KERNEL_AND_USER_COUNTER},
	[131] = {"KDSA ECDSA Sign P256", KERNEL_AND_USER_COUNTER},
	[132] = {"KDSA ECDSA Sign P384", KERNEL_AND_USER_COUNTER},
	[133] = {"KDSA ECDSA Sign P521", KERNEL_AND_USER_COUNTER},
	[134] = {"KDSA ECDSA Sign P256 protected key",
			 KERNEL_AND_USER_COUNTER},
	[135] = {"KDSA ECDSA Sign P384 protected key",
			 KERNEL_AND_USER_COUNTER},
	[136] = {"KDSA ECDSA Sign P521 protected key",
			 KERNEL_AND_USER_COUNTER},
	[137] = {"KDSA EdDSA Verify Ed25519", KERNEL_AND_USER_COUNTER},
	[138] = {"KDSA EdDSA Verify Ed448", KERNEL_AND_USER_COUNTER},
	[139] = {"KDSA EdDSA Sign Ed25519", KERNEL_AND_USER_COUNTER},
	[140] = {"KDSA EdDSA Sign Ed448", KERNEL_AND_USER_COUNTER},
	[141] = {"KDSA EdDSA Sign Ed25519 protected key",
			 KERNEL_AND_USER_COUNTER},
	[142] = {"KDSA EdDSA Sign Ed448 protected key",
			 KERNEL_AND_USER_COUNTER},
	[143] = {"PCKMO DES", KERNEL_ONLY_COUNTER},
	[144] = {"PCKMO 2key TDES", KERNEL_ONLY_COUNTER},
	[145] = {"PCKMO TDES", KERNEL_ONLY_COUNTER},
	[146] = {"PCKMO AES 128bit", KERNEL_ONLY_COUNTER},
	[147] = {"PCKMO AES 192bit", KERNEL_ONLY_COUNTER},
	[148] = {"PCKMO AES 256bit", KERNEL_ONLY_COUNTER},
	[149] = {"PCKMO ECC P256", KERNEL_ONLY_COUNTER},
	[150] = {"PCKMO ECC P384", KERNEL_ONLY_COUNTER},
	[151] = {"PCKMO ECC P521", KERNEL_ONLY_COUNTER},
	[152] = {"PCKMO ECC Ed25519", KERNEL_ONLY_COUNTER},
	[153] = {"PCKMO ECC Ed448", KERNEL_ONLY_COUNTER},
	[154] = {"Reserved 1", KERNEL_ONLY_COUNTER},
	[155] = {"Reserved 2", KERNEL_ONLY_COUNTER},
	[156] = {"KM AES-XTS (full) 128bit", KERNEL_AND_USER_COUNTER},
	[157] = {"KM AES-XTS (full) 256bit", KERNEL_AND_USER_COUNTER},
	[158] = {"KM AES-XTS (full) 128bit protected key",
		 KERNEL_AND_USER_COUNTER},
	[159] = {"KM AES-XTS (full) 256bit protected key",
		 KERNEL_AND_USER_COUNTER},
	[160] = {"KMAC HMAC SHA 224", KERNEL_AND_USER_COUNTER},
	[161] = {"KMAC HMAC SHA 256", KERNEL_AND_USER_COUNTER},
	[162] = {"KMAC HMAC SHA 384", KERNEL_AND_USER_COUNTER},
	[163] = {"KMAC HMAC SHA 512", KERNEL_AND_USER_COUNTER},
	[164] = {"KMAC HMAC SHA 224 protected key", KERNEL_AND_USER_COUNTER},
	[165] = {"KMAC HMAC SHA 256 protected key", KERNEL_AND_USER_COUNTER},
	[166] = {"KMAC HMAC SHA 384 protected key", KERNEL_AND_USER_COUNTER},
	[167] = {"KMAC HMAC SHA 512 protected key", KERNEL_AND_USER_COUNTER},
	[168] = {"PCKMO HMAC 512 protected key", KERNEL_ONLY_COUNTER},
	[169] = {"PCKMO HMAC 1024 protected key", KERNEL_ONLY_COUNTER},
	[170] = {"PCKMO AES-XTS 128bit double key protected key",
		 KERNEL_ONLY_COUNTER},
	[171] = {"PCKMO AES-XTS 256bit double key protected key",
		 KERNEL_ONLY_COUNTER}
};

/*
 * Returns counter_type of pai_counter struct
 *
 * SUPPRESS_COUNTER
 * KERNEL_AND_USER_COUNTER
 * KERNEL_ONLY_COUNTER
 */
enum counter_type is_user_space(unsigned int ctr)
{
	if (ctr >= MAX_NUM_PAI)
		return SUPPRESS_COUNTER;
	return pai[ctr].counter_type;
}

const char *get_ctr_name(unsigned int ctr)
{
	if (ctr >= MAX_NUM_PAI)
		return NULL;
	return pai[ctr].str;
}

/*
 * Returns number of PAI counters for which no kernel space is needed
 */
unsigned int get_num_user_space_ctrs(void)
{
	unsigned int counter = 0;
	unsigned int i;

	for (i = 0; i < MAX_NUM_PAI; i++) {
		if (is_user_space(i) == KERNEL_AND_USER_COUNTER)
			counter++;
	}

	return counter;
}
