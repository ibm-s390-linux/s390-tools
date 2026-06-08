/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the pkey kernel module.
 * It defines a set of IOCTL commands with its associated structures.
 *
 * Copyright IBM Corp. 2017, 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CPACF_H
#define CPACF_H

#include "lib/zt_common.h"

int cpacf_aes_cbc_enc(const u8 *key, size_t key_size,
		      const u8 *in, u8 *out, size_t size,
		      int pkey_type);
int cpacf_aes_xts_enc(const u8 *key, size_t key_size,
		      const u8 *in, u8 *out, size_t size,
		      int pkey_type);
int cpacf_aes_xts_full_enc(const u8 *key, size_t key_size,
			   const u8 *in, u8 *out, size_t size,
			   int pkey_type);
int cpacf_hmac_sha(const u8 *key, size_t key_size,
		   const u8 *in, size_t in_size,
		   u8 *mac, size_t mac_size,
		   int pkey_type);

#define MSA		17 /* message-security-assist */
#define MSA4		77 /* message-security-assist extension 4 */

/* STFLE (store facility list extended) */

static inline unsigned long stfle(u64 flist[], u8 nmemb)
{
	register unsigned long r0 __asm__("0") = (unsigned long)nmemb - 1;

	__asm__ volatile(
		".insn	s,%[opc]<<16,0(%[flist])"
		: "+d" (r0)
		: [flist] "a" (flist), [opc] "i" (0xb2b0)
		: "memory", "cc"
	);

	return r0 + 1;
}

/* KM */

/* Function codes */
#define CPACF_KM_QUERY				0
#define CPACF_KM_XTS_AES_128			50
#define CPACF_KM_XTS_AES_256			52
#define CPACF_KM_XTS_ENCRYPTED_AES_128		58
#define CPACF_KM_XTS_ENCRYPTED_AES_256		60
#define CPACF_KM_FXTS_ENCRYPTED_AES_128		90
#define CPACF_KM_FXTS_ENCRYPTED_AES_256		92

struct cpacf_km_xts_aes_128_param {
	u8 key[16];
	u8 xtsparam[16];
};

struct cpacf_km_xts_aes_256_param {
	u8 key[32];
	u8 xtsparam[16];
};

struct cpacf_km_enc_xts_aes_128_param {
	u8 protkey[48]; /* WKa(K)|WKaVP */
	u8 xtsparam[16];
};

struct cpacf_km_enc_xts_aes_256_param {
	u8 protkey[64]; /* WKa(K)|WKaVP */
	u8 xtsparam[16];
};

struct cpacf_km_xts_full_aes_128_param {
	u8 protkey[32]; /* WKa(K) */
	u8 tweak[16];
	u8 nap[16];
	u8 wkvp[32]; /* WKaVP */
};

struct cpacf_km_xts_full_aes_256_param {
	u8 protkey[64]; /* WKa(K) */
	u8 tweak[16];
	u8 nap[16];
	u8 wkvp[32]; /* WKaVP */
};

static inline int cpacf_km(unsigned long fc, void *param, u8 *out,
			   const u8 *in, unsigned long inlen,
			   unsigned long *bytes_processed)
{
	register unsigned long r0 __asm__("0") = (unsigned long)fc;
	register unsigned long r1 __asm__("1") = (unsigned long)param;
	register unsigned long r2 __asm__("2") = (unsigned long)in;
	register unsigned long r3 __asm__("3") = (unsigned long)inlen;
	register unsigned long r4 __asm__("4") = (unsigned long)out;
	u8 cc;

	__asm__ volatile(
		"0:	.insn	rre,%[opc] << 16,%[out],%[in]\n"
		"	brc	1,0b\n" /* handle partial completion */
		"	ipm	%[cc]\n"
		"	srl	%[cc],28\n"
		: [in] "+a" (r2), [inlen] "+d" (r3), [out] "+a" (r4),
		  [cc] "=d" (cc)
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb92e)
		: "cc", "memory"
	);

	if (bytes_processed != NULL)
		*bytes_processed = fc ? inlen - r3 : r3;

	return cc;
}

/* KMC */

/* Function codes */
#define CPACF_KMC_QUERY				0
#define CPACF_KMC_AES_128			18
#define CPACF_KMC_AES_192			19
#define CPACF_KMC_AES_256			20
#define CPACF_KMC_ENCRYPTED_AES_128		26
#define CPACF_KMC_ENCRYPTED_AES_192		27
#define CPACF_KMC_ENCRYPTED_AES_256		28

struct cpacf_kmc_aes_128_param {
	u8 cv[16];
	u8 key[16];
};

struct cpacf_kmc_aes_192_param {
	u8 cv[16];
	u8 key[24];
};

struct cpacf_kmc_aes_256_param {
	u8 cv[16];
	u8 key[32];
};

struct cpacf_kmc_enc_aes_128_param {
	u8 cv[16];
	u8 protkey[48]; /* WKa(K)|WKaVP */
};

struct cpacf_kmc_enc_aes_192_param {
	u8 cv[16];
	u8 protkey[56]; /* WKa(K)|WKaVP */
};

struct cpacf_kmc_enc_aes_256_param {
	u8 cv[16];
	u8 protkey[64]; /* WKa(K)|WKaVP */
};

static inline int cpacf_kmc(unsigned long fc, void *param, u8 *out,
			    const u8 *in, long inlen,
			    unsigned long *bytes_processed)
{
	register unsigned long r0 __asm__("0") = (unsigned long)fc;
	register unsigned long r1 __asm__("1") = (unsigned long)param;
	register unsigned long r2 __asm__("2") = (unsigned long)in;
	register unsigned long r3 __asm__("3") = (unsigned long)inlen;
	register unsigned long r4 __asm__("4") = (unsigned long)out;
	u8 cc;

	__asm__ volatile(
		"0:	.insn	rre,%[opc] << 16,%[out],%[in]\n"
		"	brc	1,0b\n" /* handle partial completion */
		"	ipm	%[cc]\n"
		"	srl	%[cc],28\n"
		: [in] "+a" (r2), [inlen] "+d" (r3), [out] "+a" (r4),
		  [cc] "=d" (cc)
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb92f)
		: "cc", "memory"
	);

	if (bytes_processed != NULL)
		*bytes_processed = fc ? inlen - r3 : r3;

	return cc;
}

/* KMAC */

/* Function codes */
#define CPACF_KMAC_QUERY			0
#define CPACF_KMAC_HMAC_SHA_256			113
#define CPACF_KMAC_HMAC_SHA_512			115
#define CPACF_KMAC_HMAC_ENCRYPTED_SHA_256	121
#define CPACF_KMAC_HMAC_ENCRYPTED_SHA_512	123

/* Flags */
#define CPACF_KMAC_IKP				0x8000
#define CPACF_KMAC_IIMP				0x4000
#define CPACF_KMAC_CCUP				0x2000

struct cpacf_kmac_hmac_224_256_param {
	u32 h[8];
	u64 imbl;
	unsigned char key[64];
};

struct cpacf_kmac_hmac_384_512_param {
	u64 h[8];
#ifdef __SIZEOF_INT128__
	u128 imbl;
#else
	u64 imblhi;
	u64 imbl;
#endif
	unsigned char key[128];
};

struct cpacf_kmac_enc_hmac_224_256_param {
	u32 h[8];
	u64 imbl;
	unsigned char protkey[96]; /* WKa(K)|WKaVP */
};

struct cpacf_kmac_enc_hmac_384_512_param {
	u64 h[8];
#ifdef __SIZEOF_INT128__
	u128 imbl;
#else
	u64 imblhi;
	u64 imbl;
#endif
	unsigned char protkey[160]; /* WKa(K)|WKaVP */
};

static inline int cpacf_kmac(unsigned long fc, void *param, const u8 *in,
			     unsigned long inlen)
{
	register unsigned long r0 __asm__("0") = (unsigned long)fc;
	register unsigned long r1 __asm__("1") = (unsigned long)param;
	register unsigned long r2 __asm__("2") = (unsigned long)in;
	register unsigned long r3 __asm__("3") = (unsigned long)inlen;
	u8 cc;

	__asm__ volatile(
		"0:	.insn	rre,%[opc] << 16,0,%[in]\n"
		"	brc	1,0b\n" /* handle partial completion */
		"	ipm	%[cc]\n"
		"	srl	%[cc],28\n"
		: [in] "+a" (r2), [inlen] "+d" (r3), [cc] "=d" (cc)
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb91e)
		: "cc", "memory"
	);

	return cc;
}

/* PCC */

/* Function codes */
#define CPACF_PCC_QUERY				0
#define CPACF_PCC_XTS_AES_128			50
#define CPACF_PCC_XTS_AES_256			52
#define CPACF_PCC_XTS_ENCRYPTED_AES_128		58
#define CPACF_PCC_XTS_ENCRYPTED_AES_256		60

struct cpacf_pcc_xts_aes_128_param {
	u8 key[16];
	u8 i[16];
	u8 j[16];
	u8 t[16];
	u8 xtsparams[16];
};

struct cpacf_pcc_xts_aes_256_param {
	u8 key[32];
	u8 i[16];
	u8 j[16];
	u8 t[16];
	u8 xtsparams[16];
};

struct cpacf_pcc_enc_xts_aes_128_param {
	u8 protkey[48]; /* WKa(K)|WKaVP */
	u8 i[16];
	u8 j[16];
	u8 t[16];
	u8 xtsparams[16];
};

struct cpacf_pcc_enc_xts_aes_256_param {
	u8 protkey[64]; /* WKa(K)|WKaVP */
	u8 i[16];
	u8 j[16];
	u8 t[16];
	u8 xtsparams[16];
};

/* PCC (perform cryptographic computation) */
static inline int cpacf_pcc(unsigned long fc, void *param)
{
	register unsigned long r0 __asm__("0") = (unsigned long)fc;
	register unsigned long r1 __asm__("1") = (unsigned long)param;
	u8 cc;

	__asm__ volatile(
		"0:	.insn	rre,%[opc] << 16,0,0\n" /* PCC opcode */
		"	brc	1,0b\n" /* handle partial completion */
		"	ipm	%[cc]\n"
		"	srl	%[cc],28\n"
		: [cc] "=d" (cc)
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb92c)
		: "cc", "memory"
	);

	return cc;
}

#endif
