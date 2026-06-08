/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2018, 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/auxv.h>

#include <openssl/crypto.h>

#include "lib/util_libc.h"

#include "cpacf.h"
#include "pkey.h"

#define MASK64(n)	(1ULL << (63 - (n) % 64))
#define OFF64(n)	((n) / 64)

/*
 * Checks if the specified MSA level is available.
 *
 * @param[in] msa           the MSA level to query
 *
 * @returns true if available, false otherwise
 */
static bool cpacf_msa(int msa)
{
	bool ret;

	unsigned long hwcap, facility_list_nmemb;
	u64 *facility_list = NULL, tmp;

	hwcap = getauxval(AT_HWCAP);
	if ((hwcap & HWCAP_S390_STFLE) == 0)
		return false;

	facility_list_nmemb = stfle(&tmp, 1);
	if (facility_list_nmemb > UINT8_MAX)
		return false;

	facility_list = util_zalloc(facility_list_nmemb * sizeof(u64));
	stfle(facility_list, facility_list_nmemb);

	ret = (facility_list_nmemb >= (unsigned long)OFF64(msa) + 1 &&
		(facility_list[OFF64(msa)] & MASK64(msa)) != 0);

	free(facility_list);
	return ret;
}

/*
 * Checks if the KMC instruction and the specified KMC function code is
 * supported.
 *
 * @param[in] fc            the function code to query
 *
 * @returns true if supported, false otherwise
 */
static bool cpacf_query_kmc(int fc)
{
	u64 status_word[2] = { 0 };

	if (!cpacf_msa(MSA))
		return false;

	cpacf_kmc(CPACF_KM_QUERY, &status_word, NULL, NULL, 0, NULL);

	return (status_word[OFF64(fc)] & MASK64(fc)) != 0;
}

/*
 * Checks if the KM instruction and the specified KM function code is
 * supported.
 *
 * @param[in] fc            the function code to query
 *
 * @returns true if supported, false otherwise
 */
static bool cpacf_query_km(int fc)
{
	u64 status_word[2] = { 0 };

	if (!cpacf_msa(MSA))
		return false;

	cpacf_km(CPACF_KMC_QUERY, &status_word, NULL, NULL, 0, NULL);

	return (status_word[OFF64(fc)] & MASK64(fc)) != 0;
}

/*
 * Checks if the KMAC instruction and the specified KMAC function code is
 * supported.
 *
 * @param[in] fc            the function code to query
 *
 * @returns true if supported, false otherwise
 */
static bool cpacf_query_kmac(int fc)
{
	u64 status_word[2] = { 0 };

	if (!cpacf_msa(MSA))
		return false;

	cpacf_kmac(CPACF_KMAC_QUERY, &status_word, NULL, 0);

	return (status_word[OFF64(fc)] & MASK64(fc)) != 0;
}

/*
 * Checks if the PCC instruction and the specified PCC function code is
 * supported.
 *
 * @param[in] fc            the function code to query
 *
 * @returns true if supported, false otherwise
 */
static bool cpacf_query_pcc(int fc)
{
	u64 status_word[2] = { 0 };

	if (!cpacf_msa(MSA4))
		return false;

	cpacf_pcc(CPACF_PCC_QUERY, &status_word);

	return (status_word[OFF64(fc)] & MASK64(fc)) != 0;
}

/*
 * Performs a one-shot AES-ECB encryption using a clear or protected key.
 *
 * @param[in] key           the clear or protected key
 * @param[in] key_size      the size of the clear or protected key
 * @param[in] in            the clear data to encrypt
 * @param[in] out           the output buffer to write the encrypted data to
 * @param[in] size          the size of the data to encrypt, and also the size
 *                          of the output buffer.
 * @param[in] pkey_type     the type of the protected key (PKEY_KEYTYPE_nnn)
 *                          or 0 if it is a clear key.
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int cpacf_aes_cbc_enc(const u8 *key, size_t key_size,
		      const u8 *in, u8 *out, size_t size,
		      int pkey_type)
{
	union {
		struct cpacf_kmc_aes_128_param aes_128;
		struct cpacf_kmc_aes_192_param aes_192;
		struct cpacf_kmc_aes_256_param aes_256;
		struct cpacf_kmc_enc_aes_128_param aes_128_enc;
		struct cpacf_kmc_enc_aes_192_param aes_192_enc;
		struct cpacf_kmc_enc_aes_256_param aes_256_enc;
	} kmc_param = { 0 };
	int fc, cc, rc = 0;

	switch (pkey_type) {
	case 0:
		/* clear key */
		switch (key_size) {
		case 16:
			fc = CPACF_KMC_AES_128;
			memcpy(kmc_param.aes_128.key, key,
			       sizeof(kmc_param.aes_128.key));
			break;
		case 24:
			fc = CPACF_KMC_AES_192;
			memcpy(kmc_param.aes_192.key, key,
			       sizeof(kmc_param.aes_192.key));
			break;
		case 32:
			fc = CPACF_KMC_AES_256;
			memcpy(kmc_param.aes_256.key, key,
			       sizeof(kmc_param.aes_256.key));
			break;
		default:
			rc = -EINVAL;
			goto out;
		}
		break;
	case PKEY_KEYTYPE_AES_128:
		fc = CPACF_KMC_ENCRYPTED_AES_128;

		if (key_size != sizeof(kmc_param.aes_128_enc.protkey)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(kmc_param.aes_128_enc.protkey, key,
		       sizeof(kmc_param.aes_128_enc.protkey));
		break;
	case PKEY_KEYTYPE_AES_192:
		fc = CPACF_KMC_ENCRYPTED_AES_192;

		if (key_size != sizeof(kmc_param.aes_192_enc.protkey)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(kmc_param.aes_192_enc.protkey, key,
		       sizeof(kmc_param.aes_192_enc.protkey));
		break;
	case PKEY_KEYTYPE_AES_256:
		fc = CPACF_KMC_ENCRYPTED_AES_256;

		if (key_size != sizeof(kmc_param.aes_256_enc.protkey)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(kmc_param.aes_256_enc.protkey, key,
		       sizeof(kmc_param.aes_256_enc.protkey));
		break;
	default:
		rc = -EINVAL;
		goto out;
	}

	if (!cpacf_query_kmc(fc)) {
		rc = -ENODEV;
		goto out;
	}

	cc = cpacf_kmc(fc, &kmc_param, out, in, size, NULL);
	if (cc == 1) /* WKVP mismatch */
		rc = -EAGAIN;
	else if (cc != 0)
		rc = -EIO;

out:
	OPENSSL_cleanse(&kmc_param, sizeof(kmc_param));
	return rc;
}

/*
 * Performs a one-shot AES-XTS encryption using a clear or protected key.
 *
 * @param[in] key           the clear or protected key
 * @param[in] key_size      the size of the clear or protected key
 * @param[in] in            the clear data to encrypt
 * @param[in] out           the output buffer to write the encrypted data to
 * @param[in] size          the size of the data to encrypt, and also the size
 *                          of the output buffer.
 * @param[in] pkey_type     the type of the protected key (PKEY_KEYTYPE_nnn)
 *                          or 0 if it is a clear key.
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int cpacf_aes_xts_enc(const u8 *key, size_t key_size,
		      const u8 *in, u8 *out, size_t size,
		      int pkey_type)
{
	union {
		struct cpacf_pcc_xts_aes_128_param aes_xts_128;
		struct cpacf_pcc_xts_aes_256_param aes_xts_256;
		struct cpacf_pcc_enc_xts_aes_128_param aes_xts_enc_128;
		struct cpacf_pcc_enc_xts_aes_256_param aes_xts_enc_256;
	} pcc_param = { 0 };
	union {
		struct cpacf_km_xts_aes_128_param aes_xts_128;
		struct cpacf_km_xts_aes_256_param aes_xts_256;
		struct cpacf_km_enc_xts_aes_128_param aes_xts_enc_128;
		struct cpacf_km_enc_xts_aes_256_param aes_xts_enc_256;
	} km_param = { 0 };
	int pcc_fc, km_fc, cc, rc = 0;

	switch (pkey_type) {
	case 0:
		/* clear key */
		switch (key_size) {
		case 32:
			pcc_fc = CPACF_PCC_XTS_AES_128;
			memcpy(pcc_param.aes_xts_128.key,
			       key + sizeof(pcc_param.aes_xts_128.key),
			       sizeof(pcc_param.aes_xts_128.key));
			break;
		case 64:
			pcc_fc = CPACF_PCC_XTS_AES_256;
			memcpy(pcc_param.aes_xts_256.key,
			       key + sizeof(pcc_param.aes_xts_256.key),
			       sizeof(pcc_param.aes_xts_256.key));
			break;
		default:
			rc = -EINVAL;
			goto out;
		}
		break;
	case PKEY_KEYTYPE_AES_128:
		pcc_fc = CPACF_PCC_XTS_ENCRYPTED_AES_128;

		if (key_size != 2 * sizeof(pcc_param.aes_xts_enc_128.protkey)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(pcc_param.aes_xts_enc_128.protkey,
		       key + sizeof(pcc_param.aes_xts_enc_128.protkey),
		       sizeof(pcc_param.aes_xts_enc_128.protkey));
		break;
	case PKEY_KEYTYPE_AES_256:
		pcc_fc = CPACF_PCC_XTS_ENCRYPTED_AES_256;

		if (key_size != 2 * sizeof(pcc_param.aes_xts_enc_256.protkey)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(pcc_param.aes_xts_enc_256.protkey,
		       key + sizeof(pcc_param.aes_xts_enc_256.protkey),
		       sizeof(pcc_param.aes_xts_enc_256.protkey));
		break;
	default:
		rc = -EINVAL;
		goto out;
	}

	if (!cpacf_query_pcc(pcc_fc)) {
		rc = -ENODEV;
		goto out;
	}

	cc = cpacf_pcc(pcc_fc, &pcc_param);
	if (cc == 1) /* WKVP mismatch */
		rc = -EAGAIN;
	else if (cc != 0)
		rc = -EIO;
	if (rc != 0)
		goto out;

	switch (pkey_type) {
	case 0:
		/* clear key */
		switch (key_size) {
		case 32:
			km_fc = CPACF_KM_XTS_AES_128;
			memcpy(km_param.aes_xts_128.key, key,
			       sizeof(km_param.aes_xts_128.key));
			memcpy(km_param.aes_xts_128.xtsparam,
			       pcc_param.aes_xts_128.xtsparams,
			       sizeof(km_param.aes_xts_128.xtsparam));
			break;
		case 64:
			km_fc = CPACF_KM_XTS_AES_256;
			memcpy(km_param.aes_xts_256.key, key,
			       sizeof(km_param.aes_xts_256.key));
			memcpy(km_param.aes_xts_256.xtsparam,
			       pcc_param.aes_xts_256.xtsparams,
			       sizeof(km_param.aes_xts_256.xtsparam));
			break;
		default:
			rc = -EINVAL;
			goto out;
		}
		break;
	case PKEY_KEYTYPE_AES_128:
		km_fc = CPACF_KM_XTS_ENCRYPTED_AES_128;
		memcpy(km_param.aes_xts_enc_128.protkey, key,
		       sizeof(km_param.aes_xts_enc_128.protkey));
		memcpy(km_param.aes_xts_enc_128.xtsparam,
		       pcc_param.aes_xts_enc_128.xtsparams,
		       sizeof(km_param.aes_xts_enc_128.xtsparam));
		break;
	case PKEY_KEYTYPE_AES_256:
		km_fc = CPACF_KM_XTS_ENCRYPTED_AES_256;
		memcpy(km_param.aes_xts_enc_256.protkey, key,
		       sizeof(km_param.aes_xts_enc_256.protkey));
		memcpy(km_param.aes_xts_enc_256.xtsparam,
		       pcc_param.aes_xts_enc_256.xtsparams,
		       sizeof(km_param.aes_xts_enc_256.xtsparam));
		break;
	default:
		rc = -EINVAL;
		goto out;
	}

	if (!cpacf_query_km(km_fc)) {
		rc = -ENODEV;
		goto out;
	}

	cc = cpacf_km(km_fc, &km_param, out, in, size, NULL);
	if (cc == 1) /* WKVP mismatch */
		rc = -EAGAIN;
	else if (cc != 0)
		rc = -EIO;

out:
	OPENSSL_cleanse(&pcc_param, sizeof(pcc_param));
	OPENSSL_cleanse(&km_param, sizeof(km_param));
	return rc;
}

/*
 * Performs a one-shot AES-XTS encryption using a Full-XTS protected key
 *
 * @param[in] key           the protected key
 * @param[in] key_size      the size of the protected key
 * @param[in] in            the clear data to encrypt
 * @param[in] out           the output buffer to write the encrypted data to
 * @param[in] size          the size of the data to encrypt, and also the size
 *                          of the output buffer.
 * @param[in] pkey_type     the type of the protected key (PKEY_KEYTYPE_nnn).
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int cpacf_aes_xts_full_enc(const u8 *key, size_t key_size,
			   const u8 *in, u8 *out, size_t size,
			   int pkey_type)
{
	union {
		struct cpacf_km_xts_full_aes_128_param aes_128;
		struct cpacf_km_xts_full_aes_256_param aes_256;
	} km_param = { 0 };
	int fc, cc, rc = 0;

	switch (pkey_type) {
	case PKEY_KEYTYPE_AES_XTS_128:
		fc = CPACF_KM_FXTS_ENCRYPTED_AES_128;

		if (key_size != sizeof(km_param.aes_128.protkey) +
					sizeof(km_param.aes_128.wkvp)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(km_param.aes_128.protkey, key,
		       sizeof(km_param.aes_128.protkey));
		km_param.aes_128.nap[0] = 0x01;
		memcpy(km_param.aes_128.wkvp,
		       key + sizeof(km_param.aes_128.protkey),
		       sizeof(km_param.aes_128.wkvp));
		break;
	case PKEY_KEYTYPE_AES_XTS_256:
		fc = CPACF_KM_FXTS_ENCRYPTED_AES_256;

		if (key_size != sizeof(km_param.aes_256.protkey) +
					sizeof(km_param.aes_256.wkvp)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(km_param.aes_256.protkey, key,
		       sizeof(km_param.aes_256.protkey));
		km_param.aes_256.nap[0] = 0x01;
		memcpy(km_param.aes_256.wkvp,
		       key + sizeof(km_param.aes_256.protkey),
		       sizeof(km_param.aes_256.wkvp));
		break;
	default:
		rc = -EINVAL;
		goto out;
	}

	if (!cpacf_query_km(fc)) {
		rc = -ENODEV;
		goto out;
	}

	cc = cpacf_km(fc, &km_param, out, in, size, NULL);
	if (cc == 1) /* WKVP mismatch */
		rc = -EAGAIN;
	else if (cc != 0)
		rc = -EIO;

out:
	OPENSSL_cleanse(&km_param, sizeof(km_param));
	return rc;
}

/*
 * Performs a one-shot SHA-HMAC operation using a clear or protected key.
 *
 * @param[in] key           the clear or protected key
 * @param[in] key_size      the size of the clear or protected key
 * @param[in] in            the clear data to mac
 * @param[in] in_size       the size of the data to mac
 * @param[in] mac           the output buffer to write the mac to
 * @param[in] mac_size      the size of the mac buffer
 * @param[in] pkey_type     the type of the protected key (PKEY_KEYTYPE_nnn)
 *                          or 0 if it is a clear key.
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int cpacf_hmac_sha(const u8 *key, size_t key_size,
		   const u8 *in, size_t in_size,
		   u8 *mac, size_t mac_size,
		   int pkey_type)
{
	union {
		struct cpacf_kmac_hmac_224_256_param hmac_256;
		struct cpacf_kmac_hmac_384_512_param hmac_512;
		struct cpacf_kmac_enc_hmac_224_256_param hmac_256_enc;
		struct cpacf_kmac_enc_hmac_384_512_param hmac_512_enc;
	} kmac_param = { 0 };
	int fc, cc, rc = 0;

	switch (pkey_type) {
	case 0:
		/* clear key */
		switch (key_size) {
		case 64:
			fc = CPACF_KMAC_HMAC_SHA_256;
			memcpy(kmac_param.hmac_256.key, key,
			       sizeof(kmac_param.hmac_256.key));
			kmac_param.hmac_256.imbl = in_size * 8;
			break;
		case 128:
			fc = CPACF_KMAC_HMAC_SHA_512;
			memcpy(kmac_param.hmac_512.key, key,
			       sizeof(kmac_param.hmac_512.key));
			kmac_param.hmac_512.imbl = in_size * 8;
			break;
		default:
			rc = -EINVAL;
			goto out;
		}
		break;
	case PKEY_KEYTYPE_HMAC_512:
		fc = CPACF_KMAC_HMAC_ENCRYPTED_SHA_256;

		if (key_size != sizeof(kmac_param.hmac_256_enc.protkey)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(kmac_param.hmac_256_enc.protkey, key,
		       sizeof(kmac_param.hmac_256_enc.protkey));
		kmac_param.hmac_256_enc.imbl = in_size * 8;
		break;
	case PKEY_KEYTYPE_HMAC_1024:
		fc = CPACF_KMAC_HMAC_ENCRYPTED_SHA_512;

		if (key_size != sizeof(kmac_param.hmac_512_enc.protkey)) {
			rc = -EINVAL;
			goto out;
		}

		memcpy(kmac_param.hmac_512_enc.protkey, key,
		       sizeof(kmac_param.hmac_512_enc.protkey));
		kmac_param.hmac_512_enc.imbl = in_size * 8;
		break;
	default:
		rc = -EINVAL;
		goto out;
	}

	if (!cpacf_query_kmac(fc)) {
		rc = -ENODEV;
		goto out;
	}

	cc = cpacf_kmac(fc, &kmac_param, in, in_size);
	if (cc == 1) /* WKVP mismatch */
		rc = -EAGAIN;
	else if (cc != 0)
		rc = -EIO;
	if (rc != 0)
		goto out;

	switch (pkey_type) {
	case 0:
		/* clear key */
		switch (key_size) {
		case 64:
			memcpy(mac, kmac_param.hmac_256.h,
			       MIN(mac_size, sizeof(kmac_param.hmac_256.h)));
			break;
		case 128:
			memcpy(mac, kmac_param.hmac_512.h,
			       MIN(mac_size, sizeof(kmac_param.hmac_512.h)));
			break;
		default:
			rc = -EINVAL;
			goto out;
		}
		break;
	case PKEY_KEYTYPE_HMAC_512:
		memcpy(mac, kmac_param.hmac_256_enc.h,
		       MIN(mac_size, sizeof(kmac_param.hmac_256_enc.h)));
		break;
	case PKEY_KEYTYPE_HMAC_1024:
		memcpy(mac, kmac_param.hmac_512_enc.h,
		       MIN(mac_size, sizeof(kmac_param.hmac_512_enc.h)));
		break;
	default:
		rc = -EINVAL;
		goto out;
	}

out:
	OPENSSL_cleanse(&kmac_param, sizeof(kmac_param));
	return rc;
}
