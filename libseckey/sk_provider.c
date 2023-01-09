/*
 * libseckey - Secure key library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "lib/zt_common.h"

#include "libseckey/sk_openssl.h"
#include "libseckey/sk_utilities.h"

/*
 * This source file is only used with OpenSSL >= 3.0
 */
#if OPENSSL_VERSION_PREREQ(3, 0)

#include <openssl/provider.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "openssl/param_build.h"
#include <openssl/decoder.h>

static OSSL_LIB_CTX *sk_prov_securekey_libctx;
static OSSL_LIB_CTX *sk_prov_previous_libctx;
static OSSL_PROVIDER *sk_prov_securekey_provider;
static OSSL_PROVIDER *sk_prov_default_provider;

#define SK_PROV_NAME				"securekey"
#define SK_PROV_DESCRIPTION			"Secure key provider"
#define SK_PROV_VERSION				"1.0"

#define SK_PROV_RSA_DEFAULT_MD			"SHA-1"
#define SK_PROV_EC_DEFAULT_MD_NID		"SHA-1"
#define SK_PROV_PKEY_PARAM_SK_BLOB		"sk-blob"
#define SK_PROV_PKEY_PARAM_SK_FUNCS		"sk-funcs"
#define SK_PROV_PKEY_PARAM_SK_PRIVATE		"sk-private"

#define SK_CONF_CACHED_PARAMS_OP_KEY_EXPORT	0  /* 16 possible selections */
#define SK_CONF_CACHED_PARAMS_OP_KEY_IMPORT	16 /* 16 possible selections */
#define SK_CONF_CACHED_PARAMS_OP_KEY_GET	32
#define SK_CONF_CACHED_PARAMS_OP_KEY_SET	33
#define SK_CONF_CACHED_PARAMS_OP_COUNT		34

#define SK_CONF_CACHED_PARAMS_ALGO_RSA		0
#define SK_CONF_CACHED_PARAMS_ALGO_RSA_PSS	1
#define SK_CONF_CACHED_PARAMS_ALGO_EC		2
#define SK_CONF_CACHED_PARAMS_ALGO_COUNT	3

#define SK_PROV_CACHED_PARAMS_COUNT					\
	(SK_CONF_CACHED_PARAMS_ALGO_COUNT * SK_CONF_CACHED_PARAMS_OP_COUNT)

struct sk_prov_ctx {
	const OSSL_CORE_HANDLE *handle;
	OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
	OSSL_FUNC_core_new_error_fn *c_new_error;
	OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
	OSSL_FUNC_core_vset_error_fn *c_vset_error;
	OSSL_PROVIDER *default_provider;
	void *default_provctx;
	const OSSL_ALGORITHM *cached_default_algos[OSSL_OP__HIGHEST];
	const OSSL_PARAM *cached_parms[SK_PROV_CACHED_PARAMS_COUNT];
	bool debug;
};

struct sk_prov_key {
	struct sk_prov_ctx *provctx;
	int type; /* EVP_PKEY_xxx types */
	void *default_key; /* shadow key of default provider */
	unsigned char *secure_key;
	size_t secure_key_size;
	struct sk_funcs *funcs;
	void *private;
	unsigned int ref_count;
};

struct sk_prov_op_ctx {
	struct sk_prov_ctx *provctx;
	int type; /* EVP_PKEY_xxx types */
	const char *propq;
	void *default_op_ctx; /* shadow context of default provider */
	void (*default_op_ctx_free)(void *default_op_ctx);
	struct sk_prov_key *key;
	int operation;
	OSSL_FUNC_signature_sign_fn *sign_fn;
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
};

#define sk_debug_ctx(ctx, fmt...)	sk_debug(ctx->debug, fmt)
#define sk_debug_key(key, fmt...)	sk_debug(key->provctx->debug, fmt)
#define sk_debug_op_ctx(ctx, fmt...)	sk_debug(ctx->provctx->debug, fmt)

int sk_openssl_get_pkey_ec(const unsigned char *secure_key,
			   size_t secure_key_size, int nid, size_t prime_len,
			   const unsigned char *x, const unsigned char *y,
			   const struct sk_funcs *sk_funcs, const void *private,
			   EVP_PKEY **pkey, bool debug);

int sk_openssl_get_pkey_rsa(const unsigned char *secure_key,
			    size_t secure_key_size,
			    const unsigned char *modulus, size_t modulus_length,
			    const unsigned char *pub_exp, size_t pub_exp_length,
			    int pkey_type, const struct sk_funcs *sk_funcs,
			    const void *private, EVP_PKEY **pkey, bool debug);


static OSSL_FUNC_provider_teardown_fn		sk_prov_teardown;
static OSSL_FUNC_provider_gettable_params_fn	sk_prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn		sk_prov_get_params;
static OSSL_FUNC_provider_query_operation_fn	sk_prov_query;
static OSSL_FUNC_provider_get_reason_strings_fn	sk_prov_get_reason_strings;
static OSSL_FUNC_provider_get_capabilities_fn	sk_prov_prov_get_capabilities;

static OSSL_FUNC_keymgmt_free_fn		sk_prov_keymgmt_free;
static OSSL_FUNC_keymgmt_gen_cleanup_fn		sk_prov_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn		sk_prov_keymgmt_load;
static OSSL_FUNC_keymgmt_gen_set_template_fn
					sk_prov_keymgmt_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn	sk_prov_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_fn			sk_prov_keymgmt_gen;
static OSSL_FUNC_keymgmt_get_params_fn		sk_prov_keymgmt_get_params;
static OSSL_FUNC_keymgmt_set_params_fn		sk_prov_keymgmt_set_params;
static OSSL_FUNC_keymgmt_has_fn			sk_prov_keymgmt_has;
static OSSL_FUNC_keymgmt_match_fn		sk_prov_keymgmt_match;
static OSSL_FUNC_keymgmt_validate_fn		sk_prov_keymgmt_validate;
static OSSL_FUNC_keymgmt_export_fn		sk_prov_keymgmt_export;
static OSSL_FUNC_keymgmt_import_fn		sk_prov_keymgmt_import;
static OSSL_FUNC_keymgmt_new_fn			sk_prov_keymgmt_rsa_new;
static OSSL_FUNC_keymgmt_new_fn			sk_prov_keymgmt_rsa_pss_new;
static OSSL_FUNC_keymgmt_new_fn			sk_prov_keymgmt_ec_new;
static OSSL_FUNC_keymgmt_gen_init_fn		sk_prov_keymgmt_rsa_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn	sk_prov_keymgmt_rsa_pss_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn		sk_prov_keymgmt_ec_gen_init;
static OSSL_FUNC_keymgmt_gen_settable_params_fn
					sk_prov_keymgmt_rsa_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn
				sk_prov_keymgmt_rsa_pss_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn
					sk_prov_keymgmt_ec_gen_settable_params;
static OSSL_FUNC_keymgmt_query_operation_name_fn
				sk_prov_keymgmt_rsa_query_operation_name;
static OSSL_FUNC_keymgmt_query_operation_name_fn
				sk_prov_keymgmt_ec_query_operation_name;
static OSSL_FUNC_keymgmt_gettable_params_fn
					sk_prov_keymgmt_rsa_gettable_params;
static OSSL_FUNC_keymgmt_gettable_params_fn
					sk_prov_keymgmt_rsa_pss_gettable_params;
static OSSL_FUNC_keymgmt_gettable_params_fn
					sk_prov_keymgmt_ec_gettable_params;
static OSSL_FUNC_keymgmt_settable_params_fn
					sk_prov_keymgmt_rsa_settable_params;
static OSSL_FUNC_keymgmt_settable_params_fn
					sk_prov_keymgmt_rsa_pss_settable_params;
static OSSL_FUNC_keymgmt_settable_params_fn
					sk_prov_keymgmt_ec_settable_params;
static OSSL_FUNC_keymgmt_export_types_fn
					sk_prov_keymgmt_rsa_export_types;
static OSSL_FUNC_keymgmt_export_types_fn
					sk_prov_keymgmt_rsa_pss_export_types;
static OSSL_FUNC_keymgmt_export_types_fn
					sk_prov_keymgmt_ec_export_types;
static OSSL_FUNC_keymgmt_import_types_fn
					sk_prov_keymgmt_rsa_import_types;
static OSSL_FUNC_keymgmt_import_types_fn
					sk_prov_keymgmt_rsa_pss_import_types;
static OSSL_FUNC_keymgmt_import_types_fn	sk_prov_keymgmt_ec_import_types;

static OSSL_FUNC_keyexch_newctx_fn		sk_prov_keyexch_ec_newctx;
static OSSL_FUNC_keyexch_dupctx_fn		sk_prov_keyexch_ec_dupctx;
static OSSL_FUNC_keyexch_init_fn		sk_prov_keyexch_ec_init;
static OSSL_FUNC_keyexch_set_peer_fn		sk_prov_keyexch_ec_set_peer;
static OSSL_FUNC_keyexch_derive_fn		sk_prov_keyexch_ec_derive;
static OSSL_FUNC_keyexch_set_ctx_params_fn
					sk_prov_keyexch_ec_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn
					sk_prov_keyexch_ec_settable_ctx_params;
static OSSL_FUNC_keyexch_get_ctx_params_fn sk_prov_keyexch_ec_get_ctx_params;
static OSSL_FUNC_keyexch_gettable_ctx_params_fn
					sk_prov_keyexch_ec_gettable_ctx_params;

static OSSL_FUNC_signature_newctx_fn		sk_prov_sign_rsa_newctx;
static OSSL_FUNC_signature_newctx_fn		sk_prov_sign_ec_newctx;
static OSSL_FUNC_signature_dupctx_fn		sk_prov_sign_op_dupctx;
static OSSL_FUNC_signature_sign_init_fn		sk_prov_sign_op_sign_init;
static OSSL_FUNC_signature_sign_fn		sk_prov_sign_rsa_sign;
static OSSL_FUNC_signature_sign_fn		sk_prov_sign_ec_sign;
static OSSL_FUNC_signature_verify_init_fn	sk_prov_sign_op_verify_init;
static OSSL_FUNC_signature_verify_fn		sk_prov_sign_op_verify;
static OSSL_FUNC_signature_verify_recover_init_fn
					sk_prov_sign_op_verify_recover_init;
static OSSL_FUNC_signature_verify_recover_fn	sk_prov_sign_op_verify_recover;
static OSSL_FUNC_signature_digest_sign_init_fn
					sk_prov_sign_rsa_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_init_fn
					sk_prov_sign_ec_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn
					sk_prov_sign_op_digest_sign_update;
static OSSL_FUNC_signature_digest_sign_final_fn
					sk_prov_sign_op_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn
					sk_prov_sign_op_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn
					sk_prov_sign_op_digest_verify_update;
static OSSL_FUNC_signature_digest_verify_final_fn
					sk_prov_sign_op_digest_verify_final;
static OSSL_FUNC_signature_get_ctx_params_fn	sk_prov_sign_op_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn
					sk_prov_sign_rsa_gettable_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn
					sk_prov_sign_ec_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn	sk_prov_sign_op_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn
					sk_prov_sign_rsa_settable_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn
					sk_prov_sign_ec_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn
					sk_prov_sign_op_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn
					sk_prov_sign_rsa_gettable_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn
					sk_prov_sign_ec_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn
					sk_prov_sign_op_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn
					sk_prov_sign_rsa_settable_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn
					sk_prov_sign_ec_settable_ctx_md_params;

static OSSL_FUNC_asym_cipher_newctx_fn		sk_prov_asym_rsa_newctx;
static OSSL_FUNC_asym_cipher_dupctx_fn		sk_prov_asym_op_dupctx;
static OSSL_FUNC_asym_cipher_freectx_fn		sk_prov_op_freectx;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn	sk_prov_asym_op_get_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn
					sk_prov_asym_rsa_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn	sk_prov_asym_op_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn
					sk_prov_asym_rsa_settable_ctx_params;
static OSSL_FUNC_asym_cipher_encrypt_init_fn	sk_prov_asym_op_encrypt_init;
static OSSL_FUNC_asym_cipher_encrypt_fn		sk_prov_asym_op_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_init_fn	sk_prov_asym_op_decrypt_init;
static OSSL_FUNC_asym_cipher_decrypt_fn		sk_prov_asym_rsa_decrypt;

#define SK_PROV_ERR_INTERNAL_ERROR		1
#define SK_PROV_ERR_MALLOC_FAILED		2
#define SK_PROV_ERR_INVALID_PARAM		3
#define SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING	4
#define SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED	5
#define SK_PROV_ERR_OPRATION_NOT_INITIALIZED	6
#define SK_PROV_ERR_MISSING_PARAMETER		7
#define SK_PROV_ERR_INVALID_PADDING		8
#define SK_PROV_ERR_INVALID_MD			9
#define SK_PROV_ERR_INVALID_SALTLEN		10
#define SK_PROV_ERR_SECURE_KEY_FUNC_FAILED	11

static const OSSL_ITEM sk_prov_reason_strings[] = {
	{ SK_PROV_ERR_INTERNAL_ERROR,	"Internal error" },
	{ SK_PROV_ERR_MALLOC_FAILED,	"Memory allocation failed" },
	{ SK_PROV_ERR_INVALID_PARAM,	"Invalid parameter encountered" },
	{ SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
		"A function inherited from default provider is missing" },
	{ SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
		"A function inherited from default provider has failed" },
	{ SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
		"An operation context has not been initialized" },
	{ SK_PROV_ERR_MISSING_PARAMETER,
		"A parameter of a key or a context is missing" },
	{ SK_PROV_ERR_INVALID_PADDING,
		"An invalid or unknown padding is used" },
	{ SK_PROV_ERR_INVALID_MD, "An invalid or unknown digest is used" },
	{ SK_PROV_ERR_INVALID_SALTLEN, "An invalid salt length is used" },
	{ SK_PROV_ERR_SECURE_KEY_FUNC_FAILED,
		"A secure key function has failed" },
	{0, NULL }
};

static void sk_prov_put_error(struct sk_prov_ctx *provctx, int err,
			      const char *file, int line, const char *func,
			      char *fmt, ...)
{
	va_list ap;

	if (provctx == NULL)
		return;

	va_start(ap, fmt);
	provctx->c_new_error(provctx->handle);
	provctx->c_set_error_debug(provctx->handle, file, line, func);
	provctx->c_vset_error(provctx->handle, err, fmt, ap);
	va_end(ap);
}

#define put_error_ctx(ctx, err, fmt...)					\
			do {						\
				sk_debug_ctx(ctx, "ERROR: "fmt);	\
				sk_prov_put_error(ctx, err, __FILE__,	\
					__LINE__, __func__, fmt);	\
			} while (0)
#define put_error_key(key, err, fmt...)					\
			put_error_ctx(key->provctx, err, fmt)
#define put_error_op_ctx(ctx, err, fmt...)				\
			put_error_ctx(ctx->provctx, err, fmt)

static void sk_prov_keymgmt_upref(struct sk_prov_key *key);
static struct sk_prov_key *sk_prov_keymgmt_new(struct sk_prov_ctx *provctx,
					       int type);
static int sk_prov_keymgmt_get_bits(struct sk_prov_key *key);

typedef void (*func_t)(void);

static func_t sk_prov_get_default_func(struct sk_prov_ctx *provctx,
				       int operation_id,
				       const char *algorithm,
				       int function_id)
{
	const OSSL_ALGORITHM *default_algos, *algs;
	const OSSL_DISPATCH *default_impl, *impl;
	int algolen = strlen(algorithm);
	int no_cache = 0, query = 0;
	func_t func = NULL;
	const char *found;

	if (provctx == NULL || provctx->default_provider == NULL ||
	    operation_id <= 0 || operation_id > OSSL_OP__HIGHEST)
		return NULL;

	sk_debug_ctx(provctx, "operation_id: %d, algo: %s, func: %d",
		     operation_id, algorithm, function_id);

	default_algos = provctx->cached_default_algos[operation_id];
	if (default_algos == NULL) {
		default_algos = OSSL_PROVIDER_query_operation(
				provctx->default_provider,
				operation_id, &no_cache);
		query = 1;
	}

	for (algs = default_algos; algs != NULL &&
				   algs->algorithm_names != NULL; algs++) {
		found = strcasestr(algs->algorithm_names, algorithm);
		if (found == NULL)
			continue;
		if (found[algolen] != '\0' && found[algolen] != ':')
			continue;
		if (found != algs->algorithm_names && found[-1] != ':')
			continue;

		default_impl = algs->implementation;
		for (impl = default_impl; impl->function_id != 0; impl++) {
			if (impl->function_id == function_id) {
				func = impl->function;
				break;
			}
		}
		break;
	}

	if (query == 1 && default_algos != NULL)
		OSSL_PROVIDER_unquery_operation(provctx->default_provider,
						operation_id,
						default_algos);

	if (no_cache == 0 &&
	    provctx->cached_default_algos[operation_id] == NULL)
		provctx->cached_default_algos[operation_id] = default_algos;

	sk_debug_ctx(provctx, "func: %p", func);
	return func;
}

static const char *sk_prov_get_algo(int pkey_type, bool sign)
{
	switch (pkey_type) {
	case EVP_PKEY_RSA:
		return "RSA";
	case EVP_PKEY_RSA_PSS:
		return "RSA-PSS";
	case EVP_PKEY_EC:
		if (sign)
			return "ECDSA";
		else
			return "EC";
	default:
		return NULL;
	}
}

static func_t sk_prov_get_default_keymgmt_func(struct sk_prov_ctx *provctx,
					       int pkey_type, int function_id)
{
	return sk_prov_get_default_func(provctx, OSSL_OP_KEYMGMT,
					sk_prov_get_algo(pkey_type, false),
					function_id);
}

static func_t sk_prov_get_default_keyexch_func(struct sk_prov_ctx *provctx,
					       int function_id)
{
	return sk_prov_get_default_func(provctx, OSSL_OP_KEYEXCH, "ECDH",
					function_id);
}

static func_t sk_prov_get_default_asym_func(struct sk_prov_ctx *provctx,
					    int pkey_type, int function_id)
{
	return sk_prov_get_default_func(provctx, OSSL_OP_ASYM_CIPHER,
					sk_prov_get_algo(pkey_type, false),
					function_id);
}

static func_t sk_prov_get_default_sign_func(struct sk_prov_ctx *provctx,
					    int pkey_type, int function_id)
{
	return sk_prov_get_default_func(provctx, OSSL_OP_SIGNATURE,
					sk_prov_get_algo(pkey_type, true),
					function_id);
}

static int sk_prov_get_cached_params_index(int pkey_type, int operation,
					   int selection)
{
	int ofs = 0;

	if (operation < 0 || operation >= SK_CONF_CACHED_PARAMS_OP_COUNT)
		return -1;

	switch (operation) {
	case SK_CONF_CACHED_PARAMS_OP_KEY_EXPORT:
	case SK_CONF_CACHED_PARAMS_OP_KEY_IMPORT:
		if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
			ofs += 1;
		if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
			ofs += 2;
		if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
			ofs += 4;
		if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
			ofs += 8;
		break;
	}

	switch (pkey_type) {
	case EVP_PKEY_RSA:
		return (SK_CONF_CACHED_PARAMS_ALGO_RSA *
				SK_CONF_CACHED_PARAMS_OP_COUNT) +
							operation + ofs;
	case EVP_PKEY_RSA_PSS:
		return (SK_CONF_CACHED_PARAMS_ALGO_RSA_PSS *
				SK_CONF_CACHED_PARAMS_OP_COUNT) +
							operation + ofs;
	case EVP_PKEY_EC:
		return (SK_CONF_CACHED_PARAMS_ALGO_EC *
				SK_CONF_CACHED_PARAMS_OP_COUNT) +
							operation + ofs;
	}

	return -1;
}

static const OSSL_PARAM *sk_prov_get_cached_params(struct sk_prov_ctx *provctx,
						   int pkey_type, int operation,
						   int selection)
{
	int index;

	sk_debug_ctx(provctx, "pkey_type: %d operation: %d selection: %x",
		     pkey_type, operation, selection);

	index = sk_prov_get_cached_params_index(pkey_type, operation,
						selection);
	if (index < 0) {
		put_error_ctx(provctx, SK_PROV_ERR_INTERNAL_ERROR,
			      "Invalid type, operation or selection");
		return NULL;
	}

	return provctx->cached_parms[index];
}

static const OSSL_PARAM *sk_prov_cached_params_build(
						struct sk_prov_ctx *provctx,
						int pkey_type,
						int operation,
						int selection,
						const OSSL_PARAM *params1,
						const OSSL_PARAM *params2)
{
	int index, count = 0, i, k = 0;
	OSSL_PARAM *params;

	sk_debug_ctx(provctx, "pkey_type: %d operation: %d selection: %x",
		     pkey_type, operation, selection);

	index = sk_prov_get_cached_params_index(pkey_type, operation,
						selection);
	if (index < 0) {
		put_error_ctx(provctx, SK_PROV_ERR_INTERNAL_ERROR,
			      "Invalid type, operation or selection");
		return NULL;
	}

	if (provctx->cached_parms[index] != NULL) {
		OPENSSL_free((void *)provctx->cached_parms[index]);
		provctx->cached_parms[index] = NULL;
	}

	for (i = 0; params1 != NULL && params1[i].key != NULL; i++, count++)
		;
	for (i = 0; params2 != NULL && params2[i].key != NULL; i++, count++)
		;
	sk_debug_ctx(provctx, "count: %d", count);

	count++; /* End marker */

	params = OPENSSL_zalloc(sizeof(OSSL_PARAM) * count);
	if (params == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_MALLOC_FAILED,
			      "OPENSSL_zalloc failed");
		return NULL;
	}

	for (i = 0; params1 != NULL && params1[i].key != NULL; i++, k++) {
		params[k] = params1[i];
		sk_debug_ctx(provctx, "param %d: %s", k, params[k].key);
	}
	for (i = 0; params2 != NULL && params2[i].key != NULL; i++, k++) {
		params[k] = params2[i];
		sk_debug_ctx(provctx, "param %d: %s", k, params[k].key);
	}
	params[k] = OSSL_PARAM_construct_end();

	provctx->cached_parms[index] = params;
	return provctx->cached_parms[index];
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static bool sk_prov_check_uint_param(const OSSL_PARAM params[],
				     const char *param_name,
				     const struct sk_prov_key *key,
				     int key_type,
				     unsigned int expected_value)
{
	const OSSL_PARAM *p;
	unsigned int value;

	if (key == NULL)
		return true;
	if (key->type != key_type)
		return true;

	p = OSSL_PARAM_locate_const(params, param_name);
	if (p == NULL)
		return true;

	if (OSSL_PARAM_get_uint(p, &value) != 1)
		return true;

	return value == expected_value;
}
#pragma GCC diagnostic pop

static struct sk_prov_op_ctx *sk_prov_op_newctx(struct sk_prov_ctx *provctx,
						const char *propq,
						int type)
{
	struct sk_prov_op_ctx *ctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "propq: %s type: %d",
		     propq != NULL ? propq : "", type);

	ctx = OPENSSL_zalloc(sizeof(struct sk_prov_op_ctx));
	if (ctx == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_MALLOC_FAILED,
			      "OPENSSL_zalloc failed");
		return NULL;
	}

	ctx->provctx = provctx;
	ctx->type = type;

	if (propq != NULL) {
		ctx->propq = OPENSSL_strdup(propq);
		if (ctx->propq == NULL) {
			put_error_ctx(provctx, SK_PROV_ERR_MALLOC_FAILED,
				      "OPENSSL_strdup failed");
			OPENSSL_free(ctx);
			return NULL;
		}
	}

	sk_debug_ctx(provctx, "ctx: %p", ctx);
	return ctx;
}

static void sk_prov_op_freectx(void *vctx)
{
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL)
		return;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (ctx->default_op_ctx != NULL && ctx->default_op_ctx_free != NULL)
		ctx->default_op_ctx_free(ctx->default_op_ctx);

	if (ctx->key != NULL)
		sk_prov_keymgmt_free(ctx->key);

	if (ctx->propq != NULL)
		OPENSSL_free((void *)ctx->propq);

	if (ctx->mdctx != NULL)
		EVP_MD_CTX_free(ctx->mdctx);
	if (ctx->md != NULL)
		EVP_MD_free(ctx->md);

	OPENSSL_free(ctx);
}

static struct sk_prov_op_ctx *sk_prov_op_dupctx(struct sk_prov_op_ctx *ctx)
{
	struct sk_prov_op_ctx *new_ctx;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	new_ctx = sk_prov_op_newctx(ctx->provctx, ctx->propq, ctx->type);
	if (new_ctx == NULL) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_newctx failed");
		return NULL;
	}

	new_ctx->operation = ctx->operation;
	new_ctx->default_op_ctx_free = ctx->default_op_ctx_free;
	new_ctx->sign_fn = ctx->sign_fn;

	if (ctx->mdctx != NULL) {
		new_ctx->mdctx = EVP_MD_CTX_new();
		if (new_ctx->mdctx == NULL) {
			put_error_op_ctx(ctx, SK_PROV_ERR_MALLOC_FAILED,
					 "EVP_MD_CTX_new failed");
			sk_prov_op_freectx(new_ctx);
			return NULL;
		}

		if (!EVP_MD_CTX_copy_ex(new_ctx->mdctx, ctx->mdctx)) {
			sk_debug_op_ctx(ctx,
					"ERROR: EVP_MD_CTX_copy_ex failed");
			sk_prov_op_freectx(new_ctx);
			return NULL;
		}
	};

	if (ctx->md != NULL) {
		new_ctx->md = ctx->md;
		EVP_MD_up_ref(ctx->md);
	}

	if (ctx->key != NULL) {
		new_ctx->key = ctx->key;
		sk_prov_keymgmt_upref(ctx->key);
	}

	sk_debug_op_ctx(ctx, "new_ctx: %p", new_ctx);
	return new_ctx;
}

static int sk_prov_op_init(struct sk_prov_op_ctx *ctx, struct sk_prov_key *key,
			   int operation)
{
	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p operation: %d", ctx, key,
			operation);

	if (key != NULL) {
		switch (ctx->type) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA_PSS:
			if (key->type != EVP_PKEY_RSA &&
			    key->type != EVP_PKEY_RSA_PSS) {
				put_error_op_ctx(ctx,
						 SK_PROV_ERR_INTERNAL_ERROR,
						 "key type mismatch: ctx type: "
						 "%d key type: %d",
						 ctx->type, key->type);
				return 0;
			}
			break;
		case EVP_PKEY_EC:
			if (key->type != EVP_PKEY_EC) {
				put_error_op_ctx(ctx,
						 SK_PROV_ERR_INTERNAL_ERROR,
						 "key type mismatch: ctx type: "
						 "%d key type: %d",
						 ctx->type, key->type);
				return 0;
			}
			break;
		default:
			put_error_op_ctx(ctx, SK_PROV_ERR_INTERNAL_ERROR,
					 "key type unknown: ctx type: "
					 "%d key type: %d",
					 ctx->type, key->type);
			return 0;
		}
	}

	if (key != NULL)
		sk_prov_keymgmt_upref(key);

	if (ctx->key != NULL)
		sk_prov_keymgmt_free(ctx->key);

	ctx->key = key;
	ctx->operation = operation;

	return 1;
}

static struct sk_prov_op_ctx *sk_prov_asym_op_newctx(
					struct sk_prov_ctx *provctx,
					int pkey_type)
{
	OSSL_FUNC_asym_cipher_freectx_fn *default_freectx_fn;
	OSSL_FUNC_asym_cipher_newctx_fn *default_newctx_fn;
	struct sk_prov_op_ctx *ctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "pkey_type: %d", pkey_type);

	default_newctx_fn = (OSSL_FUNC_asym_cipher_newctx_fn *)
			sk_prov_get_default_asym_func(provctx, pkey_type,
					OSSL_FUNC_ASYM_CIPHER_NEWCTX);
	if (default_newctx_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default newctx_fn");
		return NULL;
	}

	default_freectx_fn = (OSSL_FUNC_asym_cipher_freectx_fn *)
			sk_prov_get_default_asym_func(provctx, pkey_type,
					OSSL_FUNC_ASYM_CIPHER_FREECTX);
	if (default_freectx_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default freectx_fn");
		return NULL;
	}

	ctx = sk_prov_op_newctx(provctx, NULL, pkey_type);
	if (ctx == NULL) {
		sk_debug_ctx(provctx, "ERROR: sk_prov_op_newctx failed");
		return NULL;
	}

	ctx->default_op_ctx = default_newctx_fn(provctx->default_provctx);
	if (ctx->default_op_ctx == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_newctx_fn failed");
		sk_prov_op_freectx(ctx);
		return NULL;
	}
	ctx->default_op_ctx_free = default_freectx_fn;

	sk_debug_ctx(provctx, "ctx: %p", ctx);
	return ctx;
}

static void *sk_prov_asym_op_dupctx(void *vctx)
{
	OSSL_FUNC_asym_cipher_dupctx_fn *default_dupctx_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_op_ctx *new_ctx;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	default_dupctx_fn = (OSSL_FUNC_asym_cipher_dupctx_fn *)
			sk_prov_get_default_asym_func(ctx->provctx,
				ctx->type, OSSL_FUNC_ASYM_CIPHER_DUPCTX);
	if (default_dupctx_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default dupctx_fn");
		return NULL;
	}

	new_ctx = sk_prov_op_dupctx(ctx);
	if (new_ctx == NULL) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_dupctx failed");
		return NULL;
	}

	new_ctx->default_op_ctx = default_dupctx_fn(ctx->default_op_ctx);
	if (new_ctx->default_op_ctx == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_dupctx_fn failed");
		sk_prov_op_freectx(new_ctx);
		return NULL;
	}

	sk_debug_op_ctx(ctx, "new_ctx: %p", new_ctx);
	return new_ctx;
}

static int sk_prov_asym_op_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_get_ctx_params_fn *default_get_params_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_get_params_fn = (OSSL_FUNC_asym_cipher_get_ctx_params_fn *)
			sk_prov_get_default_asym_func(ctx->provctx,
				ctx->type,
				OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS);

	/* default_get_params_fn is optional */
	if (default_get_params_fn != NULL) {
		if (!default_get_params_fn(ctx->default_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_get_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static int sk_prov_asym_op_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_set_ctx_params_fn *default_set_params_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_set_params_fn = (OSSL_FUNC_asym_cipher_set_ctx_params_fn *)
			sk_prov_get_default_asym_func(ctx->provctx,
				ctx->type,
				OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS);

	/* default_set_params_fn is optional */
	if (default_set_params_fn != NULL) {
		if (!default_set_params_fn(ctx->default_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_set_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM *sk_prov_asym_op_gettable_ctx_params(
				struct sk_prov_op_ctx *ctx,
				struct sk_prov_ctx *provctx, int pkey_type)
{
	OSSL_FUNC_asym_cipher_gettable_ctx_params_fn
						*default_gettable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL || provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "pkey_type: %d", pkey_type);

	default_gettable_params_fn =
		(OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *)
			sk_prov_get_default_asym_func(provctx, pkey_type,
				OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS);

	/* default_gettable_params_fn is optional */
	if (default_gettable_params_fn != NULL)
		params = default_gettable_params_fn(ctx->default_op_ctx,
						    provctx->default_provctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_ctx(provctx, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM *sk_prov_asym_op_settable_ctx_params(
				struct sk_prov_op_ctx *ctx,
				struct sk_prov_ctx *provctx, int pkey_type)
{
	OSSL_FUNC_asym_cipher_settable_ctx_params_fn
						*default_settable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL || provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "pkey_type: %d", pkey_type);

	default_settable_params_fn =
		(OSSL_FUNC_asym_cipher_settable_ctx_params_fn *)
			sk_prov_get_default_asym_func(provctx, pkey_type,
				OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS);

	/* default_settable_params_fn is optional */
	if (default_settable_params_fn != NULL)
		params = default_settable_params_fn(ctx->default_op_ctx,
						    provctx->default_provctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_ctx(provctx, "param: %s", p->key);

	return params;
}

static EVP_MD *sk_prov_asym_op_get_oaep_md(struct sk_prov_op_ctx *ctx)
{
	char mdprops[256], mdname[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
				&mdname, sizeof(mdname)),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
				&mdprops, sizeof(mdprops)),
		OSSL_PARAM_END
	};
	EVP_MD *md;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (!sk_prov_asym_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		sk_debug_op_ctx(ctx, "sk_prov_asym_op_get_ctx_params failed");
		if (ctx->md != NULL) {
			sk_debug_op_ctx(ctx, "use digest from context: %s",
					EVP_MD_name(ctx->md));
			EVP_MD_up_ref(ctx->md);
			return ctx->md;
		}

		sk_debug_op_ctx(ctx, "use default");
		strcpy(mdname, SK_PROV_RSA_DEFAULT_MD);
		strcpy(mdprops, "");
	}

	md = EVP_MD_fetch((OSSL_LIB_CTX *)ctx->provctx->c_get_libctx(
							ctx->provctx->handle),
			  mdname, mdprops[0] != '\0' ? mdprops : ctx->propq);
	if (md == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 mdprops[0] != '\0' ? mdprops :
					ctx->propq != NULL ? ctx->propq : "");
		return NULL;
	}

	sk_debug_op_ctx(ctx, "md: %s", EVP_MD_name(md));
	return md;
}

static EVP_MD *sk_prov_asym_op_get_mgf_md(struct sk_prov_op_ctx *ctx)
{
	char mdprops[256], mdname[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
				&mdname, sizeof(mdname)),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS,
				&mdprops, sizeof(mdprops)),
		OSSL_PARAM_END
	};
	EVP_MD *md;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (!sk_prov_asym_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		sk_debug_op_ctx(ctx, "sk_prov_asym_op_get_ctx_params failed, "
				"using oaep digest");
		return sk_prov_asym_op_get_oaep_md(ctx);
	}

	md = EVP_MD_fetch((OSSL_LIB_CTX *)ctx->provctx->c_get_libctx(
							ctx->provctx->handle),
			  mdname, mdprops[0] != '\0' ? mdprops : ctx->propq);
	if (md == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 mdprops[0] != '\0' ? mdprops :
					ctx->propq != NULL ? ctx->propq : "");
		return NULL;
	}

	sk_debug_op_ctx(ctx, "md: %s", EVP_MD_name(md));
	return md;
}

static int sk_prov_asym_op_get_oaep_label(struct sk_prov_op_ctx *ctx,
					  unsigned char **label)
{
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
				label, 0),
		OSSL_PARAM_END
	};
	int oaep_label_len;


	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (!sk_prov_asym_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0])) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "sk_prov_asym_op_get_ctx_params failed to "
				 "get OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL");
		return -1;
	}

	oaep_label_len = ctx_params[0].return_size;
	sk_debug_op_ctx(ctx, "oaep_label: %p oaep_label_len: %d", *label,
			oaep_label_len);

	return oaep_label_len;
}

static int sk_prov_parse_padding(const char *padding)
{
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_NONE) == 0)
		return RSA_NO_PADDING;
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
		return RSA_PKCS1_PADDING;
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_OAEP) == 0)
		return RSA_PKCS1_OAEP_PADDING;
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_X931) == 0)
		return RSA_X931_PADDING;
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
		return RSA_PKCS1_PSS_PADDING;

	return -1;
}

static int sk_prov_asym_op_get_padding(struct sk_prov_op_ctx *ctx)
{
	char padding[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PAD_MODE,
				&padding, sizeof(padding)),
		OSSL_PARAM_END
	};

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (!sk_prov_asym_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0])) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "sk_prov_asym_op_get_ctx_params failed to "
				 "get OSSL_PKEY_PARAM_PAD_MODE");
		return -1;
	}

	sk_debug_op_ctx(ctx, "padding: %s", padding);

	return sk_prov_parse_padding(padding);
}

static int sk_prov_asym_op_encrypt_init(void *vctx, void *vkey,
					const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_encrypt_init_fn *default_encrypt_init_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_encrypt_init_fn = (OSSL_FUNC_asym_cipher_encrypt_init_fn *)
				sk_prov_get_default_asym_func(ctx->provctx,
					ctx->type,
					OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT);
	if (default_encrypt_init_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default encrypt_init_fn");
		return 0;
	}

	if (!sk_prov_op_init(ctx, key, EVP_PKEY_OP_ENCRYPT)) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_init failed");
		return 0;
	}

	if (!default_encrypt_init_fn(ctx->default_op_ctx, key->default_key,
				     params)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_encrypt_init_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_asym_op_decrypt_init(void *vctx, void *vkey,
					const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_decrypt_init_fn *default_decrypt_init_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_decrypt_init_fn = (OSSL_FUNC_asym_cipher_decrypt_init_fn *)
				sk_prov_get_default_asym_func(ctx->provctx,
					ctx->type,
					OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT);
	if (default_decrypt_init_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default decrypt_init_fn");
		return 0;
	}

	if (!sk_prov_op_init(ctx, key, EVP_PKEY_OP_DECRYPT)) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_init failed");
		return 0;
	}

	if (!default_decrypt_init_fn(ctx->default_op_ctx, key->default_key,
				     params)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_decrypt_init_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_asym_op_encrypt(void *vctx,
				   unsigned char *out, size_t *outlen,
				   size_t outsize, const unsigned char *in,
				   size_t inlen)
{
	OSSL_FUNC_asym_cipher_encrypt_fn *default_encrypt_fn;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL || in == NULL || outlen == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p inlen: %lu outsize: %lu",
			ctx, ctx->key, inlen, outsize);

	default_encrypt_fn = (OSSL_FUNC_asym_cipher_encrypt_fn *)
			sk_prov_get_default_asym_func(ctx->provctx,
				ctx->type, OSSL_FUNC_ASYM_CIPHER_ENCRYPT);
	if (default_encrypt_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default encrypt_fn");
		return 0;
	}

	if (!default_encrypt_fn(ctx->default_op_ctx, out, outlen, outsize,
				in, inlen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_encrypt_fn failed");
		return 0;
	}

	sk_debug_op_ctx(ctx, "outlen: %lu", *outlen);

	return 1;
}

static int sk_prov_asym_op_decrypt(struct sk_prov_op_ctx *ctx,
				   unsigned char *out, size_t *outlen,
				   size_t outsize, const unsigned char *in,
				   size_t inlen)
{
	OSSL_FUNC_asym_cipher_decrypt_fn *default_decrypt_fn;

	if (ctx == NULL || in == NULL || outlen == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p inlen: %lu outsize: %lu",
			ctx, ctx->key, inlen, outsize);

	default_decrypt_fn = (OSSL_FUNC_asym_cipher_decrypt_fn *)
			sk_prov_get_default_asym_func(ctx->provctx,
				ctx->type, OSSL_FUNC_ASYM_CIPHER_DECRYPT);
	if (default_decrypt_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default decrypt_fn");
		return 0;
	}

	if (!default_decrypt_fn(ctx->default_op_ctx, out, outlen, outsize,
				in, inlen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_decrypt_fn failed");
		return 0;
	}

	sk_debug_op_ctx(ctx, "outlen: %lu", *outlen);

	return 1;
}

static struct sk_prov_op_ctx *sk_prov_sign_op_newctx(
					struct sk_prov_ctx *provctx,
					const char *propq,
					int pkey_type)
{
	OSSL_FUNC_signature_freectx_fn *default_freectx_fn;
	OSSL_FUNC_signature_newctx_fn *default_newctx_fn;
	struct sk_prov_op_ctx *ctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "propq: %s pkey_type: %d",
		     propq != NULL ? propq : "", pkey_type);

	default_newctx_fn = (OSSL_FUNC_signature_newctx_fn *)
			sk_prov_get_default_sign_func(provctx, pkey_type,
					OSSL_FUNC_SIGNATURE_NEWCTX);
	if (default_newctx_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default newctx_fn");
		return NULL;
	}

	default_freectx_fn = (OSSL_FUNC_signature_freectx_fn *)
			sk_prov_get_default_sign_func(provctx, pkey_type,
					OSSL_FUNC_SIGNATURE_FREECTX);
	if (default_freectx_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default freectx_fn");
		return NULL;
	}

	ctx = sk_prov_op_newctx(provctx, propq, pkey_type);
	if (ctx == NULL) {
		sk_debug_ctx(provctx, "ERROR: sk_prov_op_newctx failed");
		return NULL;
	}

	ctx->default_op_ctx = default_newctx_fn(provctx->default_provctx,
						propq);
	if (ctx->default_op_ctx == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_newctx_fn failed");
		sk_prov_op_freectx(ctx);
		return NULL;
	}
	ctx->default_op_ctx_free = default_freectx_fn;

	sk_debug_ctx(provctx, "ctx: %p", ctx);
	return ctx;
}

static void *sk_prov_sign_op_dupctx(void *vctx)
{
	OSSL_FUNC_signature_dupctx_fn *default_dupctx_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_op_ctx *new_ctx;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	default_dupctx_fn = (OSSL_FUNC_signature_dupctx_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type, OSSL_FUNC_SIGNATURE_DUPCTX);
	if (default_dupctx_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default dupctx_fn");
		return NULL;
	}

	new_ctx = sk_prov_op_dupctx(ctx);
	if (new_ctx == NULL) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_dupctx failed");
		return NULL;
	}

	new_ctx->default_op_ctx = default_dupctx_fn(ctx->default_op_ctx);
	if (new_ctx->default_op_ctx == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_dupctx_fn failed");
		sk_prov_op_freectx(new_ctx);
		return NULL;
	}

	sk_debug_op_ctx(ctx, "new_ctx: %p", new_ctx);
	return new_ctx;
}

static int sk_prov_sign_op_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_signature_get_ctx_params_fn *default_get_params_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_get_params_fn = (OSSL_FUNC_signature_get_ctx_params_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS);

	/* default_get_params_fn is optional */
	if (default_get_params_fn != NULL) {
		if (!default_get_params_fn(ctx->default_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_get_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static int sk_prov_sign_op_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_set_ctx_params_fn *default_set_params_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
	/* OSSL_SIGNATURE_PARAM_NONCE_TYPE is used for EC sign ops only */
	if (!sk_prov_check_uint_param(params, OSSL_SIGNATURE_PARAM_NONCE_TYPE,
				      ctx->key, EVP_PKEY_EC, 0)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PARAM,
				 "Deterministic signature is not supported");
		return 0;
	}
#endif

	default_set_params_fn = (OSSL_FUNC_signature_set_ctx_params_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS);

	/* default_set_params_fn is optional */
	if (default_set_params_fn != NULL) {
		if (!default_set_params_fn(ctx->default_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_set_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM *sk_prov_sign_op_gettable_ctx_params(
				struct sk_prov_op_ctx *ctx,
				struct sk_prov_ctx *provctx, int pkey_type)
{
	OSSL_FUNC_signature_gettable_ctx_params_fn *default_gettable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL || provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "pkey_type: %d", pkey_type);

	default_gettable_params_fn =
		(OSSL_FUNC_signature_gettable_ctx_params_fn *)
			sk_prov_get_default_sign_func(provctx, pkey_type,
				OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS);

	/* default_gettable_params_fn is optional */
	if (default_gettable_params_fn != NULL)
		params = default_gettable_params_fn(ctx->default_op_ctx,
						    provctx->default_provctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_ctx(provctx, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM *sk_prov_sign_op_settable_ctx_params(
				struct sk_prov_op_ctx *ctx,
				struct sk_prov_ctx *provctx, int pkey_type)
{
	OSSL_FUNC_signature_settable_ctx_params_fn *default_settable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL || provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "pkey_type: %d", pkey_type);

	default_settable_params_fn =
		(OSSL_FUNC_signature_settable_ctx_params_fn *)
			sk_prov_get_default_sign_func(provctx, pkey_type,
				OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS);

	/* default_settable_params_fn is optional */
	if (default_settable_params_fn != NULL)
		params = default_settable_params_fn(ctx->default_op_ctx,
						    provctx->default_provctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_ctx(provctx, "param: %s", p->key);

	return params;
}

static int sk_prov_sign_op_get_ctx_md_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_signature_get_ctx_md_params_fn *default_get_md_params_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_get_md_params_fn = (OSSL_FUNC_signature_get_ctx_md_params_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type,
				OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS);

	/* default_get_md_params_fn is optional */
	if (default_get_md_params_fn != NULL) {
		if (!default_get_md_params_fn(ctx->default_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_get_md_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static int sk_prov_sign_op_set_ctx_md_params(void *vctx,
					     const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_set_ctx_md_params_fn *default_set_md_params_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_set_md_params_fn = (OSSL_FUNC_signature_set_ctx_md_params_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type,
				OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS);

	/* default_set_md_params_fn is optional */
	if (default_set_md_params_fn != NULL) {
		if (!default_set_md_params_fn(ctx->default_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_set_md_params_fn failed");
			return 0;
		}
	}

	/* Also set parameters in own MD context */
	if (ctx->mdctx)
		return EVP_MD_CTX_set_params(ctx->mdctx, params);

	return 1;
}

static const OSSL_PARAM *sk_prov_sign_op_gettable_ctx_md_params(
				struct sk_prov_op_ctx *ctx, int pkey_type)
{
	OSSL_FUNC_signature_gettable_ctx_md_params_fn
						*default_gettable_md_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "pkey_type: %d", pkey_type);

	default_gettable_md_params_fn =
		(OSSL_FUNC_signature_gettable_ctx_md_params_fn *)
			sk_prov_get_default_sign_func(ctx->provctx, pkey_type,
				OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS);

	/* default_gettable_params_fn is optional */
	if (default_gettable_md_params_fn != NULL)
		params = default_gettable_md_params_fn(ctx->default_op_ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM *sk_prov_sign_op_settable_ctx_md_params(
				struct sk_prov_op_ctx *ctx, int pkey_type)
{
	OSSL_FUNC_signature_settable_ctx_md_params_fn
						*default_settable_md_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "pkey_type: %d", pkey_type);

	default_settable_md_params_fn =
		(OSSL_FUNC_signature_settable_ctx_md_params_fn *)
			sk_prov_get_default_sign_func(ctx->provctx, pkey_type,
				OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS);

	/* default_settable_md_params_fn is optional */
	if (default_settable_md_params_fn != NULL)
		params = default_settable_md_params_fn(ctx->default_op_ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	return params;
}

static EVP_MD *sk_prov_sign_op_get_md(struct sk_prov_op_ctx *ctx)
{
	char mdprops[256], mdname[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
				&mdname, sizeof(mdname)),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES,
				&mdprops, sizeof(mdprops)),
		OSSL_PARAM_END
	};
	EVP_MD *md;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (!sk_prov_sign_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		sk_debug_op_ctx(ctx, "sk_prov_sign_op_get_ctx_params failed");
		if (ctx->md != NULL) {
			sk_debug_op_ctx(ctx, "use digest from context: %s",
					EVP_MD_name(ctx->md));
			EVP_MD_up_ref(ctx->md);
			return ctx->md;
		}

		sk_debug_op_ctx(ctx, "use default");
		strcpy(mdname, SK_PROV_RSA_DEFAULT_MD);
		strcpy(mdprops, "");
	}

	md = EVP_MD_fetch((OSSL_LIB_CTX *)ctx->provctx->c_get_libctx(
							ctx->provctx->handle),
			  mdname, mdprops[0] != '\0' ? mdprops : ctx->propq);
	if (md == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 mdprops[0] != '\0' ? mdprops :
					ctx->propq != NULL ? ctx->propq : "");
		return NULL;
	}

	sk_debug_op_ctx(ctx, "md: %s", EVP_MD_name(md));
	return md;
}

static EVP_MD *sk_prov_sign_op_get_mgf_md(struct sk_prov_op_ctx *ctx)
{
	char mdprops[256], mdname[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST,
				&mdname, sizeof(mdname)),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES,
				&mdprops, sizeof(mdprops)),
		OSSL_PARAM_END
	};
	EVP_MD *md;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (!sk_prov_sign_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		sk_debug_op_ctx(ctx, "sk_prov_sign_op_get_ctx_params failed, "
				"using signature digest");
		return sk_prov_sign_op_get_md(ctx);
	}

	md = EVP_MD_fetch((OSSL_LIB_CTX *)ctx->provctx->c_get_libctx(
							ctx->provctx->handle),
			  mdname, mdprops[0] != '\0' ? mdprops : ctx->propq);
	if (md == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 mdprops[0] != '\0' ? mdprops :
					ctx->propq != NULL ? ctx->propq : "");
		return NULL;
	}

	sk_debug_op_ctx(ctx, "md: %s", EVP_MD_name(md));
	return md;
}

static int sk_prov_sign_op_get_padding(struct sk_prov_op_ctx *ctx)
{
	char padding[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PAD_MODE,
				&padding, sizeof(padding)),
		OSSL_PARAM_END
	};

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (!sk_prov_sign_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0])) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "sk_prov_sign_op_get_ctx_params failed to "
				 "get OSSL_PKEY_PARAM_PAD_MODE");
		return -1;
	}

	sk_debug_op_ctx(ctx, "padding: %s", padding);
	return sk_prov_parse_padding(padding);
}

static int sk_prov_sign_op_get_pss_saltlen(struct sk_prov_op_ctx *ctx,
					   struct sk_prov_key *key,
					   EVP_MD *mgf_md)
{
	char saltlen[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
				&saltlen, sizeof(saltlen)),
		OSSL_PARAM_END
	};
	int salt_len, rsa_bits, max_saltlen;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	if (!sk_prov_sign_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0])) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "sk_prov_sign_op_get_ctx_params failed to "
				 "get OSSL_SIGNATURE_PARAM_PSS_SALTLEN");
		return -1;
	}

	sk_debug_op_ctx(ctx, "saltlen: %s", saltlen);

	rsa_bits = sk_prov_keymgmt_get_bits(key);
	if (rsa_bits <= 0) {
		sk_debug_op_ctx(ctx,
			"ERROR: sk_prov_keymgmt_get_bits failed");
		return -1;
	}

	max_saltlen = rsa_bits / 8 - EVP_MD_size(mgf_md) - 2;

	if (strcmp(saltlen, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
		salt_len = EVP_MD_size(mgf_md);
	else if (strcmp(saltlen, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
		salt_len = max_saltlen;
	else if (strcmp(saltlen, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
		salt_len = max_saltlen;
	else
		salt_len = atoi(saltlen);

	if (salt_len > max_saltlen || salt_len < 0) {
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_SALTLEN,
				 "invalid salt len: %d", saltlen);
		return -1;
	}

	sk_debug_op_ctx(ctx, "salt_len: %d", salt_len);
	return salt_len;
}

static int sk_prov_sign_op_sign_init(void *vctx, void *vkey,
				     const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_sign_init_fn *default_sign_init_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
	/* OSSL_SIGNATURE_PARAM_NONCE_TYPE is used for EC sign ops only */
	if (!sk_prov_check_uint_param(params, OSSL_SIGNATURE_PARAM_NONCE_TYPE,
				      key, EVP_PKEY_EC, 0)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PARAM,
				 "Deterministic signature is not supported");
		return 0;
	}
#endif

	default_sign_init_fn = (OSSL_FUNC_signature_sign_init_fn *)
				sk_prov_get_default_sign_func(ctx->provctx,
					ctx->type,
					OSSL_FUNC_SIGNATURE_SIGN_INIT);
	if (default_sign_init_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default sign_init_fn");
		return 0;
	}

	if (!sk_prov_op_init(ctx, key, EVP_PKEY_OP_SIGN)) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_init failed");
		return 0;
	}

	if (!default_sign_init_fn(ctx->default_op_ctx, key->default_key,
				  params)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_sign_init_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_sign_op_verify_init(void *vctx, void *vkey,
				       const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_verify_init_fn *default_verify_init_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_verify_init_fn = (OSSL_FUNC_signature_verify_init_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type, OSSL_FUNC_SIGNATURE_VERIFY_INIT);
	if (default_verify_init_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_init_fn");
		return 0;
	}

	if (!sk_prov_op_init(ctx, key, EVP_PKEY_OP_VERIFY)) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_init failed");
		return 0;
	}

	if (!default_verify_init_fn(ctx->default_op_ctx, key->default_key,
				    params)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_verify_init_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_sign_op_verify_recover_init(void *vctx, void *vkey,
					       const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_verify_recover_init_fn
					*default_verify_recover_init_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_verify_recover_init_fn =
		(OSSL_FUNC_signature_verify_recover_init_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type,
				OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT);
	if (default_verify_recover_init_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_recover_init_fn");
		return 0;
	}

	if (!sk_prov_op_init(ctx, key, EVP_PKEY_OP_VERIFYRECOVER)) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_init failed");
		return 0;
	}

	if (!default_verify_recover_init_fn(ctx->default_op_ctx,
					    key->default_key,
					    params)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_verify_recover_init_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_sign_op_sign(struct sk_prov_op_ctx *ctx,
				unsigned char *sig, size_t *siglen,
				size_t sigsize,
				const unsigned char *tbs, size_t tbslen)
{
	OSSL_FUNC_signature_sign_fn *default_sign_fn;

	if (ctx == NULL || tbs == NULL || siglen == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu sigsize: %lu",
			ctx, ctx->key, tbslen, sigsize);

	default_sign_fn = (OSSL_FUNC_signature_sign_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type, OSSL_FUNC_SIGNATURE_SIGN);
	if (default_sign_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default sign_fn");
		return 0;
	}

	if (!default_sign_fn(ctx->default_op_ctx, sig, siglen, sigsize,
			     tbs, tbslen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_sign_fn failed");
		return 0;
	}

	sk_debug_op_ctx(ctx, "siglen: %lu", *siglen);

	return 1;
}

static int sk_prov_sign_op_verify(void *vctx,
				  const unsigned char *sig, size_t siglen,
				  const unsigned char *tbs, size_t tbslen)
{
	OSSL_FUNC_signature_verify_fn *default_verify_fn;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL || tbs == NULL || sig == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu siglen: %lu",
			ctx, ctx->key, tbslen, siglen);

	default_verify_fn = (OSSL_FUNC_signature_verify_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type, OSSL_FUNC_SIGNATURE_VERIFY);
	if (default_verify_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_fn");
		return 0;
	}

	if (!default_verify_fn(ctx->default_op_ctx, sig, siglen, tbs, tbslen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_verify_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_sign_op_verify_recover(void *vctx,
					  unsigned char *rout, size_t *routlen,
					  size_t routsize,
					  const unsigned char *sig,
					  size_t siglen)
{
	OSSL_FUNC_signature_verify_recover_fn *default_verify_recover_fn;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL || routlen == NULL || sig == NULL)
		return 0;

	sk_debug_op_ctx(ctx,
			"ctx: %p key: %p routsize: %lu siglen: %lu",
			ctx, ctx->key, routsize, siglen);

	default_verify_recover_fn = (OSSL_FUNC_signature_verify_recover_fn *)
			sk_prov_get_default_sign_func(ctx->provctx,
				ctx->type, OSSL_FUNC_SIGNATURE_VERIFY_RECOVER);
	if (default_verify_recover_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_recover_fn");
		return 0;
	}

	if (!default_verify_recover_fn(ctx->default_op_ctx, rout, routlen,
				       routsize, sig, siglen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_verify_recover_fn failed");
		return 0;
	}

	sk_debug_op_ctx(ctx, "routlen: %lu", *routlen);

	return 1;
}

static int sk_prov_sign_op_digest_sign_init(struct sk_prov_op_ctx *ctx,
					    const char *mdname,
					    struct sk_prov_key *key,
					    const OSSL_PARAM params[],
					  OSSL_FUNC_signature_sign_fn *sign_fn)
{
	OSSL_FUNC_signature_digest_sign_init_fn *default_digest_sign_init_fn;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL || sign_fn == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p mdname: %s key: %p", ctx,
			mdname != NULL ? mdname : "", key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
	/* OSSL_SIGNATURE_PARAM_NONCE_TYPE is used for EC sign ops only */
	if (!sk_prov_check_uint_param(params, OSSL_SIGNATURE_PARAM_NONCE_TYPE,
				      key, EVP_PKEY_EC, 0)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PARAM,
				 "Deterministic signature is not supported");
		return 0;
	}
#endif

	default_digest_sign_init_fn =
			(OSSL_FUNC_signature_digest_sign_init_fn *)
				sk_prov_get_default_sign_func(ctx->provctx,
					ctx->type,
					OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT);
	if (default_digest_sign_init_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_init_fn");
		return 0;
	}

	if (!sk_prov_op_init(ctx, key, EVP_PKEY_OP_SIGN)) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_init failed");
		return 0;
	}

	if (!default_digest_sign_init_fn(ctx->default_op_ctx, mdname,
					 key->default_key, params)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_sign_init_fn failed");
		return 0;
	}

	/* For clear key, the default provider has already handled it */
	if (ctx->key->secure_key == NULL)
		return 1;

	ctx->sign_fn = sign_fn;

	if (ctx->mdctx != NULL)
		EVP_MD_CTX_free(ctx->mdctx);
	ctx->mdctx = EVP_MD_CTX_new();
	if (ctx->mdctx == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MALLOC_FAILED,
				 "EVP_MD_CTX_new failed");
		return 0;
	}

	if (ctx->md != NULL)
		EVP_MD_free(ctx->md);
	if (mdname != NULL)
		ctx->md = EVP_MD_fetch(
				(OSSL_LIB_CTX *)ctx->provctx->c_get_libctx(
							ctx->provctx->handle),
				mdname, ctx->propq);
	else
		ctx->md = sk_prov_sign_op_get_md(ctx);
	if (ctx->md == NULL) {
		sk_debug_op_ctx(ctx, "ERROR: Failed to get digest sign digest");
		EVP_MD_CTX_free(ctx->mdctx);
		ctx->mdctx = NULL;
		return 0;
	}

	return EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params);
}

static int sk_prov_sign_op_digest_sign_update(void *vctx,
					      const unsigned char *data,
					      size_t datalen)
{
	OSSL_FUNC_signature_digest_sign_update_fn
					*default_digest_sign_update_fn;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p datalen: %lu", ctx, ctx->key,
			datalen);

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_SIGN) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return 0;
	}

	/* For secure key, don't pass it to the default provider */
	if (ctx->key->secure_key != NULL)
		goto secure_key;

	default_digest_sign_update_fn =
			(OSSL_FUNC_signature_digest_sign_update_fn *)
				sk_prov_get_default_sign_func(ctx->provctx,
					ctx->type,
					OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE);
	if (default_digest_sign_update_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_update_fn");
		return 0;
	}

	if (!default_digest_sign_update_fn(ctx->default_op_ctx, data,
					   datalen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_sign_update_fn failed");
		return 0;
	}

	return 1;

secure_key:
	if (ctx->mdctx == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return 0;
	}

	return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static int sk_prov_sign_op_digest_sign_final(void *vctx,
					     unsigned char *sig,
					     size_t *siglen, size_t sigsize)
{
	OSSL_FUNC_signature_digest_sign_final_fn *default_digest_sign_final_fn;
	unsigned char digest[EVP_MAX_MD_SIZE];
	struct sk_prov_op_ctx *ctx = vctx;
	unsigned int dlen = 0;

	if (ctx == NULL || siglen == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p sigsize: %lu", ctx, ctx->key,
			sigsize);

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_SIGN) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return 0;
	}

	/* For secure key, don't pass it to the default provider */
	if (ctx->key->secure_key != NULL)
		goto secure_key;

	default_digest_sign_final_fn =
			(OSSL_FUNC_signature_digest_sign_final_fn *)
				sk_prov_get_default_sign_func(ctx->provctx,
					ctx->type,
					OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL);
	if (default_digest_sign_final_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_final_fn");
		return 0;
	}

	if (!default_digest_sign_final_fn(ctx->default_op_ctx, sig, siglen,
					  sigsize)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_sign_final_fn failed");
		return 0;
	}

	sk_debug_op_ctx(ctx, "siglen: %lu", *siglen);
	return 1;

secure_key:
	if (ctx->mdctx == NULL || ctx->sign_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return 0;
	}

	if (sig != NULL) {
		if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen)) {
			sk_debug_op_ctx(ctx,
					"ERROR: EVP_DigestFinal_ex failed");
			return 0;
		}
	}

	if (!ctx->sign_fn(ctx, sig, siglen, sigsize, digest, (size_t)dlen)) {
		sk_debug_op_ctx(ctx, "ERROR: sign_fn failed");
		return 0;
	}

	sk_debug_op_ctx(ctx, "siglen: %lu", *siglen);
	return 1;
}

static int sk_prov_sign_op_digest_verify_init(void *vctx,
					      const char *mdname,
					      void *vkey,
					      const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_digest_verify_init_fn
					*default_digest_verify_init_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p mdname: %s key: %p", ctx,
			mdname != NULL ? mdname : "", key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_digest_verify_init_fn =
			(OSSL_FUNC_signature_digest_verify_init_fn *)
				sk_prov_get_default_sign_func(ctx->provctx,
					ctx->type,
					OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT);
	if (default_digest_verify_init_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_verify_init_fn");
		return 0;
	}

	if (!sk_prov_op_init(ctx, key, EVP_PKEY_OP_VERIFY)) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_init failed");
		return 0;
	}

	if (!default_digest_verify_init_fn(ctx->default_op_ctx, mdname,
					 key->default_key, params)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_verify_init_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_sign_op_digest_verify_update(void *vctx,
						const unsigned char *data,
						size_t datalen)
{
	OSSL_FUNC_signature_digest_verify_update_fn
					*default_digest_verify_update_fn;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p datalen: %lu", ctx, ctx->key,
			datalen);

	default_digest_verify_update_fn =
		(OSSL_FUNC_signature_digest_verify_update_fn *)
			sk_prov_get_default_sign_func(ctx->provctx, ctx->type,
				OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE);
	if (default_digest_verify_update_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_verify_update_fn");
		return 0;
	}

	if (!default_digest_verify_update_fn(ctx->default_op_ctx,
					     data, datalen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_verify_update_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_sign_op_digest_verify_final(void *vctx,
					       const unsigned char *sig,
					       size_t siglen)
{
	OSSL_FUNC_signature_digest_verify_final_fn
					*default_digest_verify_final_fn;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL || sig == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p siglen: %lu", ctx, ctx->key,
			siglen);

	default_digest_verify_final_fn =
		(OSSL_FUNC_signature_digest_verify_final_fn *)
			sk_prov_get_default_sign_func(ctx->provctx, ctx->type,
				OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL);
	if (default_digest_verify_final_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_verify_final_fn");
		return 0;
	}

	if (!default_digest_verify_final_fn(ctx->default_op_ctx, sig, siglen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_verify_final_fn failed");
		return 0;
	}

	return 1;
}


static void sk_prov_keymgmt_upref(struct sk_prov_key *key)
{
	sk_debug_key(key, "key: %p", key);

	key->ref_count++;

	sk_debug_key(key, "ref_count: %u", key->ref_count);
}

static unsigned int sk_prov_keymgmt_downref(struct sk_prov_key *key)
{
	sk_debug_key(key, "key: %p ", key);

	if (key->ref_count > 0)
		key->ref_count--;

	sk_debug_key(key, "ref_count: %u", key->ref_count);

	return key->ref_count;
}

static struct sk_prov_key *sk_prov_keymgmt_new(struct sk_prov_ctx *provctx,
					       int type)
{
	OSSL_FUNC_keymgmt_new_fn *default_new_fn;
	struct sk_prov_key *key;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p type: %d", provctx,
		     type);

	default_new_fn = (OSSL_FUNC_keymgmt_new_fn *)
			sk_prov_get_default_keymgmt_func(provctx, type,
						OSSL_FUNC_KEYMGMT_NEW);
	if (default_new_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default new_fn");
		return NULL;
	}

	key = OPENSSL_zalloc(sizeof(struct sk_prov_key));
	if (key == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_MALLOC_FAILED,
			      "OPENSSL_zalloc failed");
		return NULL;
	}

	key->provctx = provctx;
	key->type = type;

	key->default_key = default_new_fn(provctx->default_provctx);
	if (key->default_key == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_new_fn failed");
		OPENSSL_free(key);
		return NULL;
	}

	sk_prov_keymgmt_upref(key);

	sk_debug_ctx(provctx, "key: %p", key);

	return key;
}

static void sk_prov_keymgmt_free(void *vkey)
{
	OSSL_FUNC_keymgmt_free_fn *default_free_fn;
	struct sk_prov_key *key = vkey;

	if (key == NULL)
		return;

	sk_debug_key(key, "key: %p", key);

	if (sk_prov_keymgmt_downref(key) > 0)
		return;

	sk_debug_key(key, "free key: %p", key);

	default_free_fn = (OSSL_FUNC_keymgmt_free_fn *)
			sk_prov_get_default_keymgmt_func(key->provctx,
					key->type, OSSL_FUNC_KEYMGMT_FREE);
	if (default_free_fn == NULL)
		sk_debug_key(key, "no default free_fn");
	else
		default_free_fn(key->default_key);

	if (key->secure_key != NULL)
		OPENSSL_free(key->secure_key);
	OPENSSL_free(key);
}

static int sk_prov_keymgmt_match(const void *vkey1, const void *vkey2,
				 int selection)
{
	OSSL_FUNC_keymgmt_match_fn *default_match_fn;
	const struct sk_prov_key *key1 = vkey1;
	const struct sk_prov_key *key2 = vkey2;

	if (key1 == NULL || key2 == NULL)
		return 0;

	sk_debug_key(key1, "key1: %p key2: %p", key1, key2);

	default_match_fn = (OSSL_FUNC_keymgmt_match_fn *)
			sk_prov_get_default_keymgmt_func(key1->provctx,
					key1->type, OSSL_FUNC_KEYMGMT_MATCH);
	if (default_match_fn == NULL) {
		put_error_key(key1, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default match_fn");
		return 0;
	}

	if (key1->type != key2->type)
		return 0;

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		/* match everything except private key */
		return default_match_fn(key1->default_key, key2->default_key,
					selection &
					    (~OSSL_KEYMGMT_SELECT_PRIVATE_KEY));
	}

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (key1->secure_key_size != key2->secure_key_size)
			return 0;
		if (key1->secure_key_size > 0) {
			if (memcmp(key1->secure_key, key2->secure_key,
				   key1->secure_key_size) != 0)
				return 0;
			selection &= (~OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
		}
	}

	return default_match_fn(key1->default_key, key2->default_key,
				selection);
}

static int sk_prov_keymgmt_validate(const void *vkey,
				    int selection, int checktype)
{
	OSSL_FUNC_keymgmt_validate_fn *default_validate_fn;
	const struct sk_prov_key *key = vkey;
	int default_selection = selection;

	if (key == NULL)
		return 0;

	sk_debug_key(key, "key: %p selection: %x checktype: %x", key,
		     selection, checktype);

	default_validate_fn = (OSSL_FUNC_keymgmt_validate_fn *)
			sk_prov_get_default_keymgmt_func(key->provctx,
					key->type, OSSL_FUNC_KEYMGMT_VALIDATE);
	if (default_validate_fn == NULL) {
		put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default validate_fn");
		return 0;
	}

	/* A secure key doesn't have the private parts in the default key */
	if (key->secure_key != NULL)
		default_selection &= (~OSSL_KEYMGMT_SELECT_PRIVATE_KEY);

	return default_validate_fn(key->default_key, default_selection,
				   checktype);
}

static int sk_prov_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_get_params_fn *default_get_params_fn;
	struct sk_prov_key *key = vkey;
	OSSL_PARAM *p;

	if (key == NULL)
		return 0;

	sk_debug_key(key, "key: %p", key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_key(key, "param: %s", p->key);

	default_get_params_fn = (OSSL_FUNC_keymgmt_get_params_fn *)
			sk_prov_get_default_keymgmt_func(key->provctx,
				key->type, OSSL_FUNC_KEYMGMT_GET_PARAMS);

	/* default_get_params_fn is optional */
	if (default_get_params_fn != NULL) {
		if (!default_get_params_fn(key->default_key, params)) {
			put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				      "default_get_params_fn failed");
			return 0;
		}
	}

	if (key->secure_key == NULL)
		return 1;

	p = OSSL_PARAM_locate(params, SK_PROV_PKEY_PARAM_SK_BLOB);
	if (p != NULL && !OSSL_PARAM_set_octet_string(p, key->secure_key,
						      key->secure_key_size)) {
		put_error_key(key, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_octet_string failed");
		return 0;
	}
	p = OSSL_PARAM_locate(params, SK_PROV_PKEY_PARAM_SK_FUNCS);
	if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, key->funcs,
						   sizeof(struct sk_funcs))) {
		put_error_key(key, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_octet_ptr failed");
		return 0;
	}
	p = OSSL_PARAM_locate(params, SK_PROV_PKEY_PARAM_SK_PRIVATE);
	if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, key->private, 0)) {
		put_error_key(key, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_octet_ptr failed");
		return 0;
	}

	return 1;
}


static int sk_prov_keymgmt_set_params(void *vkey, const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_set_params_fn *default_set_params_fn;
	struct sk_prov_key *key = vkey;
	const OSSL_PARAM *p;
	size_t len;

	if (key == NULL)
		return 0;

	sk_debug_key(key, "key: %p", key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_key(key, "param: %s",  p->key);

	default_set_params_fn = (OSSL_FUNC_keymgmt_set_params_fn *)
			sk_prov_get_default_keymgmt_func(key->provctx,
				key->type, OSSL_FUNC_KEYMGMT_SET_PARAMS);

	/* default_set_params_fn is optional */
	if (default_set_params_fn != NULL) {
		if (!default_set_params_fn(key->default_key, params)) {
			put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				      "default_set_params_fn failed");
			return 0;
		}
	}

	if (key->secure_key == NULL)
		return 1;

	p = OSSL_PARAM_locate_const(params, SK_PROV_PKEY_PARAM_SK_FUNCS);
	if (p != NULL && !OSSL_PARAM_get_octet_string_ptr(p,
				(const void **)&key->funcs, &len)) {
		put_error_key(key, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_get_octet_string_ptr failed");
		return 0;
	}

	p = OSSL_PARAM_locate_const(params, SK_PROV_PKEY_PARAM_SK_PRIVATE);
	if (p != NULL && !OSSL_PARAM_get_octet_string_ptr(p,
				(const void **)&key->private, &len)) {
		put_error_key(key, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_get_octet_string_ptr failed");
		return 0;
	}

	return 1;
}

#define SK_PROV_SECURE_KEY_FUNC_PARMS					\
	OSSL_PARAM_octet_ptr(SK_PROV_PKEY_PARAM_SK_FUNCS, NULL, 0),	\
	OSSL_PARAM_octet_ptr(SK_PROV_PKEY_PARAM_SK_PRIVATE, NULL, 0)

#define SK_PROV_SECURE_KEY_PARMS					\
	OSSL_PARAM_octet_string(SK_PROV_PKEY_PARAM_SK_BLOB, NULL, 0),	\
	SK_PROV_SECURE_KEY_FUNC_PARMS


static const OSSL_PARAM sk_prov_key_settable_params[] = {
	SK_PROV_SECURE_KEY_FUNC_PARMS,
	OSSL_PARAM_END
};

static const OSSL_PARAM sk_prov_key_gettable_params[] = {
	SK_PROV_SECURE_KEY_PARMS,
	OSSL_PARAM_END
};

static const OSSL_PARAM *sk_prov_keymgmt_gettable_params(
				struct sk_prov_ctx *provctx, int pkey_type)
{
	OSSL_FUNC_keymgmt_gettable_params_fn *default_gettable_params_fn;
	const OSSL_PARAM *default_parms = NULL, *params, *p;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "pkey_type: %d", pkey_type);

	params = sk_prov_get_cached_params(provctx, pkey_type,
					   SK_CONF_CACHED_PARAMS_OP_KEY_GET, 0);
	if (params != NULL) {
		for (p = params; p != NULL && p->key != NULL; p++)
			sk_debug_ctx(provctx, "param: %s", p->key);
		return params;
	}

	default_gettable_params_fn = (OSSL_FUNC_keymgmt_gettable_params_fn *)
			sk_prov_get_default_keymgmt_func(provctx, pkey_type,
					OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS);

	/* default_gettable_params_fn is optional */
	if (default_gettable_params_fn != NULL)
		default_parms =
			default_gettable_params_fn(provctx->default_provctx);

	return sk_prov_cached_params_build(provctx, pkey_type,
					   SK_CONF_CACHED_PARAMS_OP_KEY_GET, 0,
					   default_parms,
					   sk_prov_key_gettable_params);
}

static const OSSL_PARAM *sk_prov_keymgmt_settable_params(
				struct sk_prov_ctx *provctx, int pkey_type)
{
	OSSL_FUNC_keymgmt_settable_params_fn *default_settable_params_fn;
	const OSSL_PARAM *default_parms = NULL, *params, *p;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "pkey_type: %d", pkey_type);

	params = sk_prov_get_cached_params(provctx, pkey_type,
					   SK_CONF_CACHED_PARAMS_OP_KEY_SET, 0);
	if (params != NULL) {
		for (p = params; p != NULL && p->key != NULL; p++)
			sk_debug_ctx(provctx, "param: %s", p->key);
		return params;
	}

	default_settable_params_fn = (OSSL_FUNC_keymgmt_settable_params_fn *)
			sk_prov_get_default_keymgmt_func(provctx, pkey_type,
					OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS);

	/* default_settable_params_fn is optional */
	if (default_settable_params_fn != NULL)
		default_parms =
			default_settable_params_fn(provctx->default_provctx);

	return sk_prov_cached_params_build(provctx, pkey_type,
					   SK_CONF_CACHED_PARAMS_OP_KEY_SET, 0,
					   default_parms,
					   sk_prov_key_settable_params);
}

static int sk_prov_keymgmt_has(const void *vkey, int selection)
{
	OSSL_FUNC_keymgmt_has_fn *default_has_fn;
	const struct sk_prov_key *key = vkey;
	int default_selection = selection;

	if (key == NULL)
		return 0;

	sk_debug_key(key, "key: %p selection: %x", key,
		     selection);

	default_has_fn = (OSSL_FUNC_keymgmt_has_fn *)
			sk_prov_get_default_keymgmt_func(key->provctx,
					key->type, OSSL_FUNC_KEYMGMT_HAS);
	if (default_has_fn == NULL) {
		put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default has_fn");
		return 0;
	}

	/* A secure key doesn't have the private parts in the default key */
	if (key->secure_key != NULL)
		default_selection &= (~OSSL_KEYMGMT_SELECT_PRIVATE_KEY);

	return default_has_fn(key->default_key, default_selection);
}

struct sk_prov_export_cb {
	struct sk_prov_key *key;
	OSSL_CALLBACK *param_callback;
	void *cbarg;
};

static int sk_prov_keymgmt_export_cb(const OSSL_PARAM params[], void *arg)
{
	struct sk_prov_export_cb *cb_data = arg;
	OSSL_PARAM *np, *new_params;
	struct sk_prov_key *key;
	const OSSL_PARAM *p;
	int rc, count, i;

	if (cb_data == NULL)
		return 0;

	key = cb_data->key;

	sk_debug_key(key, "key: %p", key);

	for (count = 0, p = params; p != NULL && p->key != NULL; p++, count++)
		;
	count += 3 + 1; /* 3 addl params plus end marker */

	new_params = OPENSSL_zalloc(count * sizeof(OSSL_PARAM));
	if (new_params == NULL) {
		put_error_key(key, SK_PROV_ERR_MALLOC_FAILED,
			      "OPENSSL_zalloc failed");
		return 0;
	}

	for (i = 0, p = params; p != NULL && p->key != NULL; p++, i++) {
		sk_debug_key(key, "param: key: %s", p->key);
		new_params[i] = *p;
	}

	np = &new_params[i++];
	*np = OSSL_PARAM_construct_octet_string(SK_PROV_PKEY_PARAM_SK_BLOB,
						key->secure_key,
						key->secure_key_size);
	sk_debug_key(key, "param: key: %s", np->key);

	np = &new_params[i++];
	*np = OSSL_PARAM_construct_octet_ptr(SK_PROV_PKEY_PARAM_SK_FUNCS,
					     (void **)key->funcs,
					     sizeof(struct sk_funcs));
	sk_debug_key(key, "param: key: %s", np->key);

	np = &new_params[i++];
	*np = OSSL_PARAM_construct_octet_ptr(SK_PROV_PKEY_PARAM_SK_PRIVATE,
					     key->private, 0);
	sk_debug_key(key, "param: key: %s", np->key);

	np = &new_params[i++];
	*np = OSSL_PARAM_construct_end();

	rc = cb_data->param_callback(new_params, cb_data->cbarg);
	if (rc != 1)
		sk_debug_key(key, "ERROR: param_callback failed");

	OPENSSL_free(new_params);

	return rc;
}

static int sk_prov_keymgmt_export(void *vkey, int selection,
				  OSSL_CALLBACK *param_callback, void *cbarg)
{
	OSSL_FUNC_keymgmt_export_fn *default_export_fn;
	struct sk_prov_export_cb cb_data;
	struct sk_prov_key *key = vkey;

	if (key == NULL || param_callback == NULL)
		return 0;

	sk_debug_key(key, "key: %p selection: %x", key, selection);

	default_export_fn = (OSSL_FUNC_keymgmt_export_fn *)
			sk_prov_get_default_keymgmt_func(key->provctx,
					key->type, OSSL_FUNC_KEYMGMT_EXPORT);
	if (default_export_fn == NULL) {
		put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default export_fn");
		return 0;
	}

	if (key->secure_key == NULL ||
	    (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) {
		/*
		 * Clear key, or no private key selected, call default_export_fn
		 *  with original callback
		 */
		if (!default_export_fn(key->default_key, selection,
				       param_callback, cbarg)) {
			put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				      "default_export_fn failed");
			return 0;
		}
		return 1;
	}

	/* Let the callback add our 3 addl. params */
	cb_data.key = key;
	cb_data.param_callback = param_callback;
	cb_data.cbarg = cbarg;
	if (!default_export_fn(key->default_key, selection,
			       sk_prov_keymgmt_export_cb, &cb_data)) {
		put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_export_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_keymgmt_import(void *vkey, int selection,
				  const OSSL_PARAM params[])
{
	const OSSL_PARAM *p_blob, *p_funcs, *p_private, *p;
	OSSL_FUNC_keymgmt_import_fn *default_import_fn;
	struct sk_prov_key *key = vkey;
	size_t len;

	if (key == NULL)
		return 0;

	sk_debug_key(key, "key: %p selection: %x", key,
		     selection);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_key(key, "param: %s", p->key);

	default_import_fn = (OSSL_FUNC_keymgmt_import_fn *)
			sk_prov_get_default_keymgmt_func(key->provctx,
					key->type, OSSL_FUNC_KEYMGMT_IMPORT);
	if (default_import_fn == NULL) {
		put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default import_fn");
		return 0;
	}

	if (!default_import_fn(key->default_key, selection, params)) {
		put_error_key(key, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_import_fn failed");
		return 0;
	}

	if (key->secure_key != NULL)
		OPENSSL_free(key->secure_key);
	key->secure_key = NULL;
	key->secure_key_size = 0;
	key->funcs = NULL;
	key->private = NULL;

	p_blob = OSSL_PARAM_locate_const(params, SK_PROV_PKEY_PARAM_SK_BLOB);
	p_funcs = OSSL_PARAM_locate_const(params, SK_PROV_PKEY_PARAM_SK_FUNCS);
	p_private = OSSL_PARAM_locate_const(params,
					    SK_PROV_PKEY_PARAM_SK_PRIVATE);

	if (p_blob != NULL && p_funcs != NULL && p_private != NULL) {
		if (!OSSL_PARAM_get_octet_string(p_blob,
						 (void **)&key->secure_key, 0,
						 &key->secure_key_size)) {
			put_error_key(key, SK_PROV_ERR_INTERNAL_ERROR,
				      "OSSL_PARAM_get_octet_string failed");
			return 0;
		}

		if (!OSSL_PARAM_get_octet_string_ptr(p_funcs,
					(const void **)&key->funcs, &len)) {
			put_error_key(key, SK_PROV_ERR_INTERNAL_ERROR,
				      "OSSL_PARAM_get_octet_string_ptr failed");
			return 0;
		}

		if (!OSSL_PARAM_get_octet_string_ptr(p_private,
				(const void **)&key->private, &len)) {
			put_error_key(key, SK_PROV_ERR_INTERNAL_ERROR,
				      "OSSL_PARAM_get_octet_string_ptr failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM sk_prov_imexport_types[] = {
	SK_PROV_SECURE_KEY_PARMS,
	OSSL_PARAM_END
};

static const OSSL_PARAM *sk_prov_keymgmt_export_types(int selection,
						      int pkey_type)
{
	OSSL_FUNC_keymgmt_export_types_fn *default_export_types_fn;
	const OSSL_PARAM *default_parms = NULL, *params;
	struct sk_prov_ctx *provctx;

	provctx = OSSL_PROVIDER_get0_provider_ctx(sk_prov_securekey_provider);
	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "selection: %d pkey_type: %d", selection,
		     pkey_type);

	params = sk_prov_get_cached_params(provctx, pkey_type,
					   SK_CONF_CACHED_PARAMS_OP_KEY_EXPORT,
					   selection);
	if (params != NULL)
		return params;

	default_export_types_fn = (OSSL_FUNC_keymgmt_export_types_fn *)
			sk_prov_get_default_keymgmt_func(provctx, pkey_type,
					OSSL_FUNC_KEYMGMT_EXPORT_TYPES);

	/* default_export_types_fn is optional */
	if (default_export_types_fn != NULL)
		default_parms = default_export_types_fn(selection);

	return sk_prov_cached_params_build(provctx, pkey_type,
					   SK_CONF_CACHED_PARAMS_OP_KEY_EXPORT,
					   selection,
					   default_parms,
					   sk_prov_imexport_types);
}

static const OSSL_PARAM *sk_prov_keymgmt_import_types(int selection,
						      int pkey_type)
{
	OSSL_FUNC_keymgmt_import_types_fn *default_import_types_fn;
	const OSSL_PARAM *default_parms = NULL, *params;
	struct sk_prov_ctx *provctx;

	provctx = OSSL_PROVIDER_get0_provider_ctx(sk_prov_securekey_provider);
	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "selection: %d pkey_type: %d", selection,
		     pkey_type);

	params = sk_prov_get_cached_params(provctx, pkey_type,
					   SK_CONF_CACHED_PARAMS_OP_KEY_IMPORT,
					   selection);
	if (params != NULL)
		return params;

	default_import_types_fn = (OSSL_FUNC_keymgmt_import_types_fn *)
			sk_prov_get_default_keymgmt_func(provctx, pkey_type,
					OSSL_FUNC_KEYMGMT_EXPORT_TYPES);

	/* default_import_types_fn is optional */
	if (default_import_types_fn != NULL)
		default_parms = default_import_types_fn(selection);

	return sk_prov_cached_params_build(provctx, pkey_type,
					   SK_CONF_CACHED_PARAMS_OP_KEY_IMPORT,
					   selection,
					   default_parms,
					   sk_prov_imexport_types);
}

static struct sk_prov_op_ctx *sk_prov_keymgmt_gen_init(
				struct sk_prov_ctx *provctx, int selection,
				const OSSL_PARAM params[], int pkey_type)
{
	OSSL_FUNC_keymgmt_gen_cleanup_fn *default_gen_cleanup_fn;
	OSSL_FUNC_keymgmt_gen_init_fn *default_gen_init_fn;
	struct sk_prov_op_ctx *genctx;
	const OSSL_PARAM *p;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "selection: %x type: %d", selection, pkey_type);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_ctx(provctx, "param: %s", p->key);

	default_gen_init_fn = (OSSL_FUNC_keymgmt_gen_init_fn *)
			sk_prov_get_default_keymgmt_func(provctx, pkey_type,
					OSSL_FUNC_KEYMGMT_GEN_INIT);
	if (default_gen_init_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default gen_init_fn");
		return NULL;
	}

	default_gen_cleanup_fn = (OSSL_FUNC_keymgmt_gen_cleanup_fn *)
			sk_prov_get_default_keymgmt_func(provctx, pkey_type,
					OSSL_FUNC_KEYMGMT_GEN_CLEANUP);
	if (default_gen_cleanup_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default gen_cleanup_fn");
		return NULL;
	}

	genctx = sk_prov_op_newctx(provctx, NULL, pkey_type);
	if (genctx == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_INTERNAL_ERROR,
			      "sk_prov_op_newctx failed");
		return NULL;
	}

	if (!sk_prov_op_init(genctx, NULL, EVP_PKEY_OP_KEYGEN)) {
		put_error_ctx(provctx, SK_PROV_ERR_INTERNAL_ERROR,
			      "sk_prov_op_init failed");
		sk_prov_op_freectx(genctx);
		return NULL;
	}

	genctx->default_op_ctx = default_gen_init_fn(provctx->default_provctx,
						     selection, params);
	if (genctx->default_op_ctx == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_gen_init_fn failed");
		sk_prov_op_freectx(genctx);
		return NULL;
	}
	genctx->default_op_ctx_free = default_gen_cleanup_fn;

	sk_debug_ctx(provctx, "genctx: %p", genctx);
	return genctx;
}

static void sk_prov_keymgmt_gen_cleanup(void *vgenctx)
{
	struct sk_prov_op_ctx *genctx = vgenctx;

	if (genctx == NULL)
		return;

	sk_debug_op_ctx(genctx, "genctx: %p", genctx);
	sk_prov_op_freectx(genctx);
}

static int sk_prov_keymgmt_gen_set_params(void *vgenctx,
					  const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_gen_set_params_fn *default_gen_set_params_fn;
	struct sk_prov_op_ctx *genctx = vgenctx;
	const OSSL_PARAM *p;

	if (genctx == NULL)
		return 0;

	sk_debug_op_ctx(genctx, "genctx: %p", genctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(genctx, "param: %s", p->key);

	default_gen_set_params_fn = (OSSL_FUNC_keymgmt_gen_set_params_fn *)
			sk_prov_get_default_keymgmt_func(genctx->provctx,
				genctx->type, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS);

	/* default_gen_set_params_fn is optional */
	if (default_gen_set_params_fn != NULL) {
		if (!default_gen_set_params_fn(genctx->default_op_ctx,
					       params)) {
			put_error_op_ctx(genctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_gen_set_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM *sk_prov_keymgmt_gen_settable_params(
					struct sk_prov_op_ctx *genctx,
					struct sk_prov_ctx *provctx,
					int pkey_type)
{
	OSSL_FUNC_keymgmt_gen_settable_params_fn
						*default_gen_settable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "pkey_type: %d", pkey_type);

	default_gen_settable_params_fn =
		(OSSL_FUNC_keymgmt_gen_settable_params_fn *)
			sk_prov_get_default_keymgmt_func(provctx,
				pkey_type,
				OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS);

	/* default_gen_settable_params_fn is optional */
	if (default_gen_settable_params_fn != NULL)
		params = default_gen_settable_params_fn(genctx->default_op_ctx,
						   provctx->default_provctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_ctx(provctx, "param: %s", p->key);

	return params;
}

static int sk_prov_keymgmt_gen_set_template(void *vgenctx, void *vtempl)
{
	OSSL_FUNC_keymgmt_gen_set_template_fn *default_gen_set_template_fn;
	struct sk_prov_op_ctx *genctx = vgenctx;
	struct sk_prov_key *templ = vtempl;

	if (genctx == NULL || templ == NULL)
		return 0;

	sk_debug_op_ctx(genctx, "genctx: %p templ: %p", genctx, templ);

	default_gen_set_template_fn = (OSSL_FUNC_keymgmt_gen_set_template_fn *)
			sk_prov_get_default_keymgmt_func(genctx->provctx,
					genctx->type,
					OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE);

	if (default_gen_set_template_fn == NULL) {
		put_error_op_ctx(genctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default get_set_template_fn");
		return 0;
	}

	return default_gen_set_template_fn(genctx->default_op_ctx,
					   templ->default_key);
}

static void *sk_prov_keymgmt_gen(void *vgenctx,
				 OSSL_CALLBACK *osslcb, void *cbarg)
{
	OSSL_FUNC_keymgmt_gen_fn *default_gen_fn;
	struct sk_prov_op_ctx *genctx = vgenctx;
	struct sk_prov_key *key;

	if (genctx == NULL)
		return NULL;

	sk_debug_op_ctx(genctx, "genctx: %p", genctx);

	default_gen_fn = (OSSL_FUNC_keymgmt_gen_fn *)
			sk_prov_get_default_keymgmt_func(genctx->provctx,
					genctx->type, OSSL_FUNC_KEYMGMT_GEN);

	if (default_gen_fn == NULL) {
		put_error_op_ctx(genctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default gen_fn");
		return NULL;
	}

	key = OPENSSL_zalloc(sizeof(struct sk_prov_key));
	if (key == NULL) {
		put_error_op_ctx(genctx, SK_PROV_ERR_MALLOC_FAILED,
				 "OPENSSL_zalloc failed");
		return NULL;
	}

	key->provctx = genctx->provctx;
	key->type = genctx->type;

	key->default_key = default_gen_fn(genctx->default_op_ctx,
					  osslcb, cbarg);
	if (key->default_key == NULL) {
		put_error_op_ctx(genctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_gen_fn failed");
		OPENSSL_free(key);
		return NULL;
	}

	sk_prov_keymgmt_upref(key);

	sk_debug_op_ctx(genctx, "key: %p", key);

	return key;
}

static void *sk_prov_keymgmt_load(const void *reference, size_t reference_sz)
{
	struct sk_prov_key *key;

	if (reference == NULL)
		return NULL;

	if (reference_sz == sizeof(struct sk_prov_key)) {
		/* The contents of the reference is the address to our object */
		key = *(struct sk_prov_key **)reference;

		/* We grabbed, so we detach it */
		*(struct sk_prov_key **)reference = NULL;
		return key;
	}

	return NULL;
}

static int sk_prov_keymgmt_get_size(struct sk_prov_key *key)
{
	int size = 0;
	OSSL_PARAM key_params[] = {
		OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, &size),
		OSSL_PARAM_END
	};

	sk_debug_key(key, "key: %p", key);

	if (!sk_prov_keymgmt_get_params(key, key_params) ||
	    !OSSL_PARAM_modified(&key_params[0]) ||
	    size <= 0) {
		put_error_key(key, SK_PROV_ERR_MISSING_PARAMETER,
				 "sk_prov_keymgmt_get_params failed to "
				 "get OSSL_PKEY_PARAM_MAX_SIZE");
		return -1;
	}

	sk_debug_key(key, "size: %d", size);
	return size;
}

static int sk_prov_keymgmt_get_bits(struct sk_prov_key *key)
{
	int bits = 0;
	OSSL_PARAM key_params[] = {
		OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, &bits),
		OSSL_PARAM_END
	};

	sk_debug_key(key, "key: %p", key);

	if (!sk_prov_keymgmt_get_params(key, key_params) ||
	    !OSSL_PARAM_modified(&key_params[0]) ||
	    bits <= 0) {
		put_error_key(key, SK_PROV_ERR_MISSING_PARAMETER,
				 "sk_prov_keymgmt_get_params failed to "
				 "get OSSL_PKEY_PARAM_BITS");
		return -1;
	}

	sk_debug_key(key, "bits: %d", bits);
	return bits;
}

static void *sk_prov_keymgmt_rsa_new(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);

	return sk_prov_keymgmt_new(provctx, EVP_PKEY_RSA);
}

static const char *sk_prov_keymgmt_rsa_query_operation_name(int operation_id)
{
	switch (operation_id) {
	case OSSL_OP_SIGNATURE:
	case OSSL_OP_ASYM_CIPHER:
		return "RSA";
	}

	return NULL;
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_gettable_params(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gettable_params(provctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_settable_params(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_settable_params(provctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_export_types(int selection)
{
	return sk_prov_keymgmt_export_types(selection, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_import_types(int selection)
{
	return sk_prov_keymgmt_import_types(selection, EVP_PKEY_RSA);
}

static void *sk_prov_keymgmt_rsa_gen_init(void *vprovctx, int selection,
					  const OSSL_PARAM params[])
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gen_init(provctx, selection, params,
					EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_gen_settable_params(void *vgenctx,
								 void *vprovctx)
{
	struct sk_prov_op_ctx *genctx = vgenctx;
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gen_settable_params(genctx, provctx,
						   EVP_PKEY_RSA);
}

static void *sk_prov_keymgmt_rsa_pss_new(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_new(provctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_pss_gettable_params(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gettable_params(provctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_pss_settable_params(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_settable_params(provctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_pss_export_types(int selection)
{
	return sk_prov_keymgmt_export_types(selection, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_pss_import_types(int selection)
{
	return sk_prov_keymgmt_import_types(selection, EVP_PKEY_RSA_PSS);
}

static void *sk_prov_keymgmt_rsa_pss_gen_init(void *vprovctx, int selection,
					      const OSSL_PARAM params[])
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gen_init(provctx, selection, params,
					EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *sk_prov_keymgmt_rsa_pss_gen_settable_params(
								void *vgenctx,
								void *vprovctx)
{
	struct sk_prov_op_ctx *genctx = vgenctx;
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gen_settable_params(genctx, provctx,
						   EVP_PKEY_RSA_PSS);
}

static void *sk_prov_keymgmt_ec_new(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_new(provctx, EVP_PKEY_EC);
}

static const char *sk_prov_keymgmt_ec_query_operation_name(int operation_id)
{
	switch (operation_id) {
	case OSSL_OP_KEYEXCH:
		return "ECDH";
	case OSSL_OP_SIGNATURE:
		return "ECDSA";
	}

	return NULL;
}

static const OSSL_PARAM *sk_prov_keymgmt_ec_gettable_params(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gettable_params(provctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *sk_prov_keymgmt_ec_settable_params(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_settable_params(provctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *sk_prov_keymgmt_ec_export_types(int selection)
{
	return sk_prov_keymgmt_export_types(selection, EVP_PKEY_EC);
}

static const OSSL_PARAM *sk_prov_keymgmt_ec_import_types(int selection)
{
	return sk_prov_keymgmt_import_types(selection, EVP_PKEY_EC);
}

static void *sk_prov_keymgmt_ec_gen_init(void *vprovctx, int selection,
					 const OSSL_PARAM params[])
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gen_init(provctx, selection, params,
					EVP_PKEY_EC);
}

static const OSSL_PARAM *sk_prov_keymgmt_ec_gen_settable_params(void *vgenctx,
								void *vprovctx)
{
	struct sk_prov_op_ctx *genctx = vgenctx;
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_keymgmt_gen_settable_params(genctx, provctx,
						   EVP_PKEY_EC);
}

static void *sk_prov_keyexch_ec_newctx(void *vprovctx)
{
	OSSL_FUNC_keyexch_freectx_fn *default_freectx_fn;
	OSSL_FUNC_keyexch_newctx_fn *default_newctx_fn;
	struct sk_prov_ctx *provctx = vprovctx;
	struct sk_prov_op_ctx *ctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);

	default_newctx_fn = (OSSL_FUNC_keyexch_newctx_fn *)
		sk_prov_get_default_keyexch_func(provctx,
						 OSSL_FUNC_KEYEXCH_NEWCTX);
	if (default_newctx_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default newctx_fn");
		return NULL;
	}

	default_freectx_fn = (OSSL_FUNC_keyexch_freectx_fn *)
		sk_prov_get_default_keyexch_func(provctx,
						 OSSL_FUNC_KEYEXCH_FREECTX);
	if (default_freectx_fn == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default freectx_fn");
		return NULL;
	}

	ctx = sk_prov_op_newctx(provctx, NULL, EVP_PKEY_EC);
	if (ctx == NULL) {
		sk_debug_ctx(provctx, "ERROR: sk_prov_op_newctx failed");
		return NULL;
	}

	ctx->default_op_ctx = default_newctx_fn(provctx->default_provctx);
	if (ctx->default_op_ctx == NULL) {
		put_error_ctx(provctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_newctx_fn failed");
		sk_prov_op_freectx(ctx);
		return NULL;
	}
	ctx->default_op_ctx_free = default_freectx_fn;

	sk_debug_ctx(provctx, "ctx: %p", ctx);

	return ctx;
}

static void *sk_prov_keyexch_ec_dupctx(void *vctx)
{
	OSSL_FUNC_keyexch_dupctx_fn *default_dupctx_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_op_ctx *new_ctx;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);

	default_dupctx_fn = (OSSL_FUNC_keyexch_dupctx_fn *)
			sk_prov_get_default_keyexch_func(ctx->provctx,
					OSSL_FUNC_KEYEXCH_DUPCTX);
	if (default_dupctx_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default dupctx_fn");
		return NULL;
	}

	new_ctx = sk_prov_op_dupctx(ctx);
	if (new_ctx == NULL) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_dupctx failed");
		return NULL;
	}

	new_ctx->default_op_ctx = default_dupctx_fn(ctx->default_op_ctx);
	if (new_ctx->default_op_ctx == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_dupctx_fn failed");
		sk_prov_op_freectx(new_ctx);
		return NULL;
	}

	sk_debug_op_ctx(ctx, "new_ctx: %p", new_ctx);
	return new_ctx;
}

static int sk_prov_keyexch_ec_init(void *vctx, void *vkey,
				   const OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_init_fn *default_init_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_init_fn = (OSSL_FUNC_keyexch_init_fn *)
			sk_prov_get_default_keyexch_func(ctx->provctx,
					OSSL_FUNC_KEYEXCH_INIT);
	if (default_init_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default init_fn");
		return 0;
	}

	if (!sk_prov_op_init(ctx, key, EVP_PKEY_OP_DERIVE)) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_op_init failed");
		return 0;
	}

	if (!default_init_fn(ctx->default_op_ctx, key->default_key, params)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_init_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_keyexch_ec_set_peer(void *vctx, void *vpeerkey)

{
	OSSL_FUNC_keyexch_set_peer_fn *default_set_peer_fn;
	struct sk_prov_key *peerkey = vpeerkey;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL || peerkey == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p peerkey: %p", ctx, ctx->key,
			peerkey);

	default_set_peer_fn = (OSSL_FUNC_keyexch_set_peer_fn *)
			sk_prov_get_default_keyexch_func(ctx->provctx,
					OSSL_FUNC_KEYEXCH_SET_PEER);
	if (default_set_peer_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default set_peer_fn");
		return 0;
	}

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_DERIVE) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "derive operation not initialized");
		return 0;
	}

	if (!default_set_peer_fn(ctx->default_op_ctx, peerkey->default_key)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_set_peer_fn failed");
		return 0;
	}

	return 1;
}

static int sk_prov_keyexch_ec_derive(void *vctx,
				     unsigned char *secret, size_t *secretlen,
				     size_t outlen)
{
	OSSL_FUNC_keyexch_derive_fn *default_derive_fn;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL || secretlen == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p outlen: %lu", ctx, ctx->key,
			outlen);

	default_derive_fn = (OSSL_FUNC_keyexch_derive_fn *)
			sk_prov_get_default_keyexch_func(ctx->provctx,
					OSSL_FUNC_KEYEXCH_DERIVE);
	if (default_derive_fn == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default derive_fn");
		return 0;
	}

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_DERIVE) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "derive operation not initialized");
		return 0;
	}

	if (!default_derive_fn(ctx->default_op_ctx, secret, secretlen,
			       outlen)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_derive_fn failed");
		return 0;
	}

	sk_debug_op_ctx(ctx, "secretlen: %lu", *secretlen);

	return 1;
}

static int sk_prov_keyexch_ec_set_ctx_params(void *vctx,
					     const OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_set_ctx_params_fn *default_set_params_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_set_params_fn = (OSSL_FUNC_keyexch_set_ctx_params_fn *)
			sk_prov_get_default_keyexch_func(ctx->provctx,
				OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS);

	/* default_set_params_fn is optional */
	if (default_set_params_fn != NULL) {
		if (!default_set_params_fn(ctx->default_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_set_params_fn failed");
			return 0;
		}
	}

	return 1;

}

static const OSSL_PARAM *sk_prov_keyexch_ec_settable_ctx_params(void *vctx,
								void *vprovctx)
{
	OSSL_FUNC_keyexch_settable_ctx_params_fn
						*default_settable_params_fn;
	struct sk_prov_ctx *provctx = vprovctx;
	const OSSL_PARAM *params = NULL, *p;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL || provctx == NULL)
		return NULL;

	default_settable_params_fn =
		(OSSL_FUNC_keyexch_settable_ctx_params_fn *)
			sk_prov_get_default_keyexch_func(provctx,
				OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS);

	/* default_settable_params_fn is optional */
	if (default_settable_params_fn != NULL)
		params = default_settable_params_fn(ctx->default_op_ctx,
						    provctx->default_provctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_ctx(provctx, "param: %s", p->key);

	return params;
}

static int sk_prov_keyexch_ec_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_get_ctx_params_fn *default_get_params_fn;
	struct sk_prov_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_op_ctx(ctx, "param: %s", p->key);

	default_get_params_fn = (OSSL_FUNC_keyexch_get_ctx_params_fn *)
			sk_prov_get_default_keyexch_func(ctx->provctx,
					OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS);

	/* default_get_params_fn is optional */
	if (default_get_params_fn != NULL) {
		if (!default_get_params_fn(ctx->default_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 SK_PROV_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_get_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM *sk_prov_keyexch_ec_gettable_ctx_params(void *vctx,
								void *vprovctx)
{
	OSSL_FUNC_keyexch_gettable_ctx_params_fn
						*default_gettable_params_fn;
	struct sk_prov_ctx *provctx = vprovctx;
	const OSSL_PARAM *params = NULL, *p;
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL || provctx == NULL)
		return NULL;

	default_gettable_params_fn =
		(OSSL_FUNC_keyexch_gettable_ctx_params_fn *)
			sk_prov_get_default_keyexch_func(provctx,
				OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS);

	/* default_settable_params_fn is optional */
	if (default_gettable_params_fn != NULL)
		params = default_gettable_params_fn(ctx->default_op_ctx,
						    provctx->default_provctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		sk_debug_ctx(provctx, "param: %s", p->key);

	return params;
}

static void *sk_prov_asym_rsa_newctx(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_asym_op_newctx(provctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_asym_rsa_gettable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;
	struct sk_prov_op_ctx *ctx = vctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_asym_op_gettable_ctx_params(ctx, provctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_asym_rsa_settable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;
	struct sk_prov_op_ctx *ctx = vctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_asym_op_settable_ctx_params(ctx, provctx, EVP_PKEY_RSA);
}

static int sk_prov_asym_rsa_decrypt(void *vctx,
				    unsigned char *out, size_t *outlen,
				    size_t outsize, const unsigned char *in,
				    size_t inlen)
{
	int rsa_size, pad_mode, oaep_label_len = 0, rc;
	EVP_MD *oaep_md = NULL, *mgf_md = NULL;
	struct sk_prov_op_ctx *ctx = vctx;
	unsigned char *oaep_label = NULL;
	unsigned char *tmp = NULL;
	struct sk_prov_key *key;
	struct sk_funcs *funcs;

	if (ctx == NULL || in == NULL || outlen == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p inlen: %lu outsize: %lu",
			ctx, ctx->key, inlen, outsize);

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_DECRYPT) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "decrypt operation not initialized");
		return 0;
	}

	/* For clear key, let the default provider handle it */
	if (ctx->key->secure_key == NULL)
		return sk_prov_asym_op_decrypt(ctx, out, outlen, outsize,
					    in, inlen);

	funcs = ctx->key->funcs;
	if (funcs == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "no secure key funcs");
		return 0;
	}

	key = ctx->key;

	rsa_size = sk_prov_keymgmt_get_size(key);
	if (rsa_size <= 0) {
		sk_debug_op_ctx(ctx, "sk_prov_keymgmt_get_size failed");
		return 0;
	}

	if (out == NULL) {
		tmp = OPENSSL_zalloc(rsa_size);
		if (tmp == NULL) {
			put_error_op_ctx(ctx, SK_PROV_ERR_MALLOC_FAILED,
					 "OPENSSL_zalloc failed");
			return 0;
		}
		out = tmp;
		outsize = rsa_size;
	}

	if (outsize < (size_t)rsa_size) {
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PARAM,
				 "output buffer length invalid");
		return 0;
	}

	pad_mode = sk_prov_asym_op_get_padding(ctx);
	switch (pad_mode) {
	case RSA_NO_PADDING:
	case RSA_PKCS1_PADDING:
	case RSA_X931_PADDING:
		break;

	case RSA_PKCS1_OAEP_PADDING:
		oaep_label_len = sk_prov_asym_op_get_oaep_label(ctx,
								&oaep_label);
		if (oaep_label_len < 0) {
			sk_debug_op_ctx(ctx,
				"ERROR: sk_prov_rsa_asym_get_oaep_label failed");
			rc = 0;
			goto out;
		}

		oaep_md = sk_prov_asym_op_get_oaep_md(ctx);
		if (oaep_md == NULL) {
			sk_debug_op_ctx(ctx,
				"ERROR: sk_prov_asym_op_get_oaep_md failed");
			rc = 0;
			goto out;
		}

		mgf_md = sk_prov_asym_op_get_mgf_md(ctx);
		if (mgf_md == NULL) {
			sk_debug_op_ctx(ctx,
				"ERROR: sk_prov_asym_op_get_mgf_md failed");
			rc = 0;
			goto out;
		}
		break;
	default:
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PADDING,
				 "unknown/unsupported padding: %d", pad_mode);
		return 0;
	}

	*outlen = outsize;

	switch (pad_mode) {
	case RSA_PKCS1_OAEP_PADDING:
		if (funcs->rsa_decrypt_oaep == NULL) {
			put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
					 "no secure key decrypt function");
			rc = 0;
			goto out;
		}

		rc = funcs->rsa_decrypt_oaep(key->secure_key,
					     key->secure_key_size,
					     out, outlen, in, inlen,
					     EVP_MD_type(oaep_md),
					     EVP_MD_type(mgf_md),
					     oaep_label, oaep_label_len,
					     key->private, ctx->provctx->debug);
		break;

	default:
		if (funcs->rsa_decrypt == NULL) {
			put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
					 "no secure key decrypt function");
			rc = 0;
			goto out;
		}

		rc = funcs->rsa_decrypt(key->secure_key, key->secure_key_size,
					out, outlen, in, inlen, pad_mode,
					key->private, ctx->provctx->debug);
		break;
	}

	if (tmp != NULL) {
		OPENSSL_cleanse(tmp, outsize);
		OPENSSL_free(tmp);
	}

	if (rc != 0) {
		put_error_op_ctx(ctx, SK_PROV_ERR_SECURE_KEY_FUNC_FAILED,
				 "Secure key encrypt operation failed: rc: %d",
				 rc);
		rc = 0;
		goto out;
	}

	rc = 1;

	sk_debug_op_ctx(ctx, "outlen: %lu", *outlen);

out:
	if (oaep_md != NULL)
		EVP_MD_free(oaep_md);
	if (mgf_md != NULL)
		EVP_MD_free(mgf_md);

	return rc;
}

static void *sk_prov_sign_rsa_newctx(void *vprovctx, const char *propq)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p propq: %s", provctx,
		     propq != NULL ? propq : "");
	return sk_prov_sign_op_newctx(provctx, propq, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_sign_rsa_gettable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;
	struct sk_prov_op_ctx *ctx = vctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_sign_op_gettable_ctx_params(ctx, provctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_sign_rsa_settable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;
	struct sk_prov_op_ctx *ctx = vctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_sign_op_settable_ctx_params(ctx, provctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_sign_rsa_gettable_ctx_md_params(void *vctx)
{
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	return sk_prov_sign_op_gettable_ctx_md_params(ctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *sk_prov_sign_rsa_settable_ctx_md_params(void *vctx)
{
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	return sk_prov_sign_op_settable_ctx_md_params(ctx, EVP_PKEY_RSA);
}

static int sk_prov_sign_rsa_sign(void *vctx,
				 unsigned char *sig, size_t *siglen,
				 size_t sigsize,
				 const unsigned char *tbs, size_t tbslen)
{
	EVP_MD *sign_md = NULL, *mgf_md = NULL;
	int rsa_size, pad_mode, salt_len, rc;
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key;
	struct sk_funcs *funcs;

	if (ctx == NULL || siglen == NULL || tbs == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu sigsize: %lu",
			ctx, ctx->key, tbslen, sigsize);

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_SIGN) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "sign operation not initialized");
		return 0;
	}

	/* For clear key, let the default provider handle it */
	if (ctx->key->secure_key == NULL)
		return sk_prov_sign_op_sign(ctx, sig, siglen, sigsize,
					    tbs, tbslen);

	key = ctx->key;

	rsa_size = sk_prov_keymgmt_get_size(key);
	if (rsa_size <= 0) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_keymgmt_get_size failed");
		return 0;
	}

	if (sig == NULL) {
		*siglen = rsa_size;
		sk_debug_op_ctx(ctx, "siglen: %lu", *siglen);
		return 1;
	}

	if (sigsize < (size_t)rsa_size) {
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PARAM,
				 "signature length invalid");
		return 0;
	}

	funcs = ctx->key->funcs;
	if (funcs == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "no secure key funcs");
		return 0;
	}

	sign_md = sk_prov_sign_op_get_md(ctx);
	pad_mode = sk_prov_sign_op_get_padding(ctx);

	if (sign_md == NULL) {
		/* Sign without a signature digest, fall back to no padding */
		pad_mode = RSA_NO_PADDING;
	} else {
		if (tbslen != (size_t)EVP_MD_size(sign_md)) {
			put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PARAM,
					 "tbslen must be size of digest");
			rc = 0;
			goto out;
		}
	}

	*siglen = rsa_size;

	switch (pad_mode) {
	case RSA_PKCS1_PADDING:
	case RSA_X931_PADDING:
		if (sign_md == NULL) {
			put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
					 "padding needs a signature digest");
			rc = 0;
			goto out;
		}
		/* fall through */

	case RSA_NO_PADDING:
		if (funcs->rsa_sign == NULL) {
			put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
					 "no secure key sign function");
			rc = 0;
			goto out;

		}

		rc = funcs->rsa_sign(key->secure_key, key->secure_key_size,
				     sig, siglen, tbs, tbslen, pad_mode,
				     sign_md != NULL ?
					EVP_MD_type(sign_md) : NID_undef,
				     key->private, ctx->provctx->debug);
		break;

	case RSA_PKCS1_PSS_PADDING:
		if (sign_md == NULL) {
			put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
					 "PSS padding needs a signature digest");
			rc = 0;
			goto out;
		}

		mgf_md = sk_prov_sign_op_get_mgf_md(ctx);
		if (mgf_md == NULL) {
			sk_debug_op_ctx(ctx,
				"ERROR sk_prov_sign_op_get_mgf_md failed");
			rc = 0;
			goto out;
		}

		salt_len = sk_prov_sign_op_get_pss_saltlen(ctx, key, mgf_md);
		if (salt_len < 0) {
			sk_debug_op_ctx(ctx,
				"ERROR: sk_prov_sign_op_get_pss_saltlen failed");
			rc = 0;
			goto out;
		}

		if (funcs->rsa_pss_sign == NULL) {
			put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
					 "no secure key sign function");
			rc = 0;
			goto out;
		}

		rc = funcs->rsa_pss_sign(key->secure_key, key->secure_key_size,
					 sig, siglen, tbs, tbslen,
					 EVP_MD_type(sign_md),
					 EVP_MD_type(mgf_md),
					 salt_len, key->private,
					 ctx->provctx->debug);
		break;
	default:
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PADDING,
				 "unknown/unsupported padding: %d", pad_mode);
		rc = 0;
		goto out;
	}

	if (rc != 0) {
		put_error_op_ctx(ctx, SK_PROV_ERR_SECURE_KEY_FUNC_FAILED,
				 "Secure key sign operation failed: rc: %d",
				 rc);
		rc = 0;
		goto out;
	}

	rc = 1;

	sk_debug_op_ctx(ctx, "siglen: %lu", *siglen);

out:
	if (sign_md != NULL)
		EVP_MD_free(sign_md);
	if (mgf_md != NULL)
		EVP_MD_free(mgf_md);

	return rc;
}

static int sk_prov_sign_rsa_digest_sign_init(void *vctx,
					     const char *mdname,
					     void *vkey,
					     const OSSL_PARAM params[])
{
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;

	sk_debug_op_ctx(ctx, "ctx: %p mdname: %s key: %p", ctx,
			mdname != NULL ? mdname : "", key);
	return sk_prov_sign_op_digest_sign_init(ctx, mdname, key, params,
						sk_prov_sign_rsa_sign);
}

static void *sk_prov_sign_ec_newctx(void *vprovctx, const char *propq)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p propq: %s", provctx,
		     propq != NULL ? propq : "");
	return sk_prov_sign_op_newctx(provctx, propq, EVP_PKEY_EC);
}

static const OSSL_PARAM *sk_prov_sign_ec_gettable_ctx_params(void *vctx,
							     void *vprovctx)
{
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_sign_op_gettable_ctx_params(ctx, provctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *sk_prov_sign_ec_settable_ctx_params(void *vctx,
							     void *vprovctx)
{
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_sign_op_settable_ctx_params(ctx, provctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *sk_prov_sign_ec_gettable_ctx_md_params(void *vctx)
{
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	return sk_prov_sign_op_gettable_ctx_md_params(ctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *sk_prov_sign_ec_settable_ctx_md_params(void *vctx)
{
	struct sk_prov_op_ctx *ctx = vctx;

	if (ctx == NULL)
		return NULL;

	sk_debug_op_ctx(ctx, "ctx: %p", ctx);
	return sk_prov_sign_op_settable_ctx_md_params(ctx, EVP_PKEY_EC);
}

static int sk_prov_sign_ec_sign(void *vctx,
				unsigned char *sig, size_t *siglen,
				size_t sigsize,
				const unsigned char *tbs, size_t tbslen)
{
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key;
	EVP_MD *sign_md = NULL;
	struct sk_funcs *funcs;
	int ec_size, rc;

	if (ctx == NULL || siglen == NULL || tbs == NULL)
		return 0;

	sk_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu sigsize: %lu",
			ctx, ctx->key, tbslen, sigsize);

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_SIGN) {
		put_error_op_ctx(ctx, SK_PROV_ERR_OPRATION_NOT_INITIALIZED,
				 "sign operation not initialized");
		return 0;
	}

	/* For clear key, let the default provider handle it */
	if (ctx->key->secure_key == NULL)
		return sk_prov_sign_op_sign(ctx, sig, siglen, sigsize,
					    tbs, tbslen);

	key = ctx->key;

	ec_size = sk_prov_keymgmt_get_size(key);
	if (ec_size <= 0) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_keymgmt_get_size failed");
		return 0;
	}

	if (sig == NULL) {
		*siglen = ec_size;
		sk_debug_op_ctx(ctx, "siglen: %lu", *siglen);
		return 1;
	}

	if (sigsize < (size_t)ec_size) {
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PARAM,
				 "signature length invalid");
		return 0;
	}

	funcs = ctx->key->funcs;
	if (funcs == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "no secure key funcs");
		return 0;
	}

	sign_md = sk_prov_sign_op_get_md(ctx);
	if (sign_md == NULL) {
		sk_debug_op_ctx(ctx, "ERROR: sk_prov_sign_op_get_md failed");
		return 0;
	}

	if (tbslen != (size_t)EVP_MD_size(sign_md)) {
		put_error_op_ctx(ctx, SK_PROV_ERR_INVALID_PARAM,
				 "tbslen must be size of digest");
		rc = 0;
		goto out;
	}

	*siglen = ec_size;

	if (funcs->ecdsa_sign == NULL) {
		put_error_op_ctx(ctx, SK_PROV_ERR_MISSING_PARAMETER,
				 "no secure key sign function");
		rc = 0;
		goto out;
	}

	rc = funcs->ecdsa_sign(key->secure_key, key->secure_key_size,
				 sig, siglen, tbs, tbslen,
				 EVP_MD_type(sign_md), key->private,
				 ctx->provctx->debug);
	if (rc != 0) {
		put_error_op_ctx(ctx, SK_PROV_ERR_SECURE_KEY_FUNC_FAILED,
				 "Secure key sign operation failed: rc: %d",
				 rc);
		rc = 0;
		goto out;
	}

	rc = 1;

	sk_debug_op_ctx(ctx, "siglen: %lu", *siglen);

out:
	if (sign_md != NULL)
		EVP_MD_free(sign_md);

	return rc;
}

static int sk_prov_sign_ec_digest_sign_init(void *vctx,
					    const char *mdname,
					    void *vkey,
					    const OSSL_PARAM params[])
{
	struct sk_prov_op_ctx *ctx = vctx;
	struct sk_prov_key *key = vkey;

	sk_debug_op_ctx(ctx, "ctx: %p mdname: %s key: %p", ctx,
			mdname != NULL ? mdname : "", key);
	return sk_prov_sign_op_digest_sign_init(ctx, mdname, key, params,
						sk_prov_sign_ec_sign);
}

static const OSSL_DISPATCH sk_prov_rsa_signature_functions[] = {
	/* Signature context constructor, descructor */
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sk_prov_sign_rsa_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sk_prov_op_freectx },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sk_prov_sign_op_dupctx },
	/* Signing */
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT,
			(void (*)(void))sk_prov_sign_op_sign_init },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sk_prov_sign_rsa_sign },
	/* Verifying */
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT,
			(void (*)(void))sk_prov_sign_op_verify_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sk_prov_sign_op_verify },
	/* Verify recover */
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
			(void (*)(void))sk_prov_sign_op_verify_recover_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
			(void (*)(void))sk_prov_sign_op_verify_recover },
	/* Digest Sign */
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
			(void (*)(void))sk_prov_sign_rsa_digest_sign_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
			(void (*)(void))sk_prov_sign_op_digest_sign_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
			(void (*)(void))sk_prov_sign_op_digest_sign_final },
	/* Digest Verify */
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
			(void (*)(void))sk_prov_sign_op_digest_verify_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
			(void (*)(void))sk_prov_sign_op_digest_verify_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
			(void (*)(void))sk_prov_sign_op_digest_verify_final },
	/* Signature parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
			(void (*)(void))sk_prov_sign_op_get_ctx_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
			(void (*)(void))sk_prov_sign_rsa_gettable_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void
			(*)(void))sk_prov_sign_op_set_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
			(void (*)(void))sk_prov_sign_rsa_settable_ctx_params },
	/* MD parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
			(void (*)(void))sk_prov_sign_op_get_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
		(void (*)(void))sk_prov_sign_rsa_gettable_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
			(void (*)(void))sk_prov_sign_op_set_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
		(void (*)(void))sk_prov_sign_rsa_settable_ctx_md_params },
	{ 0, NULL }
};

static const OSSL_DISPATCH sk_prov_ecdsa_signature_functions[] = {
	/* Signature context constructor, descructor */
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sk_prov_sign_ec_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sk_prov_op_freectx },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sk_prov_sign_op_dupctx },
	/* Signing */
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT,
			(void (*)(void))sk_prov_sign_op_sign_init },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sk_prov_sign_ec_sign },
	/* Verifying */
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT,
			(void (*)(void))sk_prov_sign_op_verify_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sk_prov_sign_op_verify },
	/* Verify recover */
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
			(void (*)(void))sk_prov_sign_op_verify_recover_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
			(void (*)(void))sk_prov_sign_op_verify_recover },
	/* Digest Sign */
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
			(void (*)(void))sk_prov_sign_ec_digest_sign_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
			(void (*)(void))sk_prov_sign_op_digest_sign_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
			(void (*)(void))sk_prov_sign_op_digest_sign_final },
	/* Digest Verify */
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
			(void (*)(void))sk_prov_sign_op_digest_verify_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
			(void (*)(void))sk_prov_sign_op_digest_verify_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
			(void (*)(void))sk_prov_sign_op_digest_verify_final },
	/* Signature parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
			(void (*)(void))sk_prov_sign_op_get_ctx_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
			(void (*)(void))sk_prov_sign_ec_gettable_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void
			(*)(void))sk_prov_sign_op_set_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
			(void (*)(void))sk_prov_sign_ec_settable_ctx_params },
	/* MD parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
			(void (*)(void))sk_prov_sign_op_get_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
		(void (*)(void))sk_prov_sign_ec_gettable_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
			(void (*)(void))sk_prov_sign_op_set_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
		(void (*)(void))sk_prov_sign_ec_settable_ctx_md_params },
	{ 0, NULL }
};

static const OSSL_ALGORITHM sk_prov_signature[] = {
	{ "RSA:rsaEncryption", "provider="SK_PROV_NAME,
				sk_prov_rsa_signature_functions, NULL },
	{ "ECDSA", "provider="SK_PROV_NAME,
				sk_prov_ecdsa_signature_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_DISPATCH sk_prov_rsa_asym_cipher_functions[] = {
	/* RSA context constructor, descructor */
	{ OSSL_FUNC_ASYM_CIPHER_NEWCTX,
			(void (*)(void))sk_prov_asym_rsa_newctx },
	{ OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))sk_prov_op_freectx },
	{ OSSL_FUNC_ASYM_CIPHER_DUPCTX,
			(void (*)(void))sk_prov_asym_op_dupctx },
	/* RSA context set/get parameters */
	{ OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
			(void (*)(void))sk_prov_asym_op_get_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
			(void (*)(void))sk_prov_asym_rsa_gettable_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
			(void (*)(void))sk_prov_asym_op_set_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
			(void (*)(void))sk_prov_asym_rsa_settable_ctx_params },
	/* RSA encrypt */
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
			(void (*)(void))sk_prov_asym_op_encrypt_init },
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
			(void (*)(void))sk_prov_asym_op_encrypt },
	/* RSA decrypt */
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
			(void (*)(void))sk_prov_asym_op_decrypt_init },
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT,
			(void (*)(void))sk_prov_asym_rsa_decrypt },
	{ 0, NULL }
};

static const OSSL_ALGORITHM sk_prov_asym_cipher[] = {
	{ "RSA:rsaEncryption", "provider="SK_PROV_NAME,
				sk_prov_rsa_asym_cipher_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};


static const OSSL_DISPATCH sk_prov_rsa_keymgmt_functions[] = {
	/* Constructor, destructor */
	{ OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sk_prov_keymgmt_rsa_new },
	{ OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sk_prov_keymgmt_free },

	/* Key generation and loading */
	{ OSSL_FUNC_KEYMGMT_GEN_INIT,
			(void (*)(void))sk_prov_keymgmt_rsa_gen_init },
	{ OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
			(void (*)(void))sk_prov_keymgmt_gen_set_template },
	{ OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
			(void (*)(void))sk_prov_keymgmt_gen_set_params },
	{ OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
		(void (*)(void))sk_prov_keymgmt_rsa_gen_settable_params },
	{ OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sk_prov_keymgmt_gen },
	{ OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
			(void (*)(void))sk_prov_keymgmt_gen_cleanup },
	{ OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sk_prov_keymgmt_load },

	/* Key object checking */
	{ OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sk_prov_keymgmt_has },
	{ OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sk_prov_keymgmt_match },
	{ OSSL_FUNC_KEYMGMT_VALIDATE,
			(void (*)(void))sk_prov_keymgmt_validate },
	{ OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
		(void (*)(void))sk_prov_keymgmt_rsa_query_operation_name },

	/* Key object information */
	{ OSSL_FUNC_KEYMGMT_GET_PARAMS,
			(void (*) (void))sk_prov_keymgmt_get_params },
	{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
			(void (*) (void))sk_prov_keymgmt_rsa_gettable_params },
	{ OSSL_FUNC_KEYMGMT_SET_PARAMS,
			(void (*) (void))sk_prov_keymgmt_set_params },
	{ OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
			(void (*) (void))sk_prov_keymgmt_rsa_settable_params },

	/* Import and export routines */
	{ OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sk_prov_keymgmt_export },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
			(void (*)(void))sk_prov_keymgmt_rsa_export_types },
	{ OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sk_prov_keymgmt_import },
	{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
			(void (*)(void))sk_prov_keymgmt_rsa_import_types },
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

static const OSSL_DISPATCH sk_prov_rsapss_keymgmt_functions[] = {
	/* Constructor, destructor */
	{ OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sk_prov_keymgmt_rsa_pss_new },
	{ OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sk_prov_keymgmt_free },

	/* Key generation and loading */
	{ OSSL_FUNC_KEYMGMT_GEN_INIT,
			(void (*)(void))sk_prov_keymgmt_rsa_pss_gen_init },
	{ OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
			(void (*)(void))sk_prov_keymgmt_gen_set_template },
	{ OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
			(void (*)(void))sk_prov_keymgmt_gen_set_params },
	{ OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
		(void (*)(void))sk_prov_keymgmt_rsa_pss_gen_settable_params },
	{ OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sk_prov_keymgmt_gen },
	{ OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
			(void (*)(void))sk_prov_keymgmt_gen_cleanup },
	{ OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sk_prov_keymgmt_load },

	/* Key object checking */
	{ OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sk_prov_keymgmt_has },
	{ OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sk_prov_keymgmt_match },
	{ OSSL_FUNC_KEYMGMT_VALIDATE,
			(void (*)(void))sk_prov_keymgmt_validate },
	{ OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
		(void (*)(void))sk_prov_keymgmt_rsa_query_operation_name },

	/* Key object information */
	{ OSSL_FUNC_KEYMGMT_GET_PARAMS,
			(void (*) (void))sk_prov_keymgmt_get_params },
	{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
		(void (*) (void))sk_prov_keymgmt_rsa_pss_gettable_params },
	{ OSSL_FUNC_KEYMGMT_SET_PARAMS,
			(void (*) (void))sk_prov_keymgmt_set_params },
	{ OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
		(void (*) (void))sk_prov_keymgmt_rsa_pss_settable_params },

	/* Import and export routines */
	{ OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sk_prov_keymgmt_export },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
			(void (*)(void))sk_prov_keymgmt_rsa_pss_export_types },
	{ OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sk_prov_keymgmt_import },
	{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
			(void (*)(void))sk_prov_keymgmt_rsa_pss_import_types },
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

static const OSSL_DISPATCH sk_prov_ec_keymgmt_functions[] = {
	/* Constructor, destructor */
	{ OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sk_prov_keymgmt_ec_new },
	{ OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sk_prov_keymgmt_free },

	/* Key generation and loading */
	{ OSSL_FUNC_KEYMGMT_GEN_INIT,
			(void (*)(void))sk_prov_keymgmt_ec_gen_init },
	{ OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
			(void (*)(void))sk_prov_keymgmt_gen_set_template },
	{ OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
			(void (*)(void))sk_prov_keymgmt_gen_set_params },
	{ OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
		(void (*)(void))sk_prov_keymgmt_ec_gen_settable_params },
	{ OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sk_prov_keymgmt_gen },
	{ OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
			(void (*)(void))sk_prov_keymgmt_gen_cleanup },
	{ OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sk_prov_keymgmt_load },

	/* Key object checking */
	{ OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sk_prov_keymgmt_has },
	{ OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sk_prov_keymgmt_match },
	{ OSSL_FUNC_KEYMGMT_VALIDATE,
			(void (*)(void))sk_prov_keymgmt_validate },
	{ OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
		(void (*)(void))sk_prov_keymgmt_ec_query_operation_name },

	/* Key object information */
	{ OSSL_FUNC_KEYMGMT_GET_PARAMS,
			(void (*) (void))sk_prov_keymgmt_get_params },
	{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
			(void (*) (void))sk_prov_keymgmt_ec_gettable_params },
	{ OSSL_FUNC_KEYMGMT_SET_PARAMS,
			(void (*) (void))sk_prov_keymgmt_set_params },
	{ OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
			(void (*) (void))sk_prov_keymgmt_ec_settable_params },

	/* Import and export routines */
	{ OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sk_prov_keymgmt_export },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
			(void (*)(void))sk_prov_keymgmt_ec_export_types },
	{ OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sk_prov_keymgmt_import },
	{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
			(void (*)(void))sk_prov_keymgmt_ec_import_types },
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

static const OSSL_ALGORITHM sk_prov_keymgmt[] = {
	{ "RSA:rsaEncryption", "provider="SK_PROV_NAME,
				sk_prov_rsa_keymgmt_functions, NULL },
	{ "RSA-PSS:RSASSA-PSS", "provider="SK_PROV_NAME,
				sk_prov_rsapss_keymgmt_functions, NULL },
	{ "EC:id-ecPublicKey", "provider="SK_PROV_NAME,
				sk_prov_ec_keymgmt_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_DISPATCH sk_prov_ec_keyexch_functions[] = {
	/* Context management */
	{ OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))sk_prov_keyexch_ec_newctx },
	{ OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))sk_prov_op_freectx },
	{ OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))sk_prov_keyexch_ec_dupctx },

	/* Shared secret derivation */
	{ OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))sk_prov_keyexch_ec_init },
	{ OSSL_FUNC_KEYEXCH_SET_PEER,
		(void (*)(void))sk_prov_keyexch_ec_set_peer },
	{ OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))sk_prov_keyexch_ec_derive },

	/* Key Exchange parameters */
	{ OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
		(void (*)(void))sk_prov_keyexch_ec_set_ctx_params },
	{ OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
		(void (*)(void))sk_prov_keyexch_ec_settable_ctx_params },
	{ OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
			(void (*)(void))sk_prov_keyexch_ec_get_ctx_params },
	{ OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
		(void (*)(void))sk_prov_keyexch_ec_gettable_ctx_params },

	{ 0, NULL }
};

/*
 * Although ECDH key derivation is not supported for secure keys (would result
 * in a secure symmetric key, which OpenSSL can't handle), the provider still
 * must implement the ECDH key exchange functions and proxy them all to the
 * default provider. OpenSSL common code requires that the key management
 * provider and the key exchange provider for a derive operation is the same.
 * So for clear EC keys created with this provider, we do support the ECDH
 * operation by proxy'ing it to the default provider.
 */
static const OSSL_ALGORITHM sk_prov_keyexch[] = {
	{ "ECDH", "provider="SK_PROV_NAME, sk_prov_ec_keyexch_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_PARAM sk_prov_param_types[] = {
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL,
									0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *sk_prov_gettable_params(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_param_types;
}

static int sk_prov_get_params(void *vprovctx, OSSL_PARAM params[])
{
	struct sk_prov_ctx *provctx = vprovctx;
	OSSL_PARAM *p;

	if (provctx == NULL)
		return 0;

	sk_debug_ctx(provctx, "provctx: %p", provctx);

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SK_PROV_DESCRIPTION)) {
		put_error_ctx(provctx, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_utf8_ptr failed");
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SK_PROV_VERSION)) {
		put_error_ctx(provctx, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_utf8_ptr failed");
	return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SK_PROV_VERSION)) {
		put_error_ctx(provctx, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_utf8_ptr failed");
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1)) {
		put_error_ctx(provctx, SK_PROV_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_int failed");
		return 0;
	}

	return 1;
}

static const OSSL_ALGORITHM *sk_prov_query(void *vprovctx,
					   int operation_id, int *no_cache)
{
	struct sk_prov_ctx *provctx = vprovctx;

	if (provctx == NULL)
		return NULL;

	*no_cache = 0;

	sk_debug_ctx(provctx, "provctx: %p operation_id: %d", provctx,
		     operation_id);

	switch (operation_id) {
	case OSSL_OP_KEYMGMT:
		return sk_prov_keymgmt;
	case OSSL_OP_KEYEXCH:
		return sk_prov_keyexch;
	case OSSL_OP_SIGNATURE:
		return sk_prov_signature;
	case OSSL_OP_ASYM_CIPHER:
		return sk_prov_asym_cipher;
	}

	return NULL;
}

static void sk_prov_teardown(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;
	int i;

	if (provctx == NULL)
		return;

	sk_debug_ctx(provctx, "provctx: %p", provctx);

	for (i = 0; i < SK_PROV_CACHED_PARAMS_COUNT; i++) {
		if (provctx->cached_parms[i] != NULL)
			OPENSSL_free((void *)provctx->cached_parms[i]);
	}

	OPENSSL_free(provctx);
}

static const OSSL_ITEM *sk_prov_get_reason_strings(void *vprovctx)
{
	struct sk_prov_ctx *provctx = vprovctx;

	sk_debug_ctx(provctx, "provctx: %p", provctx);
	return sk_prov_reason_strings;
}

static int sk_prov_prov_get_capabilities(void *vprovctx,
					 const char *capability,
					 OSSL_CALLBACK *cb, void *arg)
{
	struct sk_prov_ctx *provctx = vprovctx;

	sk_debug_ctx(provctx, "provctx: %p capability: %s", provctx,
		     capability);

	if (provctx->default_provider == NULL)
		return 0;

	return OSSL_PROVIDER_get_capabilities(provctx->default_provider,
					      capability, cb, arg);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH sk_prov_dispatch_table[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))sk_prov_teardown },
	{ OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
				(void (*)(void))sk_prov_gettable_params },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))sk_prov_get_params },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sk_prov_query },
	{ OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
				(void (*)(void))sk_prov_get_reason_strings },
	{ OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
				(void (*)(void))sk_prov_prov_get_capabilities },
	{ 0, NULL }
};

static int sk_provider_init(const OSSL_CORE_HANDLE *handle,
			    const OSSL_DISPATCH *in,
			    const OSSL_DISPATCH **out, void **provctx)
{
	OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug = NULL;
	OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
	OSSL_FUNC_core_vset_error_fn *c_vset_error = NULL;
	OSSL_FUNC_core_new_error_fn *c_new_error = NULL;
	struct sk_prov_ctx *ctx;

	if (handle == NULL || in == NULL || out == NULL || provctx == NULL)
		return 0;

	for (; in->function_id != 0; in++) {
		switch (in->function_id) {
		case OSSL_FUNC_CORE_GET_LIBCTX:
			c_get_libctx = OSSL_FUNC_core_get_libctx(in);
			break;
		case OSSL_FUNC_CORE_NEW_ERROR:
			c_new_error = OSSL_FUNC_core_new_error(in);
			break;
		case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
			c_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
			break;
		case OSSL_FUNC_CORE_VSET_ERROR:
			c_vset_error = OSSL_FUNC_core_vset_error(in);
			break;
		default:
			/* Just ignore anything we don't understand */
			break;
		}
	}

	if (c_get_libctx == NULL)
		return 0;

	ctx = OPENSSL_zalloc(sizeof(struct sk_prov_ctx));
	if (ctx == NULL) {
		c_new_error(handle);
		c_set_error_debug(handle, __FILE__, __LINE__, __func__);
		c_vset_error(handle, SK_PROV_ERR_MALLOC_FAILED,
			     "Failed to allocate provider context", NULL);
		return 0;
	}

	ctx->handle = handle;
	ctx->c_get_libctx = c_get_libctx;
	ctx->c_new_error = c_new_error;
	ctx->c_set_error_debug = c_set_error_debug;
	ctx->c_vset_error = c_vset_error;
	*provctx = ctx;

	*out = sk_prov_dispatch_table;
	return 1;
}

/**
 * Initializes the secure key support for OpenSSL.
 *
 * @param debug             true to enable internal debugging
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed for various reasons
 */
int SK_OPENSSL_init(bool debug)
{
	struct sk_prov_ctx *provctx;

	if (sk_prov_securekey_libctx == NULL)
		sk_prov_securekey_libctx = OSSL_LIB_CTX_new();
	if (sk_prov_securekey_libctx == NULL) {
		sk_debug(debug, "ERROR: OSSL_LIB_CTX_new failed");
		return -ENOMEM;
	}

	if (OSSL_PROVIDER_add_builtin(sk_prov_securekey_libctx, SK_PROV_NAME,
				      sk_provider_init) != 1) {
		sk_debug(debug, "ERROR: OSSL_PROVIDER_add_builtin failed");
		return -EIO;
	}

	if (sk_prov_securekey_provider == NULL) {
		sk_prov_securekey_provider =
				OSSL_PROVIDER_load(sk_prov_securekey_libctx,
						   SK_PROV_NAME);
		if (sk_prov_securekey_provider == NULL) {
			sk_debug(debug, "ERROR: OSSL_PROVIDER_load("
				SK_PROV_NAME") failed");
			return -EIO;
		}
	}
	provctx = OSSL_PROVIDER_get0_provider_ctx(sk_prov_securekey_provider);
	provctx->debug = debug;

	if (sk_prov_default_provider == NULL) {
		sk_prov_default_provider =
				OSSL_PROVIDER_load(sk_prov_securekey_libctx,
						      "default");
		if (sk_prov_default_provider == NULL) {
			sk_debug(debug,
				 "ERROR: OSSL_PROVIDER_load(default) failed");
			SK_OPENSSL_term();
			return -EIO;
		}
	}
	provctx->default_provider = sk_prov_default_provider;
	provctx->default_provctx =
		OSSL_PROVIDER_get0_provider_ctx(sk_prov_default_provider);

	sk_prov_previous_libctx =
			OSSL_LIB_CTX_set0_default(sk_prov_securekey_libctx);
	if (sk_prov_previous_libctx == NULL) {
		sk_debug(debug, "ERROR: OSSL_LIB_CTX_set0_default failed");
		SK_OPENSSL_term();
		return -EIO;
	}

	/* Prefer the secure key provider, but allow to fall back to default */
	if (!EVP_set_default_properties(sk_prov_securekey_libctx,
					"?provider="SK_PROV_NAME)) {
		sk_debug(debug, "ERROR: EVP_set_default_properties failed");
		SK_OPENSSL_term();
		return -EIO;
	}

	sk_debug(debug, "sk_provider support initialized, provctx: %p",
		 provctx);
	return 0;
}

/**
 * Terminate the secure key support for OpenSSL.
 */
void SK_OPENSSL_term(void)
{
	if (sk_prov_securekey_provider != NULL)
		OSSL_PROVIDER_unload(sk_prov_securekey_provider);
	sk_prov_securekey_provider = NULL;

	if (sk_prov_default_provider != NULL)
		OSSL_PROVIDER_unload(sk_prov_default_provider);
	sk_prov_default_provider = NULL;

	if (sk_prov_previous_libctx != NULL)
		OSSL_LIB_CTX_set0_default(sk_prov_previous_libctx);
	sk_prov_previous_libctx = NULL;

	if (sk_prov_securekey_libctx != NULL)
		OSSL_LIB_CTX_free(sk_prov_securekey_libctx);
	sk_prov_securekey_libctx = NULL;
}

static int sk_openssl_pkey_from_data(OSSL_PARAM_BLD *bld, int pkey_type,
				     EVP_PKEY **pkey, bool debug)
{
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	const char *key_name;
	int rc = 0;

	switch (pkey_type) {
	case EVP_PKEY_EC:
		key_name = "EC";
		break;
	case EVP_PKEY_RSA:
		key_name = "RSA";
		break;
	case EVP_PKEY_RSA_PSS:
		key_name = "RSA-PSS";
		break;
	default:
		sk_debug(debug, "ERROR: unsupported PKEY type");
		return -EINVAL;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		sk_debug(debug, "ERROR: OSSL_PARAM_BLD_to_param failed");
		rc = -EIO;
		goto out;
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, key_name,
					  "provider="SK_PROV_NAME);
	if (pctx == NULL) {
		sk_debug(debug, "ERROR: EVP_PKEY_CTX_new_from_name failed");
		return -EIO;
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		sk_debug(debug, "ERROR: EVP_PKEY_fromdata_init failed");
		rc = -EIO;
		goto out;
	}

	if (EVP_PKEY_fromdata(pctx, pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
		sk_debug(debug, "ERROR: EVP_PKEY_fromdata failed");
		rc = -EIO;
		goto out;
	}

out:
	if (pctx != NULL)
		EVP_PKEY_CTX_free(pctx);
	if (params != NULL)
		OSSL_PARAM_free(params);

	return rc;
}

/**
 * Converts an EC key given by the nid and the x and y coordinates into an
 * OpenSSL PKEY and attaches the secure key together with secure key functions
 * and private pointer to it. If no secure key is provided, a public EC key
 * only PKEY is returned.
 *
 * @param secure_key        the secure key blob.
 *                          If NULL, a clear key PKEY is created.
 * @param secure_key_size   the size of the secure key blob (ignored if
 *                          secure_key is NULL)
 * @param nid               the OpenSSL nid of the EC curve used
 * @param prime_len         the length of the prime in bytes. This is also the
 *                          length of the x and y coordinates.
 * @param x                 the x coordinate as big endian binary number in
 *                          prime_len size
 * @param y                 the y coordinate as big endian binary number in
 *                          prime_len size
 * @param sk_funcs          the secure key functions to operate with the key.
 *                          Ignored if secure_key is NULL, required otherwise.
 * @param private           a private pointer that is passed to the secure key
 *                          functions (can be NULL)
 * @param pkey              On return: A PKEY containing the EC public key.
 * @param debug             true to enable internal debugging
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to generate the PKEY
 *          -ENOENT: OpenSSL does not know/support the curve (nid)
 */
int sk_openssl_get_pkey_ec(const unsigned char *secure_key,
			   size_t secure_key_size, int nid, size_t prime_len,
			   const unsigned char *x, const unsigned char *y,
			   const struct sk_funcs *sk_funcs, const void *private,
			   EVP_PKEY **pkey, bool debug)
{
	BIGNUM *bn_x = NULL, *bn_y = NULL;
	point_conversion_form_t form;
	unsigned char *pub_key = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	size_t pub_key_len;
	int rc;

	if (pkey == NULL || x == NULL || y == NULL)
		return -EINVAL;
	if (secure_key != NULL && (secure_key_size == 0 || sk_funcs == NULL))
		return -EINVAL;

	*pkey = NULL;

	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL) {
		sk_debug(debug, "ERROR: EC_GROUP_new_by_curve_name failed");
		rc = -ENOENT;
		goto out;
	}

	bn_x = BN_bin2bn(x, prime_len, NULL);
	bn_y = BN_bin2bn(y, prime_len, NULL);
	if (bn_x == NULL || bn_y == NULL) {
		sk_debug(debug, "ERROR: BN_bin2bn failed");
		rc = -ENOMEM;
		goto out;
	}

	point = EC_POINT_new(group);
	if (point == NULL) {
		sk_debug(debug, "ERROR: EC_POINT_new failed");
		rc = -ENOMEM;
		goto out;
	}

	if (!EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, NULL)) {
		sk_debug(debug, "ERROR: EC_POINT_set_affine_coordinates failed");
		rc = -EIO;
		goto out;
	}

	form = EC_GROUP_get_point_conversion_form(group);
	pub_key_len = EC_POINT_point2buf(group, point, form, &pub_key, NULL);
	if (pub_key_len == 0) {
		sk_debug(debug, "ERROR: EC_POINT_point2buf failed");
		rc = -EIO;
		goto out;
	}

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		sk_debug(debug, "ERROR: OSSL_PARAM_BLD_new failed");
		rc = -ENOMEM;
		goto out;
	}

	if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					     OBJ_nid2sn(nid), 0)
	    || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_PUB_X, bn_x)
	    || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_PUB_Y, bn_y)
	    || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
						 pub_key, pub_key_len)) {
		sk_debug(debug, "ERROR: OSSL_PARAM_BLD_push_xxx failed");
		rc = -EIO;
		goto out;
	}

	if (secure_key != NULL) {
		if (!OSSL_PARAM_BLD_push_octet_string(bld,
						SK_PROV_PKEY_PARAM_SK_BLOB,
						secure_key, secure_key_size)
		    || !OSSL_PARAM_BLD_push_octet_ptr(bld,
						SK_PROV_PKEY_PARAM_SK_FUNCS,
						(void *)sk_funcs,
						sizeof(struct sk_funcs))
		    || !OSSL_PARAM_BLD_push_octet_ptr(bld,
						SK_PROV_PKEY_PARAM_SK_PRIVATE,
						(void *)private, 0)) {
			sk_debug(debug,
				 "ERROR: OSSL_PARAM_BLD_push_xxx failed");
			rc = -EIO;
			goto out;
		}
	}

	rc = sk_openssl_pkey_from_data(bld, EVP_PKEY_EC, pkey, debug);
	if (rc != 0)
		goto out;

	rc = 0;
	sk_debug(debug, "pkey created: %p", *pkey);

out:
	if (group != NULL)
		EC_GROUP_free(group);
	if (point != NULL)
		EC_POINT_free(point);
	if (bn_x != NULL)
		BN_free(bn_x);
	if (bn_y != NULL)
		BN_free(bn_y);
	if (bld != NULL)
		OSSL_PARAM_BLD_free(bld);
	if (pub_key != NULL)
		OPENSSL_free(pub_key);

	return rc;
}

/**
 * Converts an RSA key given by the modulus and public exponent into an
 * OpenSSL PKEY and attaches the secure key together with secure key functions
 * and private pointer to it. If no secure key is provided, a public RSA key
 * only PKEY is returned.
 *
 * @param secure_key        the secure key blob.
 *                          If NULL, a clear key PKEY is created.
 * @param secure_key_size   the size of the secure key blob (ignored if
 *                          secure_key is NULL)
 * @param modulus           the modulus as big endian number
 * @param modulus_length    the length of the modulus in bytes
 * @param pub_exp           the public exponent as big endian number
 * @param pub_exp_length    the length of the public exponent in bytes
 * @param pkey_type         the PKEY type (EVP_PKEY_RSA or EVP_PKEY_RSA_PSS)
 * @param sk_funcs          the secure key functions to operate with the key.
 *                          Ignored if secure_key is NULL, required otherwise.
 * @param private           a private pointer that is passed to the secure key
 *                          functions (can be NULL)
 * @param pkey              On return: A PKEY containing the RSA public key.
 * @param debug             true to enable internal debugging
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to generate the PKEY
 */
int sk_openssl_get_pkey_rsa(const unsigned char *secure_key,
			    size_t secure_key_size,
			    const unsigned char *modulus, size_t modulus_length,
			    const unsigned char *pub_exp, size_t pub_exp_length,
			    int pkey_type, const struct sk_funcs *sk_funcs,
			    const void *private, EVP_PKEY **pkey, bool debug)
{
	BIGNUM *bn_modulus = NULL, *bn_pub_exp = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	int rc;

	if (pkey == NULL || modulus == NULL || pub_exp == NULL)
		return -EINVAL;
	if (secure_key != NULL && (secure_key_size == 0 || sk_funcs == NULL))
		return -EINVAL;
	if (pkey_type != EVP_PKEY_RSA && pkey_type != EVP_PKEY_RSA_PSS)
		return -EINVAL;

	*pkey = NULL;

	bn_modulus = BN_bin2bn(modulus, modulus_length, NULL);
	bn_pub_exp = BN_bin2bn(pub_exp, pub_exp_length, NULL);
	if (bn_modulus == NULL || bn_pub_exp == NULL) {
		sk_debug(debug, "ERROR: BN_bin2bn failed");
		rc = -ENOMEM;
		goto out;
	}

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		sk_debug(debug, "ERROR: OSSL_PARAM_BLD_new failed");
		rc = -ENOMEM;
		goto out;
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_modulus) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_pub_exp)) {
		sk_debug(debug, "ERROR: OSSL_PARAM_BLD_push_xxx failed");
		rc = -EIO;
		goto out;
	}

	if (secure_key != NULL) {
		if (!OSSL_PARAM_BLD_push_octet_string(bld,
						SK_PROV_PKEY_PARAM_SK_BLOB,
						secure_key, secure_key_size)
		    || !OSSL_PARAM_BLD_push_octet_ptr(bld,
						SK_PROV_PKEY_PARAM_SK_FUNCS,
						(void *)sk_funcs,
						sizeof(struct sk_funcs))
		    || !OSSL_PARAM_BLD_push_octet_ptr(bld,
						SK_PROV_PKEY_PARAM_SK_PRIVATE,
						(void *)private, 0)) {
			sk_debug(debug,
				 "ERROR: OSSL_PARAM_BLD_push_xxx failed");
			rc = -EIO;
			goto out;
		}
	}

	rc = sk_openssl_pkey_from_data(bld, pkey_type, pkey, debug);
	if (rc != 0)
		goto out;

	rc = 0;
	sk_debug(debug, "pkey created: %p", *pkey);

out:
	if (bn_modulus != NULL)
		BN_free(bn_modulus);
	if (bn_pub_exp != NULL)
		BN_free(bn_pub_exp);
	if (bld != NULL)
		OSSL_PARAM_BLD_free(bld);

	return rc;
}

/**
 * Get the curve NID of the EC pkey
 */
int SK_OPENSSL_get_curve_from_ec_pkey(EVP_PKEY *pkey)
{
	size_t curve_len;
	char curve[80];

	if (EVP_PKEY_id(pkey) != EVP_PKEY_EC)
		return NID_undef;

	if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
					    curve, sizeof(curve), &curve_len))
		return NID_undef;

	return OBJ_sn2nid(curve);
}

#endif
