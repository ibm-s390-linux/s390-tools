/*
 * zkey-kmip - KMIP zkey KMS plugin
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZKEY_KMIP_H
#define ZKEY_KMIP_H

#include <stddef.h>
#include <stdbool.h>

#include "kmipclient/kmipclient.h"

#include "libseckey/sk_openssl.h"

#include "../plugin-utils.h"
#include "../pkey.h"

struct plugin_handle {
	struct plugin_data pd;
	bool apqns_configured;
	enum card_type card_type;
	bool identity_key_generated;
	const char *identity_secure_key;
	bool client_cert_avail;
	bool config_complete;
	struct sk_ext_lib ext_lib;
	struct sk_ext_cca_lib cca_lib;
	struct sk_ext_ep11_lib ep11_lib;
	struct ep11_lib ep11;
	struct cca_lib cca;
};

#define KMIP_CONFIG_FILE			"kmip.conf"
#define KMIP_CONFIG_IDENTITY_KEY_FILE		"identity-key.skey"
#define KMIP_CONFIG_IDENTITY_KEY_REENC_FILE	"identity-key.reenc"
#define KMIP_CONFIG_CLIENT_CERTIFICATE_FILE	"client-certificate.pem"

#define KMIP_CONFIG_APQNS			"apqns"
#define KMIP_CONFIG_APQN_TYPE			"apqn-type"
#define KMIP_CONFIG_IDENTITY_KEY		"identity-key"
#define KMIP_CONFIG_IDENTITY_KEY_REENC		"identity-key-reenc"
#define KMIP_CONFIG_IDENTITY_KEY_ALGORITHM	"identity-key-algorithm"
#define KMIP_CONFIG_IDENTITY_KEY_PARAMS		"identity-key-params"
#define KMIP_CONFIG_CLIENT_CERTIFICATE		"client-certificate"
#define KMIP_CONFIG_CLIENT_CERT_ALGORITHM	"client-certificate-algorithm"

#define KMIP_APQN_TYPE_CCA			"CCA"
#define KMIP_APQN_TYPE_EP11			"EP11"

#define KMIP_KEY_ALGORITHM_ECC			"ECC"
#define KMIP_KEY_ALGORITHM_RSA			"RSA"
#define KMIP_KEY_ALGORITHM_RSA_PSS		"RSA-PSS"

#define KMIP_DEFAULT_IDENTITY_KEY_SPEC		"ECC:secp521r1"

#define KMIP_MAX_KEY_TOKEN_SIZE			8192

#define KMIP_CERT_EXT_KEY_USAGE			"extendedKeyUsage"
#define KMIP_CERT_EXT_KEY_USAGE_CLIENT_AUTH	"extendedKeyUsage=clientAuth"
#define KMIP_CERT_EXT_SUBJECT_ALT_NAME		"subjectAltName"
#define KMIP_CERT_EXT_SUBJECT_ALT_NAME_DNS	"subjectAltName=DNS:%s"


#endif
