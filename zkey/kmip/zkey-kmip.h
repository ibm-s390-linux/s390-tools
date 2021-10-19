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
	const char *server;
	bool client_cert_avail;
	bool connection_configured;
	bool wrapping_key_avail;
	bool config_complete;
	struct sk_ext_lib ext_lib;
	struct sk_ext_cca_lib cca_lib;
	struct sk_ext_ep11_lib ep11_lib;
	struct ep11_lib ep11;
	struct cca_lib cca;
	struct kmip_conn_config kmip_config;
	struct kmip_version kmip_version;
	struct kmip_profile *profile;
	struct kmip_connection *connection;
};

#define KMIP_CONFIG_FILE			"kmip.conf"
#define KMIP_CONFIG_IDENTITY_KEY_FILE		"identity-key.skey"
#define KMIP_CONFIG_IDENTITY_KEY_REENC_FILE	"identity-key.reenc"
#define KMIP_CONFIG_CLIENT_CERTIFICATE_FILE	"client-certificate.pem"
#define KMIP_CONFIG_SERVER_CERT_FILE		"server-cert.pem"
#define KMIP_CONFIG_SERVER_PUBKEY_FILE		"server-pubkey.pem"
#define KMIP_CONFIG_WRAPPING_KEY_FILE		"wrapping-key.skey"
#define KMIP_CONFIG_WRAPPING_KEY_REENC_FILE	"wrapping-key.reenc"

#define KMIP_CONFIG_APQNS			"apqns"
#define KMIP_CONFIG_APQN_TYPE			"apqn-type"
#define KMIP_CONFIG_IDENTITY_KEY		"identity-key"
#define KMIP_CONFIG_IDENTITY_KEY_REENC		"identity-key-reenc"
#define KMIP_CONFIG_IDENTITY_KEY_ALGORITHM	"identity-key-algorithm"
#define KMIP_CONFIG_IDENTITY_KEY_PARAMS		"identity-key-params"
#define KMIP_CONFIG_CLIENT_CERTIFICATE		"client-certificate"
#define KMIP_CONFIG_CLIENT_CERT_ALGORITHM	"client-certificate-algorithm"
#define KMIP_CONFIG_SERVER			"kmip-server"
#define KMIP_CONFIG_SERVER_INFO			"kmip-server-info"
#define KMIP_CONFIG_PROFILE			"profile"
#define KMIP_CONFIG_PROTOCOL_VERSION		"protocol-version"
#define KMIP_CONFIG_CA_BUNDLE			"ca-bundle"
#define KMIP_CONFIG_SERVER_CERT			"server-cert"
#define KMIP_CONFIG_SERVER_PUBKEY		"server-pubkey"
#define KMIP_CONFIG_VERIFY_SERVER_CERT		"verify-server-cert"
#define KMIP_CONFIG_VERIFY_HOSTNAME		"verify-hostname"
#define KMIP_CONFIG_WRAPPING_KEY		"wrapping-key"
#define KMIP_CONFIG_WRAPPING_KEY_REENC		"wrapping-key-reenc"
#define KMIP_CONFIG_WRAPPING_KEY_ALGORITHM	"wrapping-key-algorithm"
#define KMIP_CONFIG_WRAPPING_KEY_PARAMS		"wrapping-key-params"
#define KMIP_CONFIG_WRAPPING_KEY_ID		"wrapping-key-id"
#define KMIP_CONFIG_WRAPPING_KEY_LABEL		"wrapping-key-label"

#define KMIP_APQN_TYPE_CCA			"CCA"
#define KMIP_APQN_TYPE_EP11			"EP11"

#define KMIP_KEY_ALGORITHM_ECC			"ECC"
#define KMIP_KEY_ALGORITHM_RSA			"RSA"
#define KMIP_KEY_ALGORITHM_RSA_PSS		"RSA-PSS"

#define KMIP_DEFAULT_IDENTITY_KEY_SPEC		"ECC:secp521r1"

#define KMIP_CONFIG_PROTOCOL_VERSION_PROFILE	"PROFILE"

#define KMIP_MAX_KEY_TOKEN_SIZE			8192

#define KMIP_CERT_EXT_KEY_USAGE			"extendedKeyUsage"
#define KMIP_CERT_EXT_KEY_USAGE_CLIENT_AUTH	"extendedKeyUsage=clientAuth"
#define KMIP_CERT_EXT_SUBJECT_ALT_NAME		"subjectAltName"
#define KMIP_CERT_EXT_SUBJECT_ALT_NAME_DNS	"subjectAltName=DNS:%s"

#define KMIP_PROFILES_LOCATION			"/etc/zkey/kmip/profiles"
#define KMIP_PROFILES_LOCATION_ENVVAR		"ZKEY_KMIP_PROFILES"
#define KMIP_PROFILES_FILE_TYPE			".profile"
#define KMIP_PROFILES_FILE_TYPE_LEN		8
#define KMIP_PROFILES_DEFAULT_PROFILE_NAME	"default"
#define KMIP_PROFILES_DEFAULT_PROFILE	KMIP_PROFILES_DEFAULT_PROFILE_NAME \
					KMIP_PROFILES_FILE_TYPE

#define KMIP_KEY_STATE_ACTIVE			"ACTIVE"
#define KMIP_KEY_STATE_DEACTIVATED		"DEACTIVATED"
#define KMIP_KEY_STATE_COMPROMISED		"COMPROMISED"
#define KMIP_KEY_STATE_DESTROYED		"DESTROYED"
#define KMIP_KEY_STATE_DESTROYED_COMPROMISED	"DESTROYED-COMPROMISED"

#define KMIP_PROFILES_SERVER_REGEX		"server-regex"
#define KMIP_PROFILES_KMIP_VERSION		"kmip-version"
#define KMIP_PROFILES_TRANSPORT			"transport"
#define KMIP_PROFILES_ENCODING			"encoding"
#define KMIP_PROFILES_HTTPS_URI			"https-uri"
#define KMIP_PROFILES_AUTH_SCHEME		"auth-scheme"
#define KMIP_PROFILES_WRAP_KEY_ALGORITHM	"wrap-key-algorithm"
#define KMIP_PROFILES_WRAP_KEY_PARAMS		"wrap-key-params"
#define KMIP_PROFILES_WRAP_KEY_FORMAT		"wrap-key-format"
#define KMIP_PROFILES_WRAP_PADDING_METHOD	"wrap-padding-method"
#define KMIP_PROFILES_WRAP_HASHING_ALOGRITHM	"wrap-hashing-algorithm"
#define KMIP_PROFILES_SUPPORTS_LINK_ATTR	"supports-link-attr"
#define KMIP_PROFILES_SUPPORTS_DESCRIPTION_ATTR	"supports-description-attr"
#define KMIP_PROFILES_SUPPORTS_COMMENT_ATTR	"supports-comment-attr"
#define KMIP_PROFILES_CUSTOM_ATTR_SCHEME	"custom-attr-scheme"
#define KMIP_PROFILES_SUPPORTS_SENSITIVE_ATTR	"supports-sensitive-attr"
#define KMIP_PROFILES_CHECK_ALWAYS_SENS_ATTR	"check-always-sensitive-attr"

#define KMIP_PROFILES_VERSION_AUTO		"AUTO"

#define KMIP_PROFILES_TRANSPORT_TLS		"TLS"
#define KMIP_PROFILES_TRANSPORT_HTTPS		"HTTPS"

#define KMIP_PROFILES_ENCODING_TTLV		"TTLV"
#define KMIP_PROFILES_ENCODING_JSON		"JSON"
#define KMIP_PROFILES_ENCODING_XML		"XML"

#define KMIP_PROFILES_HTTPS_URI_DEFAULT		"/kmip"

#define KMIP_PROFILES_AUTH_TLS_CLIENT_CERT	"TLSClientCert"

#define KMIP_PROFILES_WRAP_KEY_ALGORITHM_RSA	"RSA"

#define KMIP_PROFILES_WRAP_KEY_FORMAT_PKCS1	"PKCS1"
#define KMIP_PROFILES_WRAP_KEY_FORMAT_PKCS8	"PKCS8"
#define KMIP_PROFILES_WRAP_KEY_FORMAT_TRANSP	"TransparentPublicKey"

#define KMIP_PROFILES_WRAP_PADDING_PKCS1_5	"PKCS1.5"
#define KMIP_PROFILES_WRAP_PADDING_OAEP		"OAEP"

#define KMIP_PROFILES_WRAP_HASHING_ALGO_SHA1	"SHA-1"
#define KMIP_PROFILES_WRAP_HASHING_ALGO_SHA256	"SHA-256"

#define KMIP_PROFILES_BOOLEAN_TRUE		"TRUE"
#define KMIP_PROFILES_BOOLEAN_FALSE		"FALSE"

#define KMIP_PROFILES_CUST_ATTR_SCHEME_V1	"v1-style"
#define KMIP_PROFILES_CUST_ATTR_SCHEME_V2	"v2-style"

enum kmip_profile_auth_scheme {
	KMIP_PROFILE_AUTH_TLS_CLIENT_CERT = 1,
};

enum kmip_profile_cust_attr_scheme {
	KMIP_PROFILE_CUST_ATTR_V1_STYLE	= 1, /* x-zkey-something */
	KMIP_PROFILE_CUST_ATTR_V2_STYLE	= 2, /* zkey-something */
};

struct kmip_profile {
	const char *name;
	const char *server_regex;
	struct kmip_version kmip_version; /* 0.0 means AUTO */
	enum kmip_transport transport; /* Default: TLS */
	enum kmip_encoding encoding; /* Default : TTLV */
	const char *https_uri; /* Default '/kmip' for HTTPS transport */
	enum kmip_profile_auth_scheme auth_scheme; /* Default: TLSClientCert */
	enum kmip_crypto_algo wrap_key_algo; /* only RSA supported currently */
	size_t wrap_key_size; /* Required for RSA */
	enum kmip_key_format_type wrap_key_format; /* Default for RSA: PKCS1 */
	enum kmip_padding_method wrap_padding_method; /* RSA default: PKCS 1.5*/
	enum kmip_hashing_algo wrap_hashing_algo; /* OAEP default: SHA-1 */
	bool supports_link_attr; /* Default: FALSE */
	bool supports_description_attr; /* Default: FALSE */
	bool supports_comment_attr; /* Default: FALSE */
	enum kmip_profile_cust_attr_scheme cust_attr_scheme;
	bool supports_sensitive_attr; /* Default: FALSE */
	bool check_always_sensitive_attr; /* Default: FALSE */
};

int profile_read(struct plugin_handle *ph, const char *profile_dir,
		 const char *profile_file, struct kmip_profile **profile);
void profile_free(struct kmip_profile *profile);
int profile_find_by_server_info(struct plugin_handle *ph,
				const char *server_info,
				struct kmip_profile **profile);
int profile_find_by_name(struct plugin_handle *ph, const char *profile_name,
			 struct kmip_profile **profile);

#endif
