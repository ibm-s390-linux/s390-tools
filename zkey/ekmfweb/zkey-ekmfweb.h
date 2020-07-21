/*
 * zkey-ekmfweb - EKMFWeb zkey KMS plugin
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZKEY_EKMFWEB_H
#define ZKEY_EKMFWEB_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "ekmfweb/ekmfweb.h"

struct plugin_handle {
	const char *config_path;
	mode_t config_path_mode;
	gid_t config_path_owner;
	struct properties *properties;
	bool apqns_configured;
	bool connection_configured;
	bool settings_retrieved;
	bool templates_retrieved;
	bool config_complete;
	struct ekmf_config ekmf_config;
	CURL *curl_handle;
	char error_msg[1024];
	bool verbose;
};

#define EKMFWEB_CONFIG_FILE			"ekmfweb.conf"
#define EKMFWEB_CONFIG_SERVER_CERT_FILE		"server-cert.pem"
#define EKMFWEB_CONFIG_SERVER_PUBKEY_FILE	"server-pubkey.pem"
#define EKMFWEB_CONFIG_LOGIN_TOKEN_FILE		"login.token"
#define EKMFWEB_CONFIG_EKMFWEB_PUBKEY_FILE	"ekmfweb-pubkey.pem"

#define EKMFWEB_CONFIG_APQNS			"apqns"
#define EKMFWEB_CONFIG_URL			"url"
#define EKMFWEB_CONFIG_CA_BUNDLE		"ca-bundle"
#define EKMFWEB_CONFIG_CLIENT_CERT		"client-cert"
#define EKMFWEB_CONFIG_CLIENT_KEY		"client-key"
#define EKMFWEB_CONFIG_CLIENT_KEY_PASSPHRASE	"client-key-passphrase"
#define EKMFWEB_CONFIG_SERVER_CERT		"server-cert"
#define EKMFWEB_CONFIG_SERVER_PUBKEY		"server-pubkey"
#define EKMFWEB_CONFIG_VERIFY_SERVER_CERT	"verify-server-cert"
#define EKMFWEB_CONFIG_VERIFY_HOSTNAME		"verify-hostname"
#define EKMFWEB_CONFIG_LOGIN_TOKEN		"login-token"
#define EKMFWEB_CONFIG_PASSCODE_URL		"passcode-url"
#define EKMFWEB_CONFIG_EKMFWEB_PUBKEY		"ekmfweb-pubkey"
#define EKMFWEB_CONFIG_TEMPLATE_XTS1		"template-xts1"
#define EKMFWEB_CONFIG_TEMPLATE_XTS2		"template-xts2"
#define EKMFWEB_CONFIG_TEMPLATE_NONXTS		"template-nonxts"
#define EKMFWEB_CONFIG_TEMPLATE_IDENTITY	"template-identity"
#define EKMFWEB_CONFIG_TEMPLATE_XTS1_LABEL	"template-xts1-label"
#define EKMFWEB_CONFIG_TEMPLATE_XTS2_LABEL	"template-xts2-label"
#define EKMFWEB_CONFIG_TEMPLATE_NONXTS_LABEL	"template-nonxts-label"
#define EKMFWEB_CONFIG_TEMPLATE_IDENTITY_LABEL	"template-identity-label"
#define EKMFWEB_CONFIG_TEMPLATE_XTS1_ID		"template-xts1-id"
#define EKMFWEB_CONFIG_TEMPLATE_XTS2_ID		"template-xts2-id"
#define EKMFWEB_CONFIG_TEMPLATE_NONXTS_ID	"template-nonxts-id"
#define EKMFWEB_CONFIG_TEMPLATE_IDENTITY_ID	"template-identity-id"

#define EKMFWEB_PASSCODE_URL			"/administration/passcode"
#define EKMFWEB_TEMPLATE_STATE_ACTIVE		"ACTIVE"
#define EKMFWEB_TEMPLATE_STATE_HISTORY		"HISTORY"
#define EKMFWEB_KEYSTORE_TYPE_PERV_ENCR		"PERVASIVE_ENCRYPTION"
#define EKMFWEB_KEYSTORE_TYPE_IDENTITY		"IDENTITY"
#define EKMFWEB_KEY_ALGORITHM_AES		"AES"
#define EKMFWEB_KEY_ALGORITHM_ECC		"ECC"
#define EKMFWEB_KEY_ALGORITHM_RSA		"RSA"
#define EKMFWEB_KEY_TYPE_CIPHER			"CIPHER"
#define EKMFWEB_KEY_STATE_ACTIVE		"ACTIVE"

#endif
