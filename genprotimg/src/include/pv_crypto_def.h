/*
 * PV cryptography related definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_CRYPTO_DEF_H
#define PV_CRYPTO_DEF_H

#include <stdint.h>

#include "lib/zt_common.h"

/* IBM signing key subject */
#define PV_IBM_Z_SUBJECT_COMMON_NAME "International Business Machines Corporation"
#define PV_IBM_Z_SUBJECT_COUNTRY_NAME "US"
#define PV_IBM_Z_SUBJECT_LOCALITY_NAME "Poughkeepsie"
#define PV_IBM_Z_SUBJECT_ORGANIZATIONONAL_UNIT_NAME_SUFFIX "Key Signing Service"
#define PV_IBM_Z_SUBJECT_ORGANIZATION_NAME "International Business Machines Corporation"
#define PV_IBM_Z_SUBJECT_STATE "New York"
#define PV_IMB_Z_SUBJECT_ENTRY_COUNT 6

/* Minimum security level for the keys/certificates used to establish a chain of
 * trust (see https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_auth_level.html
 * for details).
 */
#define PV_CERTS_SECURITY_LEVEL 2

/* SKID for DigiCert Assured ID Root CA */
#define DIGICERT_ASSURED_ID_ROOT_CA_SKID "45EBA2AFF492CB82312D518BA7A7219DF36DC80F"

union ecdh_pub_key {
	struct {
		uint8_t x[80];
		uint8_t y[80];
	};
	uint8_t data[160];
} __packed;

#endif
