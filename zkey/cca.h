/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the CCA host library.
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CCA_H
#define CCA_H

#include "lib/zt_common.h"

#define METHOD_OLD_TO_CURRENT	"RTCMK   "
#define METHOD_CURRENT_TO_NEW	"RTNMK   "

typedef void (*t_CSNBKTC)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  unsigned char *key_identifier);

typedef void (*t_CSUACFV)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *version_data_length,
			  unsigned char *version_data);

struct cca_version {
	unsigned int ver;
	unsigned int rel;
	unsigned int mod;
};

struct cca_lib {
	void *lib_csulcca;
	t_CSNBKTC dll_CSNBKTC;
	t_CSUACFV dll_CSUACFV;
	struct cca_version version;
};

int load_cca_library(struct cca_lib *cca, bool verbose);

int key_token_change(struct cca_lib *cca,
		     u8 *secure_key, unsigned int secure_key_size,
		     char *method, bool verbose);

#endif
