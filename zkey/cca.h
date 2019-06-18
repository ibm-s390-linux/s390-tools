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

typedef void (*t_CSUACFQ)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *verb_data_length,
			  unsigned char *verb_data);

typedef void (*t_CSUACRA)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *ressource_name_length,
			  unsigned char *ressource_name);

typedef void (*t_CSUACRD)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *ressource_name_length,
			  unsigned char *ressource_name);

struct cca_version {
	unsigned int ver;
	unsigned int rel;
	unsigned int mod;
};

struct cca_lib {
	void *lib_csulcca;
	t_CSNBKTC dll_CSNBKTC;
	t_CSUACFV dll_CSUACFV;
	t_CSUACFQ dll_CSUACFQ;
	t_CSUACRA dll_CSUACRA;
	t_CSUACRD dll_CSUACRD;
	struct cca_version version;
};

int load_cca_library(struct cca_lib *cca, bool verbose);

int key_token_change(struct cca_lib *cca,
		     u8 *secure_key, unsigned int secure_key_size,
		     char *method, bool verbose);

int select_cca_adapter(struct cca_lib *cca, int card, int domain, bool verbose);

#define FLAG_SEL_CCA_MATCH_CUR_MKVP	0x01
#define FLAG_SEL_CCA_MATCH_OLD_MKVP	0x02
#define FLAG_SEL_CCA_NEW_MUST_BE_SET	0x80

int select_cca_adapter_by_mkvp(struct cca_lib *cca, u64 mkvp, const char *apqns,
			       unsigned int flags, bool verbose);

void print_msg_for_cca_envvars(const char *key_name);

#endif
