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

#ifndef UTILS_H
#define UTILS_H

#include "lib/zt_common.h"

#include "pkey.h"

int sysfs_is_card_online(unsigned int card, enum card_type cardtype);

int sysfs_is_apqn_online(unsigned int card, unsigned int domain,
			 enum card_type cardtype);

int sysfs_get_card_level(unsigned int card);

enum card_type sysfs_get_card_type(unsigned int card);

#define SERIALNR_LENGTH		17

int sysfs_get_serialnr(unsigned int card, char *serialnr, bool verbose);

struct fw_version {
	unsigned int	major;
	unsigned int	minor;
	unsigned int	api_ordinal;
};

int sysfs_get_firmware_version(unsigned int card, struct fw_version *fw_version,
			       bool verbose);

#define MK_STATE_EMPTY		0
#define MK_STATE_PARTIAL	1 /* For CCA only */
#define MK_STATE_FULL		2 /* For CCA only */
#define MK_STATE_VALID		3
#define MK_STATE_INVALID	4
#define MK_STATE_UNCOMMITTED	5 /* For EP11 only */
#define MK_STATE_COMMITTED	6 /* For EP11 only */
#define MK_STATE_UNKNOWN	-1

struct mk_info_reg {
	int	mk_state;
	u8	mkvp[MKVP_LENGTH];
};

struct mk_info {
	struct mk_info_reg	new_mk;
	struct mk_info_reg	cur_mk;
	struct mk_info_reg	old_mk; /* only available on CCA cards */
};

int sysfs_get_mkvps(unsigned int card, unsigned int domain,
		    struct mk_info *mk_info, bool verbose);

typedef int(*apqn_handler_t) (unsigned int card, unsigned int domain,
			      void *handler_data);

int handle_apqns(const char *apqns, enum card_type cardtype,
		 apqn_handler_t handler, void *handler_data, bool verbose);

int print_mk_info(const char *apqns, enum card_type cardtype, bool verbose);

int cross_check_apqns(const char *apqns, u8 *mkvp, int min_level,
		      const struct fw_version *min_fw_version,
		      enum card_type cardtype, bool print_mks, bool verbose);

bool prompt_for_yes(bool verbose);

char *printable_mkvp(enum card_type cardtype, u8 *mkvp);

int copy_file(const char *in_file_name, const char *out_file_name,
	      size_t num_bytes);

char *read_passphrase_as_base64(const char *filename, bool verbose);
int store_passphrase_from_base64(const char *hex_string, const char *filename,
				 bool verbose);

#endif
