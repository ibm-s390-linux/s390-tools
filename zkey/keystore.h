/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Keystore handling functions
 *
 * Copyright IBM Corp. 2018, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <stdbool.h>

#include "pkey.h"
#include "kms.h"

struct keystore {
	bool verbose;
	char *directory;
	int lock_fd;
	mode_t mode;
	gid_t owner;
	struct kms_info *kms_info;
};

#define PROP_NAME_KEY_TYPE		"key-type"
#define PROP_NAME_CIPHER		"cipher"
#define PROP_NAME_IV_MODE		"iv-mode"
#define PROP_NAME_DESCRIPTION		"description"
#define PROP_NAME_VOLUMES		"volumes"
#define PROP_NAME_APQNS			"apqns"
#define PROP_NAME_SECTOR_SIZE		"sector-size"
#define PROP_NAME_CREATION_TIME		"creation-time"
#define PROP_NAME_CHANGE_TIME		"update-time"
#define PROP_NAME_REENC_TIME		"reencipher-time"
#define PROP_NAME_KEY_VP		"verification-pattern"
#define PROP_NAME_VOLUME_TYPE		"volume-type"
#define PROP_NAME_KMS			"kms"
#define PROP_NAME_KMS_KEY_ID		"kms-key-id"
#define PROP_NAME_KMS_KEY_LABEL		"kms-key-label"
#define PROP_NAME_KMS_XTS_KEY1_ID	"kms-xts-key1-id"
#define PROP_NAME_KMS_XTS_KEY1_LABEL	"kms-xts-key1-label"
#define PROP_NAME_KMS_XTS_KEY2_ID	"kms-xts-key2-id"
#define PROP_NAME_KMS_XTS_KEY2_LABEL	"kms-xts-key2-label"

struct keystore *keystore_new(const char *directory,
			      struct kms_info *kms_info, bool verbose);

int keystore_generate_key(struct keystore *keystore, const char *name,
			  const char *description, const char *volumes,
			  const char *apqns, bool noapqncheck,
			  size_t sector_size, size_t keybits, bool xts,
			  const char *clear_key_file, const char *volume_type,
			  const char *key_type, bool gen_passphrase,
			  const char *passphrase_file, int pkey_fd);

int keystore_generate_key_kms(struct keystore *keystore, const char *name,
			      const char *description, const char *volumes,
			      size_t sector_size, size_t keybits, bool xts,
			      const char *volume_type, const char *key_type,
			      bool gen_passphrase, const char *passphrase_file,
			      struct kms_option *kms_options,
			      size_t num_kms_options);

int keystore_import_key(struct keystore *keystore, const char *name,
			const char *description, const char *volumes,
			const char *apqns, bool noapqncheck, size_t sector_size,
			const char *import_file, const char *volume_type,
			bool gen_passphrase, const char *passphrase_file,
			struct ext_lib *lib);

int keystore_change_key(struct keystore *keystore, const char *name,
			const char *description, const char *volumes,
			const char *apqns, bool noapqncheck,
			long int sector_size, const char *volume_type,
			bool gen_passphrase, const char *passphrase_file,
			bool remove_passphrase, bool quiet);

int keystore_rename_key(struct keystore *keystore, const char *name,
			const char *newname);

int keystore_validate_key(struct keystore *keystore, const char *name_filter,
			  const char *apqn_filter, bool noapqncheck,
			  int pkey_fd);

int keystore_reencipher_key(struct keystore *keystore, const char *name_filter,
			    const char *apqn_filter,
			    bool from_old, bool to_new, bool inplace,
			    bool staged, bool complete, int pkey_fd,
			    struct ext_lib *lib);

int keystore_copy_key(struct keystore *keystore, const char *name,
		      const char *newname, const char *volumes, bool local);

int keystore_export_key(struct keystore *keystore, const char *name,
			const char *export_file);

int keystore_remove_key(struct keystore *keystore, const char *name,
			bool quiet, struct kms_option *kms_options,
			size_t num_kms_options);

int keystore_list_keys(struct keystore *keystore, const char *name_filter,
		       const char *volume_filter, const char *apqn_filter,
		       const char *volume_type, const char *key_type,
		       bool local, bool kms_bound);

int keystore_cryptsetup(struct keystore *keystore, const char *volume_filter,
			bool execute, const char *volume_type,
			const char *keyfile, size_t keyfile_offset,
			size_t keyfile_size, size_t tries, bool batch_mode,
			bool open, bool format);

int keystore_crypttab(struct keystore *keystore, const char *volume_filter,
		      const char *volume_type, const char *keyfile,
		      size_t keyfile_offset, size_t keyfile_size, size_t tries);

int keystore_convert_key(struct keystore *keystore, const char *name,
			 const char *key_type, bool noapqncheck, bool quiet,
			 int pkey_fd, struct ext_lib *lib);

int keystore_kms_keys_set_property(struct keystore *keystore,
				   const char *key_type,
				   const char *prop_name,
				   const char *prop_value);

int keystore_kms_keys_unbind(struct keystore *keystore);

int keystore_msg_for_kms_key(struct keystore *keystore, const char *key_type,
			     const char *msg);

int keystore_import_kms_keys(struct keystore *keystore,
			     const char *label_filter,
			     const char *name_filter,
			     const char *volume_filter,
			     const char *volume_type,
			     struct kms_option *kms_options,
			     size_t num_kms_options,
			     bool batch_mode, bool novolcheck);

int keystore_refresh_kms_keys(struct keystore *keystore,
			      const char *name_filter,
			      const char *volume_filter,
			      const char *volume_type, const char *key_type,
			      bool refres_properties, bool novolcheck);

void keystore_free(struct keystore *keystore);



#endif
