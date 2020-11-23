/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines functions for Key Management System (KMS) plugin
 * handling
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef KMS_H
#define KMS_H

#include "kms-plugin.h"
#include "properties.h"
#include "keystore.h"

struct kms_info {
	void *plugin_lib;
	const struct kms_functions *funcs;
	char *plugin_name;
	struct properties *props;
	struct kms_apqn *apqns;
	size_t num_apqns;
	kms_handle_t handle;
};

struct keystore;

int list_kms_plugins(bool verbose);

int check_for_kms_plugin(struct kms_info *kms_info, bool verbose);

int init_kms_plugin(struct kms_info *kms_info, bool verbose);

void free_kms_plugin(struct kms_info *kms_info);

void print_last_kms_error(const struct kms_info *kms_info);

int bind_kms_plugin(struct keystore *keystore, const char *plugin,
		    bool verbose);

int unbind_kms_plugin(struct kms_info *kms_info, struct keystore *keystore,
		      bool verbose);

int print_kms_info(struct kms_info *kms_info);

int get_kms_options(struct kms_info *kms_info, struct util_opt *opt_vec,
		    const char *placeholder_cmd, const char *plugin_command,
		    const char *opt_vec_command, int *first_plugin_opt,
		    bool verbose);

int handle_kms_option(struct kms_info *kms_info, struct util_opt *opt_vec,
		      int first_kms_option, const char *command, int option,
		      const char *optarg, struct kms_option **kms_options,
		      size_t *num_kms_options, bool verbose);

int configure_kms_plugin(struct keystore *keystore, const char *apqns,
			 struct kms_option *kms_options, size_t num_kms_options,
			 bool has_plugin_optins, bool verbose);

int reencipher_kms(struct kms_info *kms_info, bool from_old, bool to_new,
		   bool inplace, bool staged, bool complete,
		   struct kms_option *kms_options, size_t num_kms_options,
		   bool verbose);

int perform_kms_login(struct kms_info *kms_info, bool verbose);

int get_kms_apqns_for_key_type(struct kms_info *kms_info, const char *key_type,
			       bool cross_check, char **apqns, bool verbose);

int generate_kms_key(struct kms_info *kms_info, const char *name,
		     const char *key_type, struct properties *key_props,
		     bool xts, size_t keybits, const char *filename,
		     const char *passphrase_file,
		     struct kms_option *kms_options, size_t num_kms_options,
		     bool verbose);

int set_kms_key_properties(struct kms_info *kms_info,
			   struct properties *key_props,
			   const char *name, const char *description,
			   const char *volumes, const char *vol_type,
			   const char *sector_size,
			   const char **passphrase_file,
			   bool verbose);

int remove_kms_key(struct kms_info *kms_info, struct properties *key_props,
		   struct kms_option *kms_options, size_t num_kms_options,
		   bool verbose);

typedef int (*kms_process_callback)(const char *key1_id, const char *key1_label,
				    const char *key2_id, const char *key2_label,
				    bool xts, const char *name,
				    const char *key_type, size_t key_bits,
				    const char *description, const char *cipher,
				    const char *iv_mode, const char *volumes,
				    const char *volume_type, size_t sector_size,
				    const char *passphrase,
				    const char *addl_info_argz,
				    size_t addl_info_len,
				    void *private_data);

int process_kms_keys(struct kms_info *kms_info,
		     const char *label_filter, const char *name_filter,
		     const char *volume_filter, const char *volume_type,
		     struct kms_option *kms_options,  size_t num_kms_options,
		     kms_process_callback callback, void *private_data,
		     bool verbose);

int list_kms_keys(struct kms_info *kms_info, const char *label_filter,
		  const char *name_filter, const char *volume_filter,
		  const char *volume_type, struct kms_option *kms_options,
		  size_t num_kms_options, bool verbose);

int import_kms_key(struct kms_info *kms_info, const char *key1_id,
		   const char *key2_id, bool xts, const char *name,
		   unsigned char *key_blob, size_t *key_blob_length,
		   bool verbose);

int refresh_kms_key(struct kms_info *kms_info, struct properties *key_props,
		    char **description, char **cipher, char **iv_mode,
		    char **volumes, char **volume_type, ssize_t *sector_size,
		    const char *filename, const char *passphrase_file,
		    bool verbose);

#endif
