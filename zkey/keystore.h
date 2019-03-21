/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Keystore handling functions
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <stdbool.h>

#include "cca.h"
#include "pkey.h"

struct keystore {
	bool verbose;
	char *directory;
	int lock_fd;
	mode_t mode;
	gid_t owner;
};

struct keystore *keystore_new(const char *directory, bool verbose);

int keystore_generate_key(struct keystore *keystore, const char *name,
			  const char *description, const char *volumes,
			  const char *apqns, bool noapqncheck,
			  size_t sector_size, size_t keybits, bool xts,
			  const char *clear_key_file, const char *volume_type,
			  int pkey_fd);

int keystore_import_key(struct keystore *keystore, const char *name,
			const char *description, const char *volumes,
			const char *apqns, bool noapqncheck, size_t sector_size,
			const char *import_file, const char *volume_type);

int keystore_change_key(struct keystore *keystore, const char *name,
			const char *description, const char *volumes,
			const char *apqns, bool noapqncheck,
			long int sector_size, const char *volume_type);

int keystore_rename_key(struct keystore *keystore, const char *name,
			const char *newname);

int keystore_validate_key(struct keystore *keystore, const char *name_filter,
			  const char *apqn_filter, bool noapqncheck,
			  int pkey_fd);

int keystore_reencipher_key(struct keystore *keystore, const char *name_filter,
			    const char *apqn_filter,
			    bool from_old, bool to_new, bool inplace,
			    bool staged, bool complete, int pkey_fd,
			    struct cca_lib *cca);

int keystore_copy_key(struct keystore *keystore, const char *name,
		      const char *newname, const char *volumes);

int keystore_export_key(struct keystore *keystore, const char *name,
			const char *export_file);

int keystore_remove_key(struct keystore *keystore, const char *name,
			bool quiet);

int keystore_list_keys(struct keystore *keystore, const char *name_filter,
		       const char *volume_filter, const char *apqn_filter,
		       const char *volume_type);

int keystore_cryptsetup(struct keystore *keystore, const char *volume_filter,
			bool execute, const char *volume_type,
			const char *keyfile, size_t keyfile_offset,
			size_t keyfile_size, size_t tries, bool batch_mode,
			bool open, bool format);

int keystore_crypttab(struct keystore *keystore, const char *volume_filter,
		      const char *volume_type, const char *keyfile,
		      size_t keyfile_offset, size_t keyfile_size, size_t tries);

void keystore_free(struct keystore *keystore);



#endif
