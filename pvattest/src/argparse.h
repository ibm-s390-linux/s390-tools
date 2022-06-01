/*
 * Definitions used for parsing arguments.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef PVATTEST_ARGPARSE_H
#define PVATTEST_ARGPARSE_H
/* Must be included before any other header */
#include "config.h"

#include <stdint.h>

#include "libpv/glib-helper.h"
#include "libpv/macros.h"

#define PVATTEST_SUBC_STR_CREATE "create"
#define PVATTEST_SUBC_STR_PERFORM "perform"
#define PVATTEST_SUBC_STR_VERIFY "verify"

enum pvattest_command {
	PVATTEST_SUBC_INVALID,
	PVATTEST_SUBC_CREATE,
	PVATTEST_SUBC_PERFORM,
	PVATTEST_SUBC_VERIFY,
};

typedef struct {
	int log_level;
} pvattest_general_config_t;

typedef struct {
	char **host_key_document_paths;
	char **certificate_paths;
	char **crl_paths;
	char *root_ca_path;

	char *arp_key_out_path;
	char *output_path;

	gboolean phkh_img;
	gboolean phkh_att;
	gboolean no_verify;
	gboolean online;

	/* experimental flags */
	gboolean use_nonce; /* default TRUE */
	uint64_t paf; /* default 0 */
	int x_aad_size; /* default -1 -> ignore */
} pvattest_create_config_t;

typedef struct {
	char *output_path;
	char *input_path;
	/* experimental flags */
	char *user_data_path; /* default NULL */
} pvattest_perform_config_t;

typedef struct {
	char *input_path;
	char *hdr_path;
	char *arp_key_in_path;
} pvattest_verify_config_t;

typedef struct {
	pvattest_general_config_t general;
	pvattest_create_config_t create;
	pvattest_perform_config_t perform;
	pvattest_verify_config_t verify;
} pvattest_config_t;

/**
 * pvattest_parse_clear_config:
 *
 * @config: struct to be cleared
 *
 * clears but not frees all config.
 * all non config members such like char* will be freed.
 */
void pvattest_parse_clear_config(pvattest_config_t *config);

/**
 * pvattest_parse:
 *
 * @argc: ptr to argument count
 * @argv: ptr to argument vector
 * @config: output: ptr to parsed config. Target is statically allocated.
 *          You are responsible for freeing all non config ptrs.
 *          use #pvattest_parse_clear_config for that.
 *
 * Will not return if verbose or help parsed.
 *
 * Returns: selected command as enum
 */
enum pvattest_command pvattest_parse(int *argc, char **argvp[], pvattest_config_t **config,
				     GError **error) PV_NONNULL(1, 2, 3);

#define PVATTEST_ERROR g_quark_from_static_string("pv-pvattest_error-quark")
typedef enum {
	PVATTEST_ERR_INV_ARGV,
	PVATTEST_ERR_INV_ARG,
} pv_pvattest_error_e;

#endif /* PVATTEST_ARGPARSE_H */
