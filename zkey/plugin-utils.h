/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines plugin utility functions and defines
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PLUGIN_UTILS_H
#define PLUGIN_UTILS_H

#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "kms-plugin.h"
#include "cca.h"

struct plugin_data {
	const char *plugin_name;
	const char *config_path;
	mode_t config_path_mode;
	gid_t config_path_owner;
	const char *config_file;
	struct properties *properties;
	char error_msg[1024];
	bool verbose;
};

#define pr_verbose(pd, fmt...)						\
	do {								\
		if ((pd)->verbose) {					\
			fprintf(stderr, "%s: ", (pd)->plugin_name);	\
			fprintf(stderr, fmt);				\
			fprintf(stderr, "\n");				\
		}							\
	} while (0)

int plugin_init(struct plugin_data *pd, const char *plugin_name,
		const char *config_path, const char *config_file,
		bool verbose);
void plugin_term(struct plugin_data *pd);

void plugin_clear_error(struct plugin_data *pd);
void plugin_set_error(struct plugin_data *pd, const char *fmt, ...);

int plugin_load_config(struct plugin_data *pd);
int plugin_save_config(struct plugin_data *pd);
int plugin_set_file_permission(struct plugin_data *pd, const char *filename);

bool plugin_check_property(struct plugin_data *pd, const char *name);
int plugin_set_or_remove_property(struct plugin_data *pd, const char *name,
				  const char *value);

int plugin_activate_temp_file(struct plugin_data *pd, const char *temp_file,
			      const char *active_file);

int plugin_check_certificate(struct plugin_data *pd, const char *cert_file,
			     bool *self_signed, bool *valid);
int plugin_print_certificates(struct plugin_data *pd, const char *cert_pem);

int cross_check_cca_apka_apqns(struct plugin_data *pd,
			       const struct kms_apqn *apqns, size_t num_apqns);

int select_cca_adapter_by_apqns(struct plugin_data *pd, const char *apqns,
				struct cca_lib *cca_lib);

char *build_kms_apqn_string(const struct kms_apqn *apqns, size_t num_apqns);

int parse_list(const char *list, char ***elements, size_t *num_elements);

#endif
