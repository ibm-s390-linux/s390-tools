/*
 * PV arguments related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_ARGS_H
#define PV_ARGS_H

#include <glib.h>

#include "pv_comp.h"

typedef struct pv_arg {
	PvComponentType type;
	gchar *path;
} PvArg;

PvArg *pv_arg_new(PvComponentType type, const gchar *path);
void pv_arg_free(PvArg *arg);

typedef struct {
	gint log_level;
	gint no_verify;
	gboolean offline;
	gchar *pcf;
	gchar *scf;
	gchar *psw_addr; /* PSW address which will be used for the start of
			  * the actual component (e.g. Linux kernel)
			  */
	gchar *cust_root_key_path;
	gchar *cust_comm_key_path;
	gchar *gcm_iv_path;
	gchar **host_keys;
	gchar *root_ca_path; /* Trusted root CA used for the verification of the
			      * chain of trust (if specified).
			      */
	gchar **untrusted_cert_paths;
	gchar **crl_paths;
	gchar *xts_key_path;
	GSList *comps;
	gchar *output_path;
	gchar *tmp_dir;
	GPtrArray *unused_values;
} PvArgs;

PvArgs *pv_args_new(void);
void pv_args_free(PvArgs *args);

gint pv_args_parse_options(PvArgs *args, gint *argc, gchar **argv[],
			   GError **err);

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvArg, pv_arg_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvArgs, pv_args_free)

#endif
