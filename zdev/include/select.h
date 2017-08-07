/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef SELECT_H
#define SELECT_H

#include "lib/util_list.h"

#include "exit_code.h"
#include "misc.h"

struct device;
struct devtype;
struct subtype;
struct devnode;

struct select_opts {
	struct devtype *devtype;
	struct subtype *subtype;
	unsigned int all:1;
	unsigned int configured:1;
	unsigned int existing:1;
	unsigned int online:1;
	unsigned int offline:1;
	unsigned int failed:1;
	struct util_list devids;	/* List of struct strlist_node */
	struct util_list by_path;	/* List of struct strlist_node */
	struct util_list by_node;	/* List of struct strlist_node */
	struct util_list by_if;		/* List of struct strlist_node */
	struct util_list by_attr;	/* List of struct strlist_node */
};

/** selected_dev_node - Represents a selected device ID
 * dt: Devtype of selected device
 * st: Subtype of selected device
 * id: ID if selected device
 * param: Command line parameter that resulted in device selection
 * rc: Per-device selection exit code (%EXIT_OK if all went well)
 */
struct selected_dev_node {
	struct util_list_node node;
	struct devtype *dt;
	struct subtype *st;
	char *id;
	char *param;
	exit_code_t rc;
};

struct select_opts *select_opts_new(void);
void select_opts_free(struct select_opts *);
bool select_opts_dev_specified(struct select_opts *);

struct util_list *selected_dev_list_new(void);
void selected_dev_free(struct selected_dev_node *);
void selected_dev_list_free(struct util_list *);
struct selected_dev_node *selected_dev_list_add(struct util_list *,
						struct devtype *,
						struct subtype *, const char *,
						const char *, exit_code_t);
void selected_dev_print(struct selected_dev_node *, int);

exit_code_t select_devices(struct select_opts *, struct util_list *, int, int,
			   int, config_t, read_scope_t, err_t);

exit_code_t select_by_devnode(struct select_opts *, struct util_list *,
			      config_t, read_scope_t, struct devtype *,
			      struct subtype *, struct devnode *, const char *,
			      err_t);
exit_code_t select_by_node(struct select_opts *, struct util_list *,
			   config_t, read_scope_t, struct devtype *,
			   struct subtype *, const char *, err_t err);
exit_code_t select_by_path(struct select_opts *, struct util_list *, config_t,
			   read_scope_t, struct devtype *, struct subtype *,
			   const char *, err_t);
exit_code_t select_by_interface(struct select_opts *, struct util_list *,
				config_t, read_scope_t, struct devtype *,
				struct subtype *, const char *, err_t);

bool select_match_state(struct device *, struct select_opts *);
void selected_dev_list_print(struct util_list *, int);

#endif /* SELECT_H */
