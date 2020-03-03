/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MISC_H
#define MISC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "lib/zt_common.h"
#include "lib/util_list.h"
#include "exit_code.h"

#define SCOPE_ACTIVE(x)		((x) & config_active ? 1 : 0)
#define SCOPE_PERSISTENT(x)	((x) & config_persistent ? 1 : 0)
#define SCOPE_AUTOCONF(x)	((x) & config_autoconf ? 1 : 0)
#define SCOPE_ALL(x)		((x) == (config_active | config_persistent |\
					 config_autoconf))
#define SCOPE_SINGLE(x)		((x) == config_active || \
				 (x) == config_persistent || \
				 (x) == config_autoconf)

#define DELAY_INDENT	4

#define RANGE_LIMIT	256

/* Define a NULL-terminated list of strings. */
#define STRING_ARRAY(...)	((const char *[]) { __VA_ARGS__, NULL })

#define YESNO(x)	((x) ? "yes" : "no")

#define EVEN(x)		(((x) & 1) == 0)

/* Enumeration of configuration sets. Multiple configuration sets can be
 * combined using bit-wise or. */
enum {
	config_active = 1,
	config_persistent = 2,
	config_autoconf = 4,
	config_all = 7,
};
typedef int config_t;

typedef enum {
	err_ignore,
	err_print,
	err_delayed_print,
	err_delayed_forceable,
} err_t;

/**
 * read_scope_t - Define the scope of device attributes to read
 * @scope_mandatory: Read only mandatory attribute settings.
 * @scope_known: Read settings of all known attributes.
 * @scope_all: Read settings of all attributes.
 */
typedef enum {
	scope_mandatory,
	scope_known,
	scope_all,
} read_scope_t;

/* A string that can be added to a struct util_list. */
struct strlist_node {
	struct util_list_node node;
	char str[];
};

/* A pointer that can be added to a struct util_list. */
struct ptrlist_node {
	struct util_list_node node;
	void *ptr;
};

/* A dry-run file buffer. */
struct dryrun_file {
	char *filename;
	FILE *file;
	char *buffer;
	size_t size;
};

extern const char *toolname;
extern int verbose;
extern int debug_enabled;
extern int quiet;
extern int force;
extern int yes;
extern int dryrun;
extern int found_forceable;
extern int stdout_data;
extern int delayed_errors;
extern int delayed_warnings;

extern unsigned long longrun_total;
extern unsigned long longrun_current;

void misc_exit(void);
void indent(unsigned int, const char *, ...);
void error(const char *, ...);
#define err_t_print(err, ...) \
	do { \
		switch (err) { \
		case err_print: \
			error(__VA_ARGS__); \
			break; \
		case err_delayed_print: \
			delayed_err(__VA_ARGS__); \
			break; \
		case err_delayed_forceable: \
			delayed_forceable(__VA_ARGS__); \
			break; \
		default: \
			break; \
		} \
	} while (0)
void __attribute__((noreturn)) fatal(exit_code_t rc, const char *format, ...);
#define internal(...) \
	fatal(EXIT_INTERNAL_ERROR, \
	      "An internal error occurred in %s:%d: %s\n", __FILE__, __LINE__, \
	      __VA_ARGS__)
void forceable(const char *, ...);
void forceable_warn(const char *, ...);
void syntax(const char *, ...);
void _warn(const char *, ...);
#define warn(...) do { \
		if (debug_enabled) \
			fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
		_warn(__VA_ARGS__); \
	} while (0)
void _warn_once(const char *, ...);
#define warn_once(...) do { \
		if (debug_enabled) \
			fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
		_warn_once(__VA_ARGS__); \
	} while (0)
#define info(...) do { if (!quiet) fprintf(stdout_data ? stderr : stdout, \
					   __VA_ARGS__); } while (0)
#define verb(...) do { if (verbose) fprintf(stdout_data ? stderr : stdout, \
					    __VA_ARGS__); } while (0)
#define debug(...) do { \
		if (debug_enabled) \
			fprintf(stderr, "DEBUG: " __VA_ARGS__); \
		if (debug_enabled > 1) \
			print_trace(); \
	} while (0)
void oom(void);

void delayed_err(const char *, ...);
void delayed_warn(const char *, ...);
void delayed_info(const char *, ...);
void delayed_forceable(const char *, ...);
void delayed_forceable_warn(const char *, ...);
void delayed_print(int);
void delayed_clear(void);
bool delayed_messages_available(void);

bool confirm(const char *format, ...);
void set_stdout_data(void);
char *misc_strdup(const char *);
void *misc_malloc(size_t);
char *misc_asprintf(const char *, ...);
int misc_system(err_t, const char *, ...);
bool misc_read_dir(const char *, struct util_list *,
		       bool (*)(const char *, void *), void *);
bool file_is_devnode(const char *);
exit_code_t remove_file(const char *);
exit_code_t misc_read_fd(FILE *fd, void **buffer, size_t *size_ptr);
char *misc_read_text_file(const char *, int, err_t);
char *misc_read_cmd_output(const char *, int, err_t);
char *config_read_cmd_output(const char *, int, err_t);
exit_code_t misc_write_text_file(const char *, const char *, err_t);
exit_code_t misc_write_text_file_retry(const char *, const char *, err_t);
exit_code_t misc_mktemp(char **, int *);
char *misc_readlink(const char *path);
config_t get_config(int act, int pers, int ac);
bool is_zvm(void);
bool is_terminal(void);
const char *config_to_str(config_t);
bool str_to_config(const char *, config_t *);
char *quote_str(const char *, int);
char *unquote_str(const char *);
char *shrink_str(const char *);
char *misc_strrstr(const char *haystack, const char *needle);

struct util_list *strlist_new(void);
void strlist_free(struct util_list *);
struct util_list *strlist_copy(struct util_list *);
void strlist_add(struct util_list *, const char *, ...);
bool strlist_add_unique(struct util_list *, const char *, ...);
void strlist_add_multi(struct util_list *, const char *, const char *, int);
struct strlist_node *strlist_find(struct util_list *, const char *);
char *strlist_flatten(struct util_list *, const char *);
void strlist_sort_unique(struct util_list *,
			 int (*)(const void *, const void *));
int str_cmp(const void *, const void *);

struct util_list *ptrlist_new(void);
void ptrlist_free(struct util_list *, int);
void ptrlist_add(struct util_list *, void *);
void ptrlist_add_after(struct util_list *, struct ptrlist_node *, void *);
void ptrlist_add_before(struct util_list *, struct ptrlist_node *, void *);
void ptrlist_add_unique(struct util_list *, void *);
void ptrlist_remove(struct util_list *, void *);
void ptrlist_move(struct util_list *, struct util_list *,
		  struct ptrlist_node *);

struct dryrun_file *dryrun_open(const char *, FILE **);
void dryrun_close(struct dryrun_file *);
void dryrun_active(const char *, ...);
void dryrun_persistent(const char *, ...);

bool starts_with(const char *, const char *);
bool starts_with_nocase(const char *, const char *);
bool ends_with(const char *, const char *);

void line_split(const char *, int *, char ***);
void line_free(int, char **);

void print_trace(void);

int get_columns(void);

FILE *misc_fopen(const char *, const char *);
FILE *misc_popen(const char *, const char *);
int misc_fclose(FILE *);
int misc_pclose(FILE *);

void longrun_start(const char *, int);
void longrun_stop(void);

char *skip_comp(char *);
void byte_swap(uint8_t *, unsigned int *, unsigned);
bool valid_hex(const char *);
void debug_init(int, char **);

#endif /* MISC_H */
