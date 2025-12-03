/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Helper functions
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef HELPER_H
#define HELPER_H

#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_time.h"
#include "lib/zt_common.h"

#define G0(x) MAX(0, (s64) (x))

/*
 * Helper Prototypes
 */
void hyptop_helper_init(void);
char *ht_strstrip(char *str);
char *ht_strdup(const char *str);
void ht_print_head(const char *sys);
void ht_print_help_icon(void);
void ht_ebcdic_to_ascii(char *in, char *out, size_t len);
char *ht_mount_point_get(const char *fs_type);
u64 ht_ext_tod_2_us(void *tod_ext);
void ht_print_time(void);
s64 ht_calculate_smt_util(u64 core_us, u64 thr_us, u64 mgm_us, int thread_per_core);

/*
 * Memory alloc functions
 */
void *ht_zalloc(size_t size);
void *ht_alloc(size_t size);
void *ht_realloc(void *ptr, size_t size);
static inline void ht_free(void *ptr)
{
	free(ptr);
}

/*
 * Curses extensions
 */

#define KEY_RETURN	0012
#define KEY_ESCAPE	0033

void ht_bold_on(void);
void ht_bold_off(void);
void ht_reverse_on(void);
void ht_reverse_off(void);
void ht_underline_on(void);
void ht_underline_off(void);
void ht_str_to_upper(char *str);

void ht_print_scroll_bar(int row_cnt, int row_start, int row_bar_start,
			 int row_bar_bottom, int can_scroll_up,
			 int can_scroll_down, int with_boder);

/*
 * util_fmt helper functions
 */
void ht_fmt_time(void);
void ht_fmt_cpu_types(void);

/*
 * Error Macros
 */
#define ERR_MSG(x...) \
do { \
	hyptop_text_mode(); \
	fflush(stdout); \
	fprintf(stderr, "%s: ", g.prog_name);\
	fprintf(stderr, x); \
} while (0)

#define ERR_EXIT(x...) \
do { \
	hyptop_text_mode(); \
	fflush(stdout); \
	fprintf(stderr, "%s: ", g.prog_name); \
	fprintf(stderr, x); \
	hyptop_exit(1); \
	exit(1); \
} while (0)

#define ERR_EXIT_ERRNO(x...) \
do { \
	fflush(stdout); \
	fprintf(stderr, "%s: ", g.prog_name); \
	fprintf(stderr, x); \
	fprintf(stderr, " (%s)", strerror(errno)); \
	fprintf(stderr, "\n"); \
	hyptop_exit(1); \
} while (0)

#endif /* HELPER_H */
