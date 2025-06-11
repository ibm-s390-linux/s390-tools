/*
 * util - Utility function library
 *
 * Format structured data as key-value pairs, JSON, or CSV
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_fmt.h"
#include "lib/util_libc.h"
#include "lib/util_rec.h"
#include "lib/zt_common.h"

struct obj_t {
	char *name;
	bool is_list;
	bool is_row;
	bool is_prefix;
	unsigned int index;
};

struct key_t {
	char *name;
	bool persist;
};

static struct {
	enum util_fmt_t type;
	FILE *fd;
	int fileno;
	/* Format control. */
	bool hide_prefix;
	bool hide_inval;
	bool quote_all;
	bool do_filter;
	bool do_warn;
	bool hide_meta;
	bool handle_int;
	int api_level;
	const char *nl;
	/* JSON specifics. */
	unsigned int ind_base;
	unsigned int ind_width;
	char ind_char;
	bool meta_done;
	/* CSV specifics. */
	struct util_rec *csv_rec;
	bool csv_hdr;
	bool csv_data;
	/* State. */
	unsigned int lvl;
	struct obj_t *objs;
	unsigned int num_objs;
	struct key_t *keys;
	unsigned int num_keys;
	struct sigaction old_int;
	struct sigaction old_term;
	/* Methods. */
	void (*obj_start)(struct obj_t *parent, struct obj_t *obj);
	void (*obj_end)(struct obj_t *parent, struct obj_t *obj);
	void (*map)(struct obj_t *parent, unsigned int mflags, const char *key,
		    const char *val);
	void (*term)(void);
} f;

#define fwarn(fmt, ...) \
	do { if (f.do_warn) warnx(fmt, ##__VA_ARGS__); } while (0)

/* Map format name to format ID. */
static const struct {
	const char *name;
	enum util_fmt_t fmt;
} formats[] = {
	{ "json", FMT_JSON },
	{ "json-seq", FMT_JSONSEQ },
	{ "pairs", FMT_PAIRS },
	{ "csv",  FMT_CSV },
};

/* Signal mask for blocking INT and TERM signals. */
static sigset_t no_int_mask;

bool util_fmt_name_to_type(const char *name, enum util_fmt_t *type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(formats); i++) {
		if (strcasecmp(name, formats[i].name) == 0) {
			*type = formats[i].fmt;
			return true;
		}
	}
	return false;
}

static void safe_write(const char *str)
{
	size_t done, todo;
	ssize_t rc;

	if (f.fileno < 0)
		return;
	for (done = 0; (todo = strlen(&str[done])) > 0; done += (size_t)rc) {
		rc = write(f.fileno, &str[done], todo);
		if (rc <= 0)
			return;
	}
}

static void _indent(unsigned int off, bool safe)
{
	unsigned int num, i;

	if (f.type == FMT_JSONSEQ)
		return;
	num = f.ind_base + off;
	if (f.type == FMT_JSON && f.lvl > 0)
		num += f.lvl - 1;
	for (i = 0; i < num * f.ind_width; i++) {
		if (!safe) {
			fputc(f.ind_char, f.fd);
		} else if (f.fileno >= 0) {
			if (write(f.fileno, &f.ind_char, 1) <= 0)
				return;
		}
	}
}

#define indent(x)	_indent(x, false)

static void obj_free(struct obj_t *obj)
{
	free(obj->name);
	memset(obj, 0, sizeof(*obj));
}

static void disable_int(sigset_t *saved)
{
	if (f.handle_int)
		sigprocmask(SIG_BLOCK, &no_int_mask, saved);
}

static void enable_int(sigset_t *saved)
{
	if (f.handle_int) {
		/* Ensure latest updates are flushed to file descriptor. */
		fflush(f.fd);
		sigprocmask(SIG_SETMASK, saved, NULL);
	}
}

static void int_handler(int signum)
{
	struct sigaction *old;

	if (f.term)
		f.term();
	/* Re-install and call original handler. */
	old = (signum == SIGINT) ? &f.old_int : &f.old_term;
	sigaction(signum, old, NULL);
	raise(signum);
}

static void setup_int_handler(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = &int_handler;
	sigaction(SIGINT, &act, &f.old_int);
	sigaction(SIGTERM, &act, &f.old_term);
}

static void remove_int_handler(void)
{
	sigaction(SIGINT, &f.old_int, NULL);
	sigaction(SIGTERM, &f.old_term, NULL);
}

void util_fmt_exit(void)
{
	unsigned int i;

	if (f.handle_int)
		remove_int_handler();
	if (f.lvl > 0)
		fwarn("%s before remaining %d util_obj_end()", __func__, f.lvl);
	for (i = 0; i < f.num_keys; i++)
		free(f.keys[i].name);
	free(f.keys);
	for (i = 0; i < f.num_objs; i++)
		obj_free(&f.objs[i]);
	free(f.objs);
	if (f.type == FMT_CSV)
		util_rec_free(f.csv_rec);
}

void util_fmt_set_indent(unsigned int base, unsigned int width, char ind_char)
{
	f.ind_base  = base;
	f.ind_width = width;
	f.ind_char  = ind_char;
}

static unsigned int to_hex(char *str, int val, unsigned int num_digits)
{
	int digit;
	char *c;

	for (c = str + num_digits - 1; c >= str; c--) {
		digit = (val & 0xf);
		val >>= 4;
		*c = (char)((digit >= 10) ? digit - 10 + 'a' : digit + '0');
	}

	return num_digits;
}

static char get_escape(const char *map, char c)
{
	int i;

	for (i = 0; map[i] && map[i + 1]; i += 2) {
		if (map[i] == c)
			return map[i + 1];
	}
	return 0;
}

struct quote_params {
	const char *double_chars;
	const char *esc_map;
	char hex_char;
	unsigned int hex_digits;
	unsigned int max_width_per_char;
};

static char *do_quote(const char *str, const struct quote_params *p)
{
	unsigned int from, to;
	char *q, esc, c;

	/* Start with worst-case length assuming every char is replaced.  */
	q = util_zalloc(strlen(str) * p->max_width_per_char + /* "" nul */ 3);
	to = 0;
	q[to++] = '"';
	for (from = 0; (c = str[from]); from++) {
		if (p->double_chars && strchr(p->double_chars, c)) {
			/* Escape characters by doubling them ("" in CSV). */
			q[to++] = c;
			q[to++] = c;
		} else if (p->esc_map && (esc = get_escape(p->esc_map, c))) {
			/* Escape characters with backslash + letter. */
			q[to++] = '\\';
			q[to++] = esc;
		} else if (p->hex_char && !isprint(c)) {
			/* Escape characters with backslash + hex code. */
			q[to++] = '\\';
			q[to++] = p->hex_char;
			to += to_hex(&q[to], c, p->hex_digits);
		} else {
			q[to++] = c;
		}
	}
	q[to++] = '"';

	return util_realloc(q, (size_t)to + 1);
}

static char *csv_quote(const char *str)
{
	static const struct quote_params csv_quote_params = {
		.double_chars	    = "\"",
		.esc_map	    = NULL,
		.hex_char	    = 0,
		.hex_digits	    = 0,
		.max_width_per_char = 2 /* " => "" */,
	};

	return do_quote(str, &csv_quote_params);
}

static void add_key(const char *name, bool persist)
{
	struct key_t key;
	char *hdr;

	key.name    = util_strdup(name);
	key.persist = persist;
	util_add_array(&f.keys, &f.num_keys, key);
	if (f.type == FMT_CSV) {
		if (f.quote_all) {
			hdr = csv_quote(name);
			util_rec_def(f.csv_rec, name, UTIL_REC_ALIGN_LEFT, 0, hdr);
			free(hdr);
		} else {
			util_rec_def(f.csv_rec, name, UTIL_REC_ALIGN_LEFT, 0, name);
		}
		util_rec_set(f.csv_rec, name, "\"\"");
		f.csv_hdr = true;
	}
}

static struct key_t *get_key(const char *name)
{
	unsigned int i;

	for (i = 0; i < f.num_keys; i++) {
		if (strcmp(name, f.keys[i].name) == 0)
			return &f.keys[i];
	}
	return NULL;
}

void util_fmt_add_key(const char *fmt, ...)
{
	va_list args;
	char *key;

	va_start(args, fmt);
	util_vasprintf(&key, fmt, args);
	va_end(args);

	/* Only add unique keys. */
	if (!get_key(key))
		add_key(key, true);
	free(key);
}

static bool update_key(const char *name, bool persist)
{
	struct key_t *key;
	bool rc = true;

	key = get_key(name);
	if (key) {
		key->persist = persist;
	} else if (!f.do_filter) {
		add_key(name, persist);
	} else {
		fwarn("util_fmt_pair for key '%s' without util_fmt_add_key()",
		      name);
		rc = false;
	}
	return rc;
}

static struct obj_t *curr_obj(int off)
{
	int lvl = (int)f.lvl - 1 + off;

	return lvl < 0 ? NULL : &f.objs[lvl];
}

static void _util_fmt_obj_end(void);

/*
 * By s390-tools convention, all tool output must be contained in an extra
 * top-level object that includes tool-invocation meta-data.
 */
static void emit_meta_object(void)
{
	unsigned int quoted = FMT_PERSIST | FMT_QUOTE, unquoted = FMT_PERSIST;
	char hostname[HOST_NAME_MAX + 1] = { 0 }, date[30];
	struct timeval tv;
	struct tm *tm;

	f.meta_done = true;
	util_fmt_obj_start(FMT_DEFAULT, NULL);
	util_fmt_obj_start(FMT_PREFIX, "meta");

	/*
	 *  "meta": {
	 *    "api_level": 1,
	 *    "version": "2.32.0",
	 *    "host": "localhost",
	 *    "time_epoch": 1714392976,
	 *    "time": "2024-04-29 14:16:16+0200",
	 *  }
	 */
	util_fmt_pair(unquoted, "api_level", "%d", f.api_level);
	util_fmt_pair(quoted, "version", "%s", RELEASE_STRING);
	gethostname(hostname, sizeof(hostname) - 1);
	util_fmt_pair(quoted, "host", "%s", hostname);
	gettimeofday(&tv, NULL);
	util_fmt_pair(unquoted, "time_epoch", "%llu", tv.tv_sec);
	tm = localtime(&tv.tv_sec);
	if (!strftime(date, sizeof(date), "%F %T%z", tm))
		date[0] = 0;
	util_fmt_pair(quoted, "time", "%s", date);
	_util_fmt_obj_end();

	if (f.type == FMT_JSONSEQ) {
		/* Tool meta-data is a separate object for JSONSEQ. */
		util_fmt_obj_end();
	}
}

void util_fmt_obj_start(unsigned int oflags, const char *fmt, ...)
{
	struct obj_t *parent, *obj;
	char *name = NULL;
	sigset_t set;
	va_list args;

	if (!f.hide_meta && !f.meta_done && f.lvl == 0) {
		emit_meta_object();
		/*
		 * Allow override of top-level key name for supplementary
		 * output formats.
		 */
		if (!fmt)
			name = util_strdup(program_invocation_short_name);
	}
	if (fmt) {
		va_start(args, fmt);
		util_vasprintf(&name, fmt, args);
		va_end(args);
	}
	f.lvl++;
	if (f.lvl > f.num_objs)
		util_expand_array(&f.objs, &f.num_objs);
	parent         = curr_obj(-1);
	obj            = curr_obj(0);
	obj->name      = name;
	obj->is_list   = (oflags & FMT_LIST);
	obj->is_row    = (oflags & FMT_ROW);
	obj->is_prefix = (oflags & FMT_PREFIX);
	obj->index     = 0;
	if (f.obj_start) {
		disable_int(&set);
		f.obj_start(parent, obj);
		enable_int(&set);
	}
	if (parent)
		parent->index++;
}

static void _util_fmt_obj_end(void)
{
	struct obj_t *obj, *parent;
	sigset_t set;

	if (f.lvl == 0) {
		fwarn("%s without util_fmt_obj_start", __func__);
		return;
	}
	parent = curr_obj(-1);
	obj    = curr_obj(0);
	if (f.obj_end) {
		disable_int(&set);
		f.obj_end(parent, obj);
		enable_int(&set);
	}
	f.lvl--;
	obj_free(obj);
}

void util_fmt_obj_end(void)
{
	_util_fmt_obj_end();

	if (f.lvl == 1 && f.meta_done && f.type != FMT_JSONSEQ) {
		/* Emit closure for top-level meta-container object. */
		util_fmt_obj_end();
	}
}

static char *add_prefix(const char *str, bool full)
{
	struct obj_t *obj;
	unsigned int i;
	char *prefix;

	prefix = util_strdup("");
	for (i = 0; i < f.lvl; i++) {
		obj = &f.objs[i];
		if (!full && !obj->is_prefix)
			continue;
		if (obj->name) {
			if (*prefix)
				util_concatf(&prefix, ".");
			util_concatf(&prefix, "%s", obj->name);
		}
		if (obj->is_list && full)
			util_concatf(&prefix, "[%d]", obj->index - 1);
	}
	if (*prefix)
		util_concatf(&prefix, ".");
	util_concatf(&prefix, "%s", str);

	return prefix;
}

void util_fmt_pair(unsigned int mflags, const char *key, const char *fmt, ...)
{
	char *val, *prefixed_key;
	struct obj_t *obj;
	bool is_filtered;
	sigset_t set;
	va_list args;

	obj = curr_obj(0);
	if (!obj) {
		fwarn("%s before util_fmt_obj_start", __func__);
		return;
	}

	/* Filter by key. */
	if (f.do_filter) {
		prefixed_key = add_prefix(key, false);
		is_filtered = !get_key(prefixed_key);
		free(prefixed_key);
		if (is_filtered)
			return;
	}

	/* Filter by validity. */
	if (f.hide_inval && (mflags & FMT_INVAL))
		return;

	va_start(args, fmt);
	util_vasprintf(&val, fmt, args);
	va_end(args);

	if (f.map) {
		disable_int(&set);
		f.map(obj, mflags, key, val);
		enable_int(&set);
	}
	obj->index++;

	free(val);
}

static char *pairs_quote(const char *str)
{
	static const struct quote_params pairs_quote_params = {
		.double_chars	    = NULL,
		.esc_map	    = "\"\"$$``\\\\\aa\bb\ee\ff\nn\rr\tt\vv",
		.hex_char	    = 'x',
		.hex_digits	    = 2,
		.max_width_per_char = 4  /* '\x' + 2 hex_digits */,
	};

	return do_quote(str, &pairs_quote_params);
}

static void pairs_map(struct obj_t *UNUSED(obj), unsigned int mflags,
		      const char *key, const char *val)
{
	char *full_key, *qval = NULL;

	if (mflags & FMT_INVAL)
		val = "";
	indent(0);
	if (f.quote_all || (mflags & FMT_QUOTE))
		qval = pairs_quote(val);
	if (f.hide_prefix) {
		fprintf(f.fd, "%s=%s\n", key, qval ?: val);
	} else {
		full_key = add_prefix(key, true);
		fprintf(f.fd, "%s=%s\n", full_key, qval ?: val);
		free(full_key);
	}
	free(qval);
}

static char *json_quote(const char *str)
{
	static const struct quote_params json_quote_params = {
		.double_chars	    = NULL,
		.esc_map	    = "\"\"\\\\\bb\ff\nn\rr\tt",
		.hex_char	    = 'u',
		.hex_digits	    = 4,
		.max_width_per_char = 6 /* '\u' + 4 hex_digits */,
	};

	return do_quote(str, &json_quote_params);
}

static void json_obj_start(struct obj_t *parent, struct obj_t *obj)
{
	char *key;

	if (!parent && f.type == FMT_JSONSEQ) {
		/* Emit leading record separator according to RFC 7464. */
		fprintf(f.fd, "\x1e");
	}
	if (parent && parent->index > 0)
		fprintf(f.fd, ",%s", f.nl);
	indent(0);
	if (parent && !parent->is_list && obj->name) {
		key = json_quote(obj->name);
		fprintf(f.fd, "%s: ", key);
		free(key);
	}
	fprintf(f.fd, obj->is_list ? "[%s" : "{%s", f.nl);
}

static void json_obj_end(struct obj_t *parent, struct obj_t *obj)
{
	if (obj->index > 0)
		fprintf(f.fd, "%s", f.nl);
	indent(0);
	fprintf(f.fd, obj->is_list ? "]" : "}");
	if (!parent)
		fprintf(f.fd, "\n");
}

/*
 * Ensure syntactically correct JSON by emitting all pending closure elements.
 * Called in signal context - only use signal-safe functions.
 */
static void json_term(void)
{
	struct obj_t *obj, *parent;

	for (; f.lvl > 0; f.lvl--) {
		obj    = curr_obj(0);
		parent = curr_obj(-1);
		if (obj->index > 0)
			safe_write(f.nl);
		_indent(0, true);
		safe_write(obj->is_list ? "]" : "}");
		if (!parent)
			safe_write(f.nl);
	}
}

static void json_map(struct obj_t *parent, unsigned int mflags,
		     const char *key, const char *val)
{
	char *qkey, *qval = NULL;

	qkey = json_quote(key);
	if (mflags & FMT_INVAL)
		qval = util_strdup("null");
	else if (f.quote_all || (mflags & FMT_QUOTE))
		qval = json_quote(val);
	if (parent->index > 0)
		fprintf(f.fd, ",%s", f.nl);
	indent(1);
	fprintf(f.fd, "%s: %s", qkey, qval ?: val);
	free(qval);
	free(qkey);
}

static void csv_obj_start(struct obj_t *UNUSED(parent), struct obj_t *obj)
{
	if (!obj->is_row)
		return;
}

static void csv_obj_end(struct obj_t *UNUSED(parent), struct obj_t *obj)
{
	unsigned int i;

	if (!(obj->is_row || (f.lvl == 1 && f.csv_data)))
		return;
	if (f.csv_hdr) {
		/* Print row with CSV header. */
		indent(0);
		util_rec_print_hdr(f.csv_rec);
		f.csv_hdr = false;
	}
	/* Print row with CSV data. */
	indent(0);
	util_rec_print(f.csv_rec);
	f.csv_data = false;
	/* Reset non-persistent fields. */
	for (i = 0; i < f.num_keys; i++) {
		if (!f.keys[i].persist)
			util_rec_set(f.csv_rec, f.keys[i].name, "\"\"");
	}
}

static void csv_map(struct obj_t *UNUSED(obj), unsigned int mflags,
		    const char *key, const char *val)
{
	char *qval = NULL, *prefixed_key;

	/* Use empty string for invalid values. */
	if (mflags & FMT_INVAL)
		val = "";
	/* Quote value if requested. */
	if (f.quote_all || (mflags & FMT_QUOTE))
		qval = csv_quote(val);
	/* Process key and value. */
	prefixed_key = add_prefix(key, false);
	if (update_key(prefixed_key, mflags & FMT_PERSIST)) {
		util_rec_set(f.csv_rec, prefixed_key, "%s", qval ?: val);
		f.csv_data = true;
	}
	free(prefixed_key);
	free(qval);
}

static bool hide_meta_env(void)
{
	char *v;

	v = secure_getenv("FMT_NOMETA");
	return (v && strcmp(v, "1") == 0);
}

void util_fmt_init(FILE *fd, enum util_fmt_t type, unsigned int flags,
		   int api_level)
{
	memset(&f, 0, sizeof(f));
	f.type        = type;
	f.fd          = fd;
	f.fileno      = fileno(fd);
	f.hide_prefix = (flags & FMT_NOPREFIX);
	f.hide_inval  = !(flags & FMT_KEEPINVAL);
	f.hide_meta   = (flags & FMT_NOMETA) || hide_meta_env();
	f.quote_all   = (flags & FMT_QUOTEALL);
	f.do_filter   = (flags & FMT_FILTER);
	f.do_warn     = (flags & FMT_WARN);
	f.handle_int  = (flags & FMT_HANDLEINT);
	f.api_level   = api_level;
	if (type == FMT_JSONSEQ)
		f.nl = "";
	else
		f.nl = "\n";
	f.ind_width   = 2;
	f.ind_char    = ' ';
	f.meta_done   = false;
	switch (type) {
	case FMT_PAIRS:
		f.map       = &pairs_map;
		break;
	case FMT_JSON:
	case FMT_JSONSEQ:
		f.obj_start = &json_obj_start;
		f.obj_end   = &json_obj_end;
		f.map       = &json_map;
		f.term      = &json_term;
		break;
	case FMT_CSV:
		f.obj_start = &csv_obj_start;
		f.obj_end   = &csv_obj_end;
		f.map       = &csv_map;
		f.csv_rec   = util_rec_new_csv(",");
		f.csv_hdr   = true;
		f.csv_data  = false;
		break;
	}
	/* Ensure consistent number format for callers that use setlocale(). */
	setlocale(LC_NUMERIC, "C");
	if (f.handle_int) {
		setup_int_handler();
		sigemptyset(&no_int_mask);
		sigaddset(&no_int_mask, SIGINT);
		sigaddset(&no_int_mask, SIGTERM);
	}
}
