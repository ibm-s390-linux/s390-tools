/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Mini libc implementation
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"

#include <stdarg.h>

#include "boot/s390.h"

#include "error.h"
#include "sclp.h"
#include "ebcdic.h"

extern char __heap_start[];
extern char __heap_stop[];
extern char __bss_start[];
extern char __bss_stop[];
extern char __ex_table_start[];
extern char __ex_table_stop[];

struct ex_table_entry {
	unsigned int fault;
	unsigned int target;
};

#define MEM_ALLOC_START	((unsigned long) __heap_start)
#define MEM_ALLOC_END	((unsigned long) __heap_stop)
#define MEM_ALLOC_MAX 4

static uint8_t mem_page_alloc_vec[MEM_ALLOC_MAX];

/*
 * Initialize memory with value
 */
void *memset(void *s, int c, unsigned long n)
{
	char *xs;

	xs = s;
	while (n--)
		*xs++ = c;
	return s;
}

/*
 * Copy memory
 */
void *memcpy(void *dest, const void *src, unsigned long n)
{
	const char *s = src;
	char *d = dest;

	while (n--)
		*d++ = *s++;
	return dest;
}

/*
 * Move @n bytes of memory from @src to @dest. The memory regions may overlap.
 */
void *memmove(void *dest, const void *src, unsigned long n)
{
	const char *s = src;
	char *d = dest;

	if (s < d) {
		d += n;
		s += n;
		while (n--)
			*--d = *--s;
	} else {
		while (n--)
			*d++ = *s++;
	}
	return dest;
}

/*
 * Copy string
 */
char *strcpy(char *dest, const char *src)
{
	const char *s = src;
	char *d = dest;

	while (*s)
		*d++ = *s++;
	*d = 0;
	return dest;
}

/*
 * Return string length
 */
int strlen(const char *s)
{
	int len = 0;

	while (*s++)
		len++;
	return len;
}

/*
 * Concatenate two strings
 */
char *strcat(char *dest, const char *src)
{
	strcpy(dest + strlen(dest), src);
	return dest;
}

/*
 * Compare two strings
 */
int strncmp(const char *s1, const char *s2, unsigned long count)
{
	while (count--)
		if (*s1++ != *s2++)
			return *(unsigned char *)(s1 - 1) -
				*(unsigned char *)(s2 - 1);
	return 0;
}

static int skip_atoi(const char **c)
{
	int i = 0;

	do {
		i = i*10 + *((*c)++) - '0';
	} while (isdigit(**c));

	return i;
}

enum format_type {
	FORMAT_TYPE_NONE,
	FORMAT_TYPE_STR,
	FORMAT_TYPE_ULONG,
};

struct printf_spec {
	unsigned int	type:8;		/* format_type enum */
	signed int	field_width:24;	/* width of output field */
	unsigned int	zeropad:1;	/* pad numbers with zero */
	unsigned int	base:8;		/* number base, 8, 10 or 16 only */
	signed int	precision:16;	/* # of digits/chars */
};

#define FIELD_WIDTH_MAX ((1 << 23) - 1)

static int format_decode(const char *fmt, struct printf_spec *spec)
{
	const char *start = fmt;

	spec->type = FORMAT_TYPE_NONE;
	while (*fmt) {
		if (*fmt == '%')
			break;
		fmt++;
	}

	/* return current non-format string */
	if (fmt != start || !*fmt)
		return fmt - start;

	/* first char is '%', skip it */
	fmt++;
	if (*fmt == '0') {
		spec->zeropad = 1;
		fmt++;
	}

	spec->field_width = -1;
	if (isdigit(*fmt))
		spec->field_width = skip_atoi(&fmt);

	spec->precision = -1;
	if (*fmt == '.') {
		fmt++;
		if (isdigit(*fmt))
			spec->precision = skip_atoi(&fmt);
	}

	/* always use long form, i.e. ignore long qualifier */
	if (*fmt == 'l')
		fmt++;

	switch (*fmt) {
	case 's':
		spec->type = FORMAT_TYPE_STR;
		break;

	case 'o':
		spec->base = 8;
		spec->type = FORMAT_TYPE_ULONG;
		break;

	case 'u':
		spec->base = 10;
		spec->type = FORMAT_TYPE_ULONG;
		break;

	case 'x':
		spec->base = 16;
		spec->type = FORMAT_TYPE_ULONG;
		break;

	default:
		libc_stop(EINTERNAL);
	}

	return ++fmt - start;
}

static char *string(char *buf, char *end, const char *s,
		    struct printf_spec *spec)
{
	int limit = spec->precision;
	int len = 0;
	int spaces;

	/* Copy string to buffer */
	while (limit--) {
		char c = *s++;
		if (!c)
			break;
		if (buf < end)
			*buf = c;
		buf++;
		len++;
	}

	/* right align if necessary */
	if (len < spec->field_width && buf < end) {
		spaces = spec->field_width - len;
		if (spaces >= end - buf)
			spaces = end - buf;
		memmove(buf + spaces, buf, len);
		memset(buf, ' ', spaces);
		buf += spaces;
	}

	return buf;
}

static char *number(char *buf, char *end, unsigned long val,
		    struct printf_spec *spec)
{
	/* temporary buffer to prepare the string.
	 * Worst case: base = 8 -> 3 bits per char -> 2.67 chars per byte */
	char tmp[3 * sizeof(val)];
	static const char vec[] = {'0', '1', '2', '3', '4', '5', '6', '7',
				   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int field_width = spec->field_width;
	int precision = spec->precision;
	int len;

	/* prepare string in reverse order */
	len = 0;
	do {
		tmp[len++] = vec[val % spec->base];
		val /= spec->base;
	} while (val);

	if (len > precision)
		precision = len;

	field_width -= precision;
	while (field_width-- > 0) {
		char c = spec->zeropad ? '0' : ' ';
		if (buf < end)
			*buf = c;
		buf++;
	}

	/* needed if no field width but a precision is given */
	while (len < precision--) {
		if (buf < end)
			*buf = '0';
		buf++;
	}

	while (len-- > 0) {
		if (buf < end)
			*buf = tmp[len];
		buf++;
	}

	return buf;
}

/*
 * vsnprintf - Format string and place in a buffer
 *
 * This funcion only supports a subset of format options defined in the
 * C standard, i.e.
 * specifiers:
 *	* %s (strings)
 *	* %o (unsigned int octal)
 *	* %u (unsigned int decimal)
 *	* %x (unsigned int hexadecimal)
 *
 * length modifier:
 *	* 'l' (ignored, see below)
 *
 * flag:
 *	* '0' (zero padding for integers)
 *
 * precision and field width as integers, i.e. _not_ by asterix '*'.
 *
 * The integer specifiers (o, u and, x) always use the long form, i.e.
 * assume the argument to be of type 'unsigned long int'.
 *
 * Returns the number of characters the function would have generated for
 * the given input (excluding the trailing '\0'. If the return value is
 * greater than or equal @size the resulting string is trunctuated.
 */
static int vsnprintf(char *buf, unsigned long size, const char *fmt,
		     va_list args)
{
	struct printf_spec spec = {0};
	char *str, *end;

	str = buf;
	end = buf + size;

	/* use negative (large positive) buffer sizes as indication for
	 * unknown/unlimited buffer sizes. */
	if (end < buf) {
		end = ((void *)-1);
		size = end - buf;
	}

	while (*fmt) {
		const char *old_fmt = fmt;
		int read = format_decode(fmt, &spec);
		int copy;

		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE:
			copy = read;
			if (str < end) {
				if (copy > end - str)
					copy = end - str;
				memcpy(str, old_fmt, copy);
			}
			str += read;
			break;

		case FORMAT_TYPE_STR:
			str = string(str, end, va_arg(args, char *), &spec);
			break;

		case FORMAT_TYPE_ULONG:
			str = number(str, end, va_arg(args, unsigned long),
				     &spec);
			break;
		}
	}

	if (size) {
		if (str < end)
			*str = '\0';
		else
			end[-1] = '\0';
	}
	return str - buf;
}

/*
 * Write formatted string to buffer
 */
void snprintf(char *buf, unsigned long size, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vsnprintf(buf, size, fmt, va);
	va_end(va);
}

/*
 * Print formatted string to console
 */
void printf(const char *fmt, ...)
{
	char buf[LINE_LENGTH + 1];
	int len;
	va_list va;

	va_start(va, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, va);
	if (len > LINE_LENGTH) {
		buf[LINE_LENGTH - 1] = '.';
		buf[LINE_LENGTH - 2] = '.';
		buf[LINE_LENGTH - 3] = '.';
	}
	va_end(va);
	sclp_print(buf);
#ifdef ENABLE_SCLP_ASCII
	sclp_print_ascii(buf);
#endif /* ENABLE_SCLP_ASCII */
}

/*
 * Allocate one zero page
 */
unsigned long get_zeroed_page(void)
{
	const int page_count = MIN(MEM_ALLOC_MAX, (int)((MEM_ALLOC_END - MEM_ALLOC_START) / PAGE_SIZE));
	unsigned long addr;
	int i;

	for (i = 0; i < page_count; i++) {
		if (mem_page_alloc_vec[i] != 0)
			continue;
		addr = MEM_ALLOC_START + i * PAGE_SIZE;
		memset((void *) addr, 0, PAGE_SIZE);
		mem_page_alloc_vec[i] = 1;
		return addr;
	}
	libc_stop(EINTERNAL);
}

/*
 * Free page
 */
void free_page(unsigned long addr)
{
	if (addr < MEM_ALLOC_START || addr >= MEM_ALLOC_END)
		libc_stop(EINTERNAL);

	mem_page_alloc_vec[(addr - MEM_ALLOC_START) / PAGE_SIZE] = 0;
}

/*
 * Program check handler
 */
void pgm_check_handler_fn(void)
{
	struct ex_table_entry *ex_table = (void *) __ex_table_start;
	struct psw_t *psw_old = &S390_lowcore.program_old_psw;
	int i, ex_table_cnt;

	ex_table_cnt = (__ex_table_stop - __ex_table_start)
		/ sizeof(struct ex_table_entry);

	for (i = 0; i < ex_table_cnt; i++) {
		if (ex_table[i].fault == psw_old->addr) {
			psw_old->addr = ex_table[i].target;
			return;
		}
	}
	libc_stop(psw_old->addr);
}

void __noinline load_wait_psw(uint64_t psw_mask, struct psw_t *psw)
{
	struct psw_t wait_psw = { .mask = psw_mask, .addr = 0 };
	struct psw_t old_psw, *wait_psw_ptr = &wait_psw;
	unsigned long addr;

	old_psw = *psw;
	psw->mask = 0x0000000180000000ULL;
	asm volatile(
		"	larl	%[addr],.Lwait\n"
		"       stg     %[addr],8(%[wait_psw_ptr])\n"
		"       stg     %[addr],8(%[psw])\n"
		"       lpswe	%[wait_psw]\n"
		".Lwait:	\n"
		: [addr] "=&d" (addr)
		: [wait_psw] "Q" (wait_psw), [wait_psw_ptr] "a" (wait_psw_ptr),
		  [psw] "a" (psw)
		: "cc", "memory");
	*psw = old_psw;
}

/*
 * The libc startup function
 */
void initialize(void)
{
	struct psw_t *psw_pgm = &S390_lowcore.program_new_psw;

	/* Setup program check handler */
	psw_pgm->mask = 0x0000000180000000ULL;
	psw_pgm->addr = (unsigned long) pgm_check_handler;

	/* Clear bss section */
	memset(__bss_start, 0, __bss_stop - __bss_start);
	start();
}

/*
 * Load disabled wait PSW with reason code in address field
 */
void libc_stop(unsigned long reason)
{
	struct psw_t psw;

	psw.mask = 0x0002000080000000ULL;
	psw.addr = reason;

	asm volatile(
		"	lpswe	 %[psw]\n"
		: : [psw] "Q" (psw) : "cc"
		);

	while(1);
}
