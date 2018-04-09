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

#include <stdarg.h>

#include "error.h"
#include "libc.h"
#include "sclp.h"

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
#define MEM_ALLOC_CNT 4

static uint8_t mem_page_alloc_vec[MEM_ALLOC_CNT];

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

/*
 * Convert number to string
 *
 * Parameters:
 *
 * - buf:   Output buffer
 * - base:  Base used for formatting (e.g. 10 or 16)
 * - val:   Number to format
 * - zero:  If > 0, fill with leading zeros, otherwise use blanks
 * - count: Minimum number of characters used for output string
 */
static int num_to_str(char *buf, int base, unsigned long val, int zero,
		      unsigned long count)
{
	static const char conv_vec[] = {'0', '1', '2', '3', '4', '5', '6', '7',
					'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	unsigned long num = 0, val_work = val, in_number = 1;
	int i;

	/* Count number of characters needed for number */
	do {
		num++;
		val_work /= base;
	} while (val_work);
	/* Real character number overwrites count */
	if (count < num)
		count = num;
	/* Format number */
	for (i = count - 1; i >= 0; i--) {
		if (in_number) {
			buf[i] = conv_vec[val % base];
			val /= base;
			in_number = val ? 1 : 0;
		} else {
			buf[i] = zero ? '0' : ' ';
		}
	}
	buf[count] = 0;
	return count;
}

/*
 * Convert string to string with indentation
 */
static int str_to_str(char *buf, const char *str, unsigned long count)
{
	unsigned long size;

	size = strlen(str);
	if (count < size)
		count = size;
	else
		memset(buf, ' ', count - size);
	strcpy(buf + (count - size), str);
	return count;
}

/*
 * Convert string to number with given base
 */
unsigned long strtoul(const char *nptr, char **endptr, int base)
{
	unsigned long val = 0;

	while (isdigit(*nptr)) {
		if (val != 0)
			val *= base;
		val += *nptr - '0';
		nptr++;
	}
	if (endptr)
		*endptr = (char *) nptr;
	return val;
}

/*
 * Convert ebcdic string to number with given base
 */
unsigned long ebcstrtoul(char *nptr, char **endptr, int base)
{
	unsigned long val = 0;

	while (ebc_isdigit(*nptr)) {
		if (val != 0)
			val *= base;
		val += *nptr - 0xf0;
		nptr++;
	}
	if (endptr)
		*endptr = (char *) nptr;
	return val;
}

/*
 * Convert string to number with given base
 */
static int sprintf_fmt(char type, char *buf, unsigned long val, int zero,
		       int count)
{
	switch (type) {
	case 's':
		return str_to_str(buf, (const char *) val, count);
	case 'x':
		return num_to_str(buf, 16, val, zero, count);
	case 'u':
		return num_to_str(buf, 10, val, zero, count);
	default:
		libc_stop(EINTERNAL);
	}
	return 0;
}

/*
 * Print formated string (va version)
 */
static void vsprintf(char *str, const char *fmt, va_list va)
{
	unsigned long val, zero, count;
	char *fmt_next;

	do {
		if (*fmt == '%') {
			fmt++;
			if (*fmt == '0') {
				zero = 1;
				fmt++;
			} else {
				zero = 0;
			}
			/* No number found by strtoul: count=0 fmt_next=fmt */
			count = strtoul(fmt, &fmt_next, 10);
			fmt = fmt_next;
			if (*fmt == 'l')
				fmt++;
			val = va_arg(va, unsigned long);
			str += sprintf_fmt(*fmt, str, val, zero, count);
			fmt++;
		} else {
			*str++ = *fmt++;
		}
	} while (*fmt);
	*str = 0;
}

/*
 * Write formated string to string
 */
void sprintf(char *str, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vsprintf(str, fmt, va);
	va_end(va);
}

/*
 * Print formated string
 */
void printf(const char *fmt, ...)
{
	char buf[81];
	va_list va;

	va_start(va, fmt);
	vsprintf(buf, fmt, va);
	sclp_print(buf);
	va_end(va);
}

/*
 * Allocate one zero page
 */
unsigned long get_zeroed_page(void)
{
	unsigned long addr;
	int i;

	for (i = 0; i < MEM_ALLOC_CNT; i++) {
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

__attribute__ ((noinline)) void load_wait_psw(uint64_t psw_mask, struct psw_t *psw)
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
