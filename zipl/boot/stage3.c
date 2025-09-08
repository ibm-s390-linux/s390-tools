/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Main program for stage3 bootloader
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "sclp.h"
#include "menu.h"
#include "boot/error.h"
#include "boot/sigp.h"
#include "boot/s390.h"
#include "boot/sigp.h"
#include "boot/linux_layout.h"
#include "boot/loaders_layout.h"

#include "stage3.h"
#include "ebcdic.h"
#include "ebcdic_conv.h"

#define for_each_rb_entry(entry, rb) \
	for (entry = rb->entries; \
	     (void *) entry + sizeof(*entry) <= (void *) rb + rb->len; \
	     entry++)

static const char *msg_sipl_inval = "Secure boot failure: invalid load address";
static const char *msg_sipl_unverified = "Secure boot failure: unverified load address";
static const char *msg_sipl_noparm = "Secure boot failure: unable to load ipl parameter";

static inline void __noreturn start_kernel(void)
{
	struct psw_t *psw = &S390_lowcore.program_new_psw;
	unsigned long addr, code;

	/* Setup program check handler */
	psw->mask = 0x000000180000000ULL;
	code = 1;

	asm volatile(
		/* Setup program check handler */
		"       larl    %[addr],.no_diag308\n"
		"       stg     %[addr],8(%[psw])\n"
		"       diag    %[code],%[code],0x308\n"
		".no_diag308:\n"
		"       sam31\n"
		"       sr      %%r1,%%r1\n"
		"       sr      %%r2,%%r2\n"
		"       sigp    %%r1,%%r2,%[order]\n"
		"       lpsw    0\n"
		: [addr] "=&d" (addr),
		  [code] "+&d" (code)
		: [psw] "a" (psw),
		  [order] "L" (SIGP_SET_ARCHITECTURE));
	while (1);
}

unsigned int
is_verified_address(unsigned long image_addr)
{
	struct ipl_rb_component_entry *comp;
	struct ipl_rb_components *comps;
	struct ipl_pl_hdr *pl_hdr;
	struct ipl_rl_hdr *rl_hdr;
	struct ipl_rb_hdr *rb_hdr;
	unsigned long tmp;
	void *rl_end;

	/*
	 * There is an IPL report, to find it load the pointer to the
	 * IPL parameter information block from lowcore and skip past
	 * the IPL parameter list, then align the address to a double
	 * word boundary.
	 */
	tmp = (unsigned long) S390_lowcore.ipl_parmblock_ptr;
	pl_hdr = (struct ipl_pl_hdr *) tmp;
	tmp = (tmp + pl_hdr->len + 7) & -8UL;
	rl_hdr = (struct ipl_rl_hdr *) tmp;
	/* Walk through the IPL report blocks in the IPL Report list */
	comps = NULL;
	rl_end = (void *) rl_hdr + rl_hdr->len;
	rb_hdr = (void *) rl_hdr + sizeof(*rl_hdr);
	while ((void *) rb_hdr + sizeof(*rb_hdr) < rl_end &&
	       (void *) rb_hdr + rb_hdr->len <= rl_end) {
		switch (rb_hdr->rbt) {
		case IPL_RBT_COMPONENTS:
			comps = (struct ipl_rb_components *) rb_hdr;
			break;
		default:
			break;
		}

		rb_hdr = (void *) rb_hdr + rb_hdr->len;
	}

	if (!comps)
		return 0;

	for_each_rb_entry(comp, comps) {
		if (image_addr == comp->addr &&
		    comp->flags & IPL_RB_COMPONENT_FLAG_SIGNED &&
		    comp->flags & IPL_RB_COMPONENT_FLAG_VERIFIED)
			return 1;
	}
	return 0;
}

unsigned int
secure_boot_enabled()
{
	struct ipl_pl_hdr *pl_hdr;
	unsigned int rc;

	pl_hdr = (void *)get_zeroed_page();
	switch (diag308(DIAG308_STORE, pl_hdr)) {
	case DIAG308_RC_OK:
		rc = pl_hdr->version <= IPL_MAX_SUPPORTED_VERSION &&
			!!(pl_hdr->flags & IPL_FLAG_SECURE);
		break;
	case DIAG308_RC_NOCONFIG:
		rc = 0;
		break;
	default:
		panic(ESECUREBOOT, "%s", msg_sipl_noparm);
		break;
	}
	free_page((unsigned long) pl_hdr);

	return rc;
}

#define ZIPL_ENVBLK_SIGNATURE	"# zIPL Environment Block\n"
#define STR_HASH_SIZE (16)

struct env_hash_entry {
	unsigned int next;
	unsigned int name;
};

/**
 * ITEMS: pointer to pre-allocated page, where the new item will be allocated
 * NAME: null-terminated name
 */
static void hash_table_add(struct env_hash_entry *items,
			   struct env_hash_entry **buckets,
			   unsigned int *new_idx,
			   unsigned long name)
{
	struct env_hash_entry *new;
	unsigned int hash;

	new = &items[*new_idx];
	new->name = name;
	hash = strhash((unsigned char *)name, NULL, STR_HASH_SIZE);
	new->next = (unsigned long)buckets[hash];
	buckets[hash] = new;
	(*new_idx)++;
}

/**
 * Check if string STR coincides with string SHORT_STR prepended
 * with a logical PREFIX (if any).
 * Return 1, if coincides. Otherwise, return 0.
 */
static int str_eq(char *str, char *short_str, char *prefix)
{
	if (prefix)
		return strlen(str) == strlen(short_str) + 1 &&
			*str == *prefix &&
			!strncmp(str + 1, short_str, strlen(short_str));
	return strlen(str) == strlen(short_str) &&
		!strncmp(str, short_str, strlen(str));
}

static struct env_hash_entry *hash_table_find(struct env_hash_entry **buckets,
					      char *name, char *prefix)
{
	struct env_hash_entry *item;

	if (strlen(name) == 0)
		return NULL;
	item = buckets[strhash((unsigned char *)name, prefix, STR_HASH_SIZE)];
	while (item) {
		if (str_eq((char *)(unsigned long)item->name, name, prefix))
			return item;
		item = (struct env_hash_entry *)(unsigned long)item->next;
	}
	return NULL;
}

/**
 * Format of environment block:
 *
 * magic'\n'name1=value1'\n'...nameN=valueN'\n'zero-padding
 */
static void parse_envblk(struct env_hash_entry *items,
			 struct env_hash_entry **buckets,
			 unsigned int *nr)
{
	char sgn[] = ZIPL_ENVBLK_SIGNATURE;
	unsigned int len = 0;
	unsigned int off = 0;
	char *name;
	char *value;

	ebcdic_to_ascii((unsigned char *)sgn,
			(unsigned char *)sgn, sizeof(sgn) - 1);

	if (strncmp((char *)_stage3_parms.envblk_addr, sgn, sizeof(sgn) - 1)) {
		printf("Bad envblk\n");
		return;
	}
	/* we rely that environment block is consistent */
	name = (char *)_stage3_parms.envblk_addr + sizeof(sgn) - 1;
	/*
	 * calculate significant length of the environment block
	 * (excluding trailing zeros)
	 */
	while (len < _stage3_parms.envblk_len) {
		if (name[len] == 0)
			break;
		len++;
	}
	while (off < len) {
		value = strchr(name, 0x3D /* = */) + 1;
		/* null-terminate the name */
		*(value - 1) = 0;
		hash_table_add(items, buckets, nr, (unsigned long)name);
		off += (value - name); /* offset of the value */

		name = strchr(value, 0x0A /* /n */) + 1;
		/* null-terminate the value */
		*(name - 1) = 0;
		off += (name - value); /* offset of the next name (if any) */
	}
}

/**
 * Lookup by NAME prepended with optional PREFIX in the hash table.
 * First, search by prefixed NAME. If nothing was found, then search
 * by NAME without prefix
 */
static struct env_hash_entry *lookup_item(struct env_hash_entry **buckets,
					  char *name, char *prefix)
{
	struct env_hash_entry *result;

	result = hash_table_find(buckets, name, prefix);
	if (result)
		return result;
	return prefix ? hash_table_find(buckets, name, NULL) : NULL;
}

/**
 * Find all instances of the pattern ${NAME} in the command line, and replace
 * each one with corresponding VALUE as found in the hash table by NAME
 * and SITE_ID, using lookup_item() search procedure.
 *
 * CMDL_LEN: length of the command line to be processed
 * BUCKETS: hash table of pairs (NAME, VALUE)
 * SITE_ID: pointer to an alphanumerical string representing a number
 */
void process_parm_line(struct env_hash_entry **buckets, unsigned int cmdl_len,
		       unsigned int max_len, char *site_id)
{
	struct env_hash_entry *item;
	char empty_str = 0;
	char *cmdl_end;
	char *start;
	char *end;
	char *val;
	int len;

	start = (char *)COMMAND_LINE;
	cmdl_end = start + cmdl_len;

	while (start < cmdl_end) {
		start = strchr(start, 0x24 /* $ */);

		if (start == NULL || start + 3 >= cmdl_end)
			/* no more instances */
			break;
		if (*(start + 1) != 0x7B /* { */) {
			/* skip "$" without braces */
			start += 1;
			continue;
		}
		end = strchr(start, 0x7D /* } */);
		if (end == NULL || end >= cmdl_end)
			/* no more instances */
			break;
		/*
		 * terminate the NAME and find a respective item
		 * in the hash table by that NAME prefixed with
		 * site-ID (if any)
		 */
		*end = 0;
		item = lookup_item(buckets, start + 2, site_id);
		if (!item) {
			/*
			 * Item to replace with not found.
			 * The case of "${}" (empty NAME) also gets here!
			 *
			 * Assign the empty string to remove the instance
			 * from the command line
			 */
			val = &empty_str;
		} else {
			val = (char *)(unsigned long)item->name +
				strlen((char *)(unsigned long)item->name) + 1;
		}
		/*
		 * try to replace the instance by VALUE as found
		 * in the hash table by NAME
		 */
		len = strlen(val);

		if (cmdl_len + len - (end - start + 1) >= max_len)
			/* VALUE doesn't fit */
			break;
		/*
		 * make a room with the beginning at "$" by moving
		 * the rest of parm line at the right of "}" to @dst,
		 * which is (offset of "$" + size of the VALUE")
		 */
		memmove(start + len, end + 1, cmdl_end - (end + 1));
		/*
		 * copy VALUE to the room
		 */
		memcpy(start, val, len);
		cmdl_end += (len - (end - start + 1));
		start += len;
	}
	if (cmdl_len > cmdl_end - (char *)COMMAND_LINE)
		memset(cmdl_end, 0,
		       cmdl_len - (cmdl_end - (char *)COMMAND_LINE));
}

/*
 * This represents a number as a pair consisting of an
 * alphanumerical string, and a variable which contains
 * its numerical value (as a result of strtoul conversion)
 */
struct nr_pair {
	char str[PARAM_SIZE];
	unsigned long val;
};

#define IPL_SC	  (*((struct subchannel_id *) &S390_lowcore.subchannel_id))

/**
 * Parse LOADPARM to identify a site to be activated.
 * If the site is identified, then store its ID in the structure
 * pointed out by NP
 */
static void get_active_site_by_loadparm(struct nr_pair *np)
{
	char loadparm[PARAM_SIZE + 1];
	char *endptr;
	int i = 0;

	memset(loadparm, 0, sizeof(loadparm));

	if (sclp_param(loadparm))
		return;
	/*
	 * extract site-ID as a sequence of digits after the first
	 * leading 'S'
	 */
	while (i < PARAM_SIZE) {
		if (loadparm[i++] == 'S') {
			if (loadparm[i] == 'S') {
				/*
				 * the case of automatic
				 * site activation by SSID
				 */
				if ((IPL_SC).one) {
					np->val = (IPL_SC).ssid;
					snprintf(np->str, PARAM_SIZE - 1,
						 "%u", np->val);
					return;
				}
				/* site undefined */
				return;
			}
			np->val = ebcdic_strtoul(&loadparm[i], &endptr, 10);
			memcpy(np->str, &loadparm[i], endptr - &loadparm[i]);
			/*
			 * not more than (PARAM_SIZE - 1) bytes were copied!
			 */
			return;
		}
	}
}

static char *get_active_site(struct nr_pair *np)
{
	memset(np->str, 0, sizeof(np->str));
	np->val = 0;

	get_active_site_by_loadparm(np);
	if (!np->str[0]) {
		/* No site-ID was found in LOADPARM */
		return NULL;
	}
	ebcdic_to_ascii((unsigned char *)np->str,
			(unsigned char *)np->str,
			strlen(np->str));
	return np->str;
}

/**
 * LEN: length of the command line to be processed
 */
static void handle_environment(unsigned int len, unsigned int max_len)
{
	struct env_hash_entry *buckets[STR_HASH_SIZE];
	struct env_hash_entry *items;
	unsigned int nr_items = 0;
	struct nr_pair np;

	if (_stage3_parms.envblk_addr == 0 ||
	    _stage3_parms.envblk_addr == UNSPECIFIED_ADDRESS)
		return;

	memset(buckets, 0, sizeof(buckets));
	items = (struct env_hash_entry *)get_zeroed_page();
	/*
	 * scan in-memory environment block and populate hash table
	 */
	parse_envblk(items, buckets, &nr_items);
	/*
	 * find environment variables in the command line and
	 * replace them with their values as found in the hash table
	 */
	process_parm_line(buckets, len, max_len, get_active_site(&np));
	free_page((unsigned long)items);
}

static void verify_secure_boot(void)
{
	/*
	 * IPL process is secure we have to use default IPL values and
	 * check if the psw jump address is within at the start of a
	 * verified component. If it is not IPL is aborted.
	 */
	if (_stage3_parms.image_addr != IMAGE_LOAD_ADDRESS ||
	    _stage3_parms.load_psw != DEFAULT_PSW_LOAD)
		panic(ESECUREBOOT, "%s", msg_sipl_inval);

	if (!is_verified_address(_stage3_parms.load_psw & PSW32_ADDR_MASK))
		panic(ESECUREBOOT, "%s", msg_sipl_unverified);
}

static void setup_cmdline(void)
{
	char *cextra = (char *)COMMAND_LINE_EXTRA;
	char *cmdline =  (char *)COMMAND_LINE;
	unsigned int cmdline_len = 0;
	unsigned int max_cmdline_len = *(unsigned long *)MAX_COMMAND_LINE_SIZE;

	if (!max_cmdline_len)
		max_cmdline_len = LEGACY_COMMAND_LINE_SIZE;

	/* if valid command line is given, copy it into new kernel space */
	if (_stage3_parms.parm_addr != UNSPECIFIED_ADDRESS) {
		strlcpy(cmdline, (void *)(unsigned long *)_stage3_parms.parm_addr,
		       max_cmdline_len);
	}
	/* determine length of original parm line */
	cmdline_len = MIN((unsigned int)strlen(cmdline), max_cmdline_len - 1);

	/* convert extra parameter to ascii */
	if (!_stage3_parms.extra_parm || !*cextra)
		goto noextra;

	/* Handle extra kernel parameters specified in DASD boot menu. */
	ebcdic_to_ascii((unsigned char *)cextra, (unsigned char *)cextra, COMMAND_LINE_EXTRA_SIZE);

	while (isspace(*cextra))
		cextra++;

	/*
	 * if extra parm string starts with '=' replace original string,
	 * else append
	 */
	if (*cextra == 0x3d) {
		strlcpy(cmdline, cextra+1, max_cmdline_len);
	} else if (*cextra && cmdline_len + 1 <= max_cmdline_len - 1) {
		/* add blank */
		cmdline[cmdline_len++] = 0x20;
		strlcpy(cmdline + cmdline_len, cextra, max_cmdline_len - cmdline_len);
	}

noextra:
	handle_environment(strlen(cmdline), max_cmdline_len);
}

void start(void)
{
	unsigned int subchannel_id;

	if (secure_boot_enabled())
		verify_secure_boot();

	ebcdic_update_table();

	/*
	 * cut the kernel header
	 */
	memmove((void *)_stage3_parms.image_addr,
		(void *)_stage3_parms.image_addr + IMAGE_LOAD_ADDRESS,
		_stage3_parms.image_len - IMAGE_LOAD_ADDRESS);

	/* store subchannel ID into low core and into new kernel space */
	subchannel_id = S390_lowcore.subchannel_id;
	*(unsigned int *)__LC_IPLDEV = subchannel_id;
	*(unsigned long long *)IPL_DEVICE = subchannel_id;

	setup_cmdline();

	/* copy initrd start address and size intop new kernle space */
	*(unsigned long long *)INITRD_START = _stage3_parms.initrd_addr;
	*(unsigned long long *)INITRD_SIZE = _stage3_parms.initrd_len;

	/*
	 * store address of new kernel to 0 to be able to start it.
	 * -fno-delete-null-pointer-checks allows us to dereference 0 here,
	 * which otherwise would be an UB.
	 */
	*(volatile unsigned long long *)0 = _stage3_parms.load_psw;

	kdump_stage3();

	/* start new kernel */
	start_kernel();
}

void panic_notify(unsigned long UNUSED(rc))
{
}
