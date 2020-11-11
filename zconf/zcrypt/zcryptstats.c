/*
 * zcryptstats - Show usage statistics of IBM Crypto Express adapters
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <asm/chsc.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/utsname.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

#ifndef offsetof
	#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif
#ifndef offsetofend
	#define offsetofend(type, member) \
		(offsetof(type, member) + sizeof(((type *)0)->member))
#endif

#define SYSFS_DEVICES_AP_PATH		"devices/ap"
#define SYSFS_DEVICES_CARD		"devices/ap/card%02x"
#define SYSFS_DEVICES_APQN		"devices/ap/card%02x/%02x.%04x"
#define SYSFS_DEVICES_CARD_ONLINE	"devices/ap/card%02x/online"
#define SYSFS_DEVICES_APQN_ONLINE	"devices/ap/card%02x/%02x.%04x/online"
#define CHSC_DEVICE			"/dev/chsc"
#define NUM_CARDS_OLD			64
#define NUM_CARDS			256
#define NUM_DOMAINS			256

#define MASK_WORD_BITS			(sizeof(uint32_t) * 8)
#define MASK_WORD_NO(n)			((n) / MASK_WORD_BITS)
#define MASK_BIT_IN_WORD(n)		((n) % MASK_WORD_BITS)
#define MASK_BIT(n)			(0x80000000 >> MASK_BIT_IN_WORD(n))

struct chsc_apdn {
	uint8_t ap_index;
	uint8_t domain_index;
} __packed;

struct chsc_scdmd_request {
	struct chsc_header header;
	struct chsc_apdn first_drid;
	struct chsc_apdn last_drid;
	uint32_t s:1;
	uint32_t reserved1:31;
	uint32_t reserved2;
	uint32_t apsm[8];
	uint32_t dsm[8];
} __packed;

struct chsc_scdmd_response {
	struct chsc_header header;
	uint32_t reserved1;
	uint16_t p:1;
	uint16_t reserved2:15;
	struct chsc_apdn crid;
	uint32_t reserved3;
} __packed;

struct chsc_scdmd_area {
	struct chsc_scdmd_request request;
	struct chsc_scdmd_response response;
	uint8_t response_data[CHSC_SIZE - sizeof(struct chsc_scdmd_request) -
			 sizeof(struct chsc_scdmd_response)];
} __packed;

struct chsc_scmd_request {
	struct chsc_header header;
	uint8_t reserved1;
	uint8_t zeros1:6;
	uint8_t one:1;
	uint8_t zero:1;
	uint8_t fcs;
	uint8_t lcs;
	uint32_t reserved2;
	uint32_t reserved3;
} __packed;

struct chsc_scmd_response {
	struct chsc_header header;
	uint32_t reserved1;
	uint32_t p:1;
	uint32_t reserved2:31;
	uint32_t reserved3;
} __packed;

struct chsc_scmd_area {
	struct chsc_scmd_request request;
	struct chsc_scmd_response response;
	uint8_t response_data[CHSC_SIZE - sizeof(struct chsc_scmd_request) -
			 sizeof(struct chsc_scmd_response)];
} __packed;

struct chsc_cmb_header {
	uint8_t reserved1;
	uint8_t ct; /* AP_DEVICE_TYPE_xxx values */
	uint8_t format;
	uint8_t ax;
	float s;
	uint32_t v;
	uint8_t dx;
	uint8_t mt;
	uint16_t l4;
} __packed;

struct chsc_cmb_entry {
	u64 t;
	u64 c;
} __packed;

struct chsc_cmb_area {
	struct chsc_cmb_header header;
	struct chsc_cmb_entry entries[32];
} __packed;

#define CRYPTO_TYPE_PCICC	3
#define CRYPTO_TYPE_PCICA	4
#define CRYPTO_TYPE_PCIXCC	5
#define CRYPTO_TYPE_CEX2A	6
#define CRYPTO_TYPE_CEX2C	7
#define CRYPTO_TYPE_CEX3A	8
#define CRYPTO_TYPE_CEX3C	9
#define CRYPTO_TYPE_CEX4S	10
#define CRYPTO_TYPE_CEX5S	11
#define CRYPTO_TYPE_CEX6S	12
#define CRYPTO_TYPE_CEX7S	13

#define CRYPTO_TYPE_TOLERATION	CRYPTO_TYPE_CEX7S

struct crypto_counter {
	const char *name;
	bool is_totals;
};

struct crypto_mode {
	const char *name;
	char indicatior_char;
	unsigned int num_counters;
	const struct crypto_counter *counters;
};

struct crypto_type {
	const char *name;
	unsigned int num_modes;
	const struct crypto_mode *modes;
};

#define NUM_COPROC_COUNTERS	2
const struct crypto_counter counter_coproc[NUM_COPROC_COUNTERS] = {
		{ .name = "All", .is_totals = true },
		{ .name = "RSA Key-gen" },
};

#define NUM_ACCEL_COUNTERS	6
const struct crypto_counter counter_accel[NUM_ACCEL_COUNTERS] = {
		{ .name = "RSA 1024 ME" },
		{ .name = "RSA 2048 ME" },
		{ .name = "RSA 1024 CRT" },
		{ .name = "RSA 2048 CRT" },
		{ .name = "RSA 4096 ME" },
		{ .name = "RSA 4096 CTR" },
};

#define NUM_EP11_COUNTERS	5
const struct crypto_counter counter_ep11[NUM_EP11_COUNTERS] = {
		{ .name = "Asym. Slow" },
		{ .name = "Asym. Fast" },
		{ .name = "Symm. Partial" },
		{ .name = "Symm. Complete" },
		{ .name = "Asym. Key-gen" },
};

#define NUM_PCICA_COUNTERS	20
const struct crypto_counter counter_pcica[NUM_PCICA_COUNTERS] = {
		{ .name = "RSA 1024 ME (E0)" },
		{ .name = "RSA 2048 ME (E0)" },
		{ .name = "RSA 1024 CRT (E0)" },
		{ .name = "RSA 2048 CRT (E0)" },
		{ .name = "RSA 1024 ME (E1)" },
		{ .name = "RSA 2048 ME (E1)" },
		{ .name = "RSA 1024 CRT (E1)" },
		{ .name = "RSA 2048 CRT (E1)" },
		{ .name = "RSA 1024 ME (E2)" },
		{ .name = "RSA 2048 ME (E2)" },
		{ .name = "RSA 1024 CRT (E2)" },
		{ .name = "RSA 2048 CRT (E2)" },
		{ .name = "RSA 1024 ME (E3)" },
		{ .name = "RSA 2048 ME (E3)" },
		{ .name = "RSA 1024 CRT (E3)" },
		{ .name = "RSA 2048 CRT (E3)" },
		{ .name = "RSA 1024 ME (E4)" },
		{ .name = "RSA 2048 ME (E4)" },
		{ .name = "RSA 1024 CRT (E4)" },
		{ .name = "RSA 2048 CRT (E4)" },
};

#define NUM_COPROC_MODES	1
const struct crypto_mode mode_coproc[1] = {
		{ .num_counters = NUM_COPROC_COUNTERS,
		  .counters = counter_coproc},
};

#define NUM_ACCEL_MODES		1
const struct crypto_mode mode_accel[1] = {
		{ .num_counters = NUM_ACCEL_COUNTERS,
		  .counters = counter_accel },
};

#define NUM_PCICA_MODES		1
const struct crypto_mode mode_pcica[1] = {
		{ .num_counters = NUM_PCICA_COUNTERS,
		  .counters = counter_pcica },
};

#define NUM_CEX4567_MODES	11
const struct crypto_mode mode_cex4567[NUM_CEX4567_MODES] = {
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ .name  = "Accelerator", .indicatior_char = 'A',
		  .num_counters = NUM_ACCEL_COUNTERS,
		  .counters = counter_accel },
		{ .name  = "CCA co-processor", .indicatior_char = 'C',
		  .num_counters = NUM_COPROC_COUNTERS,
		  .counters = counter_coproc},
		{ .name  = "EP11 co-processor", .indicatior_char = 'P',
		  .num_counters = NUM_EP11_COUNTERS,
		  .counters = counter_ep11 },
};

#define NUM_CRYPTO_TYPES	14
const struct crypto_type crypto_types[NUM_CRYPTO_TYPES] = {
		{ 0 },
		{ 0 },
		{ 0 },
		{ .name = "PCICC", .num_modes = NUM_COPROC_MODES,
		  .modes = mode_coproc },
		{ .name = "PCICA", .num_modes = NUM_PCICA_MODES,
		  .modes = mode_pcica },
		{ .name = "PCIXCC", .num_modes = NUM_COPROC_MODES,
		  .modes = mode_coproc},
		{ .name = "CEX2A", .num_modes = NUM_ACCEL_MODES,
		  .modes = mode_accel },
		{ .name = "CEX2C", .num_modes = NUM_COPROC_MODES,
		  .modes = mode_coproc },
		{ .name = "CEX3A", .num_modes = NUM_ACCEL_MODES,
		  .modes = mode_accel },
		{ .name = "CEX3C", .num_modes = NUM_COPROC_MODES,
		  .modes = mode_coproc },
		{ .name = "CEX4", .num_modes = NUM_CEX4567_MODES,
		  .modes = mode_cex4567 },
		{ .name = "CEX5", .num_modes = NUM_CEX4567_MODES,
		  .modes = mode_cex4567 },
		{ .name = "CEX6", .num_modes = NUM_CEX4567_MODES,
		  .modes = mode_cex4567 },
		{ .name = "CEX7", .num_modes = NUM_CEX4567_MODES,
		  .modes = mode_cex4567 },
};


struct type_mapping {
	uint8_t from_type;
	uint8_t from_mode;
	uint8_t to_type;
	uint8_t to_mode;
	struct type_mapping *next;
};

struct device_selection {
	int card;
	int domain; /* -1 if not specified */
	struct device_selection *next;
};

struct interval_data {
	bool current_valid;
	bool previous_valid;
	struct chsc_cmb_area current;
	struct chsc_cmb_area previous;
};

struct card_data {
	struct interval_data data;
	struct interval_data *domains[NUM_DOMAINS];
};

struct interval_values {
	u64 count;
	double rate;
	double utilization;
	double duration;
};

struct print_func {
	int (*print_initialize)(void);
	int (*print_terminate)(void);
	int (*print_header)(void);
	int (*print_footer)(void);
	int (*print_interval_header)(unsigned long interval_count,
				     const char *timestamp);
	int (*print_interval_footer)(void);
	int (*print_device_header)(bool is_apqn, uint8_t card, uint8_t domain,
				   const char *type, const char *timestamp);
	int (*print_device_footer)(void);
	int (*print_counter_data)(bool is_apqn, uint8_t card, uint8_t domain,
				  const char *type, const char *timestamp,
				  const char *name,
				  struct interval_values *vals);
	int (*print_counter_separator)(void);
};

#define pr_call(func)	g.print_funcs->func == NULL ? 0 : g.print_funcs->func

static int default_print_initialize(void);
static int default_print_terminate(void);
static int default_print_header(void);
static int default_print_footer(void);
static int default_print_interval_header(unsigned long interval_count,
					 const char *timestamp);
static int default_print_device_header(bool is_apqn, uint8_t card,
				       uint8_t domain, const char *type,
				       const char *timestamp);
static int default_print_device_footer(void);
static int default_print_counter_data(bool is_apqn, uint8_t card,
				      uint8_t domain, const char *type,
				      const char *timestamp, const char *name,
				      struct interval_values *vals);
static int default_print_counter_separator(void);

static const struct print_func default_print = {
	.print_initialize = default_print_initialize,
	.print_terminate = default_print_terminate,
	.print_header = default_print_header,
	.print_footer = default_print_footer,
	.print_interval_header = default_print_interval_header,
	.print_device_header = default_print_device_header,
	.print_device_footer = default_print_device_footer,
	.print_counter_data = default_print_counter_data,
	.print_counter_separator = default_print_counter_separator,
};

static int json_print_initialize(void);
static int json_print_header(void);
static int json_print_footer(void);
static int json_print_interval_header(unsigned long interval_count,
				      const char *timestamp);
static int json_print_interval_footer(void);
static int json_print_device_header(bool is_apqn, uint8_t card,
				    uint8_t domain, const char *type,
				    const char *timestamp);
static int json_print_device_footer(void);
static int json_print_counter_data(bool is_apqn, uint8_t card, uint8_t domain,
				   const char *type, const char *timestamp,
				   const char *name,
				   struct interval_values *vals);

static const struct print_func json_print = {
	.print_initialize = json_print_initialize,
	.print_header = json_print_header,
	.print_footer = json_print_footer,
	.print_interval_header = json_print_interval_header,
	.print_interval_footer = json_print_interval_footer,
	.print_device_header = json_print_device_header,
	.print_device_footer = json_print_device_footer,
	.print_counter_data = json_print_counter_data,
};


static int table_print_initialize(void);
static int table_print_terminate(void);
static int table_print_header(void);
static int table_print_interval_footer(void);
static int table_print_counter_data(bool is_apqn, uint8_t card, uint8_t domain,
				    const char *type, const char *timestamp,
				    const char *name,
				    struct interval_values *vals);

static const struct print_func table_print = {
	.print_initialize = table_print_initialize,
	.print_terminate = table_print_terminate,
	.print_header = table_print_header,
	.print_interval_footer = table_print_interval_footer,
	.print_counter_data = table_print_counter_data,
};

static int csv_print_initialize(void);
static int csv_print_terminate(void);
static int csv_print_header(void);
static int csv_print_counter_data(bool is_apqn, uint8_t card, uint8_t domain,
				    const char *type, const char *timestamp,
				    const char *name,
				    struct interval_values *vals);

static const struct print_func csv_print = {
	.print_initialize = csv_print_initialize,
	.print_terminate = csv_print_terminate,
	.print_header = csv_print_header,
	.print_counter_data = csv_print_counter_data,
};

/*
 * Program configuration
 */
const struct util_prg prg = {
	.desc = "Display usage statistics of IBM Crypto Express adapters",
	.args = "[DEVICE_IDS]",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2019,
			.pub_last = 2019,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Global variables for program options
 */
static struct zcryptstats_globals {
	long interval;
	unsigned long count;
	bool no_totals;
	bool only_totals;
	bool no_apqn;
	char *map_type;
	char **device_ids;
	bool all;
	bool only_online;
	bool verbose;
	int chsc_fd;
	uint8_t max_card_used;
	uint32_t card_mask[8];
	uint8_t min_card;
	uint8_t max_card;
	uint32_t domain_mask[8];
	uint8_t min_domain;
	uint8_t max_domain;
	struct device_selection *dev_selection;
	struct type_mapping *type_mapping;
	struct card_data *cards[NUM_CARDS];
	const struct print_func *print_funcs;
	struct util_rec *device_rec;
	struct util_rec *counter_rec;
	bool first_device;
	bool first_counter;
} g = {
	.interval = 10,
	.chsc_fd = -1,
	.print_funcs = &default_print,
};


static volatile bool quit;

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
	},
	{
		.option = {"interval", required_argument, NULL, 'i'},
		.argument = "INTERVAL",
		.desc = "Specifies the interval time in seconds. If omitted, a "
			"default interval of 10 seconds is used",
	},
	{
		.option = {"count", required_argument, NULL, 'c'},
		.argument = "COUNT",
		.desc = "Specifies  the  number of reports that are generated "
			"at INTERVAL seconds apart. If omitted, reports are "
			"generated continuously, until stopped with control-C",
	},
	{
		.option = {"output", required_argument, NULL, 'o'},
		.argument = "JSON|TABLE|CSV",
		.desc = "Displays the statistics in the specified format. If "
			"this option is omitted, a comprehensive report is "
			"displayed. Supported output formats are: JSON, TABLE, "
			"CSV. With TABLE and CSV the display of the individual "
			"counters are omitted, and only the totals are "
			"displayed. CSV and TABLE output formats imply option "
			"--only-totals",
	},
	{
		.option = {"no-totals", 0, NULL, 't'},
		.desc = "Excludes the totals of all counters of a card "
			"device or queue device (APQN). It can not be "
			"specified together with option --only-totals or "
			"option --output TABLE|CSV",
	},
	{
		.option = {"only-totals", 0, NULL, 'T'},
		.desc = "Displays only the totals of all counters of a card "
			"device or a queue device (APQN), but not the "
			"individual counters. This option is implied with "
			"option --output TABLE|CSV",
	},
	{
		.option = {"no-apqn", 0, NULL, 'a'},
		.desc = "Displays only the counters of the card device, but "
			"omits the counters of the queue device (APQN). If the "
			"system does not support obtaining cryptographic "
			"performance measurement data on the queue devices, "
			"then this option is implied",
	},
	{
		.option = {"map-type", required_argument, NULL, 'M'},
		.argument = "MAPPING",
		.desc = "Maps unknown cryptographic device types and modes to "
			"known types and modes. This option should only be "
			"used when new, so far unknown cryptographic devices "
			"are found. You can then map them to known devices and "
			"modes, provided that the new cryptographic devices "
			"report the same counters as the known cryptographic "
			"device to which it is mapped. The mapping "
			"specification consists of a comma-separated list of "
			"FROM-TYPE:FROM-MODE=TO-TYPE:TO-MODE specifications. "
			"The type and mode values must be specified in decimal "
			"notation",
	},
	{
		.option = {"all", 0, NULL, 'A'},
		.desc = "Displays all cards devices and queue devices (APQNs), "
			"not only those that are available to the Linux "
			"system. Using this option additional cryptographic "
			"devices that are available in the CEC, but not "
			"available to the Linux system are also monitored. "
			"This option can not be specified together with option "
			"--only-online",
	},
	{
		.option = {"only-online", 0, NULL, 'O'},
		.desc = "Displays only online cards devices and queue devices "
			"(APQNs). This option can not be specified together "
			"with option --all"
	},
	{
		.option = {"verbose", 0, NULL, 'V'},
		.desc = "Prints additional information messages during "
			"processing",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#define pr_verbose(fmt...)	do { \
					if (g.verbose) \
						warnx(fmt); \
				} while (0)

/*
 * Describe adapter ids
 */
static void print_adapter_id_help(void)
{
	printf("\n");
	printf("DEVICE_IDS\n");
	util_print_indented("  List of cryptographic device IDs separated by "
			    "blanks for which statistics are displayed. "
			    "DEVICE_ID can either be a card device ID "
			    "('<card-id>') or a queue device ID (<card-id>."
			    "<domain-id>'). To filter all devices by domain, "
			    "provide '.<domain-id>'. If no IDs are given, "
			    "statistics are displayed for all available "
			    "devices.", 2);
	printf("\n");
	printf("EXAMPLE:\n");
	util_print_indented("  Display statistics for all cryptographic "
			    "devices with card ID '02.", 2);
	printf("  # zcryptstats 02\n");
	printf("\n");
	util_print_indented("  Display statistics for cryptographic devices "
			    "with card ID '02' and domain ID '0005'.", 2);
	printf("  # zcryptstats 02.0005\n");
	printf("\n");
}

static struct type_mapping *find_type_mapping(uint8_t from_type,
					      uint8_t from_mode)
{
	struct type_mapping *map = g.type_mapping;

	while (map != NULL) {
		if (map->from_type == from_type && map->from_mode == from_mode)
			return map;
		map = map->next;
	}
	return NULL;
}

/*
 * Get the name of the card for a crypto type and mode.
 * Note: This function might return the address of a static string variable.
 * It is only valid until this function is called again.
 */
static const char *get_card_name(uint8_t type, uint8_t mode)
{
	const struct crypto_type *ct;
	const struct crypto_mode *m;
	static char temp_name[250];
	struct type_mapping *map;

	map = find_type_mapping(type, mode);
	if (map != NULL) {
		type = map->to_type;
		mode = map->to_mode;
	} else if (type >= NUM_CRYPTO_TYPES) {
		type = CRYPTO_TYPE_TOLERATION;
	}

	if (type >= NUM_CRYPTO_TYPES)
		return "UNKNOWN ADAPTER TYPE";

	ct = &crypto_types[type];
	if (ct->name == NULL || ct->modes == NULL || ct->num_modes == 0)
		return "UNKNOWN ADAPTER TYPE";

	if (mode >= ct->num_modes)
		return ct->name;

	m = &ct->modes[mode];
	snprintf(temp_name, sizeof(temp_name) - 1, "%s%c (%s)", ct->name,
		 m->indicatior_char, m->name != NULL ? m->name : "");
	return temp_name;
}

/*
 * Get the name of a counter for a crypto type, mode and index.
 * Note: This function might return the address of a static string variable.
 * It is only valid until this function is called again.
 */
static const char *get_counter_name(uint8_t type, uint8_t mode, uint8_t index)
{
	const struct crypto_type *ct;
	const struct crypto_mode *m;
	static char temp_name[250];
	struct type_mapping *map;

	map = find_type_mapping(type, mode);
	if (map != NULL) {
		type = map->to_type;
		mode = map->to_mode;
	} else if (type >= NUM_CRYPTO_TYPES) {
		type = CRYPTO_TYPE_TOLERATION;
	}

	if (type >= NUM_CRYPTO_TYPES)
		goto generic;

	ct = &crypto_types[type];
	if (ct->name == NULL || ct->modes == NULL || ct->num_modes == 0)
		goto generic;

	if (mode >= ct->num_modes)
		goto generic;

	m = &ct->modes[mode];
	if (m->counters == NULL || m->num_counters == 0)
		goto generic;

	if (index >= m->num_counters)
		goto generic;

	return m->counters[index].name;

generic:
	snprintf(temp_name, sizeof(temp_name) - 1, "COUNTER %u", index);
	return temp_name;
}

/*
 * Returns true if a counter for a crypto type, mode and index represents the
 * total number of operations.
 */
static bool is_counter_totals(uint8_t type, uint8_t mode, uint8_t index)
{
	const struct crypto_type *ct;
	const struct crypto_mode *m;
	struct type_mapping *map;

	map = find_type_mapping(type, mode);
	if (map != NULL) {
		type = map->to_type;
		mode = map->to_mode;
	} else if (type >= NUM_CRYPTO_TYPES) {
		type = CRYPTO_TYPE_TOLERATION;
	}

	if (type >= NUM_CRYPTO_TYPES)
		return false;

	ct = &crypto_types[type];
	if (ct->name == NULL || ct->modes == NULL || ct->num_modes == 0)
		return false;

	if (mode >= ct->num_modes)
		return false;

	m = &ct->modes[mode];
	if (m->counters == NULL || m->num_counters == 0)
		return false;

	if (index >= m->num_counters)
		return false;

	return m->counters[index].is_totals;
}

/*
 * Returns true if the card is available
 */
static bool is_card_available(uint8_t card)
{
	char *path;
	bool ret;

	path = util_path_sysfs(SYSFS_DEVICES_CARD, card);
	ret = util_path_is_dir(path);
	free(path);

	return ret;
}

/*
 * Returns true if the APQN is available
 */
static bool is_apqn_available(uint8_t card, uint8_t domain)
{
	char *path;
	bool ret;

	path = util_path_sysfs(SYSFS_DEVICES_APQN, card, card, domain);
	ret = util_path_is_dir(path);
	free(path);

	return ret;
}

/*
 * Returns true if the card is online
 */
static bool is_card_online(uint8_t card)
{
	unsigned long online;
	char *path;
	int rc;

	path = util_path_sysfs(SYSFS_DEVICES_CARD_ONLINE, card);
	rc = util_file_read_ul(&online, 10, path);
	free(path);

	return rc == 0 && online != 0;
}

/*
 * Returns true if the APQN is online
 */
static bool is_apqn_online(uint8_t card, uint8_t domain)
{
	unsigned long online;
	char *path;
	int rc;

	path = util_path_sysfs(SYSFS_DEVICES_APQN_ONLINE, card, card, domain);
	rc = util_file_read_ul(&online, 10, path);
	free(path);

	if (rc != 0)
		return false;

	return online != 0;
}

/*
 * Updates the APQNs data with data for the current interval.
 */
static void update_apqn_data(uint8_t card, uint8_t domain,
			     struct chsc_cmb_area *cmb, size_t cmb_len)
{
	struct card_data *cd = g.cards[card];
	struct interval_data *dd;

	if (cd == NULL) {
		cd = util_malloc(sizeof(struct card_data));
		memset(cd, 0, sizeof(struct card_data));
		g.cards[card] = cd;

		pr_verbose("Card %02x added", card);
	}

	dd = cd->domains[domain];
	if (dd == NULL) {
		dd = util_malloc(sizeof(struct interval_data));
		memset(dd, 0, sizeof(struct interval_data));
		cd->domains[domain] = dd;

		pr_verbose("APQN %02x.%04x added", card, domain);
	} else {
		if (!dd->current_valid) {
			dd->previous = dd->current;
			dd->previous_valid = true;
		}
	}

	memset(&dd->current, 0, sizeof(struct chsc_cmb_area));
	memcpy(&dd->current, cmb, cmb_len);
	dd->current_valid = true;
}

/*
 * Updates the card's data with data for the current interval.
 */
static void update_card_data(uint8_t card, struct chsc_cmb_area *cmb,
			     size_t cmb_len)
{
	struct card_data *cd = g.cards[card];

	if (cd == NULL) {
		cd = util_malloc(sizeof(struct card_data));
		memset(cd, 0, sizeof(struct card_data));
		g.cards[card] = cd;

		pr_verbose("Card %02x added", card);
	} else {
		if (!cd->data.current_valid) {
			cd->data.previous = cd->data.current;
			cd->data.previous_valid = true;
		}
	};

	memset(&cd->data.current, 0, sizeof(struct chsc_cmb_area));
	memcpy(&cd->data.current, cmb, cmb_len);
	cd->data.current_valid = true;
}

/*
 * Frees the interval data of a card
 */
static void free_card_data(struct card_data *cd)
{
	struct interval_data *dd;
	int domain;

	if (cd == NULL)
		return;

	for (domain = 0; domain < NUM_DOMAINS; domain++) {
		dd = cd->domains[domain];
		if (dd == NULL)
			continue;

		free(dd);
		cd->domains[domain] = NULL;
	}

	free(cd);
}

/*
 * Frees the interval data
 */
static void free_interval_data(void)
{
	struct card_data *cd;
	int card;

	for (card = 0; card < NUM_CARDS; card++) {
		cd = g.cards[card];
		if (cd == NULL)
			continue;

		free_card_data(cd);
		g.cards[card] = NULL;
	}
}

/*
 * Returns the highest card index used by the system.
 * If there is a card with an index > 0x3f, then the returned number is 0xff,
 * else 0x3f is returned.
 */
static int get_max_card_index(uint8_t *max_index)
{
	struct dirent **dev_vec = NULL;
	int i, count, card, rc = 0;
	char *path;

	path = util_path_sysfs(SYSFS_DEVICES_AP_PATH);
	if (!util_path_is_dir(path)) {
		warnx("Crypto device driver is not available");
		rc = -ENODEV;
		goto out;
	}

	count = util_scandir(&dev_vec, NULL, path, "card[0-9a-fA-F]+");
	if (count < 1) {
		warnx("No crypto card devices found");
		rc = -ENODEV;
		goto out;
	}

	*max_index = NUM_CARDS_OLD - 1;
	for (i = 0; i < count; i++) {
		if (sscanf(dev_vec[i]->d_name, "card%x", &card) != 1)
			continue;
		if (card >= NUM_CARDS_OLD)
			*max_index = NUM_CARDS - 1;
	}

	pr_verbose("Max card index used: %u", *max_index);

out:
	free(path);
	if (dev_vec != NULL)
		free(dev_vec);
	return rc;
}

/*
 * Returns the size of the CMB. The size is either contained in l4 field
 * of the cmb, or a fix length dependent on the crypto type, if l4 is zero.
 */
static size_t get_cmb_length(struct chsc_cmb_area *cmb)
{
	size_t len = cmb->header.l4;

	if (len != 0)
		return len;

	switch (cmb->header.ct) {
	case CRYPTO_TYPE_PCICC:
	case CRYPTO_TYPE_PCIXCC:
	case CRYPTO_TYPE_CEX2C:
	case CRYPTO_TYPE_CEX3C:
		return 64;
	case CRYPTO_TYPE_PCICA:
		return 336;
	case CRYPTO_TYPE_CEX2A:
	case CRYPTO_TYPE_CEX3A:
		return 80;
	default:
		warnx("Zero length value in CMB");
		return 0;
	}
}

/*
 * Return true if the device is in the device selection list and mask
 */
static bool filter_device(uint8_t card, uint8_t domain, bool is_apqn)
{
	struct device_selection *dev;
	bool found;

	/* Check for selection mask */
	if ((g.card_mask[MASK_WORD_NO(card)] &
				MASK_BIT(card)) == 0) {
		pr_verbose("Skipping card %02x (mask)", card);
		return false;
	}
	if (is_apqn) {
		if ((g.domain_mask[MASK_WORD_NO(domain)] &
					MASK_BIT(domain)) == 0) {
			pr_verbose("Skipping APQN %02x.%04x (mask)", card,
				   domain);
			return false;
		}
	}

	/* Check for device selection list */
	if (g.dev_selection != NULL) {
		dev = g.dev_selection;
		found = false;
		while (dev != NULL) {
			if (is_apqn == false) {
				/* Its a card */
				if (card == (dev->card >= 0 ? dev->card :
						card)) {
					found = true;
					break;
				}
			} else {
				/* Its an APQN */
				if (card == (dev->card >= 0 ? dev->card :
						card) &&
				    domain == (dev->domain >= 0 ? dev->domain :
						domain)) {
					found = true;
					break;
				}
			}

			dev = dev->next;
		}

		if (!found) {
			if (is_apqn)
				pr_verbose("Skipping APQN %02x.%04x "
					   "(selection)", card, domain);
			else
				pr_verbose("Skipping card %02x (selection)",
					   card);
			return false;
		}
	}

	if (g.all)
		return true;

	/* Check if card/APQN is available in the system (SYSFS) */
	if (!is_card_available(card)) {
		pr_verbose("Skipping card %02x (not available)", card);
		return false;
	}
	if (is_apqn && !is_apqn_available(card, domain)) {
		pr_verbose("Skipping APQN %02x.%04x (not available)",
			   card, domain);
		return false;
	}

	if (g.only_online) {
		/* Check if card/APQN is online */
		if (!is_card_online(card)) {
			pr_verbose("Skipping card %02x (not online)", card);
			return false;
		}
		if (is_apqn && !is_apqn_online(card, domain)) {
			pr_verbose("Skipping APQN %02x.%04x (not online)",
				   card, domain);
			return false;
		}
	}

	return true;
}

/*
 * Process a crypto measurement block.
 * Passes back the actual length of the CMB processed and its card number.
 * Returns -ENODEV when the CMB is skipped.
 */
static int process_cmb(struct chsc_cmb_area *cmb, size_t size, size_t *length,
		       uint8_t *card)
{
	size_t len;

	len = get_cmb_length(cmb);
	if (len == 0)
		return -EINVAL;

	if (len > size) {
		warnx("Length value in CMB exceeds size of CMB");
		return -EINVAL;
	}

	if (card != NULL)
		*card = cmb->header.ax;
	if (length != NULL)
		*length = len;

	if (filter_device(cmb->header.ax, cmb->header.dx,
			  cmb->header.format == 1) == false)
		return -ENODEV;

	if (cmb->header.format == 1)
		update_apqn_data(cmb->header.ax, cmb->header.dx, cmb, len);
	else
		update_card_data(cmb->header.ax, cmb, len);

	return 0;
}

/*
 * Translate the CHSC response code to an error (0 or negative errno)
 */
static int chsc_error_from_response(int response)
{
	if (response != 0x0001)
		pr_verbose("CHSC Response code: %04x", response);

	switch (response) {
	case 0x0001:
		return 0;
	case 0x0002:
		return -EOPNOTSUPP;
	case 0x0003:
	case 0x0006:
	case 0x0007:
	case 0x0008:
	case 0x000a:
	case 0x0103:
	case 0x0104:
		return -EINVAL;
	case 0x0004:
		return -EOPNOTSUPP;
	case 0x000b:
		return -EBUSY;
	case 0x0102:
		return -ENOMEM;
	case 0x0105:
		return -EACCES;
	case 0x0100:
	case 0x0107:
		return -ENODEV;
	default:
		return -EIO;
	}
}

/*
 * Process the APQN measurement data and extract the CMBs
 */
static int process_apqn_measurement_data(struct chsc_scdmd_area *scdmd_area)
{
	size_t size = scdmd_area->response.header.length -
				sizeof(struct chsc_scdmd_response);
	size_t len, ofs = 0;
	int rc;

	while (ofs < size) {
		rc = process_cmb((struct chsc_cmb_area *)
					&scdmd_area->response_data[ofs],
				 size - ofs, &len, NULL);
		if (rc != 0 && rc != -ENODEV)
			return rc;
		ofs += len;

	}

	return 0;
}

/*
 * Get Crypto Measurement data on the APQN level
 */
static int get_apqn_measurement_data(uint8_t card)
{
	struct chsc_scdmd_area scdmd_area;
	int rc;

	memset(&scdmd_area, 0, sizeof(scdmd_area));
	do {
		scdmd_area.request.header.code = 0x102d;
		scdmd_area.request.header.length =
				sizeof(struct chsc_scdmd_request);
		if (scdmd_area.response.p) {
			scdmd_area.request.first_drid =
						scdmd_area.response.crid;
		} else {
			scdmd_area.request.first_drid.ap_index = card;
			scdmd_area.request.first_drid.domain_index =
								g.min_domain;
		}
		scdmd_area.request.last_drid.ap_index = card;
		scdmd_area.request.last_drid.domain_index = g.max_domain;
		scdmd_area.request.s = 1;
		scdmd_area.request.apsm[MASK_WORD_NO(card)] |= MASK_BIT(card);
		memcpy(scdmd_area.request.dsm, g.domain_mask,
				sizeof(scdmd_area.request.dsm));

		rc = ioctl(g.chsc_fd, CHSC_START_SYNC, &scdmd_area);
		if (rc != 0) {
			rc = -errno;
			warnx("Failed to get APQN measurement data for card "
			      "%02x: %s", card, strerror(errno));
			break;
		}

		rc = chsc_error_from_response(scdmd_area.response.header.code);
		if (rc != 0) {
			if (rc != -EOPNOTSUPP && rc != -ENODEV) {
				warnx("Failed to get APQN crypto measurement "
				      "data for card %02x: %s", card,
				      strerror(-rc));
			} else {
				pr_verbose("Failed to get APQN crypto "
					   "measurement data for card %02x: %s",
					   card, strerror(-rc));
				/*
				 * ignore return code other than -EOPNOTSUPP
				 * and -ENODEV
				 */
				rc = 0;
			}
			break;
		}

		rc = process_apqn_measurement_data(&scdmd_area);
		if (rc != 0)
			break;
	} while (scdmd_area.response.p);

	return rc;
}

/*
 * Process the card measurement data and extract the CMBs
 */
static int process_card_measurement_data(struct chsc_scmd_area *scmd_area,
					 uint8_t *last_card)
{
	size_t size = scmd_area->response.header.length -
				sizeof(struct chsc_scmd_response);
	size_t len, ofs = 0;
	int rc;

	while (ofs < size) {
		rc = process_cmb((struct chsc_cmb_area *)
					&scmd_area->response_data[ofs],
					size - ofs, &len, last_card);
		if (rc != 0 && rc != -ENODEV)
			return rc;
		ofs += len;

		if (rc == -ENODEV)
			continue;

		if (!g.no_apqn) {
			rc = get_apqn_measurement_data(*last_card);
			if (rc != 0)
				return rc;
		}
	}

	return 0;
}

/*
 * Get Crypto Measurement data on the card level
 */
static int get_card_measurement_data(void)
{
	struct chsc_scmd_area scmd_area;
	uint8_t last_card = 0;
	int rc;

	memset(&scmd_area, 0, sizeof(scmd_area));
	do {
		scmd_area.request.header.code = 0x102e;
		scmd_area.request.header.length =
				sizeof(struct chsc_scmd_request);
		scmd_area.request.one = 1;
		scmd_area.request.fcs = g.min_card;
		scmd_area.request.lcs = g.max_card;

		rc = ioctl(g.chsc_fd, CHSC_START_SYNC, &scmd_area);
		if (rc != 0) {
			rc = -errno;
			warnx("Failed to get card measurement data: %s",
			      strerror(errno));
			break;
		}

		rc = chsc_error_from_response(scmd_area.response.header.code);
		if (rc != 0) {
			warnx("Failed to get card crypto measurement data: %s",
			      strerror(-rc));
			break;
		}

		rc = process_card_measurement_data(&scmd_area, &last_card);
		if (rc != 0)
			break;

		if (scmd_area.response.p)
			scmd_area.request.fcs = last_card + 1;
	} while (scmd_area.response.p && last_card < g.max_card);

	return rc;
}

/*
 * Signal handler for SIGALRM
 */
static void alarm_handler(int UNUSED(sig))
{
	if (!quit)
		alarm(g.interval);
}

/*
 * Signal handler for SIGINT and SIGTERM
 */
static void int_handler(int UNUSED(sig))
{
	quit = true;
	raise(SIGALRM);
}

/*
 * Calculates the time difference between tv1 and tv2 in seconds
 */
static float time_diff(struct timeval *tv1, struct timeval *tv2)
{
	struct timeval tv_diff;

	tv_diff.tv_sec = tv2->tv_sec - tv1->tv_sec;
	tv_diff.tv_usec = tv2->tv_usec - tv1->tv_usec;
	if (tv_diff.tv_usec < 0) {
		tv_diff.tv_sec--;
		tv_diff.tv_usec += 1000000;
	}

	return (float)tv_diff.tv_sec +  (float)(0.000001 * tv_diff.tv_usec);
}

/*
 * Initialize the default print format
 */
static int default_print_initialize(void)
{
	g.device_rec = util_rec_new_wide("-");
	util_rec_def(g.device_rec, "device", UTIL_REC_ALIGN_LEFT, 7,
		     "DEVICE");
	util_rec_def(g.device_rec, "kind", UTIL_REC_ALIGN_LEFT, 5, "");
	util_rec_def(g.device_rec, "type", UTIL_REC_ALIGN_LEFT, 33,
		     "TYPE");
	util_rec_def(g.device_rec, "time", UTIL_REC_ALIGN_LEFT, 20,
			     "TIMESTAMP");

	g.counter_rec = util_rec_new_wide("-");
	util_rec_def(g.counter_rec, "name", UTIL_REC_ALIGN_LEFT, 18,
		     "COUNTER");
	util_rec_def(g.counter_rec, "ops", UTIL_REC_ALIGN_RIGHT, 10,
		     "OPS");
	util_rec_def(g.counter_rec, "rate", UTIL_REC_ALIGN_RIGHT, 12,
		     "RATE");
	util_rec_def(g.counter_rec, "utilization", UTIL_REC_ALIGN_RIGHT,
		     12, "UTILIZATION");
	util_rec_def(g.counter_rec, "duration", UTIL_REC_ALIGN_RIGHT,
		     15, "AVG.DURATION");

	return 0;
}

/*
 * Terminate the default print format
 */
static int default_print_terminate(void)
{
	util_rec_free(g.counter_rec);
	util_rec_free(g.device_rec);

	return 0;
}

/*
 * Print the header lines for the default print format
 */
static int default_print_header(void)
{
	char timestamp[64];
	struct utsname un;
	struct tm *tm;
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(timestamp, sizeof(timestamp), "%x", tm);

	if (uname(&un) != 0)
		return -errno;

	printf("%s %s (%s) \t%s\t%s\n\n", un.sysname, un.release,
		 un.nodename, timestamp, un.machine);

	return 0;
}

/*
 * Print the footer lines for the default print format
 */
static int default_print_footer(void)
{
	printf("\n");
	return 0;
}

/*
 * Print the interval header lines for the default print format
 */
static int default_print_interval_header(unsigned long interval_count,
					 const char *timestamp)
{

	printf("*****************************************************"
	       "***************\n");
	printf("TIME: %s\t\tINTERVAL: %lu\n\n", timestamp, interval_count);
	return 0;
}

/*
 * Prints the separator lines in front of a device for the default print format
 */
static int default_print_device_header(bool is_apqn, uint8_t card,
				       uint8_t domain, const char *type,
				       const char *timestamp)
{
	if (is_apqn)
		util_rec_set(g.device_rec, "device", "%02x.%04x", card,
			    domain);
	else
		util_rec_set(g.device_rec, "device", "%02x", card);
	util_rec_set(g.device_rec, "kind", "%s",
		     is_apqn ? "APQN" : "CARD");
	util_rec_set(g.device_rec, "type", "%s", type);
	util_rec_set(g.device_rec, "time", "%s", timestamp);

	util_rec_print_hdr(g.device_rec);
	util_rec_print(g.device_rec);
	printf("\n");

	util_rec_set_indent(g.counter_rec, is_apqn ? 8 : 4);
	util_rec_print_hdr(g.counter_rec);

	return 0;
}

/*
 * Prints the separator lines after a device for the default print format
 */
static int default_print_device_footer(void)
{

	printf("\n");
	return 0;
}


/**
 * Prints the counter data for the default print format
 */
static int default_print_counter_data(bool UNUSED(is_apqn),
				      uint8_t UNUSED(card),
				      uint8_t UNUSED(domain),
				      const char *UNUSED(type),
				      const char *UNUSED(timestamp),
				      const char *name,
				      struct interval_values *vals)
{
	util_rec_set(g.counter_rec, "name", "%s", name);
	util_rec_set(g.counter_rec, "ops", "%llu", vals->count);
	util_rec_set(g.counter_rec, "rate", "%.2f", vals->rate);
	util_rec_set(g.counter_rec, "utilization", "%.2f %%",
			vals->utilization * 100);
	if (vals->duration >= 1)
		util_rec_set(g.counter_rec, "duration", "%.3f sec ",
			     vals->duration);
	else if (vals->duration >= 0.001)
		util_rec_set(g.counter_rec, "duration", "%.3f msec",
			     vals->duration * 1000);
	else
		util_rec_set(g.counter_rec, "duration", "%.3f usec",
			     vals->duration * 1000000);
	util_rec_print(g.counter_rec);

	return 0;
}

/*
 * Prints a separator between the counter lines and the totals line for the
 * default print format
 */
static int default_print_counter_separator(void)
{
	util_rec_print_separator(g.counter_rec);
	return 0;
}

/*
 * Initialize the JSON print format
 */
static int json_print_initialize(void)
{
	/* Use a decimal point to make JSON code compliant with RFC7159 */
	setlocale(LC_NUMERIC, "C");
	return 0;
}

/*
 * Print the header lines for the JSON print format
 */
static int json_print_header(void)
{
	char timestamp[64];
	struct utsname un;
	struct tm *tm;
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(timestamp, sizeof(timestamp), "%x", tm);

	if (uname(&un) != 0)
		return -errno;

	printf("{\"zcryptstats\": {\n");
	printf("\t\"host\": {\n");
	printf("\t\t\"nodename\": \"%s\",\n", un.nodename);
	printf("\t\t\"sysname\": \"%s\",\n", un.sysname);
	printf("\t\t\"release\": \"%s\",\n", un.release);
	printf("\t\t\"machine\": \"%s\",\n", un.machine);
	printf("\t\t\"date\": \"%s\",\n", timestamp);
	printf("\t\t\"statistics\": [\n");

	return 0;
}

/*
 * Print the footer lines for the JSON print format
 */
static int json_print_footer(void)
{
	printf("\n\t\t]\n");
	printf("\t}\n");
	printf("}}\n");

	return 0;
}

/*
 * Print the interval header lines for the JSON print format
 */
static int json_print_interval_header(unsigned long interval_count,
				      const char *timestamp)
{
	if (interval_count > 1)
		printf(",\n");
	printf("\t\t\t{\n");
	printf("\t\t\t\t\"interval\": %lu, \"timestamp\": \"%s\","
	       " \"devices\": [\n", interval_count, timestamp);

	return 0;
}

/*
 * Print the interval footer lines for the JSON print format
 */
static int json_print_interval_footer(void)
{
	if (!g.first_device)
		printf("\n");
	printf("\t\t\t\t]\n");
	printf("\t\t\t}");

	return 0;
}

/*
 * Prints the separator lines in front of a device for the JSON print format
 */
static int json_print_device_header(bool is_apqn, uint8_t card,
				    uint8_t domain, const char *type,
				    const char *UNUSED(timestamp))
{
	if (!g.first_device)
		printf(",\n");
	printf("\t\t\t\t\t{");
	if (is_apqn)
		printf("\"device\": \"%02x.%04x\"", card,
		       domain);
	else
		printf("\"device\": \"%02x\"", card);
	printf(", \"type\": \"%s\",\n", type);
	printf("\t\t\t\t\t \"counters\": [\n");

	return 0;
}

/*
 * Prints the separator lines after a device for the JSON print format
 */
static int json_print_device_footer(void)
{
	if (!g.first_counter)
		printf("\n");
	printf("\t\t\t\t\t ]}");

	return 0;
}


/**
 * Prints the counter data for the JSON print format
 */
static int json_print_counter_data(bool UNUSED(is_apqn),
				   uint8_t UNUSED(card),
				   uint8_t UNUSED(domain),
				   const char *UNUSED(type),
				   const char *UNUSED(timestamp),
				   const char *name,
				   struct interval_values *vals)
{
	if (!g.first_counter)
		printf(",\n");
	printf("\t\t\t\t\t\t{\"counter\": \"%s\", \"ops\": %llu, "
	       "\"rate\": %.2f, \"utilization\": %.2f, \"duration\": %.9f}",
	       name, vals->count, vals->rate, vals->utilization * 100,
	       vals->duration);

	return 0;
}

static int table_print_initialize(void)
{
	g.counter_rec = util_rec_new_wide("-");
	util_rec_def(g.counter_rec, "time", UTIL_REC_ALIGN_LEFT, 20,
			     "TIMESTAMP");
	util_rec_def(g.counter_rec, "device", UTIL_REC_ALIGN_LEFT, 7,
		     "DEVICE");
	util_rec_def(g.counter_rec, "ops", UTIL_REC_ALIGN_RIGHT, 10,
		     "OPS");
	util_rec_def(g.counter_rec, "rate", UTIL_REC_ALIGN_RIGHT, 12,
		     "RATE");
	util_rec_def(g.counter_rec, "utilization", UTIL_REC_ALIGN_RIGHT,
		     12, "UTILIZATION");
	util_rec_def(g.counter_rec, "duration", UTIL_REC_ALIGN_RIGHT,
		     15, "AVG.DURATION");
	return 0;
}

static int table_print_terminate(void)
{
	util_rec_free(g.counter_rec);
	return 0;
}

static int table_print_header(void)
{
	int rc;

	rc = default_print_header();
	if (rc != 0)
		return rc;

	util_rec_print_hdr(g.counter_rec);
	return 0;
}

static int table_print_interval_footer(void)
{
	util_rec_print_separator(g.counter_rec);
	return 0;
}

static int table_print_counter_data(bool is_apqn, uint8_t card, uint8_t domain,
				    const char *UNUSED(type),
				    const char *timestamp,
				    const char *UNUSED(name),
				    struct interval_values *vals)
{
	if (is_apqn)
		util_rec_set(g.counter_rec, "device", "%02x.%04x", card,
			    domain);
	else
		util_rec_set(g.counter_rec, "device", "%02x", card);
	util_rec_set(g.counter_rec, "time", "%s", timestamp);

	util_rec_set(g.counter_rec, "ops", "%llu", vals->count);
	util_rec_set(g.counter_rec, "rate", "%.2f", vals->rate);
	util_rec_set(g.counter_rec, "utilization", "%.2f %%",
		     vals->utilization * 100);
	if (vals->duration >= 1)
		util_rec_set(g.counter_rec, "duration", "%.3f sec ",
			     vals->duration);
	else if (vals->duration >= 0.001)
		util_rec_set(g.counter_rec, "duration", "%.3f msec",
			     vals->duration * 1000);
	else
		util_rec_set(g.counter_rec, "duration", "%.3f usec",
			     vals->duration * 1000000);

	util_rec_print(g.counter_rec);

	return 0;
}

static int csv_print_initialize(void)
{
	/* Use a decimal point to not conflict with the colon separator char */
	setlocale(LC_NUMERIC, "C");

	g.counter_rec = util_rec_new_csv(",");
	util_rec_def(g.counter_rec, "time", UTIL_REC_ALIGN_LEFT, 20,
			     "TIMESTAMP");
	util_rec_def(g.counter_rec, "device", UTIL_REC_ALIGN_LEFT, 7,
		     "DEVICE");
	util_rec_def(g.counter_rec, "ops", UTIL_REC_ALIGN_RIGHT, 10,
		     "OPS");
	util_rec_def(g.counter_rec, "rate", UTIL_REC_ALIGN_RIGHT, 12,
		     "RATE");
	util_rec_def(g.counter_rec, "utilization", UTIL_REC_ALIGN_RIGHT,
		     12, "UTILIZATION");
	util_rec_def(g.counter_rec, "duration", UTIL_REC_ALIGN_RIGHT,
		     15, "AVG.DURATION");
	return 0;
}

static int csv_print_terminate(void)
{
	util_rec_free(g.counter_rec);
	return 0;
}

static int csv_print_header(void)
{
	util_rec_print_hdr(g.counter_rec);
	return 0;
}


static int csv_print_counter_data(bool is_apqn, uint8_t card, uint8_t domain,
				  const char *UNUSED(type),
				  const char *timestamp,
				  const char *UNUSED(name),
				  struct interval_values *vals)
{
	if (is_apqn)
		util_rec_set(g.counter_rec, "device", "%02x.%04x", card,
			    domain);
	else
		util_rec_set(g.counter_rec, "device", "%02x", card);
	util_rec_set(g.counter_rec, "time", "%s", timestamp);
	util_rec_set(g.counter_rec, "ops", "%llu", vals->count);
	util_rec_set(g.counter_rec, "rate", "%.2f", vals->rate);
	util_rec_set(g.counter_rec, "utilization", "%.2f %%",
		     vals->utilization * 100);
	util_rec_set(g.counter_rec, "duration", "%.9f", vals->duration);

	util_rec_print(g.counter_rec);

	return 0;
}

/*
 * Calculates number of ops, utilization, duration and rate of an
 * interval from the timer values, scale and interval time.
 */
static void calc_interval_values(struct chsc_cmb_entry *current,
				 struct chsc_cmb_entry *previous,
				 float scale,
				 float interval_time,
				 struct interval_values *result)
{
	u64 tdiff;

	tdiff = current->t - previous->t;
	result->count = current->c - previous->c;
	result->utilization = (double)(tdiff) * scale / interval_time;
	if (result->count > 0)
		result->duration = (double)(tdiff) * scale / result->count;
	else
		result->duration = 0;
	result->rate = (double)result->count / interval_time;
}

/*
 * Print the measurement data of an interval
 */
static int print_interval_data(struct interval_data *data,
			       const char *timestamp, float interval_time)
{
	struct chsc_cmb_entry total_current;
	struct chsc_cmb_entry total_previous;
	struct interval_values vals;
	const char *type, *counter;
	uint32_t mask = 0x80000000;
	bool totals_found = false;
	size_t len;
	int i, rc;

	len = get_cmb_length(&data->current);
	type = get_card_name(data->current.header.ct, data->current.header.mt);

	rc = pr_call(print_device_header)(data->current.header.format == 1,
					  data->current.header.ax,
					  data->current.header.dx, type,
					  timestamp);
	if (rc != 0)
		return rc;

	memset(&total_current, 0, sizeof(total_current));
	memset(&total_previous, 0, sizeof(total_previous));

	g.first_counter = true;

	for (i = 0; i < 32 &&
	     offsetofend(struct chsc_cmb_area, entries[i]) <= len; i++) {
		if (data->current.header.v & mask) {
			if (is_counter_totals(data->current.header.ct,
					      data->current.header.mt, i)) {
				total_current.t = data->current.entries[i].t;
				total_current.c = data->current.entries[i].c;
				total_previous.t = data->previous.entries[i].t;
				total_previous.c = data->previous.entries[i].c;
				totals_found = true;
			} else if (!totals_found) {
				total_current.t += data->current.entries[i].t;
				total_current.c += data->current.entries[i].c;
				total_previous.t += data->previous.entries[i].t;
				total_previous.c += data->previous.entries[i].c;
			}

			if (g.only_totals)
				continue;

			calc_interval_values(&data->current.entries[i],
					     &data->previous.entries[i],
					     data->current.header.s,
					     interval_time,
					     &vals);

			counter = get_counter_name(data->current.header.ct,
						   data->current.header.mt, i);

			rc = pr_call(print_counter_data)(
					data->current.header.format == 1,
					data->current.header.ax,
					data->current.header.dx, type,
					timestamp, counter, &vals);
			if (rc != 0)
				break;

			g.first_counter = false;
		}
		mask >>= 1;
	}

	if (!g.no_totals) {
		rc = pr_call(print_counter_separator)();
		if (rc != 0)
			return rc;

		calc_interval_values(&total_current, &total_previous,
				     data->current.header.s, interval_time,
				     &vals);

		rc = pr_call(print_counter_data)(
				data->current.header.format == 1,
				data->current.header.ax,
				data->current.header.dx, type,
				timestamp, "Total", &vals);
		if (rc != 0)
			return rc;
	}

	rc = pr_call(print_device_footer)();
	if (rc != 0)
		return rc;

	return 0;
}

/*
 * Print the measured data
 */
static int print_measurement_data(unsigned long interval_count,
				  float interval_time, const char *timestamp)
{
	bool header_printed = false;
	struct interval_data *dd;
	struct card_data *cd;
	int card, domain, rc;

	g.first_device = true;
	for (card = 0; card < NUM_CARDS; card++) {
		cd = g.cards[card];
		if (cd == NULL)
			continue;

		if (!cd->data.current_valid) {
			/* Not update in last interval -> free it */
			free_card_data(cd);
			g.cards[card] = NULL;

			pr_verbose("Card %02x removed", card);
			continue;
		}

		if (cd->data.previous_valid) {
			if (memcmp(&cd->data.current.header,
				   &cd->data.previous.header,
				   sizeof(struct chsc_cmb_header)) != 0) {
				free_card_data(cd);
				g.cards[card] = NULL;

				pr_verbose("CMB header mismatch, card %02x "
					   "removed", card);
				continue;
			}

			if (!header_printed) {
				rc = pr_call(print_interval_header)(
						interval_count, timestamp);
				if (rc != 0)
					return rc;
				header_printed = true;
			}

			rc = print_interval_data(&cd->data, timestamp,
						 interval_time);
			if (rc != 0)
				return rc;

			g.first_device = false;
		}

		cd->data.current_valid = false;

		for (domain = 0; domain < NUM_DOMAINS; domain++) {
			dd = cd->domains[domain];
			if (dd == NULL)
				continue;

			if (!dd->current_valid) {
				/* Not update in last interval -> free it */
				free(dd);
				cd->domains[domain] = NULL;

				pr_verbose("APQN %02x.%04x removed", card,
					   domain);
			}

			if (dd->previous_valid) {
				if (memcmp(&dd->current.header,
					   &dd->previous.header,
					   sizeof(struct chsc_cmb_header))) {
					free(dd);
					cd->domains[domain] = NULL;

					pr_verbose("CMB header mismatch, APQN "
						   "%02x.%04x removed", card,
						   domain);
					continue;
				}

				rc = print_interval_data(dd, timestamp,
							 interval_time);
				if (rc != 0)
					return rc;
			}

			dd->current_valid = false;
		}
	}

	if (header_printed) {
		rc = pr_call(print_interval_footer)();
		if (rc != 0)
			return rc;
	} else if (interval_count > 0) {
		pr_verbose("No data was reported in this interval");
		warnx("Failed to get card crypto measurement data: %s",
		      strerror(ENODEV));
		return -ENODEV;
	}

	return 0;
}

/*
 * Perform the measurement in intervals
 */
static int perform_measurement(void)
{
	struct timeval tv_current, tv_previous;
	struct sigaction alrm_act, int_act;
	unsigned long interval_count = 0;
	float interval_time;
	char timestamp[64];
	struct tm *tm;
	int rc;

	/* Set a handler for SIGINT/SIGTERM */
	memset(&int_act, 0, sizeof(int_act));
	int_act.sa_handler = int_handler;
	sigaction(SIGINT, &int_act, NULL);
	sigaction(SIGTERM, &int_act, NULL);

	/* Set a handler for SIGALRM */
	memset(&alrm_act, 0, sizeof(alrm_act));
	alrm_act.sa_handler = alarm_handler;
	sigaction(SIGALRM, &alrm_act, NULL);

	rc = pr_call(print_initialize)();
	if (rc != 0)
		return rc;

	rc = pr_call(print_header)();
	if (rc != 0)
		return 0;

	alarm(g.interval);

	memset(&tv_current, 0, sizeof(tv_current));
	while (!quit) {
		pr_verbose("Interval %lu", interval_count);

		tv_previous = tv_current;
		rc = gettimeofday(&tv_current, NULL);
		if (rc != 0)
			break;

		tm = localtime(&tv_current.tv_sec);
		if (tm == NULL)
			break;
		strftime(timestamp, sizeof(timestamp), "%x %X", tm);
		interval_time = time_diff(&tv_previous, &tv_current);

		rc = get_card_measurement_data();
		if (rc != 0)
			break;

		rc = print_measurement_data(interval_count, interval_time,
					    timestamp);
		if (rc != 0)
			break;

		if (g.count > 0 && interval_count >= g.count) {
			pr_verbose("Interval limit reached");
			break;
		}
		interval_count++;

		if (quit)
			break;

		pause();
	}

	if (quit)
		pr_verbose("Measurement stopped by user");

	alarm(0);
	memset(&alrm_act, 0, sizeof(alrm_act));
	alrm_act.sa_handler = SIG_DFL;
	sigaction(SIGALRM, &alrm_act, NULL);

	rc = pr_call(print_footer)();
	if (rc != 0)
		return 0;

	rc = pr_call(print_terminate)();
	if (rc != 0)
		return rc;

	return 0;
}

/*
 * Parse the type mapping specification:
 * TYPE:MODE=TYPE:MODE[,TYPE:MODE=TYPE:MODE[,...]]
 */
static int parse_type_mapping(char *mapping)
{
	unsigned int from_type, to_type, from_mode, to_mode;
	struct type_mapping *map;
	char *tok;

	tok = strtok(mapping, ",");
	while (tok != NULL) {
		if (sscanf(tok, "%u:%u=%u:%u", &from_type, &from_mode,
			   &to_type, &to_mode) != 4) {
			warnx("Invalid type mapping: %s", tok);
			return -EINVAL;
		}

		pr_verbose("from_type: %u from_mode: %u to_type: %u "
			   "to_mode: %u", from_type, from_mode, to_type,
			   to_mode);

		if (from_type < NUM_CRYPTO_TYPES &&
		    crypto_types[from_type].name != NULL &&
		    from_mode < crypto_types[from_type].num_modes &&
		    crypto_types[from_type].modes[from_mode].counters != NULL) {
			warnx("Cannot map a known type/mode to another "
			      "type/mode: %s", tok);
			return -EINVAL;
		}

		if (to_type >= NUM_CRYPTO_TYPES ||
		    crypto_types[to_type].name == NULL ||
		    to_mode >= crypto_types[to_type].num_modes ||
		    crypto_types[to_type].modes[to_mode].counters == NULL) {
			warnx("Cannot map a type/mode to an unknown "
			      "type/mode: %s", tok);
			return -EINVAL;
		}

		map = util_malloc(sizeof(struct type_mapping));
		map->from_type = from_type;
		map->from_mode = from_mode;
		map->to_type = to_type;
		map->to_mode = to_mode;

		map->next = g.type_mapping;
		g.type_mapping = map;

		tok = strtok(NULL, ",");
	}

	return 0;
}

static void free_type_mapping(void)
{
	struct type_mapping *map = g.type_mapping;
	struct type_mapping *next;

	while (map != NULL) {
		next = map->next;
		free(map);
		map = next;
	}
}

static int add_device_selection(const char *device_id)
{
	int card = -1, domain = -1;
	struct device_selection *dev;

	pr_verbose("device_id: '%s'", device_id);

	/* check for 'card[.domain]' specification */
	if (sscanf(device_id, "%x.%x", &card, &domain) >= 1) {
		pr_verbose("card: %d domain: %d", card, domain);
		if (card < 0 || card > g.max_card_used) {
			warnx("Invalid card specified: %s", device_id);
			return -EINVAL;
		}
		g.card_mask[MASK_WORD_NO(card)] |= MASK_BIT(card);
		g.min_card = MIN(g.min_card, card);
		g.max_card = MAX(g.max_card, card);

		if (domain >= 0) {
			if (domain > NUM_DOMAINS) {
				warnx("Invalid domain specified: %s",
				      device_id);
				return -EINVAL;
			}
			g.domain_mask[MASK_WORD_NO(domain)] |=
					MASK_BIT(domain);
			g.min_domain = MIN(g.max_domain, domain);
			g.max_domain = MAX(g.max_domain, domain);
		} else {
			memset(g.domain_mask, 0xff, sizeof(g.domain_mask));
			g.min_domain = 0;
			g.max_domain = NUM_DOMAINS - 1;
		}

		dev = util_malloc(sizeof(struct device_selection));
		dev->card = card;
		dev->domain = domain;
		dev->next = g.dev_selection;
		g.dev_selection = dev;

		return 0;
	}
	/* check for '.domain' specification */
	if (device_id[0] == '.' &&
	    sscanf(device_id + 1, "%x", &domain) == 1) {
		pr_verbose("domain: %d", domain);
		if (domain < 0 || domain > NUM_DOMAINS) {
			warnx("Invalid domain specified: %s", device_id);
			return -EINVAL;
		}

		g.domain_mask[MASK_WORD_NO(domain)] |= MASK_BIT(domain);
		g.min_domain = MIN(g.max_domain, domain);
		g.max_domain = MAX(g.max_domain, domain);
		memset(g.card_mask, 0xff, sizeof(g.card_mask));
		g.min_card = 0;
		g.max_card = g.max_card_used;

		dev = util_malloc(sizeof(struct device_selection));
		dev->card = -1;
		dev->domain = domain;
		dev->next = g.dev_selection;
		g.dev_selection = dev;

		return 0;
	}

	warnx("Invalid device ID specified: %s", device_id);
	return -EINVAL;
}

/*
 * Frees the device selection list
 */
static void free_device_selection(void)
{
	struct device_selection *dev = g.dev_selection;
	struct device_selection *next;

	while (dev != NULL) {
		next = dev->next;
		free(dev);

		dev = next;
	}
}

/*
 * Build the AP and domain selection mask from the specified device ID's.
 */
static int parse_device_selection(void)
{
	int i, rc;

	g.min_card = NUM_CARDS - 1;
	g.max_card = 0;
	g.min_domain = NUM_DOMAINS - 1;
	g.max_domain = 0;

	for (i = 0; g.device_ids[i] != NULL; i++) {
		rc = add_device_selection(g.device_ids[i]);
		if (rc != 0)
			return rc;
	}

	if (i == 0) {
		/* No device-IDs specified */
		memset(g.card_mask, 0xff, sizeof(g.card_mask));
		g.min_card = 0;
		g.max_card = g.max_card_used;
		memset(g.domain_mask, 0xff, sizeof(g.domain_mask));
		g.min_domain = 0;
		g.max_domain = NUM_DOMAINS - 1;
	}

	pr_verbose("Min card: %u, max card: %u", g.min_card, g.max_card);
	pr_verbose("Min domain: %u, max domain: %u", g.min_domain,
		   g.max_domain);

	return 0;
}

/*
 * Entry point
 */
int main(int argc, char *argv[])
{
	char *endp;
	int c, rc;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;
		switch (c) {
		case 'i':
			g.interval = strtoll(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' ||
			    g.interval <= 0 ||
			    (g.interval == LLONG_MAX && errno == ERANGE)) {
				warnx("Invalid value for '--interval'|"
				      "'-i': '%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case 'c':
			g.count = strtoull(optarg, &endp, 0);
			if (*optarg == '\0' || *endp != '\0' || g.count == 0 ||
			    (g.count == LLONG_MAX && errno == ERANGE)) {
				warnx("Invalid value for '--count'|"
				      "'-c': '%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case 'o':
			if (strcasecmp(optarg, "JSON") == 0) {
				g.print_funcs = &json_print;
			} else if (strcasecmp(optarg, "TABLE") == 0) {
				g.only_totals = true;
				g.print_funcs = &table_print;
			} else if (strcasecmp(optarg, "CSV") == 0) {
				g.only_totals = true;
				g.print_funcs = &csv_print;
			} else {
				warnx("Invalid value for '--output'|"
				      "'-o': '%s'", optarg);
				util_prg_print_parse_error();
				return EXIT_FAILURE;
			}
			break;
		case 't':
			g.no_totals = true;
			break;
		case 'T':
			g.only_totals = true;
			break;
		case 'a':
			g.no_apqn = true;
			break;
		case 'M':
			g.map_type = optarg;
			break;
		case 'A':
			g.all = true;
			break;
		case 'O':
			g.only_online = true;
			break;
		case 'V':
			g.verbose = true;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			print_adapter_id_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}

	/* remaining positional args are device IDs */
	g.device_ids = &argv[optind];

	if (g.only_totals && g.no_totals) {
		warnx("Either --no-totals or --only-totals can be specified, "
		      "but not both");
		return EXIT_FAILURE;
	}

	if (g.only_online && g.all) {
		warnx("Either --only-online or --all can be specified, "
		      "but not both");
		return EXIT_FAILURE;
	}

	pr_verbose("Interval: %ld Count: %ld", g.interval, g.count);

	rc = get_max_card_index(&g.max_card_used);
	if (rc != 0) {
		rc = EXIT_FAILURE;
		goto out;
	}

	rc = parse_device_selection();
	if (rc != 0) {
		rc = EXIT_FAILURE;
		goto out;
	}

	if (g.map_type != NULL) {
		rc = parse_type_mapping(g.map_type);
		if (rc != 0) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}

	g.chsc_fd = open(CHSC_DEVICE, O_RDWR);
	if (g.chsc_fd < 0) {
		rc = errno;
		warnx("File '%s:' %s", CHSC_DEVICE, strerror(errno));
		if (rc == ENOENT)
			warnx("You might have to load kernel module 'chsc_sch' "
			      "using 'modprobe chsc_sch'");
		return EXIT_FAILURE;
	}
	pr_verbose("Device '%s' has been opened successfully", CHSC_DEVICE);

	/* Don't buffer data if redirected to a pipe */
	setbuf(stdout, NULL);

	rc = perform_measurement();
	if (rc != 0) {
		rc = EXIT_FAILURE;
		goto out;
	}
out:
	if (g.chsc_fd >= 0)
		close(g.chsc_fd);
	free_device_selection();
	free_type_mapping();
	free_interval_data();

	return rc;
}

