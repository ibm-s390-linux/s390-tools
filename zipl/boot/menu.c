/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Bootmenu Subroutines
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "menu.h"
#include "sclp.h"
#include "ebcdic.h"
#include "boot/linux_layout.h"
#include "boot/loaders_layout.h"

static const char *msg_econfig = "Error: undefined configuration\n";

static void menu_prompt(int timeout)
{
	if (timeout)
		printf("Please choose (default will boot in %u seconds):",
		       timeout);
	else
		printf("Please choose:");
}

static int menu_read(void)
{
	char *temp_area =  (char *)get_zeroed_page();
	int timeout, rc, i, count = 0;
	char *endptr;
	int value;

	timeout = __stage2_params.timeout;

	while (1) {
		/* print prompt */
		menu_prompt(timeout);

		/* wait for input or timeout */
		while (count == 0) {
			rc = sclp_read(timeout, temp_area, &count);
			if (rc != 0) {
				/* timeout or error during read, boot default */
				value = 0;
				goto out_free_page;
			}
			/* disable timeout in case of retry */
			timeout = 0;
		}

		if (count > LINE_LENGTH)
			count = LINE_LENGTH;

		/* input under zVM needs to be converted to lower case */
		if (is_zvm())
			for (i = 0; i < count; i++)
				temp_area[i] = ebcdic_tolower(temp_area[i]);
		value = ebcdic_strtoul(temp_area, &endptr, 10);

		if ((endptr != temp_area) && (value < BOOT_MENU_ENTRIES - 1) &&
		    (__stage2_params.config[value] != 0)) {
			/* valid config found - finish */
			break;
		} else {
			/* no valid config retry */
			printf(msg_econfig);
			memset(temp_area, 0, PAGE_SIZE);
			count = 0;
		}
	}

	if (temp_area + count > endptr)
		memcpy((void *)COMMAND_LINE_EXTRA, endptr,
		       (temp_area + count - endptr));
out_free_page:
	free_page((unsigned long) temp_area);
	return value;
}

static int menu_list(void)
{
	char *name;
	int i;

	for (i = 0; i < BOOT_MENU_ENTRIES; i++) {
		if (__stage2_params.config[i] == 0)
			continue;
		name = __stage2_params.config[i] + ((void *)&__stage2_params);
		printf("%s\n", name);
		if (i == 0)
			printf("\n");
	}

	return 0;
}

enum param_result {
	NUMBER_FOUND  = 0,
	PRINT_PROMPT  = 1,
	NOTHING_FOUND = 2,
	SCLP_ERROR    = 3,
};

/*
 * Interpret loadparm
 *
 * Parameter
 *     value - to store configuration number
 *
 * Return
 *     0 - found number to boot, stored in value
 *     1 - print prompt
 *     2 - nothing found
 *     3 - sclp error
 */
static enum param_result menu_param(unsigned long *value)
{
	char loadparm[PARAM_SIZE];
	char *endptr;
	int i;

	/* try to fetch loadparms from sclp into 'loadparm' */
	if (sclp_param(loadparm) != 0)
		return SCLP_ERROR;

	/* parse number from loadparm */
	*value = ebcdic_strtoul(loadparm, &endptr, 10);

	/* got number, done */
	if (endptr != loadparm)
		return NUMBER_FOUND;

	/* no number, check for keyword */
	i = 0;
	/* skip leading whitespaces */
	while ((i < PARAM_SIZE) && ecbdic_isspace(loadparm[i]))
		i++;

	if (!strncmp(&loadparm[i], "PROMPT", 6))
		return PRINT_PROMPT;

	return NOTHING_FOUND;
}

int menu(void)
{
	enum { DEFAULT_MENU_ENTRY = 0 };
	unsigned long value = DEFAULT_MENU_ENTRY;
	int sclp_lm_available;
	char *cmd_line_extra;
	char endstring[15];

	cmd_line_extra = (char *)COMMAND_LINE_EXTRA;
	memset(cmd_line_extra, 0, COMMAND_LINE_EXTRA_SIZE);

	/* Try to initialize SCLP line-mode console. But do not fail in case no
	 * SCLP line-mode console is available.
	 */
	sclp_lm_available = sclp_setup(SCLP_INIT) == 0;

	switch (menu_param(&value)) {
	case NUMBER_FOUND:
		/* got number from loadparm, boot it */
		goto boot;
	case PRINT_PROMPT:
		/* print menu */
		break;
	case SCLP_ERROR:
		/* failed to read from sclp, boot default */
		printf("SCLP_ERROR\n");
		goto boot;
	case NOTHING_FOUND:
		if (__stage2_params.flag == 0) {
			/* menu disabled, boot default */
			goto boot;
		}
		break;
	}

	/* SCLP line-mode unavailable; skip menu and input */
	if (!sclp_lm_available)
		goto boot;

	/* print banner */
	printf("%s\n", ((void *)&__stage2_params) + __stage2_params.banner);

	/* print config list */
	menu_list();

	if (is_zvm())
		printf("Note: VM users please use '#cp vi vmsg <input>'\n");

	value = menu_read();

boot:
	/* sanity - config entry not valid */
	if (value > BOOT_MENU_ENTRIES || __stage2_params.config[value] == 0)
		panic(EINTERNAL, "%s", msg_econfig);

	printf("Booting %s\n",
	       (char *)(__stage2_params.config[value] +
			(void *)&__stage2_params + TEXT_OFFSET));

	/* append 'BOOT_IMAGE=<num>' to parmline */
	snprintf(endstring, sizeof(endstring), " BOOT_IMAGE=%u", value);
	if ((strlen(cmd_line_extra) + strlen(endstring)) < LEGACY_COMMAND_LINE_SIZE)
		strcat(cmd_line_extra, endstring);

	sclp_setup(SCLP_DISABLE);

	return value;
}
