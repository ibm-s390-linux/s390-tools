/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * Config file parsing
 *
 * Copyright IBM Corp. 2007, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "cpuplugd.h"

/*
 * Return the value of a variable which parse_config() found within the
 * configuration file. Use only for values valid >= 0, because -1 is returned
 * in error case.
 */
static long parse_positive_value(char *ptr)
{
	long value = 0;
	unsigned int i;

	if (ptr == NULL)
		return -1;
	for (i = 0; i < strlen(ptr); i++) {
		if (isdigit(ptr[i]) == 0)
			return -1;
	}
	sscanf(ptr, "%ld", &value);
	return value;
}

char *get_var_rvalue(char *var_name)
{
	char tmp_name[MAX_VARNAME + 3]; /* +3 for '\0', '=' and '\n' */
	unsigned int tmp_length;
	char *rvalue;

	tmp_name[0] = '\n';
	strncpy(&tmp_name[1], var_name, MAX_VARNAME + 1); /* +1 for '\0' */
	tmp_length = strlen(tmp_name);
	tmp_name[tmp_length] = '=';
	tmp_name[tmp_length + 1] = '\0';
	rvalue = strstr(varinfo, tmp_name);
	if (rvalue == NULL)
		return NULL;
	rvalue += strlen(tmp_name);
	return rvalue;
}

static void add_var(char *name, char *rvalue)
{
	size_t offset, size;
	unsigned int i;

	if (get_var_rvalue(name))
		cpuplugd_exit("Variable defined twice: %s\n", name);
	for (i = 0; i < sym_names_count; i++) {
		if (strncmp(name, sym_names[i].name,
			    MAX(strlen(sym_names[i].name), strlen(name))) != 0)
			continue;
		cpuplugd_exit("Cannot use (pre-defined) variable name: %s\n",
			      name);
	}

	offset = strlen(varinfo);
	/* +3 because of extra '=', '\n' and '\0' */
	size = offset + strlen(name) + strlen(rvalue) + 3;
	if (size > varinfo_size)
		//TODO realloc?
		cpuplugd_exit("buffer for variables too small: need %ld, "
			      "have %ld (bytes)\n", size, varinfo_size);
	size -= offset;
	snprintf(&varinfo[offset], size, "%s=%s\n", name, rvalue);
	return;
}

static int check_term(char *symbol, char *name, char *rvalue, struct term **term)
{
	if (!strncasecmp(name, symbol, strlen(symbol))) {
		cpuplugd_debug("found the following rule: %s = %s\n",
			       name, rvalue);
		*term = parse_term(&rvalue, OP_PRIO_NONE);
		if (rvalue[0] == '\0')
			return 1;
		cpuplugd_exit("parsing error at %s, position: %s\n", symbol,
			      rvalue);
	}
	return 0;
}

static int check_value(char *symbol, char *name, char *rvalue, long *value)
{
	if (!strncasecmp(name, symbol, strlen(symbol))) {
		*value = parse_positive_value(rvalue);
		cpuplugd_debug("found %s value: %ld\n", symbol, *value);
		if (*value >= 0)
			return 1;
		cpuplugd_exit("parsing error at update\n");
	}
	return 0;
}

/*
 * Parse a single line of the configuration file
 */
static void parse_configline(char *line)
{
	char *match, *name, *rvalue, *start, *stop;
	int i, j;
	size_t len;
	char temp[strlen(line) + 1];

	if (line[0] == '#')
		return;
	for (i = j = 0; line[i] != 0; i++) /* Remove whitespace. */
		if (!isblank(line[i]) && !isspace(line[i]))
			temp[j++] = line[i];
	temp[j] = '\0';
	match = strchr(temp, '=');
	if (match == NULL)
		return;
	*match = '\0';		/* Separate name and right hand value */
	name = temp;		/* left side of = */
	rvalue = match + 1;	/* right side of = */
	/*
	 * remove the double quotes
	 * example:  CPU_MIN="2"
	 */
	start = strchr(rvalue, '"');	/* points to first " */
	stop = strrchr(rvalue, '"');	/* points to last " */
	len = stop - start;
	if (start != NULL && stop != NULL && len > 0) {
		rvalue[len] = '\0';
		rvalue = rvalue + 1;
	} else
		cpuplugd_exit("the configuration file has syntax "
			      "errors at %s, position: %s\n", name, rvalue);

	if (check_term("hotplug", name, rvalue, &cfg.hotplug))
		return;
	if (check_term("hotunplug", name, rvalue, &cfg.hotunplug))
		return;
	if (check_term("memplug", name, rvalue, &cfg.memplug))
		return;
	if (check_term("memunplug", name, rvalue, &cfg.memunplug))
		return;
	if (check_term("cmm_inc", name, rvalue, &cfg.cmm_inc))
		return;
	if (check_term("cmm_dec", name, rvalue, &cfg.cmm_dec))
		return;

	if (check_value("update", name, rvalue, &cfg.update)) {
		if (cfg.update > 0)
			return;
		cpuplugd_exit("update must be > 0\n");
	}
	if (check_value("cpu_min", name, rvalue, &cfg.cpu_min)) {
		if (cfg.cpu_min > 0)
			return;
		cpuplugd_exit("cpu_min must be > 0\n");
	}
	if (check_value("cpu_max", name, rvalue, &cfg.cpu_max)) {
		if (cfg.cpu_max == 0)
			/* if cpu_max is 0, we use the overall number of cpus */
			cfg.cpu_max = get_numcpus();
		return;
	}
	if (check_value("cmm_min", name, rvalue, &cfg.cmm_min))
		return;
	if (check_value("cmm_max", name, rvalue, &cfg.cmm_max))
		return;

	cpuplugd_debug("found the following variable: %s = %s\n",
		       name, rvalue);
	if (strlen(name) > MAX_VARNAME)
		cpuplugd_exit("Variable name too long (max. length is "
			      "%i chars): %s\n", MAX_VARNAME, name);
	add_var(name, rvalue);
}

/*
 * Function used to parse the min and max values at the beginning of the
 * configuration file as well as the hotplug and hotunplug rules.
 */
void parse_configfile(char *file)
{
	char linebuffer[MAX_LINESIZE + 2]; /* current line incl. \n and \0 */
	char *linep_offset;
	FILE *filp;

	filp = fopen(file, "r");
	if (!filp)
		cpuplugd_exit("Opening configuration file failed: %s\n",
			      strerror(errno));
	while (fgets(linebuffer, sizeof(linebuffer), filp) != NULL) {
		if (!(linep_offset = strchr(linebuffer, '\n')))
			cpuplugd_exit("Line is too long (max. length is %i "
				      "characters): %s\n", MAX_LINESIZE,
				      linebuffer);
		parse_configline(linebuffer);
	}
	fclose(filp);
}

/*
 * Check if the required settings are found in the configuration file.
 * "Autodetect" if cpu and/or memory hotplug configuration entries
 * where specified
 */
void check_config()
{
	int cpuid;
	int lpar_status;

	lpar_status = check_lpar();
	if (cfg.update < 0)
		cpuplugd_exit("No valid update interval specified.\n");
	if (cfg.cpu_max < cfg.cpu_min && cfg.cpu_max != 0)
		cpuplugd_exit("cpu_max below cpu_min, aborting.\n");
	if (cfg.cpu_max < 0 || cfg.cpu_min < 0 || cfg.hotplug == NULL ||
	    cfg.hotunplug == NULL) {
		cpuplugd_error("No valid CPU hotplug configuration "
			       "detected.\n");
		cpu = 0;
	} else {
		cpu = 1;
		cpuplugd_debug("Valid CPU hotplug configuration detected.\n");
	}
	if (cfg.cmm_max < 0 || cfg.cmm_min < 0 || cfg.memplug == NULL ||
	    cfg.memunplug == NULL || cfg.cmm_inc == NULL ||
	    cfg.cmm_max < cfg.cmm_min) {
		cpuplugd_error("No valid memory hotplug configuration "
			       "detected.\n");
		memory = 0;
	} else {
		memory = 1;
		/*
		 * check if all the necessary files exit below /proc
		 */
		if (check_cmmfiles() != 0 && lpar_status == 0) {
			cpuplugd_info("Can not open /proc/sys/vm/cmm_pages. "
				      "The memory hotplug function will be "
				      "disabled.\n");
			memory = 0;
		}
		if (memory == 1  && lpar_status == 0)
			cpuplugd_debug("Valid memory hotplug configuration "
				       "detected.\n");
		if (memory == 1  && lpar_status == 1) {
			cpuplugd_debug("Valid memory hotplug configuration "
				       "detected inside LPAR. "
				       "The memory hotplug function will be "
				       "disabled. \n");
			memory = 0;
		}
	}
	if (memory == 0 && cpu == 0)
		cpuplugd_exit("Exiting, because neither a valid cpu nor a val"
			      "id memory hotplug configuration was found.\n");
	/*
	* Save the number of online cpus and the cmm_pagesize at startup,
	* so that we can enable exactly the same amount when the daemon ends
	*/
	if (cpu) {
		num_cpu_start = get_num_online_cpus();
		cpuplugd_debug("Daemon started with %d active cpus.\n",
			       num_cpu_start);
		/*
		 * Check that the initial number of cpus is not below the
		 * minimum
		 */
		if (num_cpu_start < cfg.cpu_min &&
		    get_numcpus() >= cfg.cpu_min) {
			cpuplugd_debug("The number of online cpus is below "
				       "the minimum and will be increased.\n");
			cpuid = 0;
			while (get_num_online_cpus() < cfg.cpu_min &&
			       cpuid < get_numcpus()) {
				if (is_online(cpuid) == 1) {
					cpuid++;
					continue;
				}
				cpuplugd_debug("cpu with id %d is currently offline "
					       "and will be enabled\n", cpuid);
				hotplug(cpuid);
				cpuid++;
			}
		}
		if (get_num_online_cpus() > cfg.cpu_max) {
			cpuplugd_debug("The number of online cpus is above the maximum"
				       " and will be decreased.\n");
			cpuid = 0;
			while (get_num_online_cpus() > cfg.cpu_max &&
			       cpuid < get_numcpus()) {
				if (is_online(cpuid) != 1) {
					cpuid++;
					continue;
				}
				cpuplugd_debug("cpu with id %d is currently online "
				       "and will be disabled\n", cpuid);
				hotunplug(cpuid);
				cpuid++;
			}
		}
		if (cfg.cpu_min > get_numcpus())
			/*
			 * This check only works if nobody used the
			 * additional_cpus in the boot parameter section
			 */
			cpuplugd_exit("The minimum amount of cpus is above "
				      "the number of available cpus.\n"
				      "Detected %d available cpus\n",
				      get_numcpus());
		if (get_num_online_cpus() < cfg.cpu_min)
			cpuplugd_exit("Failed to set the number of online "
				      "cpus to the minimum. Aborting.\n");
	}
	if (memory == 1) {
		/*
		 * Check that the initial value of cmm_pages is not below
		 * cmm_min or above cmm_max
		 */
		cmm_pagesize_start = get_cmmpages_size();
		if (cmm_pagesize_start < cfg.cmm_min) {
			cpuplugd_debug("cmm_pages is below minimum and will "
				       "be increased.\n");
			set_cmm_pages(cfg.cmm_min);
		}
		if (cmm_pagesize_start > cfg.cmm_max) {
			cpuplugd_debug("cmm_pages is above the maximum and will"
				       " be decreased.\n");
			set_cmm_pages(cfg.cmm_max);
		}
	}
}
