/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * Daemon functions
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "cpuplugd.h"

const char *name = NAME;
static const char *pid_file = PIDFILE;

const char *const usage =
    "Usage: %s [OPTIONS]\n"
    "\n"
    "Daemon to dynamically hotplug cpus and memory based on a set of rules\n"
    "Use OPTIONS described below.\n"
    "\n"
    "\t-c, --config  CONFIGFILE	Path to the configuration file\n"
    "\t-f, --foreground		Run in foreground, do not detach\n"
    "\t-h, --help			Print this help, then exit\n"
    "\t-v, --version			Print version information, then exit\n"
    "\t-V, --verbose			Provide more verbose output\n";

/*
 *  Print command usage
 */
void print_usage(int is_error, char program_name[])
{
	fprintf(is_error ? stderr : stdout, usage, program_name);
	exit(is_error ? 1 : 0);
}

/*
 * Print command version
 */
void print_version()
{
	printf("%s: Linux on System z CPU hotplug daemon version %s\n",
		name, RELEASE_STRING);
	printf("Copyright IBM Corp. 2007, 2017\n");
	exit(0);
}

/*
 * Store daemon's pid so it can be stopped
 */
void store_pid(void)
{
	FILE *filp;

	filp = fopen(pid_file, "w");
	if (!filp) {
		cpuplugd_error("cannot open pid file %s: %s\n", pid_file,
			       strerror(errno));
		exit(1);
	}
	fprintf(filp, "%d\n", getpid());
	fclose(filp);
}

/*
 * Check that we don't try to start this daemon twice
 */
void check_if_started_twice()
{
	FILE *filp;
	int pid, rc;

	filp = fopen(pid_file, "r");
	if (filp) {
		rc = fscanf(filp, "%d", &pid);
		if (rc != 1) {
			cpuplugd_error("Reading pid file failed. Aborting!\n");
			exit(1);
		}
		cpuplugd_error("pid file %s still exists.\nThis might indicate "
			       "that an instance of this daemon is already "
			       "running.\n", pid_file);
		exit(1);
	}
}

/*
 * Clean up method
 */
void clean_up()
{
	cpuplugd_info("terminated\n");
	remove(pid_file);
	remove(LOCKFILE);
	reactivate_cpus();
	if (memory)
		cleanup_cmm();
	exit(1);
}

/*
 * End the deamon
 */
void kill_daemon(int UNUSED(a))
{
	cpuplugd_info("shutting down\n");
	remove(pid_file);
	remove(LOCKFILE);
	reactivate_cpus();
	if (memory)
		cleanup_cmm();
	exit(0);
}

/*
 * Reload the daemon (for lsb compliance)
 */
void reload_handler(int UNUSED(a))
{
	reload_pending = 1;
}

void reload_daemon()
{
	unsigned int temp_history;
	long temp_mem;
	int temp_cpu;

	cpuplugd_info("cpuplugd restarted\n");
	/*
	 * Before we parse the configuration file again we have to save
	 * the original values prior to startup. If we don't do this cpuplugd
	 * will no longer know how many cpus the system had before the daemon
	 * was started and therefor can't restore theres in case it is stopped
	 */
	temp_cpu = num_cpu_start;
	temp_mem = cmm_pagesize_start;
	temp_history = history_max;

	/* clear varinfo before re-reading variables from config file */
	memset(varinfo, 0, varinfo_size);
	history_max = 1;
	parse_configfile(configfile);
	if (history_max > MAX_HISTORY)
		cpuplugd_exit("History depth %i exceeded maximum (%i)\n",
			      history_max, MAX_HISTORY);
	if (history_max != temp_history) {
		free(meminfo);
		free(vmstat);
		free(cpustat);
		free(timestamps);
		setup_history();
	}
	check_config();

	num_cpu_start = temp_cpu;
	cmm_pagesize_start = temp_mem;
}

/*
 * Set up for handling SIGTERM or SIGINT
 */
void handle_signals(void)
{
	struct sigaction act;

	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	act.sa_handler = kill_daemon;
	if (sigaction(SIGTERM, &act, NULL) < 0) {
		cpuplugd_error("sigaction( SIGTERM, ... ) failed - reason %s\n",
			       strerror(errno));
		exit(1);
	}
	if (sigaction(SIGINT, &act, NULL) < 0) {
		cpuplugd_error("sigaction( SIGINT, ... ) failed - reason %s\n",
			       strerror(errno));
		exit(1);
	}
}

/*
 * Signal handler for sighup. This is used to force the deamon to reload its
 * configuration file.
 * This feature is also required by a lsb compliant init script
 */
void handle_sighup(void)
{
	struct sigaction act;

	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	act.sa_handler = reload_handler;
	if (sigaction(SIGHUP, &act, NULL) < 0) {
		cpuplugd_error("sigaction( SIGHUP, ... ) failed - reason %s\n",
			       strerror(errno));
		exit(1);
	}
}

/* Check if we are running in an LPAR environment.
 * This functions return 1 if we run inside an lpar and 0 otherwise
 */
int check_lpar()
{
	int rc;
	FILE *filp;
	size_t bytes_read;
	char buffer[2048];
	char *contains_vm;

	rc = 0;
	filp = fopen("/proc/cpuinfo", "r");
	if (!filp)
		cpuplugd_exit("cannot open /proc/cpuinfo: %s\n",
			      strerror(errno));
	bytes_read = fread(buffer, 1, sizeof(buffer) - 1, filp);
	if (bytes_read == 0)
		cpuplugd_exit("Reading /proc/cpuinfo failed: %s\n",
			      strerror(errno));
	 /* NUL-terminate the text */
	buffer[bytes_read] = '\0';
	contains_vm = strstr(buffer, "version = FF");
	if (contains_vm == NULL) {
		rc = 1;
		cpuplugd_debug("Detected System running in LPAR mode\n");
	} else
		cpuplugd_debug("Detected System running in z/VM mode\n");
	fclose(filp);
	return rc;
}
