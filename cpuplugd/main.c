/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * Main functions
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <fcntl.h>
#include <fenv.h>
#include <sys/file.h>
#include <sys/time.h>
#include <time.h>

#include "cpuplugd.h"

struct symbol_names sym_names[] = {
	{ "loadavg", OP_SYMBOL_LOADAVG },
	{ "runnable_proc", OP_SYMBOL_RUNABLE },
	{ "onumcpus", OP_SYMBOL_CPUS },
	{ "user", OP_SYMBOL_USER },
	{ "nice", OP_SYMBOL_NICE },
	{ "system", OP_SYMBOL_SYSTEM },
	{ "idle", OP_SYMBOL_IDLE },
	{ "iowait", OP_SYMBOL_IOWAIT },
	{ "irq", OP_SYMBOL_IRQ },
	{ "softirq", OP_SYMBOL_SOFTIRQ },
	{ "steal", OP_SYMBOL_STEAL },
	{ "guest_nice", OP_SYMBOL_GUEST_NICE },
	{ "guest", OP_SYMBOL_GUEST },
	{ "swaprate", OP_SYMBOL_SWAPRATE },
	{ "apcr", OP_SYMBOL_APCR },
	{ "freemem", OP_SYMBOL_FREEMEM },
	{ "meminfo.", OP_SYMBOL_MEMINFO },
	{ "vmstat.", OP_SYMBOL_VMSTAT },
	{ "cpustat.", OP_SYMBOL_CPUSTAT },
	{ "time", OP_SYMBOL_TIME },
};

struct config cfg = {
	.cpu_max = -1,
	.cpu_min = -1,
	.update = -1,
	.cmm_min = -1,
	.cmm_max = -1,
	.cmm_inc = NULL,
	.cmm_dec = NULL,
	.memplug = NULL,
	.memunplug = NULL,
	.hotplug = NULL,
	.hotunplug = NULL,
};

int num_cpu_start, memory, cpu, reload_pending;
long cmm_pagesize_start;
unsigned long meminfo_size, vmstat_size, cpustat_size, varinfo_size;
char *meminfo, *vmstat, *cpustat, *varinfo;
double *timestamps;
unsigned int history_max, history_current, history_prev, sym_names_count;

static struct symbols symbols;
static jmp_buf jmpenv;
static struct sigaction act;

/*
 * Handle the sigfpe signal which we might catch during rule evaluating
 */
static void sigfpe_handler(int UNUSED(sig))
{
	longjmp(jmpenv, 1);
}

static void eval_cpu_rules(void)
{
	double diffs[CPUSTATS], diffs_total, percent_factor;
	char *procinfo_current, *procinfo_prev;
	int cpu, nr_cpus, on_off;

	nr_cpus = get_numcpus();
	procinfo_current = cpustat + history_current * cpustat_size;
	procinfo_prev = cpustat + history_prev * cpustat_size;

	diffs[0] = get_proc_value(procinfo_current, "user", ' ') -
		   get_proc_value(procinfo_prev, "user", ' ');
	diffs[1] = get_proc_value(procinfo_current, "nice", ' ') -
		   get_proc_value(procinfo_prev, "nice", ' ');
	diffs[2] = get_proc_value(procinfo_current, "system", ' ') -
		   get_proc_value(procinfo_prev, "system", ' ');
	diffs[3] = get_proc_value(procinfo_current, "idle", ' ') -
		   get_proc_value(procinfo_prev, "idle", ' ');
	diffs[4] = get_proc_value(procinfo_current, "iowait", ' ') -
		   get_proc_value(procinfo_prev, "iowait", ' ');
	diffs[5] = get_proc_value(procinfo_current, "irq", ' ') -
		   get_proc_value(procinfo_prev, "irq", ' ');
	diffs[6] = get_proc_value(procinfo_current, "softirq", ' ') -
		   get_proc_value(procinfo_prev, "softirq", ' ');
	diffs[7] = get_proc_value(procinfo_current, "steal", ' ') -
		   get_proc_value(procinfo_prev, "steal", ' ');
	diffs[8] = get_proc_value(procinfo_current, "guest", ' ') -
		   get_proc_value(procinfo_prev, "guest", ' ');
	diffs[9] = get_proc_value(procinfo_current, "guest_nice", ' ') -
		   get_proc_value(procinfo_prev, "guest_nice", ' ');

	diffs_total = get_proc_value(procinfo_current, "total_ticks", ' ') -
		      get_proc_value(procinfo_prev, "total_ticks", ' ');
	if (diffs_total == 0)
		diffs_total = 1;

	symbols.loadavg = get_proc_value(procinfo_current, "loadavg", ' ');
	symbols.runnable_proc = get_proc_value(procinfo_current,
					       "runnable_proc", ' ');
	symbols.onumcpus = get_proc_value(procinfo_current, "onumcpus", ' ');

	percent_factor = 100 * symbols.onumcpus;
	symbols.user = (diffs[0] / diffs_total) * percent_factor;
	symbols.nice = (diffs[1] / diffs_total) * percent_factor;
	symbols.system = (diffs[2] / diffs_total) * percent_factor;
	symbols.idle = (diffs[3] / diffs_total) * percent_factor;
	symbols.iowait = (diffs[4] / diffs_total) * percent_factor;
	symbols.irq = (diffs[5] / diffs_total) * percent_factor;
	symbols.softirq = (diffs[6] / diffs_total) * percent_factor;
	symbols.steal = (diffs[7] / diffs_total) * percent_factor;
	symbols.guest = (diffs[8] / diffs_total) * percent_factor;
	symbols.guest_nice = (diffs[9] / diffs_total) * percent_factor;

	/* only use this for development and testing */
	cpuplugd_debug("cpustat values:\n%s", cpustat + history_current *
		       cpustat_size);
	if (debug && foreground == 1) {
		printf("-------------------- CPU --------------------\n");
		printf("cpu_min: %ld\n", cfg.cpu_min);
		printf("cpu_max: %ld\n", cfg.cpu_max);
		printf("loadavg: %f \n", symbols.loadavg);
		printf("user percent = %f\n", symbols.user);
		printf("nice percent = %f\n", symbols.nice);
		printf("system percent = %f\n", symbols.system);
		printf("idle percent = %f\n", symbols.idle);
		printf("iowait percent = %f\n", symbols.iowait);
		printf("irq percent = %f\n", symbols.irq);
		printf("softirq percent = %f\n", symbols.softirq);
		printf("steal percent = %f\n", symbols.steal);
		printf("guest percent = %f\n", symbols.guest);
		printf("guest_nice percent = %f\n", symbols.guest_nice);
		printf("numcpus %d\n", nr_cpus);
		printf("runnable_proc: %d\n", (int) symbols.runnable_proc);
		printf("---------------------------------------------\n");
		printf("onumcpus:   %d\n", (int) symbols.onumcpus);
		printf("---------------------------------------------\n");
		printf("hotplug: ");
		print_term(cfg.hotplug);
		printf("\n");
		printf("hotunplug: ");
		print_term(cfg.hotunplug);
		printf("\n");
		printf("---------------------------------------------\n");
	}

	on_off = 0;
	/* Evaluate the hotplug rule */
	if (eval_term(cfg.hotplug, &symbols))
		on_off++;
	/* Evaluate the hotunplug rule only if hotplug did not match */
	else if (eval_term(cfg.hotunplug, &symbols))
		on_off--;
	if (on_off > 0) {
		/* check the cpu nr limit */
		if (symbols.onumcpus + 1 > cfg.cpu_max) {
			/* cpu limit reached */
			cpuplugd_debug("maximum cpu limit is reached\n");
			return;
		}
		/* try to find a offline cpu */
		for (cpu = 0; cpu < nr_cpus; cpu++)
			if (is_online(cpu) == 0 && cpu_is_configured(cpu) != 0)
				break;
		if (cpu < nr_cpus) {
			cpuplugd_debug("cpu with id %d is currently offline "
				       "and will be enabled\n", cpu);
			if (hotplug(cpu) == -1)
				cpuplugd_debug("unable to find a cpu which "
					       "can be enabled\n");
		} else {
			/*
			 * In case we tried to enable a cpu but this failed.
			 * This is the case if a cpu is deconfigured
			 */
			cpuplugd_debug("unable to find a cpu which can "
				       "be enabled\n");
		}
	} else if (on_off < 0) {
		/* check cpu nr limit */
		if (symbols.onumcpus <= cfg.cpu_min) {
			cpuplugd_debug("minimum cpu limit is reached\n");
			return;
		}
		/* try to find a online cpu */
		for (cpu = get_numcpus() - 1; cpu >= 0; cpu--) {
			if (is_online(cpu) != 0)
				break;
		}
		if (cpu > 0) {
			cpuplugd_debug("cpu with id %d is currently online "
				       "and will be disabled\n", cpu);
			hotunplug(cpu);
		}
	}
}

static void eval_mem_rules(double interval)
{
	long cmmpages_size, cmm_inc, cmm_dec, cmm_new;
	double free_memory, swaprate, apcr;
	char *procinfo_current, *procinfo_prev;

	procinfo_current = meminfo + history_current * meminfo_size;
	free_memory = get_proc_value(procinfo_current, "MemFree", ':');

	procinfo_current = vmstat + history_current * vmstat_size;
	procinfo_prev = vmstat + history_prev * vmstat_size;
	swaprate = (get_proc_value(procinfo_current, "pswpin", ' ') +
		    get_proc_value(procinfo_current, "pswpout", ' ') -
		    get_proc_value(procinfo_prev, "pswpin", ' ') -
		    get_proc_value(procinfo_prev, "pswpout", ' ')) /
		    interval;
	apcr = (get_proc_value(procinfo_current, "pgpgin", ' ') +
		get_proc_value(procinfo_current, "pgpgout", ' ') -
		get_proc_value(procinfo_prev, "pgpgin", ' ') -
		get_proc_value(procinfo_prev, "pgpgout", ' ')) /
		interval;

	cmmpages_size = get_cmmpages_size();
	symbols.apcr = apcr;			// apcr in 512 byte blocks / sec
	symbols.swaprate = swaprate;		// swaprate in 4K pages / sec
	symbols.freemem = free_memory / 1024;	// freemem in MB

	cmm_inc = eval_double(cfg.cmm_inc, &symbols);
	/* cmm_dec is optional */
	if (cfg.cmm_dec)
		cmm_dec = eval_double(cfg.cmm_dec, &symbols);
	else
		cmm_dec = cmm_inc;

	/* only use this for development and testing */
	if (debug && foreground == 1) {
		printf("------------------- Memory ------------------\n");
		printf("cmm_min: %ld\n", cfg.cmm_min);
		printf("cmm_max: %ld\n", cfg.cmm_max);
		printf("swaprate: %f\n", symbols.swaprate);
		printf("apcr: %f\n", symbols.apcr);
		printf("cmm_inc: %ld = ", cmm_inc);
		print_term(cfg.cmm_inc);
		printf("\n");
		printf("cmm_dec: %ld = ", cmm_dec);
		if (cfg.cmm_dec)
			print_term(cfg.cmm_dec);
		else
			print_term(cfg.cmm_inc);
		printf("\n");
		printf("free memory: %f MB\n", symbols.freemem);
		printf("---------------------------------------------\n");
		printf("cmm_pages: %ld\n", cmmpages_size);
		printf("---------------------------------------------\n");
		printf("memplug: ");
		print_term(cfg.memplug);
		printf("\n");
		printf("memunplug: ");
		print_term(cfg.memunplug);
		printf("\n");
		printf("---------------------------------------------\n");
	}

	cmm_new = cmmpages_size;
	/* Evaluate the memplug rule */
	if (eval_term(cfg.memplug, &symbols)) {
		if (cmm_dec < 0) {
			cpuplugd_error("cmm_dec went negative (%ld), set it "
				       "to 0.\n", cmm_dec);
			cmm_dec = 0;
		}
		cmm_new -= cmm_dec;
	/* Evaluate the memunplug rule only if memplug did not match */
	} else if (eval_term(cfg.memunplug, &symbols)) {
		if (cmm_inc < 0) {
			cpuplugd_error("cmm_inc went negative (%ld), set it "
				       "to 0.\n", cmm_inc);
			cmm_inc = 0;
		}
		cmm_new += cmm_inc;
	}
	if (cmm_new < cfg.cmm_min) {
		cpuplugd_debug("minimum memory limit is reached\n");
		cmm_new = cfg.cmm_min;
	}
	if (cmm_new > cfg.cmm_max) {
		cpuplugd_debug("maximum memory limit is reached\n");
		cmm_new = cfg.cmm_max;
	}
	if (cmm_new != cmmpages_size)
		set_cmm_pages(cmm_new);
}

static void time_read(double *timestamps)
{
	struct timeval tv;
	int rc;

	cpuplugd_debug("\n==================== New interval "
		       "====================\n");
	rc = gettimeofday(&tv, NULL);
	if (!rc) {
		*timestamps = tv.tv_sec + (double) tv.tv_usec / 1000000;
		cpuplugd_debug("Timestamp: %s           (%f seconds since "
			       "the Epoch)\n", ctime(&tv.tv_sec), *timestamps);
	} else
		cpuplugd_exit("gettimeofday failed: %s\n", strerror(errno));
	return;
}

void setup_history()
{
	/*
	 * The /proc file size will vary during intervals, use double of current
	 * size to have enough buffer for growing values.
	 */
	meminfo_size = proc_read_size("/proc/meminfo") * 2;
	vmstat_size = proc_read_size("/proc/vmstat") * 2;
	cpustat_size = CPUSTAT_SIZE;

	meminfo = malloc(meminfo_size * (history_max + 1));
	if (!meminfo)
		cpuplugd_exit("Out of memory: meminfo\n");
	vmstat = malloc(vmstat_size * (history_max + 1));
	if (!vmstat)
		cpuplugd_exit("Out of memory: vmstat\n");
	cpustat = malloc(cpustat_size * (history_max + 1));
	if (!cpustat)
		cpuplugd_exit("Out of memory: cpustat\n");
	timestamps = malloc(sizeof(double) * (history_max + 1));
	if (!timestamps)
		cpuplugd_exit("Out of memory: timestamps\n");

	/*
	 * Read history data, at least 1 interval for swaprate, apcr, idle, etc.
	 */
	history_current = 0;
	cpuplugd_info("Waiting %i intervals to accumulate history.\n",
		      history_max);
	do {
		time_read(&timestamps[history_current]);
		proc_read(meminfo + history_current * meminfo_size,
			  "/proc/meminfo", meminfo_size);
		proc_read(vmstat + history_current * vmstat_size,
			  "/proc/vmstat", vmstat_size);
		proc_cpu_read(cpustat + history_current * cpustat_size);
		sleep(cfg.update);
		history_current++;
	} while (history_current < history_max);
	history_current--;
}

int main(int argc, char *argv[])
{
	double interval;
	int fd, rc;

	reload_pending = 0;
	sym_names_count = sizeof(sym_names) / sizeof(struct symbol_names);
	varinfo_size = VARINFO_SIZE;
	varinfo = calloc(varinfo_size, 1);
	if (!varinfo) {
		cpuplugd_error("Out of memory: varinfo\n");
		exit(1);
	}
	/*
	 * varinfo must start with '\n' for correct string matching
	 * in get_var_rvalue().
	 */
	varinfo[0] = '\n';

	/* Parse the command line options */
	parse_options(argc, argv);

	/* flock() lock file to prevent multiple instances of cpuplugd */
	fd = open(LOCKFILE, O_CREAT | O_RDONLY, S_IRUSR);
	if (fd == -1) {
		cpuplugd_error("Cannot open lock file %s: %s\n", LOCKFILE,
			       strerror(errno));
		exit(1);
	}
	rc = flock(fd, LOCK_EX | LOCK_NB);
	if (rc) {
		cpuplugd_error("flock() failed on lock file %s: %s\nThis might "
			       "indicate that an instance of this daemon is "
			       "already running.\n", LOCKFILE, strerror(errno));
		exit(1);
	}

	/* Make sure that the daemon is not started multiple times */
	check_if_started_twice();
	/* Store daemon pid also in foreground mode */
	handle_signals();
	handle_sighup();

	/* Need 1 history level minimum for internal symbols */
	history_max = 1;
	/*
	 * Parse arguments from the configuration file, also calculate
	 * history_max
	 */
	parse_configfile(configfile);
	if (history_max > MAX_HISTORY)
		cpuplugd_exit("History depth %i exceeded maximum (%i)\n",
			      history_max, MAX_HISTORY);
	/* Check the settings in the configuration file */
	check_config();

	if (!foreground) {
		rc = daemonize();
		if (rc < 0)
			cpuplugd_exit("Detach from terminal failed: %s\n",
				      strerror(errno));
	}
	/* Unlock lock file */
	flock(fd, LOCK_UN);
	close(fd);

	/* Install signal handler for floating point exceptions */
	rc = feenableexcept(FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW |
			    FE_INVALID);
	act.sa_flags = SA_NODEFER;
	sigemptyset(&act.sa_mask);
	act.sa_handler = sigfpe_handler;
	if (sigaction(SIGFPE, &act, NULL) < 0)
		cpuplugd_exit("sigaction( SIGFPE, ... ) failed - reason %s\n",
			      strerror(errno));

	setup_history();

	/* Main loop */
	while (1) {
		if (reload_pending) {		// check for daemon reload
			reload_daemon();
			reload_pending = 0;
		}

		history_prev = history_current;
		history_current = (history_current + 1) % (history_max + 1);
		time_read(&timestamps[history_current]);
		proc_read(meminfo + history_current * meminfo_size,
			  "/proc/meminfo", meminfo_size);
		proc_read(vmstat + history_current * vmstat_size,
			  "/proc/vmstat", vmstat_size);
		proc_cpu_read(cpustat + history_current * cpustat_size);
		interval = timestamps[history_current] -
			   timestamps[history_prev];
		cpuplugd_debug("config update interval: %ld seconds\n",
			       cfg.update);
		cpuplugd_debug("real update interval: %f seconds\n", interval);

		/* Run code that may signal failure via longjmp. */
		if (cpu == 1) {
			if (setjmp(jmpenv) == 0)
				eval_cpu_rules();
			else
				cpuplugd_error("Floating point exception, "
					       "skipping cpu rule "
					       "evaluation.\n");
		}
		if (memory == 1) {
			if (setjmp(jmpenv) == 0)
				eval_mem_rules(interval);
			else
				cpuplugd_error("Floating point exception, "
					       "skipping memory rule "
					       "evaluation.\n");
		}
		sleep(cfg.update);
	}
	return 0;
}
