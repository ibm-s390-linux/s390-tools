/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * Header file
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __USE_ISOC99
#define __USE_ISOC99
#endif
#include <ctype.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/zt_common.h"

#define NAME		"cpuplugd"
#define MAX_HISTORY	100
#define PIDFILE		"/run/cpuplugd.pid"
#define LOCKFILE	"/var/lock/cpuplugd.lock"
#define PROCINFO_LINE	512
#define CPUSTAT_SIZE	1024
#define VARINFO_SIZE	4096
#define MAX_VARNAME	128
#define MAX_LINESIZE	2048
#define CPUSTATS	10

/*
 *  Precedence of C operators
 *  full list:
 *  http://www.imada.sdu.dk/~svalle/
 *  courses/dm14-2005/mirror/c/_7193_tabular246.gif
 *
 *  ()
 *  +-
 *  * /
 *  < >
 *  &
 *  |
 */
enum op_prio {
	OP_PRIO_NONE,
	OP_PRIO_OR,
	OP_PRIO_AND,
	/* greater and lower */
	OP_PRIO_CMP,
	OP_PRIO_ADD,
	OP_PRIO_MULT
};

enum operation {
	/* Leaf operators */
	OP_SYMBOL_LOADAVG,
	OP_SYMBOL_RUNABLE,
	OP_SYMBOL_CPUS,
	OP_SYMBOL_USER,
	OP_SYMBOL_NICE,
	OP_SYMBOL_SYSTEM,
	OP_SYMBOL_IDLE,
	OP_SYMBOL_IOWAIT,
	OP_SYMBOL_IRQ,
	OP_SYMBOL_SOFTIRQ,
	OP_SYMBOL_STEAL,
	OP_SYMBOL_GUEST,
	OP_SYMBOL_GUEST_NICE,
	OP_SYMBOL_APCR,
	OP_SYMBOL_SWAPRATE,
	OP_SYMBOL_FREEMEM,
	OP_SYMBOL_MEMINFO,
	OP_SYMBOL_VMSTAT,
	OP_SYMBOL_CPUSTAT,
	OP_SYMBOL_TIME,
	OP_CONST,
	/* Unary operators */
	OP_NEG,
	OP_NOT,
	/* Binary operators */
	OP_AND,
	OP_OR,
	OP_GREATER,
	OP_LESSER,
	OP_PLUS,
	OP_MINUS,
	OP_MULT,
	OP_DIV,
	/* ... */
	/*Variables which are eligible within rules*/
	VAR_LOAD,       /* loadaverage */
	VAR_RUN,        /* number of runnable processes */
	VAR_ONLINE     /* number of online cpus */
};

struct symbols {
	double loadavg;
	double runnable_proc;
	double onumcpus;
	double idle;
	double freemem;
	double apcr;
	double swaprate;
	double user;
	double nice;
	double system;
	double iowait;
	double irq;
	double softirq;
	double steal;
	double guest;
	double guest_nice;
};

struct term {
	enum operation op;
	double value;
	struct term *left, *right;
	char *proc_name;
	unsigned int index;
};

/*
 * List of  argurments taken fromt the configuration file
 *
 */
struct config {
	long cpu_max;
	long cpu_min;
	long update;
	long cmm_max;
	long cmm_min;
	struct term *cmm_inc;
	struct term *cmm_dec;
	struct term *hotplug;
	struct term *hotunplug;
	struct term *memplug;
	struct term *memunplug;
};

struct symbol_names {
	char *name;
	enum operation symop;
};

extern int foreground;
extern char *configfile;
extern int debug;        /* is verbose specified? */
extern int memory;
extern int cpu;
extern int num_cpu_start; /* # of online cpus at the time of the startup */
extern long cmm_pagesize_start; /* cmm_pageize at the time of daemon startup */
extern struct config cfg;
extern int reload_pending;
extern unsigned long meminfo_size;
extern unsigned long vmstat_size;
extern unsigned long cpustat_size;
extern unsigned long varinfo_size;
extern char *meminfo;
extern char *vmstat;
extern char *cpustat;
extern char *varinfo;
extern double *timestamps;
extern unsigned int history_max;
extern unsigned int history_current;
extern struct symbol_names sym_names[];
extern unsigned int sym_names_count;

int get_numcpus();
int get_num_online_cpus();
void get_loadavg_runnable(double *loadavg, double *runnable);
void clean_up();
void reactivate_cpus();
void parse_configfile(char *file);
void print_term(struct term *fn);
struct term *parse_term(char **p, enum op_prio prio);
int eval_term(struct term *fn, struct symbols *symbols);
double eval_double(struct term *fn, struct symbols *symbols);
double get_proc_value(char *procinfo, char *name, char separator);
void proc_read(char *procinfo, char *path, unsigned long size);
void proc_cpu_read(char *procinfo);
unsigned long proc_read_size(char *path);
char *get_var_rvalue(char *var_name);
void cleanup_cmm(void);
int hotplug(int cpuid);
int hotunplug(int cpuid);
int is_online(int cpuid);
long get_cmmpages_size();
void parse_options(int argc, char **argv);
void check_if_started_twice();
void handle_signals(void);
void handle_sighup(void);
void reload_daemon(void);
int daemonize(void);
int check_cmmfiles(void);
void check_config();
void set_cmm_pages(long size);
int check_lpar();
int cpu_is_configured(int cpuid);
void setup_history(void);


#define cpuplugd_info(fmt, ...) ({			\
	if (foreground == 1)				\
		printf(fmt, ##__VA_ARGS__);		\
	if (foreground == 0)				\
		syslog(LOG_INFO, fmt, ##__VA_ARGS__);	\
})

#define cpuplugd_error(fmt, ...) ({			\
	if (foreground == 1)				\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	if (foreground == 0)				\
		syslog(LOG_ERR, fmt, ##__VA_ARGS__);	\
})

#define cpuplugd_debug(fmt, ...) ({			\
	if (debug)					\
		cpuplugd_info(fmt, ##__VA_ARGS__);	\
})

#define cpuplugd_exit(fmt, ...) ({			\
	cpuplugd_error(fmt, ##__VA_ARGS__);		\
	clean_up();					\
})
