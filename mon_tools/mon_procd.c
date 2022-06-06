/*
 * mon_procd - Write process data to the z/VM monitor stream
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <linux/types.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dir.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

#include "mon_procd.h"

struct name_lens_t {
	__u16 ruser_len;
	__u16 euser_len;
	__u16 egroup_len;
	__u16 wchan_len;
	__u16 cmd_len;
	__u16 cmdline_len;
};

static int num_cpus;
static int curr_small_max, curr_big_max;
static int prev_small_max, prev_big_max;
static unsigned int pg_to_kb_shift, sort_tbl_size;
static float e_time;
static struct timeval prev_time, curr_time;
static struct cpudata_t cpudata;
static struct proc_sum_t proc_sum;
static struct task_sort_t *prev_sort_tbl, *curr_sort_tbl;
static struct name_lens_t name_lens;

static int attach;
static int mw_dev;
static char *temp;
static char fname[32];
static char buf[BUF_SIZE];
static char mon_record[MAX_REC_LEN];
static long sample_interval = 60;

static const char *pid_file = "/run/mon_procd.pid";

/*
 * Clean up when SIGTERM or SIGINT received
 */
void stop_procd(int UNUSED(a))
{
	remove(pid_file);
	exit(0);
}

/*
 * Set up for handling SIGTERM or SIGINT
 */
static void procd_handle_signals(void)
{
	struct sigaction act;

	act.sa_flags = 0;
	sigemptyset( &act.sa_mask );

	act.sa_handler = stop_procd;
	if (sigaction(SIGTERM, &act, NULL) < 0) {
		fprintf(stderr, "sigaction( SIGTERM, ... ) failed - "
			"reason %s\n", strerror( errno ) );
		exit(1);
	}
	act.sa_handler = stop_procd;
	if (sigaction(SIGINT, &act, NULL) < 0) {
		fprintf(stderr, "sigaction( SIGINT, ... ) failed - "
			"reason %s\n", strerror( errno ) );
		exit(1);
	}
}

/*
 * Open /dev/monwriter
 */
static void procd_open_monwriter(void)
{
	mw_dev = open("/dev/monwriter", O_EXCL | O_RDWR);
	if (mw_dev == -1) {
		printf("cannot open /dev/monwriter: %s\n", strerror(errno));
		exit(1);
	}
}

/*
 * Store daemon's pid so it can be stopped
 */
static int store_pid(void)
{
	FILE *f = fopen(pid_file, "w");

	if (!f) {
		syslog(LOG_ERR, "cannot open pid file %s: %s", pid_file,
		       strerror(errno));
		return -1;
	}
	fprintf(f, "%d\n", getpid());
	fclose(f);
	return 0;
}

/*
 * Stop sampling of any buffers that are not longer needed
 */
static void stop_unused(int curr_max, int prev_max)
{
	struct monwrite_hdr *mw_hdrp;
	int i;

	mw_hdrp = (struct monwrite_hdr *)mon_record;
	mw_hdrp->applid = PROCD_APPLID;
	mw_hdrp->record_num = TASK_FLAG;
	mw_hdrp->hdrlen = sizeof(struct monwrite_hdr);
	mw_hdrp->mon_function = MONWRITE_STOP_INTERVAL;
	mw_hdrp->datalen = 0;
	for (i = 0; i < prev_max - curr_max; i += 2) {
		mw_hdrp->mod_level = curr_max + i;
		if (write(mw_dev, mw_hdrp, sizeof(struct monwrite_hdr)) == -1)
			syslog(LOG_ERR, "write error on STOP: %s\n",
			       strerror(errno));
	}
}

/*
 * Write process data to monitor stream
 */
static void procd_write_ent(void *entry, int size, char flag)
{
	struct monwrite_hdr *mw_hdrp;
	struct procd_hdr *mw_pchdrp;

	char *mw_tmpp;
	char *mw_bufp;
	int write_len;

	mw_bufp = mon_record;
	mw_hdrp = (struct monwrite_hdr *)mw_bufp;
	write_len = size + sizeof(struct monwrite_hdr)
		+ sizeof(struct procd_hdr);
	/* fill in monwrite_hdr */
	if (flag == TASK_FLAG) {
		if (write_len <= SMALL_MON_RECORD_LEN) {
			write_len = SMALL_MON_RECORD_LEN;
			mw_hdrp->mod_level = curr_small_max;
			curr_small_max += 2;
		} else {
			write_len = MAX_REC_LEN;
			mw_hdrp->mod_level = curr_big_max;
			curr_big_max += 2;
		}
	} else {
		mw_hdrp->mod_level = 0;
	}
	mw_hdrp->datalen = write_len - sizeof(struct monwrite_hdr);
	mw_hdrp->applid = PROCD_APPLID;
	mw_hdrp->record_num = flag;
	mw_hdrp->hdrlen = sizeof(struct monwrite_hdr);
	mw_hdrp->mon_function = MONWRITE_START_INTERVAL;

	/* fill in procd_hdr */
	mw_tmpp = mw_bufp + sizeof(struct monwrite_hdr);
	mw_pchdrp = (struct procd_hdr *)mw_tmpp;
	mw_pchdrp->time_stamp = (__u64) curr_time.tv_sec;
	mw_pchdrp->data_len = (__u16) size;
	mw_pchdrp->data_offset = (__u16) sizeof(struct procd_hdr);

	/* fill in entry information */
	mw_tmpp += sizeof(struct procd_hdr);
	if (flag == SUM_FLAG)
		memcpy(mw_tmpp, entry, size);
	else
		memcpy(mw_tmpp, entry, sizeof(struct task_t));

	if (write(mw_dev, mw_bufp, write_len) == -1)
		syslog(LOG_ERR, "write error: %s\n", strerror(errno));
}

/*
 * Open and read a file into a buffer, terminated with buf[size/num] = '\0'
*/
static int read_file(char *fname, char *buf, int size)
{
	int num, fp;

	fp = open(fname, O_RDONLY);
	if (!fp)
		return -1;

	num = read(fp, buf, size);
	if (num < 0) {
		close(fp);
		return -1;
	}
	buf[num] = '\0';

	close(fp);
	return num;
}

/*
 * Get uptime
*/
static void read_uptime(void)
{
	double uptm;

	if (read_file("/proc/uptime", buf, sizeof(buf) - 1) <= 0)
		return;

	if (sscanf(buf, "%lf ", &uptm) < 1) {
		syslog(LOG_ERR, "bad data in %s \n", fname);
		return;
	}
	proc_sum.uptime = (__u64)uptm;
}

/*
 * Get number of users
*/
static void count_users(void)
{
	struct utmp *temp;

	proc_sum.users = 0;
	setutent();
	while ((temp = getutent())) {
		if (temp->ut_type == USER_PROCESS)
			proc_sum.users++;
	}
	endutent();
}

/*
 * Get load averages
*/
static void read_loadavg(void)
{
	int ret_num;

	if (read_file("/proc/loadavg", buf, sizeof(buf) - 1) <= 0)
		return;

	ret_num = sscanf(buf, "%s %s %s", proc_sum.loadavg_1,
			proc_sum.loadavg_5, proc_sum.loadavg_15);

	if (ret_num < 3)
		syslog(LOG_ERR, "bad data in %s \n", fname);
}

/*
 * Calculate the state percentages for a CPU
*/
static void cal_cpu(struct cpudata_t *cpudt, struct cpu_t *cpu)
{
	__u64 total_time;

	total_time = cpudt->usr - cpudt->usr_prev;
	total_time += cpudt->sys - cpudt->sys_prev;
	total_time += cpudt->nice - cpudt->nice_prev;
	if (cpudt->idle - cpudt->idle_prev > 0)
		total_time += cpudt->idle - cpudt->idle_prev;
	total_time += cpudt->iowt - cpudt->iowt_prev;
	total_time += cpudt->irq - cpudt->irq_prev;
	total_time += cpudt->sirq - cpudt->sirq_prev;
	total_time += cpudt->steal - cpudt->steal_prev;

	if (total_time < 1)
		total_time = 1;

	cpu->num_cpus = cpudt->id;
	cpu->puser = (__u16)((cpudt->usr - cpudt->usr_prev) * 10000
			/ total_time);
	cpu->psystem = (__u16)((cpudt->sys - cpudt->sys_prev) * 10000
			/ total_time);
	cpu->pnice = (__u16)((cpudt->nice - cpudt->nice_prev) * 10000
			/ total_time);
	if (cpudt->idle - cpudt->idle_prev > 0)
		cpu->pidle = (__u16)((cpudt->idle - cpudt->idle_prev) * 10000
				/ total_time);
	else
		cpu->pidle = 0;
	cpu->piowait = (__u16)((cpudt->iowt - cpudt->iowt_prev) * 10000
			/ total_time);
	cpu->pirq = (__u16)((cpudt->irq - cpudt->irq_prev) * 10000
			/ total_time);
	cpu->psoftirq = (__u16)((cpudt->sirq - cpudt->sirq_prev) * 10000
			/ total_time);
	cpu->psteal = (__u16)((cpudt->steal - cpudt->steal_prev) * 10000
			/ total_time);

	cpudt->usr_prev = cpudt->usr;
	cpudt->sys_prev = cpudt->sys;
	cpudt->nice_prev = cpudt->nice;
	cpudt->idle_prev = cpudt->idle;
	cpudt->iowt_prev = cpudt->iowt;
	cpudt->irq_prev = cpudt->irq;
	cpudt->sirq_prev = cpudt->sirq;
	cpudt->steal_prev = cpudt->steal;
}

/*
 * Get CPU summary information
*/
static void read_cpu(void)
{
	unsigned long long u, n, s, i, w, x, y, z;

	if (read_file("/proc/stat", buf, sizeof(buf) - 1) <= 0)
		return;

	u = n = s = i = w = x = y = z = 0;
	temp = strstr(buf, "cpu");
	if (temp)
		sscanf(temp, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
			&u, &n, &s, &i, &w, &x, &y, &z);
	else
		syslog(LOG_ERR, "no cpu in /proc/stat\n");
	cpudata.usr = (__u64)u;
	cpudata.nice = (__u64)n;
	cpudata.sys = (__u64)s;
	cpudata.idle = (__u64)i;
	cpudata.iowt = (__u64)w;
	cpudata.irq = (__u64)x;
	cpudata.sirq = (__u64)y;
	cpudata.steal = (__u64)z;
	cpudata.id = (__u32)num_cpus;
	cal_cpu(&cpudata, &proc_sum.cpu);
}

/*
 * Get memory information
*/
static void read_mem(void)
{
	unsigned long long mtotal, mfree, mbuf;
	unsigned long long stotal, sfree, scached;

	if (read_file("/proc/meminfo", buf, sizeof(buf) - 1) <= 0)
		return;

	mtotal = mfree = mbuf = stotal = sfree = scached = 0;
	temp = strstr(buf, "MemTotal");
	if (temp)
		sscanf(temp, "MemTotal: %Lu kB", &mtotal);
	else
		syslog(LOG_ERR, "no MemTotal in /proc/meminfo\n");
	temp = strstr(buf, "MemFree");
	if (temp)
		sscanf(temp, "MemFree: %Lu kB", &mfree);
	else
		syslog(LOG_ERR, "no MemFree in /proc/meminfo\n");
	temp = strstr(buf, "Buffers");
	if (temp)
		sscanf(temp, "Buffers: %Lu kB", &mbuf);
	else
		syslog(LOG_ERR, "no Buffers in /proc/meminfo\n");
	temp = strstr(buf, "SwapTotal");
	if (temp)
		sscanf(temp, "SwapTotal: %Lu kB", &stotal);
	else
		syslog(LOG_ERR, "no SwapTotal in /proc/meminfo\n");
	temp = strstr(buf, "SwapFree");
	if (temp)
		sscanf(temp, "SwapFree: %Lu kB", &sfree);
	else
		syslog(LOG_ERR, "no SwapFree in /proc/meminfo\n");
	temp = strstr(buf, "Cached");
	if (temp)
		sscanf(temp, "Cached: %Lu kB", &scached);
	else
		syslog(LOG_ERR, "no Cached in /proc/meminfo\n");

	proc_sum.mem.total = (__u64)mtotal;
	proc_sum.mem.free = (__u64)mfree;
	proc_sum.mem.buffers = (__u64)mbuf;
	proc_sum.swap.total = (__u64)stotal;
	proc_sum.swap.free = (__u64)sfree;
	proc_sum.swap.cached = (__u64)scached;
	proc_sum.mem.used = proc_sum.mem.total - proc_sum.mem.free;
	proc_sum.swap.used = proc_sum.swap.total - proc_sum.swap.free;
}

/*
 * Get virtual memory information
*/
static void read_vmem(void)
{
	unsigned long long pgin, pgout, swpin, swpout;

	if (read_file("/proc/vmstat", buf, sizeof(buf) - 1) <= 0)
		return;

	pgin = pgout = swpin = swpout = 0;
	temp = strstr(buf, "pgpgin");
	if (temp)
		sscanf(temp, "pgpgin %Lu", &pgin);
	else
		syslog(LOG_ERR, "no pgpgin in /proc/vmstat\n");
	temp = strstr(buf, "pgpgout");
	if (temp)
		sscanf(temp, "pgpgout %Lu", &pgout);
	else
		syslog(LOG_ERR, "no pgpgout in /proc/vmstat\n");
	temp = strstr(buf, "pswpin");
	if (temp)
		sscanf(temp, "pswpin %Lu", &swpin);
	else
		syslog(LOG_ERR, "no pswpin in /proc/vmstat\n");
	temp = strstr(buf, "pswpout");
	if (temp)
		sscanf(temp, "pswpout %Lu", &swpout);
	else
		syslog(LOG_ERR, "no pswpout in /proc/vmstat\n");

	proc_sum.mem.pgpgin = (__u64)(pgin << pg_to_kb_shift);
	proc_sum.mem.pgpgout = (__u64)(pgout << pg_to_kb_shift);
	proc_sum.swap.pswpin = (__u64)swpin;
	proc_sum.swap.pswpout = (__u64)swpout;
}

/*
 * Get process summary information
*/
static void read_summary(void)
{
	read_uptime();
	count_users();
	read_loadavg();
	read_cpu();
	read_mem();
	read_vmem();
}

/*
 * Get memory information for a task
*/
static int read_statm(struct task_t *task)
{
	long size, res, sh, trs, lrs, drs, dt;

	snprintf(fname, sizeof(fname), "/proc/%u/statm", task->pid);
	if (read_file(fname, buf, sizeof(buf) - 1) == -1)
		return 0;

	sscanf(buf, "%ld %ld %ld %ld %ld %ld %ld",
		&size, &res, &sh, &trs, &lrs, &drs, &dt);
	task->size = (__u64)(size << pg_to_kb_shift);
	task->resident = (__u64)(res << pg_to_kb_shift);
	task->swap = task->size - task->resident;
	task->share = (__u64)(sh << pg_to_kb_shift);
	task->trs = (__u64)(trs << pg_to_kb_shift);
	task->drs = (__u64)(drs << pg_to_kb_shift);
	task->dt = (__u64)dt;

	task->pmem = (__u16)(task->resident * 10000 / proc_sum.mem.total);
	return 1;
}

/*
 * Get status information for a task from /proc/.../status
*/
static int read_status(struct task_t *task)
{
	int ruid, euid, egid;
	char *lenp, *namep;
	struct passwd *pwd;
	struct group *grp;

	snprintf(fname, sizeof(fname), "/proc/%u/status", task->pid);
	if (read_file(fname, buf, sizeof(buf) - 1) == -1)
		return 0;

	ruid = euid = egid = 0;
	temp = strstr(buf, "Uid");
	if (temp)
		sscanf(temp, "Uid: %d %d", &ruid, &euid);
	else
		syslog(LOG_ERR, "no Uid in /proc/%u/status\n", task->pid);
	temp = strstr(buf, "Gid");
	if (temp)
		sscanf(temp, "Gid: %*d %d", &egid);
	else
		syslog(LOG_ERR, "no Gid in /proc/%u/status\n", task->pid);
	task->euid = (__u16)euid;

	lenp = mon_record + sizeof(struct monwrite_hdr);
	lenp += sizeof(struct procd_hdr);
	lenp += sizeof(struct task_t);
	namep = lenp + sizeof(__u16);
	pwd = getpwuid(ruid);
	if (!pwd)
		name_lens.ruser_len = sprintf(namep, "%u", ruid);
	else {
		name_lens.ruser_len = strlen(pwd->pw_name);
		if (name_lens.ruser_len > MAX_NAME_LEN)
			name_lens.ruser_len = MAX_NAME_LEN;
		memcpy(namep, pwd->pw_name, name_lens.ruser_len);
	}
	memcpy(lenp, &name_lens.ruser_len, sizeof(__u16));

	lenp = namep + name_lens.ruser_len;
	namep = lenp + sizeof(__u16);
	pwd = getpwuid(task->euid);
	if (!pwd)
		name_lens.euser_len = sprintf(namep, "%u", task->euid);
	else {
		name_lens.euser_len = strlen(pwd->pw_name);
		if (name_lens.euser_len > MAX_NAME_LEN)
			name_lens.euser_len = MAX_NAME_LEN;
		memcpy(namep, pwd->pw_name, name_lens.euser_len);
	}
	memcpy(lenp, &name_lens.euser_len, sizeof(__u16));

	lenp = namep + name_lens.euser_len;
	namep = lenp + sizeof(__u16);
	grp = getgrgid(egid);
	if (!grp)
		name_lens.egroup_len = sprintf(namep, "%u", egid);
	else {
		name_lens.egroup_len = strlen(grp->gr_name);
		if (name_lens.egroup_len > MAX_NAME_LEN)
			name_lens.egroup_len = MAX_NAME_LEN;
		memcpy(namep, grp->gr_name, name_lens.egroup_len);
	}
	memcpy(lenp, &name_lens.egroup_len, sizeof(__u16));
	return 1;
}

/*
 * Calculate percentage of CPU used by a task since last sampling
*/
static void cal_task_pcpu(struct task_t *task, const unsigned long long tics)
{
	unsigned int i, size;
	__u64 etics;

	if (proc_sum.task.total + 1 >= sort_tbl_size) {
		sort_tbl_size = sort_tbl_size * 5 / 4 + 100;
		size = sort_tbl_size * sizeof(struct task_sort_t);
		curr_sort_tbl = realloc(curr_sort_tbl, size);
		if (!curr_sort_tbl) {
			fprintf(stderr, "Allocating memory failed - "
			"reason %s\n", strerror(errno));
			exit(1);
		}
		prev_sort_tbl = realloc(prev_sort_tbl, size);
		if (!prev_sort_tbl) {
			fprintf(stderr, "Allocating memory failed - "
			"reason %s\n", strerror(errno));
			exit(1);
		}
	}
	curr_sort_tbl[proc_sum.task.total].pid = task->pid;
	curr_sort_tbl[proc_sum.task.total].tics = (__u64)tics;

	etics = (__u64)tics;
	for (i = 0; i < sort_tbl_size; i++) {
		if (prev_sort_tbl[i].pid == task->pid) {
			etics -= prev_sort_tbl[i].tics;
			break;
		}
	}
	task->pcpu = (__u16)((etics * 10000 / Hertz) / (e_time * num_cpus));
	if (task->pcpu > 9999)
		task->pcpu = 9999;
}

/*
 * Get status information for a task from /proc/.../stat
*/
static int read_stat(struct task_t *task)
{
	unsigned long long maj_flt = 0, utime = 0, stime = 0, cutime = 0,
			   cstime = 0;
	unsigned long flags = 0, pri = 0, nice = 0;
	char *cmd_start, *cmd_end, *cmdlenp, *cmdp;
	int ppid = 0, tty = 0, proc = 0, rc;

	snprintf(fname, sizeof(fname), "/proc/%u/stat", task->pid);
	if (read_file(fname, buf, sizeof(buf) - 1) == -1)
		return 0;

	cmd_start = strchr(buf, '(') + 1;
	cmd_end = strrchr(cmd_start, ')');
	name_lens.cmd_len = cmd_end - cmd_start;
	cmdlenp = mon_record + sizeof(struct monwrite_hdr);
	cmdlenp += sizeof(struct procd_hdr);
	cmdlenp += sizeof(struct task_t);
	cmdlenp += sizeof(__u16) + name_lens.ruser_len;
	cmdlenp += sizeof(__u16) + name_lens.euser_len;
	cmdlenp += sizeof(__u16) + name_lens.egroup_len;
	cmdlenp += sizeof(__u16) + name_lens.wchan_len;

	if (name_lens.cmd_len <= 0)
		name_lens.cmd_len = 0;
	else {
		cmdp = cmdlenp + sizeof(__u16);
		if (name_lens.cmd_len > MAX_NAME_LEN)
			name_lens.cmd_len = MAX_NAME_LEN;
		memcpy(cmdp, cmd_start, name_lens.cmd_len);
	}
	memcpy(cmdlenp, &name_lens.cmd_len, sizeof(__u16));

	cmd_end += 2;
	rc = sscanf(cmd_end,
		"%c %d %*d %*d %d %*d "
		"%lu %*s %*s %Lu %*s "
		"%Lu %Lu %Lu %Lu "
		"%ld %ld "
		"%*d %*s "
		"%*s %*s %*s "
		"%*s %*s %*s %*s %*s %*s "
		"%*s %*s %*s %*s "
		"%*s %*s %*s "
		"%*d %d "
		"%*s %*s",
		&task->state, &ppid, &tty,
		&flags, &maj_flt,
		&utime, &stime, &cutime, &cstime,
		&pri, &nice,
		&proc);
	if (rc != 12)
		syslog(LOG_ERR, "bad data in %s \n", fname);
	task->ppid = (__u32)ppid;
	task->tty = (__u16)tty;
	task->flags = (__u32)flags;
	task->maj_flt = (__u64)maj_flt;
	task->priority = (__s16)pri;
	task->nice = (__s16)nice;
	task->processor = (__u32)proc;
	task->total_time = (__u64)((utime + stime) * 100 / Hertz);
	task->ctotal_time = (__u64)((utime + stime + cutime + cstime) * 100
				/ Hertz);
	cal_task_pcpu(task, utime + stime);

	return 1;
}

/*
 * Get the sleeping in function of a task
*/
static int read_wchan(struct task_t *task)
{
	int num;
	char *wchanlenp, *wchanp;

	snprintf(fname, sizeof(fname), "/proc/%u/wchan", task->pid);
	num = read_file(fname, buf, sizeof(buf) -1);

	if (num < 0)
		return 0;

	wchanlenp = mon_record + sizeof(struct monwrite_hdr);
	wchanlenp += sizeof(struct procd_hdr);
	wchanlenp += sizeof(struct task_t);
	wchanlenp += sizeof(__u16) + name_lens.ruser_len;
	wchanlenp += sizeof(__u16) + name_lens.euser_len;
	wchanlenp += sizeof(__u16) + name_lens.egroup_len;
	wchanp = wchanlenp + sizeof(__u16);

	name_lens.wchan_len = num;
	if (num == 0) {
		memcpy(wchanlenp, &name_lens.wchan_len, sizeof(__u16));
		return 1;
	}
	buf[num] = '\0';

	if (buf[0] == '0' && buf[1] == '\0') {
		memcpy(wchanlenp, &name_lens.wchan_len, sizeof(__u16));
		wchanp[0] = '-';
		return 1;
	}

	if (buf[0] == 's' && !strncmp(buf, "sys_", 4)) {
		name_lens.wchan_len -= 4;
		if (name_lens.wchan_len > MAX_NAME_LEN)
			name_lens.wchan_len = MAX_NAME_LEN;
		memcpy(wchanlenp, &name_lens.wchan_len, sizeof(__u16));
		memcpy(wchanp, buf + 4, name_lens.wchan_len);
		return 1;
	}

	if (buf[0] == 'd' && !strncmp(buf, "do_", 3)) {
		name_lens.wchan_len -= 3;
		if (name_lens.wchan_len > MAX_NAME_LEN)
			name_lens.wchan_len = MAX_NAME_LEN;
		memcpy(wchanlenp, &name_lens.wchan_len, sizeof(__u16));
		memcpy(wchanp, buf + 3, name_lens.wchan_len);
		return 1;
	}

	temp = buf;
	while (*temp == '_') {
		temp++;
		name_lens.wchan_len--;
	}
	if (name_lens.wchan_len > MAX_NAME_LEN)
		name_lens.wchan_len = MAX_NAME_LEN;
	memcpy(wchanlenp, &name_lens.wchan_len, sizeof(__u16));
	memcpy(wchanp, temp, name_lens.wchan_len);
	return 1;
}

/*
 * Get command line of a task
*/
static int read_cmdline(struct task_t *task)
{
	int i, num;
	char *cmdlnlenp, *cmdlinep;

	snprintf(fname, sizeof(fname), "/proc/%u/cmdline", task->pid);
	num = read_file(fname, buf, sizeof(buf) - 1);
	if (num == -1)
		return 0;
	for (i = 0; i < num; i++) {
		if (buf[i] < ' ' || buf[i] > '~')
			buf[i] = ' ';
	}
	name_lens.cmdline_len = num;
	cmdlnlenp = mon_record + sizeof(struct monwrite_hdr);
	cmdlnlenp += sizeof(struct procd_hdr);
	cmdlnlenp += sizeof(struct task_t);
	cmdlnlenp += sizeof(__u16) + name_lens.ruser_len;
	cmdlnlenp += sizeof(__u16) + name_lens.euser_len;
	cmdlnlenp += sizeof(__u16) + name_lens.egroup_len;
	cmdlnlenp += sizeof(__u16) + name_lens.wchan_len;
	cmdlnlenp += sizeof(__u16) + name_lens.cmd_len;
	cmdlinep = cmdlnlenp + sizeof(__u16);

	memcpy(cmdlnlenp, &name_lens.cmdline_len, sizeof(__u16));
	if (name_lens.cmdline_len > 0)
		memcpy(cmdlinep, buf, name_lens.cmdline_len);
	return 1;
}

/*
 * Usage sorting help function
*/
static int sort_usage(const void *et1, const void *et2)
{
	return ((struct task_sort_t *)et2)->cpu_mem_usage
		- ((struct task_sort_t *)et1)->cpu_mem_usage;
}

/*
 * Adjust task state counters
*/
static void task_count(char oldst, char newst)
{
	if (oldst == newst)
		return;

	switch (oldst) {
	case 'R':
		proc_sum.task.running--;
		break;
	case 'S':
	case 'D':
		proc_sum.task.sleeping--;
		break;
	case 'T':
		proc_sum.task.stopped--;
		break;
	case 'Z':
		proc_sum.task.zombie--;
		break;
	}
	switch (newst) {
	case 'R':
		proc_sum.task.running++;
		break;
	case 'S':
	case 'D':
		proc_sum.task.sleeping++;
		break;
	case 'T':
		proc_sum.task.stopped++;
		break;
	case 'Z':
		proc_sum.task.zombie++;
		break;
	}
}

/*
 * Read and calculate memory and cpu usages of a task
*/
static void task_usage(struct task_t *task)
{
	long res;
	unsigned long long utime, stime;

	snprintf(fname, sizeof(fname), "/proc/%u/statm", task->pid);
	if (read_file(fname, buf, sizeof(buf) - 1) == -1)
		return;
	sscanf(buf, "%*s %ld %*s %*s %*s %*s %*s", &res);
	task->resident = (__u64)(res << pg_to_kb_shift);
	task->pmem = (__u16)(task->resident * 10000 / proc_sum.mem.total);

	snprintf(fname, sizeof(fname), "/proc/%u/stat", task->pid);
	if (read_file(fname, buf, sizeof(buf) - 1) == -1)
		return;
	sscanf(buf,
		"%*s %*s "
		"%c %*s %*s %*s %*s %*s "
		"%*s %*s %*s %*s %*s "
		"%Lu %Lu ",
		&task->state,
		&utime, &stime);
	cal_task_pcpu(task, utime + stime);

	curr_sort_tbl[proc_sum.task.total].cpu_mem_usage = task->pcpu +
		task->pmem;
	curr_sort_tbl[proc_sum.task.total].state = task->state;
	task_count('\0', task->state);
	proc_sum.task.total++;
}

/*
 * read tasks information and write to monitor stream
*/
static void read_tasks(void)
{
	int size;
	unsigned int i = 0, j = 0;
	DIR *proc_dir;
	struct direct *entry;
	struct task_t task;

	proc_dir = opendir("/proc");
	if (!proc_dir) {
		syslog(LOG_ERR, "failed /proc open: %s ", strerror(errno));
		return;
	}

	while ((entry = readdir(proc_dir))) {
		if (!entry->d_name)
			break;
		if (!isdigit(entry->d_name[0]) || !atoi(entry->d_name))
			continue;
		memset(&task, 0, sizeof(struct task_t));
		task.pid = atoi(entry->d_name);
		task_usage(&task);
	}
	closedir(proc_dir);

	if (proc_sum.task.total > MAX_TASK_REC)
		qsort(curr_sort_tbl, proc_sum.task.total,
			sizeof(struct task_sort_t), sort_usage);

	/* only write up to top 100 processes data to monitor stream */
	while ((i < proc_sum.task.total) && (j < MAX_TASK_REC)) {
		memset(&task, 0, sizeof(struct task_t));
		memset(mon_record, 0, sizeof(mon_record));
		task.pid = curr_sort_tbl[i].pid;
		if (read_statm(&task) && read_status(&task) &&
			read_wchan(&task) && read_stat(&task) &&
			read_cmdline(&task)) {
			task_count(curr_sort_tbl[i].state, task.state);
			size = sizeof(struct task_t);
			size += sizeof(struct name_lens_t);
			size += name_lens.ruser_len + name_lens.euser_len;
			size += name_lens.egroup_len + name_lens.wchan_len;
			size += name_lens.cmd_len + name_lens.cmdline_len;
			procd_write_ent(&task, size, TASK_FLAG);
			j++;
		} else
			task_count(curr_sort_tbl[i].state, '\0');
		i++;
	}
	proc_sum.task.total -= i - j;
}

/*
 * Run as background process
 */
static void procd_daemonize(void)
{
	int pipe_fds[2], startup_rc = 1;
	pid_t pid;

	if (pipe(pipe_fds) == -1) {
		syslog(LOG_ERR, "pipe error: %s\n", strerror(errno));
		exit(1);
	}

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "fork error: %s\n", strerror(errno));
		exit(1);
	}
	if (pid > 0) {
		/* Wait for startup return code from daemon */
		if (read(pipe_fds[0], &startup_rc, sizeof(startup_rc)) == -1)
			syslog(LOG_ERR, "pipe read error: %s\n", strerror(errno));
		/* With startup_rc == 0, pid file was written at this point */
		exit(startup_rc);
	}

	/* Change the file mode mask */
	umask(0);

	/* Catch SIGINT and SIGTERM to clean up pid file on exit */
	procd_handle_signals();

	/* Create a new SID for the child process */
	if (setsid() < 0) {
		syslog(LOG_ERR, "setsid error: %s\n",  strerror(errno));
		goto notify_parent;
	}

	/* Change the current working directory */
	if (chdir("/") < 0) {
		syslog(LOG_ERR, "chdir error: %s\n",  strerror(errno));
		goto notify_parent;
	}

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* Store daemon pid */
	if (store_pid() < 0)
		goto notify_parent;
	startup_rc = 0;

notify_parent:
	/* Inform waiting parent about startup return code */
	if (write(pipe_fds[1], &startup_rc, sizeof(startup_rc)) == -1) {
		syslog(LOG_ERR, "pipe write error: %s\n", strerror(errno));
		exit(1);
	}
	if (startup_rc != 0)
		exit(startup_rc);
}

static int procd_do_work(void)
{
	int pgsize;
	struct timezone tz;
	struct task_sort_t *tmp;

	prev_small_max = 0;
	prev_big_max = 1;
	num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (num_cpus < 1)
		num_cpus = 1;

	pg_to_kb_shift = 0;
	pgsize = getpagesize();
	while (pgsize > 1024) {
		pgsize >>= 1;
		pg_to_kb_shift++;
	}

	syslog(LOG_INFO, "procd sample interval: %lu\n", sample_interval);
	while (1) {
		gettimeofday(&curr_time, &tz);
		e_time = (curr_time.tv_sec - prev_time.tv_sec) +
			(float)(curr_time.tv_usec - prev_time.tv_usec)
			/ 1000000.0;
		memset(&proc_sum, 0, sizeof(struct proc_sum_t));
		tmp = prev_sort_tbl;
		prev_sort_tbl = curr_sort_tbl;
		curr_sort_tbl = tmp;
		curr_small_max = 0;
		curr_big_max = 1;
		read_summary();
		read_tasks();
		memset(mon_record, 0, sizeof(mon_record));
		procd_write_ent(&proc_sum, sizeof(struct proc_sum_t), SUM_FLAG);

		if (curr_small_max < prev_small_max)
			stop_unused(curr_small_max, prev_small_max);
		if (curr_big_max < prev_big_max)
			stop_unused(curr_big_max, prev_big_max);

		prev_small_max = curr_small_max;
		prev_big_max = curr_big_max;
		prev_time.tv_sec = curr_time.tv_sec;
		prev_time.tv_usec = curr_time.tv_usec;
		sleep(sample_interval);
	}
	return 1;
}

/*
 Parse options
*/
static int parse_options(int argc, char **argv)
{
	int opt;

	do {
		opt = getopt_long(argc, argv, opt_string, options, NULL);
		switch (opt) {
		case -1:
			/* Reached end of parameter list. */
			break;
		case 'h':
			printf("%s", help_text);
			exit(0);
		case 'v':
			printf( "mon_procd: version %s\n", RELEASE_STRING);
			printf("Copyright IBM Corp. 2007, 2017\n");
			exit(0);
		case 'a':
			attach = 1;
			break;
		case 'i':
			sample_interval = strtol(optarg, NULL, 10);
			if (sample_interval <= 0) {
				fprintf(stderr, "Error: Invalid interval "
					"(needs to be greater than 0)\n");
				return(1);
			}
			break;
		default:
			fprintf(stderr, "Try ' --help' for more"
				" information.\n");
			return(1);
		}
	} while (opt != -1);
	return(0);
}

int main(int argc, char **argv)
{
	int rc;

	attach = 0;
	rc = parse_options(argc, argv);
	if (rc > 0)
		return rc;
	procd_open_monwriter();
	openlog("mon_procd", 0, LOG_DAEMON);
	if (!attach)
		procd_daemonize();
	rc = procd_do_work();
	close(mw_dev);
	return rc;
}
