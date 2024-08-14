/*
 * cpacfstats - display and maintain CPACF perf counters
 *
 * cpacfstatsd daemon implementation
 *
 * Copyright IBM Corp. 2015, 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include "lib/zt_common.h"
#include "lib/util_file.h"
#include "cpacfstats.h"

static volatile int stopsig;

/*
 * This list contains the counter numbers sorted by instruction
 */
static const unsigned int pai_idx[] = {
	// KM
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	// KMC
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
	// KMA
	29, 30, 31, 32, 33, 34,
	// KMF
	35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
	// KMCTR
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
	// KMO
	59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
	// KIMD
	71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
	// KLMD
	81, 82, 83, 84, 85, 86, 87, 88, 89,
	// KMAC
	90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
	// PCC
	102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
	114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
	// PRNO
	125, 126, 127,
	// KDSA
	128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
	140, 141, 142,
	// PCKMO
	143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153,
	// Reserved
	154, 155
};

static const char *const name = "cpacfstatsd";

static const char *const usage =
	"Usage: %s [OPTIONS]\n"
	"\n"
	"Daemon to provide access to CPACF perf counters\n"
	"Use OPTIONS described below:\n"
	"\n"
	"\t-h, --help          Print this help, then exit\n"
	"\t-v, --version       Print version information, then exit\n"
	"\t-f, --foreground    Run in foreground, do not detach\n";

static int daemonized;

static int recv_query(int s, enum ctr_e *ctr, enum cmd_e *cmd)
{
	struct msg m;
	int rc;

	rc = recv_msg(s, &m, DEFAULT_RECV_TIMEOUT);
	if (rc == 0) {
		if (m.head.m_ver != VERSION) {
			eprint("Received msg with wrong version %d != %d\n",
			       m.head.m_ver, VERSION);
			return -1;
		}
		if (m.head.m_type != QUERY) {
			eprint("Received msg with wrong type %d != %d\n",
			       m.head.m_type, QUERY);
			return -1;
		}
		*ctr = m.query.m_ctr;
		*cmd = m.query.m_cmd;
	}

	return rc;
}

static int send_answer(int s, int ctr, int state, uint64_t value)
{
	struct msg m;

	memset(&m, 0, sizeof(m));

	m.head.m_ver = VERSION;
	m.head.m_type = ANSWER;
	m.answer.m_ctr = ctr;
	m.answer.m_state = state;
	m.answer.m_value = value;

	return send_msg(s, &m, DEFAULT_SEND_TIMEOUT);
}

/*
 * Print according to protocol for PAI:
 * - first the state and the number of PAI counters that follow
 * - if state is ENABLED:
 *   - for each PAI counter the value with state ENABLED
 * Note that the PAI counters are 0-based, not 1 based as in PoP!
 * Sending ends with the first error.
 */
static int do_send_pai(int s, int user, unsigned int *counter)
{
	int ctr, state, i, rc = 0;
	unsigned int current_ctr;
	uint64_t value;

	ctr = user ? PAI_USER : PAI_KERNEL;

	state = perf_ctr_state(ctr);
	if (state != ENABLED)
		return rc;
	for (i = 0; i < MAX_NUM_PAI; ++i) {
		current_ctr = pai_idx[i];
		if ((user && is_user_space(current_ctr) != KERNEL_AND_USER_COUNTER) ||
		    (!user && is_user_space(current_ctr) == SUPPRESS_COUNTER) ||
		    counter[current_ctr] != 1)
			continue;
		rc = perf_read_pai_ctr(current_ctr, user, &value);
		if (rc != 0) {
			send_answer(s, current_ctr, rc, 0);
			break;
		}
		send_answer(s, current_ctr, state, value);
	}
	return rc;
}

static int do_enable(int s, enum ctr_e ctr, unsigned int *supported_counters)
{
	uint64_t value = 0;
	int i, rc = 0;
	int state;

	for (i = 0; i < NUM_COUNTER; i++) {
		if (i == ALL_COUNTER)
			continue;
		if (i == (int) ctr || ctr == ALL_COUNTER) {
			state = perf_ctr_state(i);
			if (state == DISABLED) {
				rc = perf_enable_ctr(i, supported_counters);
				if (rc != 0) {
					send_answer(s, i, rc, 0);
					break;
				}
				state = ENABLED;
			}
			if (state != UNSUPPORTED) {
				rc = perf_read_ctr(i, &value, supported_counters);
				if (rc != 0) {
					send_answer(s, i, rc, 0);
					break;
				}
			}
			send_answer(s, i, state, value);
			if (i == PAI_USER)
				rc = do_send_pai(s, 1, supported_counters);
			if (i == PAI_KERNEL)
				rc = do_send_pai(s, 0, supported_counters);
		}
	}
	if (rc == 0) {
		rc = perf_read_ctr(HOTPLUG_DETECTED, &value, NULL);
		send_answer(s, HOTPLUG_DETECTED, rc, value);
	}
	return rc;
}

static int do_disable(int s, enum ctr_e ctr, unsigned int *supported_counters)
{
	int i, rc = 0;
	uint64_t value;

	for (i = 0; i < NUM_COUNTER; i++) {
		if (i == ALL_COUNTER)
			continue;
		if (i == (int) ctr || ctr == ALL_COUNTER) {
			if (perf_ctr_state(i) == ENABLED) {
				rc = perf_disable_ctr(i, supported_counters);
				if (rc != 0) {
					send_answer(s, i, rc, 0);
					break;
				}
			}
			send_answer(s, i, perf_ctr_state(i), 0);
		}
	}
	if (rc == 0) {
		rc = perf_read_ctr(HOTPLUG_DETECTED, &value, NULL);
		send_answer(s, HOTPLUG_DETECTED, rc, value);
	}
	return rc;
}

static int do_reset(int s, enum ctr_e ctr, unsigned int *supported_counters)
{
	int i, rc = 0, state;
	uint64_t value;

	for (i = 0; i < NUM_COUNTER; i++) {
		if (i == ALL_COUNTER)
			continue;
		if (i == (int) ctr || ctr == ALL_COUNTER) {
			state = perf_ctr_state(i);
			if (state == ENABLED) {
				rc = perf_reset_ctr(i, &value, supported_counters);
				if (rc != 0) {
					send_answer(s, i, rc, 0);
					break;
				}
			}
			send_answer(s, i, state, value);
			if (i == PAI_USER)
				rc = do_send_pai(s, 1, supported_counters);
			if (i == PAI_KERNEL)
				rc = do_send_pai(s, 0, supported_counters);
		}
	}
	if (rc == 0) {
		rc = perf_read_ctr(HOTPLUG_DETECTED, &value, NULL);
		send_answer(s, HOTPLUG_DETECTED, rc, value);
	}
	return rc;
}

static int do_print(int s, enum ctr_e ctr, unsigned int *supported_counters)
{
	int i, rc = 0, state;
	uint64_t value = 0;

	for (i = 0; i < NUM_COUNTER; i++) {
		if (i == ALL_COUNTER)
			continue;
		if (i == (int) ctr || ctr == ALL_COUNTER) {
			state = perf_ctr_state(i);
			if (state == ENABLED) {
				rc = perf_read_ctr(i, &value, supported_counters);
				if (rc != 0) {
					send_answer(s, i, rc, 0);
					break;
				}
			}
			send_answer(s, i, state, value);
			if (i == PAI_USER)
				rc = do_send_pai(s, 1, supported_counters);
			if (i == PAI_KERNEL)
				rc = do_send_pai(s, 0, supported_counters);
		}
	}
	if (rc == 0) {
		rc = perf_read_ctr(HOTPLUG_DETECTED, &value, NULL);
		send_answer(s, HOTPLUG_DETECTED, rc, value);
	}
	return rc;
}

static int become_daemon(int *startup_pipe)
{
	int child_initialized = 0, fd;
	int pipefds[2];
	FILE *f;

	/* syslog */
	openlog("cpacfstatsd", 0, LOG_DAEMON);

	if (pipe(pipefds) != 0) {
		eprint("pipe() failed, errno=%d [%s]\n", errno, strerror(errno));
		return -1;
	}

	/*
	 * fork and terminate parent
	 * Reasons:
	 * - opens new command line prompt
	 * - the child process is guaranteed not to be the process group leader
	 *   necessary for setsid.
	 */

	switch (fork()) {
	case -1:  /* error */
		eprint("Fork() failed, errno=%d [%s]\n",
		       errno, strerror(errno));
		return -1;
	case 0:   /* child */
		break;
	default:  /* parent */
		(void)close(pipefds[1]);
		if (read(pipefds[0], &child_initialized, sizeof(child_initialized)) !=
		    sizeof(child_initialized)) {
			eprint("Couldn't read from PIPE, errno=%d [%s]\n", errno, strerror(errno));
			(void)close(pipefds[0]);
			_exit(EXIT_FAILURE);
		}
		(void)close(pipefds[0]);
		if (!child_initialized)
			_exit(EXIT_FAILURE);
		_exit(0);
	}

	/* Executed within the child context only */
	(void)close(pipefds[0]);
	*startup_pipe = pipefds[1];

	if (chdir("/") != 0) {
		eprint("Chdir('/') failed, errno=%d [%s]\n",
		       errno, strerror(errno));
		return -1;
	}

	/* start new session */
	if (setsid() == -1) {
		eprint("Setsid() failed, errno=%d [%s]\n",
		       errno, strerror(errno));
		return -1;
	}

	/* clear umask so that socket has right default permission */
	umask(0007);

	/* make stdin, stdout and stderr use /dev/null */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		eprint("Could not open /dev/null, errno=%d [%s]\n",
		       errno, strerror(errno));
		return -1;
	}
	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	close(fd);

	daemonized = 1;

	/* make pid file, fails if the file exists */
	f = fopen(PID_FILE, "w+x");
	if (!f) {
		eprint("Couldn't create pid file '%s', errno=%d [%s]\n",
		       PID_FILE, errno, strerror(errno));
		return -1;
	}
	fprintf(f, "%lu", (unsigned long)getpid());
	fflush(f);
	fclose(f);
	chmod(PID_FILE, 0644);

	return 0;
}

static void remove_sock(void)
{
	remove(SOCKET_FILE);
}

static int check_pidfile(void)
{
	unsigned long pid;
	FILE *f;

	f = fopen(PID_FILE, "r");
	if (!f) {
		if (errno == ENOENT) {
			/* pid file does not exit, pid file check is ok */
			return 0;
		}
		/* unknown errno, pid file check is not ok */
		eprint("Unknown error on pid file check '%s', errno=%d [%s]\n",
		       PID_FILE, errno, strerror(errno));
		return -1;
	}

	/* pid file could be opened, scan pid in there */
	if (fscanf(f, "%lu", &pid) != 1) {
		/*
		 * invalid, maybe a leftover from a previous run
		 * remove and return pid file check ok
		 */
		fclose(f);
		remove(PID_FILE);
		return 0;
	}
	fclose(f);

	/* check if this process is still running */
	if (kill(pid, 0) != 0) {
		/*
		 * failure, assume this means there is no such pid running
		 * remove pid file and return pid file check ok
		 */
		remove(PID_FILE);
		return 0;
	}

	/*
	 * looks like there is another cpacfstatsd running
	 * return with pid file check failure
	 */
	eprint("Looks like there is another cpacfstatsd (pid=%lu) running\n",
	       pid);
	eprint("Please check and maybe remove stale pid file '%s'\n",
	       PID_FILE);

	return -1;
}

static void remove_pidfile(void)
{
	remove(PID_FILE);
}

void signalhandler(int sig)
{
	perf_stop();
	stopsig = sig;
}

int eprint(const char *format, ...)
{
	char buf[512];
	va_list vargs;
	int i, n;

	i = snprintf(buf, sizeof(buf), "%s: ", name);
	va_start(vargs, format);
	n = vsnprintf(buf+i, sizeof(buf)-i, format, vargs);
	va_end(vargs);

	if (n > 0) {
		if (daemonized)
			syslog(LOG_WARNING, "%s", buf);
		else
			fputs(buf, stderr);
	}

	return n;
}

/*
 * returns -1 on error
 * returns X where X is the found counters in dir
 *
 * the supplied array supported_counters[] is filled in this function with the
 * available PAI counters found in SYSFS_PAI_COUNTER
 */
static void supported_functions(unsigned int supported_counters[])
{
	const char *dir = SYSFS_PAI_COUNTER;
	struct dirent *dp = NULL;
	char filepath[PATH_MAX];
	unsigned int num;
	DIR *dfd = NULL;

	dfd = opendir(dir);
	if (dfd == NULL)
		return;

	while ((dp = readdir(dfd)) != NULL) {
		if ((strcmp(dp->d_name, ".") != 0) &&
		    (strcmp(dp->d_name, "..") != 0)) {
			snprintf(filepath, sizeof(filepath), "%s%s", dir, dp->d_name);
			if (util_file_read_va(filepath, "event=0x10%x", &num) != 1)
				continue;
			if (num > 0 && num <= MAX_NUM_PAI)
				supported_counters[num - 1] = 1;
		}
	}

	closedir(dfd);
	return;
}

int main(int argc, char *argv[])
{
	int rc, sfd, foreground = 0, startup_pipe = -1, initialized = 0;
	unsigned int supported_counters[MAX_NUM_PAI] = { 0 };
	struct sigaction act;

	if (argc > 1) {
		int opt, idx = 0;
		const struct option long_opts[] = {
			{ "help", 0, NULL, 'h' },
			{ "foreground", 0, NULL, 'f' },
			{ "version", 0, NULL, 'v' },
			{ NULL, 0, NULL, 0 } };
		while (1) {
			opt = getopt_long(argc, argv,
					  "hfv", long_opts, &idx);
			if (opt == -1)
				break; /* no more arguments */
			switch (opt) {
			case 'h':
				printf(usage, name);
				return 0;
			case 'f':
				foreground = 1;
				break;
			case 'v':
				printf("%s: Linux on System z CPACF Crypto Activity Counters Daemon\n"
				       "Version %s\n%s\n",
				       name, RELEASE_STRING, COPYRIGHT);
				return 0;
			default:
				printf("%s: Invalid argument, try -h or --help for more information\n",
					name);
				return EXIT_FAILURE;
			}
		}
	}

	if (check_pidfile() != 0) {
		eprint("Stalled pid file or daemon already running, terminating\n");
		return EXIT_FAILURE;
	}

	if (!foreground) {
		if (become_daemon(&startup_pipe) != 0) {
			eprint("Couldn't daemonize\n");
			goto error;
		}
	}

	supported_functions(supported_counters);

	if (perf_init(supported_counters) != 0) {
		eprint("Couldn't initialize perf lib\n");
		goto error;
	}
	atexit(perf_close);

	sfd = open_socket(SERVER);
	if (sfd < 0) {
		eprint("Couldn't initialize server socket\n");
		goto error;
	}
	atexit(remove_sock);

	memset(&act, 0, sizeof(act));
	act.sa_handler = signalhandler;
	act.sa_flags = 0;
	if (sigaction(SIGINT, &act, 0) != 0) {
		eprint("Couldn't establish signal handler for SIGINT, errno=%d [%s]\n",
		       errno, strerror(errno));
		goto error;
	}
	if (sigaction(SIGTERM, &act, 0) != 0) {
		eprint("Couldn't establish signal handler for SIGTERM, errno=%d [%s]\n",
		       errno, strerror(errno));
		goto error;
	}
	/* Ignore SIGPIPE such that we see EPIPE as return from write. */
	signal(SIGPIPE, SIG_IGN);

	eprint("Running\n");
	initialized = 1;
	/* `startup_pipe` has been initialized, so we know we are
	 * running in daemon mode. Let's write to the pipe so that the
	 * parent knows that the initialization is complete.
	 */
	if (startup_pipe != -1 &&
	    write(startup_pipe, &initialized, sizeof(initialized)) != sizeof(initialized))
		goto error;
	(void)close(startup_pipe);
	startup_pipe = -1;

	while (!stopsig) {
		enum ctr_e ctr;
		enum cmd_e cmd;
		int s;

		s = accept(sfd, NULL, NULL);
		if (s < 0) {
			if (errno == EINTR)
				continue;
			eprint("Accept() failure, errno=%d [%s]\n",
			       errno, strerror(errno));
			goto error;
		}

		rc = recv_query(s, &ctr, &cmd);
		if (rc != 0) {
			eprint("Recv_query() failed, ignoring\n");
			close(s);
			continue;
		}

		if (cmd == ENABLE)
			rc = do_enable(s, ctr, supported_counters);
		else if (cmd == DISABLE)
			rc = do_disable(s, ctr, supported_counters);
		else if (cmd == RESET)
			rc = do_reset(s, ctr, supported_counters);
		else if (cmd == PRINT)
			rc = do_print(s, ctr, supported_counters);
		else {
			eprint("Received unknown command %d, ignoring\n",
			       (int) cmd);
			close(s);
			continue;
		}
	}

	if (stopsig == SIGTERM)
		eprint("Caught signal SIGTERM, terminating...\n");
	else if (stopsig == SIGINT)
		eprint("Caught signal SIGINT, terminating...\n");
	else
		eprint("Caught signal %d, terminating...\n", stopsig);
	remove_pidfile();

	return 0;

error:
	if (startup_pipe != -1) {
		/* Notify the parent process that there was an error */
		if (write(startup_pipe, &initialized, sizeof(initialized)) != sizeof(initialized))
			eprint("Couldn't write to PIPE, errno=%d [%s]\n", errno, strerror(errno));
		(void)close(startup_pipe);
	}

	return EXIT_FAILURE;
}
