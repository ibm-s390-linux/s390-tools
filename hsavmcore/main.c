/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "lib/util_log.h"

#include "common.h"
#include "config.h"
#include "cmdline_options.h"
#include "mount.h"
#include "swap.h"
#include "hsa.h"
#include "hsa_mem.h"
#include "hsa_file.h"
#include "proxy.h"
#include "overlay.h"

#define MAX_WAIT_VMCORE_OVERLAY_SECS 5

static int bind_mount_vmcore(const char *src, const char *target,
			     int max_wait_secs)
{
	struct stat st;
	int ret;

	util_log_print(UTIL_LOG_INFO, "Wait %d secs for %s to appear\n",
		       max_wait_secs, src);

	while (max_wait_secs--) {
		if (!stat(src, &st))
			break;
		sleep(1);
	}

	if (stat(src, &st)) {
		util_log_print(UTIL_LOG_ERROR, "Timeout for appearance of %s\n",
			       src);
		return -1;
	}

	ret = bind_mount(src, target);
	if (ret < 0)
		return -1;

	return 0;
}

static void block_all_signals(void)
{
	sigset_t signal_set;

	sigfillset(&signal_set);
	pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
}

static void unblock_all_signals(void)
{
	sigset_t signal_set;

	sigfillset(&signal_set);
	pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL);
}

static void *vmcore_overlay_server(void *arg)
{
	struct vmcore_overlay *vmcore_overlay = (struct vmcore_overlay *)arg;
	int ret;

	util_log_print(UTIL_LOG_DEBUG, "vmcore overlay thread: start\n");

	/* Unblock all signals because vmcore overlay handles them */
	unblock_all_signals();

	/* Blocks until a signal has been received or an error occurred */
	ret = serve_vmcore_overlay(vmcore_overlay);

	util_log_print(UTIL_LOG_DEBUG, "vmcore overlay thread: end (%d)\n",
		       ret);

	return (void *)(long)ret;
}

static void terminate_vmcore_overlay(pthread_t tid)
{
	pthread_kill(tid, SIGINT);
	pthread_join(tid, NULL);
}

static int wait_for_vmcore_overlay(pthread_t tid)
{
	int ret;

	pthread_join(tid, (void **)&ret);

	return ret;
}

int main(int argc, char *argv[])
{
	struct vmcore_overlay *vmcore_overlay;
	struct vmcore_proxy *vmcore_proxy;
	int exit_code = EXIT_SUCCESS, ret;
	struct hsa_reader *hsa_reader;
	pthread_t vmcore_overlay_tid;
	struct config config;

	init_config(&config);

	parse_cmdline_options(argc, argv, &config);

	if (strlen(config.swap)) {
		ret = swap_on(config.swap);
		if (ret < 0) {
			exit_code = EXIT_FAILURE;
			goto done;
		}
	}

	if (config.mount_debugfs) {
		ret = mount_debugfs(DEBUGFS_MOUNT_POINT);
		if (ret < 0) {
			exit_code = EXIT_FAILURE;
			goto swap_off;
		}
	}

	if (config.use_hsa_mem)
		hsa_reader =
			make_hsa_mem_reader(config.zcore_hsa_path,
					    config.vmcore_path, config.hsa_size,
					    config.release_hsa);
	else
		hsa_reader = make_hsa_file_reader(config.zcore_hsa_path,
						  config.vmcore_path,
						  config.workdir_path,
						  config.hsa_size,
						  config.release_hsa);
	if (!hsa_reader) {
		exit_code = EXIT_FAILURE;
		goto unmount_debugfs;
	}

	vmcore_proxy = make_vmcore_proxy(config.vmcore_path, hsa_reader);
	if (!vmcore_proxy) {
		exit_code = EXIT_FAILURE;
		goto destroy_hsa_reader;
	}

	vmcore_overlay = make_vmcore_overlay(vmcore_proxy, OVERLAY_MOUNT_POINT,
					     config.fuse_debug);
	if (!vmcore_overlay) {
		exit_code = EXIT_FAILURE;
		goto destroy_vmcore_proxy;
	}

	/* vmcore overlay thread handles all signals */
	block_all_signals();

	/* Start vmcore overlay thread which handles file system calls */
	ret = pthread_create(&vmcore_overlay_tid, NULL, vmcore_overlay_server,
			     vmcore_overlay);
	if (ret < 0) {
		exit_code = EXIT_FAILURE;
		goto destroy_vmcore_overlay;
	}

	/* Bind mount /proc/vmcore */
	if (config.bind_mount_vmcore) {
		ret = bind_mount_vmcore(OVERLAY_MOUNT_POINT "/" VMCORE_FILE,
					config.bind_mount_vmcore_path,
					MAX_WAIT_VMCORE_OVERLAY_SECS);
		if (ret < 0) {
			terminate_vmcore_overlay(vmcore_overlay_tid);
			exit_code = EXIT_FAILURE;
			goto destroy_vmcore_overlay;
		}
	}

#ifdef HAVE_SYSTEMD
	/* Tell systemd that service is ready now */
	ret = sd_notify(0, "READY=1");
	if (ret <= 0)
		util_log_print(UTIL_LOG_WARN, "Failed to notify systemd (%d)\n",
			       ret);
#endif

	ret = wait_for_vmcore_overlay(vmcore_overlay_tid);
	if (ret < 0)
		exit_code = EXIT_FAILURE;

#ifdef HAVE_SYSTEMD
	/* Tell systemd that service is stopping now */
	ret = sd_notify(0, "STOPPING=1");
	if (ret <= 0)
		util_log_print(UTIL_LOG_WARN, "Failed to notify systemd (%d)\n",
			       ret);
#endif

	unblock_all_signals();

	if (config.bind_mount_vmcore)
		unmount_detach(config.bind_mount_vmcore_path);

destroy_vmcore_overlay:
	destroy_vmcore_overlay(vmcore_overlay);

destroy_vmcore_proxy:
	destroy_vmcore_proxy(vmcore_proxy);

destroy_hsa_reader:
	destroy_hsa_reader(hsa_reader);

unmount_debugfs:
	if (config.mount_debugfs)
		unmount_detach(DEBUGFS_MOUNT_POINT);

swap_off:
	if (strlen(config.swap))
		swap_off(config.swap);

done:
	return exit_code;
}
