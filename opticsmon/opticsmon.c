/*
 * opticsmon - Report optics monitoring data to firmware
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <sys/timerfd.h>
#include <time.h>
#include <linux/if.h>

#include "lib/util_list.h"
#include "lib/pci_list.h"
#include "lib/util_prg.h"
#include "lib/util_opt.h"
#include "lib/util_fmt.h"
#include "lib/util_libc.h"

#include <openssl/evp.h>

#include "optics_info.h"
#include "optics_sclp.h"
#include "ethtool.h"
#include "link_mon.h"

#define API_LEVEL 1

struct options {
	bool monitor;
	bool report;
	bool module_info;
	bool quiet;

	uint32_t interval_seconds;
};

struct opticsmon_ctx {
	struct options opts;
	struct ethtool_nl_ctx ethtool_ctx;
	struct link_mon_nl_ctx lctx;
	struct util_list *zpci_list;
};

static const struct util_prg prg = {
	.desc = "Use opticsmon to monitor the health of the optical modules\n"
		"of directly attached PCI based NICs",
	.copyright_vec = { {
				   .owner = "IBM Corp.",
				   .pub_first = 2024,
				   .pub_last = 2024,
			   },
			   UTIL_PRG_COPYRIGHT_END }
};

#define OPT_DUMP 128

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPERATION OPTIONS"),
	{
		.option = { "monitor", no_argument, NULL, 'm' },
		.desc = "Run continuously and report on link state changes "
			"collecting optics health data when a change is detected",
	},
	{
		.option = { "send-report", no_argument, NULL, 'r' },
		.desc = "Report the optics health data to the Support Element",
	},
	{
		.option = { "quiet", no_argument, NULL, 'q' },
		.desc = "Be quiet and don't print optics health summary",
	},
	{
		.option = { "module-info", no_argument, NULL, OPT_DUMP },
		.desc = "Include a base64 encoded binary dump of the module's "
			"SFF-8636/8472/8024 standard data for each netdev. "
			"This matches \"ethtool --module-info <netdev> raw on\"",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_SECTION("OPTIONS WITH ARGUMENTS"),
	{
		.option = { "interval", required_argument, NULL, 'i' },
		.argument = "seconds",
		.desc = "Interval in seconds at which to collect monitoring data "
			"in the absence of link state changes. A value larger than "
			"24 hours (86400 seconds) is clamped down to 24 hours.",
	},
	UTIL_OPT_SECTION("GENERAL OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static void parse_cmdline(int argc, char *argv[], struct options *opts)
{
	uint32_t seconds;
	int cmd, ret;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	do {
		cmd = util_opt_getopt_long(argc, argv);

		switch (cmd) {
		case 'm':
			opts->monitor = true;
			break;
		case 'r':
			opts->report = true;
			break;
		case 'q':
			opts->quiet = true;
			break;
		case OPT_DUMP:
			opts->module_info = true;
			break;
		case 'i':
			ret = sscanf(optarg, "%u", &seconds);
			if (ret != 1) {
				fprintf(stderr,
					"Failed to parse interval argument \"%s\" as seconds\n",
					optarg);
				exit(EXIT_FAILURE);
			}
			if (seconds < 86400)
				opts->interval_seconds = seconds;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case -1:
			/* End of options string */
			break;
		}
	} while (cmd != -1);
}

static int module_info_pair(struct optics *oi)
{
	size_t b64_calclen, b64len;
	int rc = EXIT_SUCCESS;
	char *b64;

	b64_calclen = (oi->size / 3) * 4;
	if (oi->size % 3 > 0)
		b64_calclen += 4;

	b64 = util_zalloc(b64_calclen + 1); /* adds NUL byte */
	b64len = EVP_EncodeBlock((unsigned char *)b64, oi->raw, oi->size);
	if (b64len != b64_calclen) {
		fprintf(stderr, "encoding base64 via openssl failed\n");
		rc = EXIT_FAILURE;
		goto out;
	}
	util_fmt_pair(FMT_QUOTE, "module_info", b64);
out:
	free(b64);
	return rc;
}

static void optics_json_print(struct opticsmon_ctx *ctx, struct zpci_netdev *nd, struct optics *oi)
{
	util_fmt_obj_start(FMT_DEFAULT, "netdev");
	util_fmt_pair(FMT_QUOTE, "name", nd->name);
	util_fmt_pair(FMT_QUOTE, "operstate", zpci_operstate_str(nd->operstate));
	util_fmt_obj_start(FMT_DEFAULT, "optics");
	util_fmt_pair(FMT_QUOTE, "type", optics_type_str(optics_type(oi)));
	util_fmt_pair(FMT_QUOTE, "rx_los", optics_los_str(optics_rx_los(oi)));
	util_fmt_pair(FMT_QUOTE, "tx_los", optics_los_str(optics_tx_los(oi)));
	util_fmt_pair(FMT_QUOTE, "tx_fault", optics_los_str(optics_rx_los(oi)));
	if (ctx->opts.module_info)
		module_info_pair(oi);
	util_fmt_obj_end();
	util_fmt_obj_end();
}

static int dump_adapter_data(struct opticsmon_ctx *ctx, struct zpci_dev *zdev)
{
	struct optics **ois;
	int num_ois = 0;
	char *pci_addr;
	int i, rc;

	ois = util_zalloc(sizeof(ois[0]) * zdev->num_netdevs);
	for (i = 0; i < zdev->num_netdevs; i++) {
		rc = ethtool_nl_get_optics(&ctx->ethtool_ctx, zdev->netdevs[i].name, &ois[i]);
		if (rc)
			goto free_ois;
		num_ois++;
	}
	if (!ctx->opts.quiet) {
		util_fmt_obj_start(FMT_DEFAULT, "adapter");
		util_fmt_pair(FMT_QUOTE, "pft", zpci_pft_str(zdev));
		util_fmt_obj_start(FMT_DEFAULT, "ids");
		util_fmt_pair(FMT_QUOTE, "fid", "0x%0x", zdev->fid);
		if (zdev->uid_is_unique)
			util_fmt_pair(FMT_QUOTE, "uid", "0x%0x", zdev->uid);
		pci_addr = zpci_pci_addr(zdev);
		util_fmt_pair(FMT_QUOTE, "pci_address", pci_addr);
		free(pci_addr);
		util_fmt_obj_end();
		util_fmt_obj_start(FMT_LIST, "netdevs");
		for (i = 0; i < zdev->num_netdevs; i++)
			optics_json_print(ctx, &zdev->netdevs[i], ois[i]);
		util_fmt_obj_end(); /* netdevs list */
		util_fmt_obj_end(); /* adapter */
		fflush(stdout);
	}
	if (ctx->opts.report) {
		for (i = 0; i < zdev->num_netdevs; i++) {
			rc = sclp_issue_optics_report(zdev, ois[i]);
			if (rc == -ENOTSUP) {
				fprintf(stderr, "Skipping %s which does not support reporting\n",
					zdev->netdevs[i].name);
			} else if (rc < 0) {
				fprintf(stderr, "Error issuing SCLP for optics data failed: %s\n",
					strerror(-rc));
			}
		}
	}
free_ois:
	for (i = 0; i < num_ois; i++)
		optics_free(ois[i]);
	free(ois);
	return rc;
}

static void zpci_list_reload(struct util_list **zpci_list)
{
	if (*zpci_list)
		zpci_free_dev_list(*zpci_list);
	*zpci_list = zpci_dev_list();
}

static void dump_all_adapter_data(struct opticsmon_ctx *ctx)
{
	struct zpci_dev *zdev;

	zpci_list_reload(&ctx->zpci_list);
	util_list_iterate(ctx->zpci_list, zdev) {
		/* Filter non-NIC devices and VFs */
		if (zpci_is_vf(zdev) || !zdev->num_netdevs)
			continue;
		dump_adapter_data(ctx, zdev);
	}
}

static int oneshot_mode(struct opticsmon_ctx *ctx)
{
	util_fmt_init(stdout, FMT_JSON, FMT_DEFAULT, API_LEVEL);
	if (!ctx->opts.quiet)
		util_fmt_obj_start(FMT_LIST, "adapters");
	dump_all_adapter_data(ctx);
	if (!ctx->opts.quiet)
		util_fmt_obj_end();
	util_fmt_exit();

	return EXIT_SUCCESS;
}

void on_link_change(struct zpci_netdev *netdev, void *arg)
{
	struct opticsmon_ctx *ctx = arg;
	struct zpci_netdev *found_netdev;
	struct zpci_dev *zdev = NULL;
	int reloads = 1;

	do {
		if (ctx->zpci_list) {
			zdev = zpci_find_by_netdev(ctx->zpci_list, netdev->name, &found_netdev);
			if (zdev) {
				/* Skip data collection if operational state is
				 * unchanged
				 */
				if (found_netdev->operstate == netdev->operstate)
					return;
				/* Update operation state for VFs even though
				 * they are skipped just for a consistent view
				 */
				found_netdev->operstate = netdev->operstate;
				/* Only collect optics data for PFs */
				if (!zpci_is_vf(zdev))
					dump_adapter_data(ctx, zdev);
				return;
			}
		}
		/* Could be uninitalized list or a new device, retry after reload  */
		zpci_list_reload(&ctx->zpci_list);
		reloads--;
	} while (reloads > 0);
}

#define MAX_EVENTS 8

static int monitor_wait_loop(struct opticsmon_ctx *ctx, int sigfd, int timerfd)
{
	struct epoll_event events[MAX_EVENTS];
	struct signalfd_siginfo fdsi;
	int i, nlfd, epfd, nfds;
	struct epoll_event ev;
	uint64_t expirations;
	ssize_t sread;

	epfd = epoll_create1(EPOLL_CLOEXEC);

	ev.events = EPOLLIN;
	ev.data.fd = sigfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev) == -1)
		return -EIO;

	ev.events = EPOLLIN;
	ev.data.fd = timerfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, timerfd, &ev) == -1)
		return -EIO;

	nlfd = link_mon_nl_waitfd_getfd(&ctx->lctx);
	ev.events = EPOLLIN;
	ev.data.fd = nlfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, nlfd, &ev) == -1)
		return -EIO;

	while (1) {
		nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
		if (nfds < 0)
			return nfds;
		for (i = 0; i < nfds; i++) {
			/* signal fd */
			if (events[i].data.fd == sigfd) {
				sread = read(sigfd, &fdsi, sizeof(fdsi));
				if (sread != sizeof(fdsi))
					return -EIO;
				switch (fdsi.ssi_signo) {
				case SIGINT:
				case SIGTERM:
				case SIGQUIT:
					return 0;
				/* Unexpected signal */
				default:
					return -EIO;
				}
				/* timer fd */
			} else if (events[i].data.fd == timerfd) {
				sread = read(timerfd, &expirations, sizeof(uint64_t));
				if (sread != sizeof(uint64_t))
					return -EIO;
				if (!expirations)
					continue;
				dump_all_adapter_data(ctx);
				/* netlink fd */
			} else if (events[i].data.fd == nlfd) {
				link_mon_nl_waitfd_read(&ctx->lctx);
			}
		}
	}
	return 0;
}

static int monitor_mode(struct opticsmon_ctx *ctx)
{
	struct itimerspec timerspec;
	int sigfd, timerfd, ret;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
		return -EIO;

	sigfd = signalfd(-1, &mask, 0);
	if (sigfd == -1) {
		fprintf(stderr, "Failed to create signalfd\n");
		return -EIO;
	}

	timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timerfd == -1) {
		fprintf(stderr, "Failed to create timerfd\n");
		ret = -EIO;
		goto close_signalfd;
	}

	/* Set initial expiration to 1 ns so we gather optics data at startup */
	timerspec.it_value.tv_sec = 0;
	timerspec.it_value.tv_nsec = 1;
	timerspec.it_interval.tv_sec = ctx->opts.interval_seconds;
	timerspec.it_interval.tv_nsec = 0;
	ret = timerfd_settime(timerfd, 0, &timerspec, NULL);
	if (ret == -1) {
		fprintf(stderr, "Failed to arm timer\n");
		goto close_timerfd;
	}

	util_fmt_init(stdout, FMT_JSONSEQ, FMT_DEFAULT, API_LEVEL);
	ret = link_mon_nl_waitfd_create(&ctx->lctx, on_link_change, ctx);
	if (ret) {
		fprintf(stderr, "Failed to create link monitoring socket\n");
		goto close_timerfd;
	}

	monitor_wait_loop(ctx, sigfd, timerfd);

	link_mon_nl_waitfd_destroy(&ctx->lctx);
	util_fmt_exit();
close_signalfd:
	close(sigfd);
close_timerfd:
	close(timerfd);
	return ret;
}

int main(int argc, char **argv)
{
	struct opticsmon_ctx ctx = { .opts = { .interval_seconds = 86400 } };
	int ret;

	parse_cmdline(argc, argv, &ctx.opts);
	ethtool_nl_connect(&ctx.ethtool_ctx);
	if (ctx.opts.monitor)
		ret = monitor_mode(&ctx);
	else
		ret = oneshot_mode(&ctx);
	ethtool_nl_close(&ctx.ethtool_ctx);

	if (ctx.zpci_list)
		zpci_free_dev_list(ctx.zpci_list);

	return ret;
}
