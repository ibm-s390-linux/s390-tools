/*
 * qethqoat - Query the OSA address table and display physical and logical
 *            device information
 *
 * Copyright IBM Corp. 2012, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <iconv.h>
#include <net/if.h>
#include <netdb.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "qethqoat.h"

static iconv_t l_iconv_ebcdic_ascii;

static void hex_dump(char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i && !(i % 16))
			printf("\n");
		printf("%02x ", *(buf + i));
	}
	printf("\n");
}

static int mac_is_zero(__u8 *mac)
{
	return !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}

static void ebctoasc(char *inout, size_t len)
{
	iconv(l_iconv_ebcdic_ascii, &inout, &len, &inout, &len);
}

static void print_version()
{
	printf("qethqoat: Tool to query the OSA address table version %s\n",
		RELEASE_STRING);
	printf("Copyright IBM Corp. 2012, 2017\n");
}

static void print_ip4(struct qeth_qoat_des_ip4 *ip4, int hdr)
{
	struct in_addr ia;
	ia.s_addr = ip4->ip4_address;
	if (hdr)
		printf("\n%-39s %s\n%-39s %s\n", "IPv4 Address:",
		"IPA Flags:", "-------------", "----------");
	printf("%-39s 0x%08x\n", inet_ntoa(ia), ip4->flags);
}

static void print_ip4mc(struct qeth_qoat_des_ip4mc *ip4mc, int hdr)
{
	struct in_addr ia;
	ia.s_addr = ip4mc->ip4_mc_address;
	if (hdr)
		printf("\n%-39s %s\n%-39s %s\n", "IPv4 Multicast Address:",
		"MAC Address:", "-----------------------", "------------");
	printf("%-39s %02x:%02x:%02x:%02x:%02x:%02x\n", inet_ntoa(ia),
		ip4mc->ip4_mc_mac[0], ip4mc->ip4_mc_mac[1],
		ip4mc->ip4_mc_mac[2], ip4mc->ip4_mc_mac[3],
		ip4mc->ip4_mc_mac[4], ip4mc->ip4_mc_mac[5]);
}

static void print_ip6(struct qeth_qoat_des_ip6 *ip6, int hdr)
{
	char tmp[128];
	struct in6_addr ia;

	memcpy(&ia.s6_addr, &ip6->ip6_address, 16);
	inet_ntop(AF_INET6, &ia, tmp, 128);
	if (hdr)
		printf("\n%-39s %s\n%-39s %s\n", "IPv6 Address:",
		"IPA Flags:", "-------------", "----------");
	printf("%-39s 0x%08x\n", tmp, ip6->flags);
}

static void print_ip6mc(struct qeth_qoat_des_ip6mc *ip6mc, int hdr)
{
	char tmp[128];
	struct in6_addr ia;

	memcpy(&ia.s6_addr, &ip6mc->ip6_mc_address, 16);
	inet_ntop(AF_INET6, &ia, tmp, 128);
	if (hdr)
		printf("\n%-39s %s\n%-39s %s\n", "IPv6 Multicast Address:",
		"MAC Address:", "-----------------------", "------------");
	printf("%-39s %02x:%02x:%02x:%02x:%02x:%02x\n", tmp,
		ip6mc->ip6_mc_mac[0], ip6mc->ip6_mc_mac[1],
		ip6mc->ip6_mc_mac[2], ip6mc->ip6_mc_mac[3],
		ip6mc->ip6_mc_mac[4], ip6mc->ip6_mc_mac[5]);
}

static void print_vmac(struct qeth_qoat_des_vmac *vmac, int hdr)
{
	if (hdr)
		printf("\nvmac\n----\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
		vmac->vmac[0], vmac->vmac[1], vmac->vmac[2],
		vmac->vmac[3], vmac->vmac[4], vmac->vmac[5]);
}

static void print_vlan(struct qeth_qoat_des_vlan *vlan, int hdr)
{
	if (hdr)
		printf("\nvlan\n----\n");
	printf("%d\n", vlan->vlanid);
}

static void print_gmac(struct qeth_qoat_des_gmac *gmac, int hdr)
{
	if (hdr)
		printf("\ngmac\n----\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
		gmac->gmac[0], gmac->gmac[1], gmac->gmac[2],
		gmac->gmac[3], gmac->gmac[4], gmac->gmac[5]);
}

static void print_aiq(struct qeth_qoat_des_aiq *aiq, int hdr)
{
	if (hdr)
		printf("\naiq routing variables\n---------------------\n");
	printf("0x%x %d %d\n", aiq->protocol, aiq->src_port, aiq->des_port);
}

static void print_physical(struct qeth_qoat_physical *phdr)
{
	char *speed, *media, *jumbo, *osagen, *chpid_type;
	char tmp[128];

	printf("PCHID: 0x%04x\n", phdr->pchid);

	printf("CHPID: 0x%02x\n", phdr->chpid);

	printf("Manufacturer MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		phdr->physical_mac[0], phdr->physical_mac[1],
		phdr->physical_mac[2], phdr->physical_mac[3],
		phdr->physical_mac[4], phdr->physical_mac[5]);

	printf("Configured MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		phdr->logical_mac[0], phdr->logical_mac[1],
		phdr->logical_mac[2], phdr->logical_mac[3],
		phdr->logical_mac[4], phdr->logical_mac[5]);

	printf("Data device sub-channel address: 0x%04x\n",
		phdr->data_sub_channel);

	printf("CULA: 0x%02x\n", phdr->cula);

	printf("Unit address: 0x%02x\n", phdr->unit_address);

	printf("Physical port number: %d\n", phdr->physical_port);

	printf("Number of output queues: %d\n", phdr->nr_out_queues);

	printf("Number of input queues: %d\n", phdr->nr_in_queues);

	printf("Number of active input queues: %d\n",
		phdr->nr_active_in_queues);

	switch (phdr->interface_flags_chpid_type) {
	case OAT_IFF_CHPID_TYPE_OSD:
		chpid_type = "OSD";
		break;
	case OAT_IFF_CHPID_TYPE_OSX:
		chpid_type = "OSX";
		break;
	case OAT_IFF_CHPID_TYPE_OSM:
		chpid_type = "OSM";
		break;
	default:
		sprintf(tmp, "unknown (0x%x)",
			phdr->interface_flags_chpid_type);
		chpid_type = tmp;
	}
	printf("CHPID Type: %s\n", chpid_type);
	printf("Interface flags: 0x%08x\n", phdr->interface_flags);

	switch (phdr->osa_gen) {
	case OAT_OSA_GEN_OSAE3:
		osagen = "OSA-Express3";
		break;
	case OAT_OSA_GEN_OSAE4S:
		osagen = "OSA-Express4S";
		break;
	case OAT_OSA_GEN_OSAE5S:
		osagen = "OSA-Express5S";
		break;
	case OAT_OSA_GEN_OSAE6S:
		osagen = "OSA-Express6S";
		break;
	case OAT_OSA_GEN_OSAE7S:
		osagen = "OSA-Express7S";
		break;
	default:
		sprintf(tmp, "unknown (0x%x)", phdr->osa_gen);
		osagen = tmp;
	}
	printf("OSA Generation: %s\n", osagen);

	switch (phdr->port_speed) {
	case OAT_PORT_SPEED_10mbs_half:
		speed = "10 Mb/s / half duplex";
		break;
	case OAT_PORT_SPEED_10mbs_full:
		speed = "10 Mb/s / full duplex";
		break;
	case OAT_PORT_SPEED_100mbs_half:
		speed = "100 Mb/s / half duplex";
		break;
	case OAT_PORT_SPEED_100mbs_full:
		speed = "100 Mb/s / full duplex";
		break;
	case OAT_PORT_SPEED_1000mbs_half:
		speed = "1000 Mb/s / half duplex";
		break;
	case OAT_PORT_SPEED_1000mbs_full:
		speed = "1000 Mb/s / full duplex";
		break;
	case OAT_PORT_SPEED_NA:
		speed = "NA / NA";
		break;
	case OAT_PORT_SPEED_10gbs_full:
		speed = "10 Gb/s / full duplex";
		break;
	case OAT_PORT_SPEED_25gbs_full:
		speed = "25 Gb/s / full duplex";
		break;
	case OAT_PORT_SPEED_UNKNOWN:
		speed = "unknown / unknown";
		break;
	default:
		sprintf(tmp, "(0x%x) / (0x%x)", phdr->port_speed,
			phdr->port_speed);
		speed = tmp;
	}
	printf("Port speed/mode: %s\n", speed);

	switch (phdr->port_media) {
	case OAT_PORT_MEDIA_COPPER:
		media = "copper";
		break;
	case OAT_PORT_MEDIA_MULTI_MODE:
		media = "multi mode (SR/SX)";
		break;
	case OAT_PORT_MEDIA_SINGLE_MODE:
		media = "single mode (LR/LX)";
		break;
	default:
		sprintf(tmp, "unknown (0x%x)", phdr->port_media);
		media = tmp;
	}
	printf("Port media type: %s\n", media);

	if (phdr->port_media_att & OAT_PORT_MEDIA_ATT_JUMBO)
		jumbo = "yes";
	else
		jumbo = "no";
	printf("Jumbo frames: %s\n", jumbo);

	printf("Firmware: 0x%08x\n", phdr->firmware);

	printf("\n");
}

static void print_logical(struct qeth_qoat_logical *lhdr)
{
	char prouter[] = "primary";
	char srouter[] = "secondary";
	char nrouter[] = "no";
	char *router;

	if (lhdr->ip4_primary_router)
		router = prouter;
	else if (lhdr->ip4_secondary_router)
		router = srouter;
	else
		router = nrouter;
	printf("IPv4 router: %s %s\n", router, lhdr->ip4_active_router ?
		"active" : "");

	if (lhdr->ip6_primary_router)
		router = prouter;
	else if (lhdr->ip6_secondary_router)
		router = srouter;
	else
		router = nrouter;
	printf("IPv6 router: %s %s\n", router, lhdr->ip6_active_router ?
		"active" : "");

	printf("IPv4 vmac router: %s\n", lhdr->ip4_vmac_router ? "yes" : "no");
	printf("IPv6 vmac router: %s\n", lhdr->ip6_vmac_router ? "yes" : "no");

	printf("Connection isolation: %s\n", lhdr->isolation_f ?
		"active" : "not active");

	printf("Connection isolation VEPA: %s\n", lhdr->isolation_vepa ?
		"yes" : "no");

	if (lhdr->ip4_global_vlan_active)
		printf("IPv4 global vlan id: %d\n", lhdr->ip4_global_vlanid);

	if (lhdr->ip4_vmac_active)
		printf("IPv4 l3 vmac: %02x:%02x:%02x:%02x:%02x:%02x"
			" %s generated\n",
			lhdr->ip4_vmac[0], lhdr->ip4_vmac[1],
			lhdr->ip4_vmac[2], lhdr->ip4_vmac[3],
			lhdr->ip4_vmac[4], lhdr->ip4_vmac[4],
			lhdr->ip4_vmac_source ? "OSA" : "Host");

	if (lhdr->ip6_global_vlan_active)
		printf("IPv6 global vlan id: %d\n", lhdr->ip6_global_vlanid);

	if (lhdr->ip6_vmac_active)
		printf("IPv6 l3 vmac: %02x:%02x:%02x:%02x:%02x:%02x"
			" %s generated\n",
			lhdr->ip6_vmac[0], lhdr->ip6_vmac[1],
			lhdr->ip6_vmac[2], lhdr->ip6_vmac[3],
			lhdr->ip6_vmac[4], lhdr->ip6_vmac[4],
			lhdr->ip6_vmac_source ? "OSA" : "Host");


	if (lhdr->port_name_f) {
		ebctoasc((char *)lhdr->port_name, 8);
		printf("Port name: %.8s\n", lhdr->port_name);
	}

	printf("IPv4 assists enabled: 0x%08x\n", lhdr->ip4_ass_enabled);
	printf("IPv6 assists enabled: 0x%08x\n", lhdr->ip6_ass_enabled);
	printf("IPv4 outbound checksum enabled: 0x%08x\n",
		lhdr->out_csum_enabled);
	printf("IPv6 outbound checksum enabled: 0x%08x\n",
		lhdr->out_csum_enabled6);
	printf("IPv4 inbound checksum enabled: 0x%08x\n",
		lhdr->in_csum_enabled);
	printf("IPv6 inbound checksum enabled: 0x%08x\n",
		lhdr->in_csum_enabled6);

	if (lhdr->l2_vlanid)
		printf("L2 vlan id: %d\n", lhdr->l2_vlanid);

	if (!mac_is_zero(lhdr->l2_vmac))
		printf("L2 vmac: %02x:%02x:%02x:%02x:%02x:%02x\n",
			lhdr->l2_vmac[0], lhdr->l2_vmac[1], lhdr->l2_vmac[2],
			lhdr->l2_vmac[3], lhdr->l2_vmac[4], lhdr->l2_vmac[5]);
}

static void parse_descriptor(struct qeth_qoat_hdr *oat_hdr,
	struct qeth_print_hdr *phdr, char *buf, int *processed)
{
	int i;
	char *ptr;

	*processed += oat_hdr->len;
	for (i = 0; i < oat_hdr->type.descriptor.reply_entry_count; i++) {
		ptr = buf + *processed;
		switch (oat_hdr->type.descriptor.des_type) {
		case OAT_DES_TYPE_IP4:
			print_ip4((struct qeth_qoat_des_ip4 *)ptr, phdr->ip4_h);
			phdr->ip4_h = 0;
			break;
		case OAT_DES_TYPE_IP4MC:
			print_ip4mc((struct qeth_qoat_des_ip4mc *)ptr,
				phdr->ip4mc_h);
			phdr->ip4mc_h = 0;
			break;
		case OAT_DES_TYPE_IP6:
			print_ip6((struct qeth_qoat_des_ip6 *)ptr, phdr->ip6_h);
			phdr->ip6_h = 0;
			break;
		case OAT_DES_TYPE_IP6MC:
			print_ip6mc((struct qeth_qoat_des_ip6mc *)ptr,
				phdr->ip6mc_h);
			phdr->ip6mc_h = 0;
			break;
		case OAT_DES_TYPE_VMAC:
			print_vmac((struct qeth_qoat_des_vmac *)ptr,
				phdr->vmac_h);
			phdr->vmac_h = 0;
			break;
		case OAT_DES_TYPE_VLAN:
			print_vlan((struct qeth_qoat_des_vlan *)ptr,
				phdr->vlan_h);
			phdr->vlan_h = 0;
			break;
		case OAT_DES_TYPE_GMAC:
			print_gmac((struct qeth_qoat_des_gmac *)ptr,
				phdr->gmac_h);
			phdr->gmac_h = 0;
			break;
		case OAT_DES_TYPE_AIQ:
			print_aiq((struct qeth_qoat_des_aiq *)ptr,
				phdr->aiq_h);
			phdr->aiq_h = 0;
			break;
		default:
			printf("Unknown descriptor (0x%x)\n",
				oat_hdr->type.descriptor.des_type);
			hex_dump(ptr,
				oat_hdr->type.descriptor.reply_entry_len);
		}
		*processed += oat_hdr->type.descriptor.reply_entry_len;
	}
}

static int print_IPA_error(int rc)
{
	switch (rc) {
	case 0x0:
		break;
	case 0x4:
		fprintf(stderr, "Error: Command not supported\n");
		break;
	case 0x8:
		fprintf(stderr,
			"Error: Invalid/unsupported sub_command/scope\n");
		break;
	case 0x10:
		fprintf(stderr, "Error: No active data connection\n");
		break;
	case 0x14:
		fprintf(stderr, "Error: OSA temporary resource shortage\n");
		break;
	default:
		return 1;
	}
	return 0;
}

static void parse_data(char *buf, int len)
{
	int buffer_processed;
	int frame_processed;
	struct qeth_qoat_ipa_reply *ipa_hdr;
	struct qeth_qoat_hdr *oat_hdr;
	struct qeth_print_hdr phdr = {1, 1, 1, 1, 1, 1, 1, 1};

	buffer_processed = 0;
	do {
		frame_processed = 0;
		ipa_hdr = (struct qeth_qoat_ipa_reply *)
			(buf + buffer_processed);
		if (print_IPA_error(ipa_hdr->rc))
			fprintf(stderr, "OSA reported error code 0x%x\n",
				ipa_hdr->rc);

		if (ipa_hdr->subcommand == 0) {
			printf("Supported Scope mask: 0x%08x\n",
				ipa_hdr->supported_scope);
			printf("Supported Descriptor hdr types: 0x%08x\n",
				ipa_hdr->supported_descriptor);
		}
		frame_processed += sizeof(struct qeth_qoat_ipa_reply);

		if (frame_processed >= ipa_hdr->len)
			break;

		do {
			oat_hdr = (struct qeth_qoat_hdr *)
				(buf + buffer_processed + frame_processed);
			switch (oat_hdr->hdr_type) {
			case OAT_HDR_TYPE_PHYSICAL:
				print_physical(&oat_hdr->type.physical);
				frame_processed += oat_hdr->len;
				break;
			case OAT_HDR_TYPE_LOGICAL:
				print_logical(&oat_hdr->type.logical);
				frame_processed += oat_hdr->len;
				break;
			case OAT_HDR_TYPE_DESCRIPTOR:
				parse_descriptor(oat_hdr, &phdr,
					buf + buffer_processed,
					&frame_processed);
				break;
			default:
				printf("Unknown oat hdr (0x%x)\n",
					oat_hdr->hdr_type);
				return;
			}
		} while (frame_processed < ipa_hdr->len);

		buffer_processed += ipa_hdr->len;
	} while (buffer_processed < len);
}

static void printusage()
{
	fprintf(stdout, "Usage: qethqoat [-h] [-v]\n"
		"       qethqoat [-r] [-s scope] interface\n"
		"       qethqoat -f file\n\n"
		"Use qethqoat to query the OSA address table and display "
		"physical and logical\ndevice information\n\n"
		"-h,  --help     Displays the help information.\n"
		"-r,  --raw      Writes raw data to stdout.\n"
		"-f,  --file     Reads input from file.\n"
		"-v,  --version  Prints the version number.\n"
		"-s,  --scope    Defines the scope of the query.\n"
		"\t  0  Query the level of the OSA address table\n"
		"\t  1  Interface (default)\n"
	);
}

static const struct option qethqoat_opts[] = {
	{ "help",	0, 0, 'h'},
	{ "raw",	0, 0, 'r'},
	{ "file",	1, 0, 'f'},
	{ "version",	0, 0, 'v'},
	{ "scope",	1, 0, 's'},
	{ 0, 0, 0, 0}
};

static const char qethqoat_opts_str[] = "vhrf:s:";

int main(int argc, char **argv)
{
	struct qoat_opts opts;
	int sd, c, rc, index;
	struct ifreq ifr;
	struct qeth_query_oat_data oat_data;
	size_t datalen = 131072;

	opts.raw = 0;
	opts.scope = 1;
	opts.file = NULL;

	while ((c = getopt_long(argc, argv, qethqoat_opts_str, qethqoat_opts,
		&index)) != -1) {
		switch (c) {
		case 'h':
			printusage();
			return 0;
		case 'r':
			opts.raw = 1;
			break;
		case 'f':
			opts.file = optarg;
			break;
		case 's':
			opts.scope = atoi(optarg);
			break;
		case 'v':
			print_version();
			return 0;
		default:
			printusage();
			return 1;
		}
	}

	if (optind == argc) {
		if (!opts.file) {	/* No -f file, interface name needed */
			printusage();
			return 1;
		}
	} else {
		if (opts.file) { /* Have -f file, no interface name allowed */
			printusage();
			return 1;
		}
		opts.ifname = argv[optind];
		if (strlen(opts.ifname) >= IFNAMSIZ) {
			fprintf(stderr, "qethqoat: Interface name too long\n");
			return 1;
		}
	}

	oat_data.command = 0;
	oat_data.ptr = (__u64)(unsigned long)malloc(datalen);
	if (!oat_data.ptr) {
		perror("qethqoat");
		return 1;
	}
	oat_data.buffer_len = datalen;
	oat_data.response_len = 0;

	if (opts.file) {
		FILE *rf = fopen(opts.file, "r");
		if (!rf) {
			perror("qethqoat");
			free((void *)(unsigned long)oat_data.ptr);
			return 1;
		}
		oat_data.response_len = fread(
			(char *)(unsigned long)oat_data.ptr,
			sizeof(char), oat_data.buffer_len, rf);
		fclose(rf);
		goto parse;
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("qethqoat");
		free((void *)(unsigned long)oat_data.ptr);
		return 1;
	}

	strncpy(ifr.ifr_name, opts.ifname, IFNAMSIZ);
	oat_data.command = opts.scope;
	ifr.ifr_ifru.ifru_data = (void *)&oat_data;

	rc = ioctl(sd, SIOC_QETH_QUERY_OAT, &ifr);
	if (rc) {
		if (print_IPA_error(rc))
			perror("qethqoat");
		close(sd);
		free((void *)(unsigned long)oat_data.ptr);
		return 1;
	}
	close(sd);
parse:
	if (opts.raw) {
		fwrite((char *)(unsigned long)oat_data.ptr,
			sizeof(char), oat_data.response_len, stdout);
	} else {
		l_iconv_ebcdic_ascii = iconv_open("ISO-8859-1", "EBCDIC-US");
		if (l_iconv_ebcdic_ascii == (iconv_t) -1) {
			perror("qethqoat");
			free((void *)(unsigned long)oat_data.ptr);
			return 1;
		}
		parse_data((char *)(unsigned long)oat_data.ptr,
			oat_data.response_len);
	}
	free((void *)(unsigned long)oat_data.ptr);
	return 0;
}
