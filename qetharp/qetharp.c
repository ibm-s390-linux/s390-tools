/*
 * qetharp - Read and flush the ARP cache on OSA Express network cards
 * 
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "qetharp.h"

#ifndef QETH_QARP_WITH_IPV6
#define IP_TYPE() ipaddr_type
#define QETH_QARP_WITH_IPV6 0x4000
#define QETH_QARP_MEDIASPECIFIC_BYTES 32
enum qeth_arp_ipaddrtype {
	QETHARP_IP_ADDR_V4 = 1,
	QETHARP_IP_ADDR_V6 = 2,
};
struct qeth_arp_entrytype {
	__u8 mac;
	__u8 ip;
};
struct qeth_arp_qi_entry5_ipv6 {
	__u8 media_specific[QETH_QARP_MEDIASPECIFIC_BYTES];
	struct qeth_arp_entrytype type;
	__u8 ipaddr[16];
} __attribute__((packed));
struct qeth_arp_qi_entry5_short_ipv6 {
	struct qeth_arp_entrytype type;
	__u8 ipaddr[16];
} __attribute__((packed));
struct qeth_arp_qi_entry7_ipv6 {
	__u8 media_specific[QETH_QARP_MEDIASPECIFIC_BYTES];
	struct qeth_arp_entrytype type;
	__u8 macaddr[6];
	__u8 ipaddr[16];
} __attribute__((packed));
struct qeth_arp_qi_entry7_short_ipv6 {
	struct qeth_arp_entrytype type;
	__u8 macaddr[6];
	__u8 ipaddr[16];
} __attribute__((packed));
#else
#define IP_TYPE() type.ip
#endif
/*****************************************************
 *            Function implementation                *
 *****************************************************/

static inline void
qeth_hex_dump(unsigned char *buf, int len)
{
	int i;
	
	for (i = 0; i < len; i++) {
		if (i && !(i % 16))
			printf("\n");
		printf("%02x ", *(buf + i));
	}
	printf("\n");
}

static void
show_header() 
{
	printf("%-40.40s%-20.20s%-10.10s%-16.16s\n",
	       "Address","HWaddress","HWType","Iface");
}

static int ip_to_str(char *tmpbuff, __u8 ipaddr_type, __u8 *ip)
{
	int rc;
	if (ipaddr_type == IP_VERSION_4) {
		sprintf(tmpbuff,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
	} else if (ipaddr_type == IP_VERSION_6) {
		sprintf(tmpbuff, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
			":%02x%02x:%02x%02x:%02x%02x",
			ip[0],ip[1],ip[2],ip[3],ip[4],
			ip[5],ip[6],ip[7],ip[8],ip[9],
			ip[10],ip[11],ip[12],ip[13],ip[14],
			ip[15]);
	} else {
		rc = 1;
		goto out;
	}
	rc = 0;

out:
	return rc;
}


static int lookup_hostname(const char * addr, char *hostname, size_t buflen)
{
	struct addrinfo *addrinfo;
	int rc;

	if (getaddrinfo(addr, NULL, NULL, &addrinfo)) {
		rc = 1;
	} else {
		if (getnameinfo(addrinfo->ai_addr,
				addrinfo->ai_addrlen,
				hostname,
				buflen, NULL, 0, 0)) {
			rc = 1;
		} else {
			rc = 0;
		}
		freeaddrinfo(addrinfo);
	}
	return rc;
}

static
void show_entry5(__u8 ipaddr_type, __u8 *ip, struct option_info *opin)
{
	char tmpbuff[50];

	if (ip_to_str(tmpbuff, ipaddr_type, ip)) {
	        printf("unknown entry format\n");
		goto out;
	}

	if (opin->compact_output == OPTION_INFO_COMPACT_OUTPUT) {
		printf("%s\n", tmpbuff);
	} else {
		char *name;
		char fqhn[NI_MAXHOST];

		if (opin->host_resolution) {
			name = tmpbuff;
		} else {
			if (lookup_hostname(tmpbuff, fqhn, sizeof(fqhn))) {
				name = tmpbuff;
			} else {
				name = fqhn;
			}
		}
		printf("%-40.40s%-20.20s%-10.10s%-16.16s\n", name, "", "hiper",
			opin->dev_name);
	}

out:
	return;
}

static int
get_arp_from_hipersockets(struct qeth_arp_query_user_data *udata,
			  struct option_info *opin) 
{
	struct qeth_arp_qi_entry5 *entry;
	struct qeth_arp_qi_entry5_short *entry_s;
	__u32 bytes_done;
	int i;

        bytes_done = 6;
	if (udata->mask_bits & QETH_QARP_STRIP_ENTRIES) {
		for (i = 0; i < (int)udata->u.no_entries; i++) {
			entry_s = (struct qeth_arp_qi_entry5_short *)
				(((char *)udata) + bytes_done);
			show_entry5(entry_s->IP_TYPE(), entry_s->ipaddr,opin);
			bytes_done += entry_s->IP_TYPE() == IP_VERSION_4 ?
				sizeof(struct qeth_arp_qi_entry5_short) :
				sizeof(struct qeth_arp_qi_entry5_short_ipv6);
		}
	} else {
		for (i = 0; i < (int)udata->u.no_entries; i++) {
			entry = (struct qeth_arp_qi_entry5 *)
				(((char *)udata) + 6 + i * sizeof(*entry));
			show_entry5(entry->IP_TYPE(), entry->ipaddr, opin);
		}
	}
	return 0;
}

static
void show_entry7(__u8 ipaddr_type, __u8 *ip, __u8 *mac,
		 unsigned short flags, struct option_info *opin)
{
	char tmpbuff[50];

	if (ip_to_str(tmpbuff, ipaddr_type, ip)) {
	        printf("unknown entry format\n");
		goto out;
	}

	if (opin->compact_output == OPTION_INFO_COMPACT_OUTPUT) {
		printf("%s\n", tmpbuff);
	} else {
		char *name;
		char macstrbuf[20];
		char fqhn[NI_MAXHOST];

		if (opin->host_resolution) {
			name = tmpbuff;
		} else {
			if (lookup_hostname(tmpbuff, fqhn, sizeof(fqhn))) {
				name = tmpbuff;
			} else {
				name = fqhn;
			}
		}
		sprintf(macstrbuf,"%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

		printf("%-40.40s%-20.20s%-10.10s%-16.16s\n", name, macstrbuf,
			(flags==OSACARD_FLAGS)? "ether":
			(flags==OSA_TR_FLAGS)? "tr":"n/a",
			opin->dev_name);
	}
out:
	return;
}

static int
get_arp_from_osacard(struct qeth_arp_query_user_data *udata,
		     unsigned short flags, struct option_info *opin) 
{
	struct qeth_arp_qi_entry7 *entry;
	struct qeth_arp_qi_entry7_short *entry_s;
	size_t bytes_done = 0;
	int i;

	if (udata->mask_bits & QETH_QARP_STRIP_ENTRIES) {
		for (i = 0; i < (int)udata->u.no_entries; i++){
			entry_s = (struct qeth_arp_qi_entry7_short *)
				(((char *)udata) + 6 + bytes_done);
			show_entry7(entry_s->IP_TYPE(), entry_s->ipaddr,
				    entry_s->macaddr, flags, opin);
			bytes_done += entry_s->IP_TYPE() == IP_VERSION_4 ?
				sizeof(struct qeth_arp_qi_entry7_short) :
				sizeof(struct qeth_arp_qi_entry7_short_ipv6);
		}
	} else {
		for (i = 0; i < (int)udata->u.no_entries; i++){ 	
			entry = (struct qeth_arp_qi_entry7 *)
				(((char *)udata) + 6 + bytes_done);
			show_entry7(entry->IP_TYPE(), entry->ipaddr,
				    entry->macaddr, flags, opin);
			bytes_done += entry->IP_TYPE() == IP_VERSION_4 ?
				sizeof(struct qeth_arp_qi_entry7_short) :
				sizeof(struct qeth_arp_qi_entry7_short_ipv6);
		}
	}
	return 0;
}

static int
qetharp_purge(struct option_info *opin)
{
	int sd;
 	struct ifreq ifr;

	if (!opin->dev_name) {
		printf("\nError: no interface specified!\n");
		return 1;
	}
		
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket failed: %m\n");
		return 1;
	}
	strcpy(ifr.ifr_name, opin->dev_name);
	if (ioctl(sd, SIOC_QETH_ARP_FLUSH_CACHE, &ifr) < 0) {
		close(sd);
		perror("\nUnsuccessful");
		return 1;
	}

	return 0;
}

static int
qetharp_add(struct option_info *opin)
{
	int sd;
 	struct ifreq ifr;
	struct qeth_arp_cache_entry arp_entry;
	unsigned int i1,i2,i3,i4,i5,i6,r;

	memset(&arp_entry, 0, sizeof(struct qeth_arp_cache_entry));
	if (!opin->dev_name) {
		printf("\nError: no interface specified!\n");
		return 1;
	}
	if (!opin->ip_addr) {
		printf("\nError: no ip address specified!\n");
		return 1;
	}
	r=sscanf(opin->ip_addr,"%u.%u.%u.%u",&i1,&i2,&i3,&i4);
	if ( (r!=4) || (i1>255) || (i2>255) || (i3>255) || (i4>255) ) {
		printf("\nError: invalid ip address specified!\n");
		return 1;
	}
	arp_entry.ipaddr[0]=i1;
	arp_entry.ipaddr[1]=i2;
	arp_entry.ipaddr[2]=i3;
	arp_entry.ipaddr[3]=i4;
	
	if (!opin->mac_addr) {
		printf("\nError: no MAC address specified!\n");
		return 1;
	}
	r=sscanf(opin->mac_addr,"%x:%x:%x:%x:%x:%x",&i1,&i2,&i3,&i4,&i5,&i6);
	if ( (r!=6) || (i1>255) || (i2>255) || (i3>255) || 
	     (i4>255) || (i5>255) || (i6>255) ) {
		printf("\nError: invalid MAC address specified!\n");
		return 1;
	}
	arp_entry.macaddr[0]=i1;
	arp_entry.macaddr[1]=i2;
	arp_entry.macaddr[2]=i3;
	arp_entry.macaddr[3]=i4;
	arp_entry.macaddr[4]=i5;
	arp_entry.macaddr[5]=i6;

	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket failed: %m\n");
		return 1;
	}
	strcpy(ifr.ifr_name, opin->dev_name);
	ifr.ifr_ifru.ifru_data = (void*)&arp_entry;

	if (ioctl(sd, SIOC_QETH_ARP_ADD_ENTRY, &ifr) < 0) {
		close(sd);
		perror("\nUnsuccessful");
		return 1;
	}

	return 0;
}

static int
qetharp_delete(struct option_info *opin)
{
	int sd;
 	struct ifreq ifr;
	struct qeth_arp_cache_entry arp_entry;
	unsigned int i1,i2,i3,i4,r;

	memset(&arp_entry,0,sizeof(struct qeth_arp_cache_entry));
	if (!opin->dev_name) {
		printf("\nError: no interface specified!\n");
		return 1;
	}
	if (!opin->ip_addr) {
		printf("\nError: no ip address specified!\n");
		return 1;
	}
	r=sscanf(opin->ip_addr,"%u.%u.%u.%u",&i1,&i2,&i3,&i4);
	if ( (r!=4) || (i1>255) || (i2>255) || (i3>255) || (i4>255) ) {
		printf("\nError: invalid ip address specified!\n");
		return 1;
	}
	arp_entry.ipaddr[0]=i1;
	arp_entry.ipaddr[1]=i2;
	arp_entry.ipaddr[2]=i3;
	arp_entry.ipaddr[3]=i4;
	
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket failed: %m\n");
		return 1;
	}
	strcpy(ifr.ifr_name, opin->dev_name);
	ifr.ifr_ifru.ifru_data = (void*)&arp_entry;

	if (ioctl(sd, SIOC_QETH_ARP_REMOVE_ENTRY, &ifr) < 0) {
		close(sd);
		perror("\nUnsuccessful");
		return 1;
	}

	return 0;
}

static int
qetharp_query(struct option_info *opin)
{
	int sd;
 	struct ifreq ifr;
	struct qeth_arp_query_user_data *udata;
	int memsize,result;
	unsigned short mask_bits;

	if (!opin->dev_name) {
		printf("\nError: no interface specified!\n");
		return 1;
	}
		
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket failed: %m\n");
		return 1;
	}
	strcpy(ifr.ifr_name, opin->dev_name);
	memsize = QETH_QARP_USER_DATA_SIZE;
	udata = malloc(QETH_QARP_USER_DATA_SIZE);
	memcpy(&udata->u.data_len, &memsize, sizeof(int));
	udata->mask_bits = QETH_QARP_STRIP_ENTRIES;
	if (opin->ipv6) {
		udata->mask_bits |= QETH_QARP_WITH_IPV6;
	}
	ifr.ifr_ifru.ifru_data = (char *) udata;
	if (ioctl(sd, SIOC_QETH_ARP_QUERY_INFO, &ifr) < 0) {
		close(sd);
		perror("\nUnsuccessful");
		return 1;
	}
	if (opin->compact_output!=OPTION_INFO_COMPACT_OUTPUT) {
		show_header();
	}
	if (!udata->u.no_entries) {
		/* rational: mask_bits are not defined in that case */
		return 0;
	}
	mask_bits = udata->mask_bits & QETH_QARP_REQUEST_MASK;
	if (mask_bits == HIPERSOCKET_FLAGS) 
	        result = get_arp_from_hipersockets(udata, opin);
	else if (mask_bits == OSACARD_FLAGS)
		result = get_arp_from_osacard(udata, mask_bits, opin);
	else if (mask_bits == OSA_TR_FLAGS)
		result = get_arp_from_osacard(udata, mask_bits, opin);
	else {
		perror("\nReceived entries with invalid format");
		return 1;
	}
	free(udata);

	return result;
}

static void
qetharp_usage(void)
{
	printf("qetharp [-[nc6]q interface]|[-p interface]|\n" \
	       "\t\t[-a interface -i ip-addr -m MAC-addr]|\n" \
	       "\t\t[-d interface -i ip-addr] [-h] [-v ]\n\n");
	printf("where:\n" \
	       "\tq: prints ARP entries found on the card\n" \
	       "\tn: in conjunction with the -q option it shows\n" \
	       "\t\tnumerical addresses instead of trying to\n" \
	       "\t\tresolve IP addresses to host names.\n" \
	       "\tc: in conjunction with the -q option it shows\n" \
	       "\t\tonly numerical addresses without any\n" \
	       "\t\tother information.\n" \
	       "\t6: in conjunction with the -q option it shows\n" \
	       "\t\tIPv6 related entries, if applicable\n" \
	       "\tp: flushes the ARP table of the card\n" \
	       "\ta: add static ARP entry\n" \
	       "\td: delete static ARP entry\n" \
	       "\tv: prints version information\n"
	       "\th: prints this usage information\n");
}

static int
qetharp_parse_info(struct option_info *opin)
{
	if (opin->dev_name && (strlen(opin->dev_name) >= IFNAMSIZ)) {
		printf("\nError: interface name too long\n");
		return 1;
	}
	if ((opin->purge_flag+opin->query_flag+
	    opin->add_flag+opin->delete_flag)==0) {
		qetharp_usage();
		return 1;
	}
	if ((opin->purge_flag+opin->query_flag+
	    opin->add_flag+opin->delete_flag)!=1) {
		printf("\nUse only one of the options '-a', " \
		       "'-d', '-p' and 'q' per call.\n");
		return 1;
	}
	if (opin->purge_flag &&
	    (opin->query_flag || opin->host_resolution)) {
		printf("\nError in using '-p' option:\n" \
			"\tYou can not use '-p' option in conjunction with " \
			"'-q' or '-n'.\n");
		return 1;
	}
	if (opin->purge_flag) {
		return qetharp_purge(opin);
	}
	if ((opin->host_resolution) && 
	    !(opin->query_flag)) {
		printf("\nError in using '-n' option:\n" \
		       "\t'-q' option missing!\n");
		return 1;
	}
	if ((opin->ipv6) &&
	    !(opin->query_flag)) {
		printf("\nError in using '-6' option:\n" \
		       "\t'-q' option missing!\n");
		return 1;
	}
	if (opin->query_flag) {
		return qetharp_query(opin);
	}
	if (opin->add_flag) {
		if ((!opin->ip_flag)||(!opin->mac_flag)) {
			printf("\nError in using '-a' option:\n" \
			       "\t'-i' or '-m' option missing!\n");
			return 1;
		}
		return qetharp_add(opin);
	}
	if (opin->delete_flag) {
		if (!opin->ip_flag) {
			printf("\nError in using '-d' option:\n" \
			       "\t'-i' option missing!\n");
			return 1;
		}
		return qetharp_delete(opin);
	}
	return 0;
}

 
int main(int argc, char **argv) 
{
	
	int index,c,result;
	struct option_info info;

	result=0;

	memset(&info, 0, sizeof(info));
	c = getopt_long(argc, argv, QETHARP_GETOPT_STRING,
				qetharp_options, &index);
	if (c == -1 ) {
	        qetharp_usage();
		exit(0);
	}
	while (c != -1) {
		switch (c) {
		case 'h':
		        qetharp_usage();
			exit(0);
		case 'v':
			printf("qetharp: version %s\n",
				RELEASE_STRING);
			printf( "%s\n",COPYRIGHT );
			exit(0);
		case 'q':
			info.dev_name = optarg;
			info.query_flag =  OPTION_INFO_QUERY;
			break;
		case 'n':
			info.host_resolution =  OPTION_INFO_NO_RESOLUTION;
			break;
		case '6':
			info.ipv6 = OPTION_INFO_IPV6;
			break;
		case 'p':
			info.dev_name = optarg;
			info.purge_flag = OPTION_INFO_PURGE;
			break;
		case 'c':
			info.compact_output = OPTION_INFO_COMPACT_OUTPUT;
			break;
		case 'a':
			info.dev_name = optarg;
			info.add_flag = OPTION_INFO_ADD;
			break;
		case 'd':
			info.dev_name = optarg;
			info.delete_flag = OPTION_INFO_DELETE;
			break;
		case 'i':
			info.ip_addr = optarg;
			info.ip_flag = OPTION_INFO_IP;
			break;
		case 'm':
			info.mac_addr = optarg;
			info.mac_flag = OPTION_INFO_MAC;
			break;
		default:
			fprintf(stderr, "Try 'qetharp --help' for more"
					" information.\n");
			exit(1);
		}
		c = getopt_long(argc, argv,QETHARP_GETOPT_STRING,
				qetharp_options,&index);
	}
	result = qetharp_parse_info(&info);
	return result;
}

