/*
 * qetharp - Read and flush the ARP cache on OSA Express network cards
 * 
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __QETHARP_H__
#define __QETHARP_H__

#include <linux/if.h>
#include <linux/types.h>

#include "qeth26.h"

#define ifr_name	ifr_ifrn.ifrn_name	/* interface name 	*/
#define ifr_hwaddr	ifr_ifru.ifru_hwaddr	/* MAC address 		*/
#define	ifr_addr	ifr_ifru.ifru_addr	/* address		*/
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-p lnk	*/
#define	ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address	*/
#define	ifr_netmask	ifr_ifru.ifru_netmask	/* interface net mask	*/
#define	ifr_flags	ifr_ifru.ifru_flags	/* flags		*/
#define	ifr_metric	ifr_ifru.ifru_ivalue	/* metric		*/
#define	ifr_mtu		ifr_ifru.ifru_mtu	/* mtu			*/
#define ifr_map		ifr_ifru.ifru_map	/* device map		*/
#define ifr_slave	ifr_ifru.ifru_slave	/* slave device		*/
#define	ifr_data	ifr_ifru.ifru_data	/* for use by interface	*/
#define ifr_ifindex	ifr_ifru.ifru_ivalue	/* interface index	*/
#define ifr_bandwidth	ifr_ifru.ifru_ivalue    /* link bandwidth	*/
#define ifr_qlen	ifr_ifru.ifru_ivalue	/* Queue length 	*/
#define ifr_newname	ifr_ifru.ifru_newname	/* New name		*/


/*****************************************************
 *    Declarations for OSA Relevant Things           *
 *****************************************************/


#define DATA_SIZE 20000
#define HIPERSOCKET_FLAGS  5
#define OSACARD_FLAGS      7
#define OSA_TR_FLAGS       0xf

#define MAC_LENGTH             6
#define IPV4_LENGTH            4
#define IPV6_LENGTH            16
#define IP_VERSION_4           1
#define IP_VERSION_6           2

/*****************************************************
 *            Declarations for parsing options       *
 *****************************************************/

#define QETHARP_GETOPT_STRING "p:q:a:d:i:m:n6chv"

#define OPTION_INFO_QUERY              1
#define OPTION_INFO_PURGE              1
#define OPTION_INFO_NO_RESOLUTION      1
#define OPTION_INFO_COMPACT_OUTPUT     1
#define OPTION_INFO_ADD                1
#define OPTION_INFO_DELETE             1
#define OPTION_INFO_IP                 1
#define OPTION_INFO_MAC                1
#define OPTION_INFO_IPV6               1

/*****************************************************
 *            Declarations for version string        *
 *****************************************************/
#define COPYRIGHT "Copyright IBM Corp. 2003, 2017"

static struct option qetharp_options[]=
{
	{ "query",        1, 0, 'q'},  
	{ "purge",        1, 0, 'p'},
	{ "ipv6",         0, 0, '6'},
	{ "numeric",      0, 0, 'n'},
	{ "compact",      0, 0, 'c'},
	{ "add",          1, 0, 'a'},
	{ "delete",       1, 0, 'd'},
	{ "ip",           1, 0, 'i'},
	{ "mac",          1, 0, 'm'},
	{ "help",         0, 0, 'h'},
	{ "version",      0, 0, 'v'},
	{0,0,0,0}
};

struct option_info {
	int purge_flag;
	int query_flag;
	int host_resolution;
	int compact_output;
	int ipv6;
	int add_flag;
	int delete_flag;
	int ip_flag;
	int mac_flag;
	char *dev_name;
	char *ip_addr;
	char *mac_addr;
};

#endif /* __QETHARP_H__ */
