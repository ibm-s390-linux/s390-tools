/*
 * osasnmpd - IBM OSA-Express network card SNMP subagent
 *
 * Defines constants and data structures used by the OSA-E subagent.
 *
 * Copyright IBM Corp. 2002, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#ifndef NETSNMP_DS_APPLICATION_ID
#define NETSNMP_DS_APPLICATION_ID DS_APPLICATION_ID
#endif
#ifndef NETSNMP_DS_AGENT_ROLE
#define NETSNMP_DS_AGENT_ROLE DS_AGENT_ROLE
#endif
#ifndef NETSNMP_DS_AGENT_X_SOCKET
#define NETSNMP_DS_AGENT_X_SOCKET DS_AGENT_X_SOCKET
#endif
/* version number of this agent */

/* default log file - don't change it here, use parameter -l */
#define OSAE_LOGFILE       "/var/log/osasnmpd.log"

/* definitions for subagent to master agent definition */
#define NET_SNMP_PEERNAME  "localhost"
#define NET_SNMP_COMMUNITY "public"

/* need this for OSA Express ioctl's */
#define QETH_PROCFILE "/proc/qeth"
#define QETH_IOC_MAGIC 'Z'
#define QETH_IOCPROC_REGISTER	      	_IOW(QETH_IOC_MAGIC, 1, int)
#define QETH_UPDATE_MIB_SIGNAL		SIGUSR1
#define QETH_QUERY_IPA_DATA           	_IOWR(QETH_IOC_MAGIC, 7, int )
#define QETH_CHECK_OSA_DEVICE		_IOWR(QETH_IOC_MAGIC, 8, int )
#define IFNAME_MAXLEN 16    /* max length for linux interface names */
#define SUFFIX_MAXLEN 13    /* max length of suffix length for net-snmp */
#define MIB_AREA_LEN  25000 /* default size for register MIB data */
#define MAX_GET_DATA  4094  /* maximum GET response data length */
#define GET_AREA_LEN  MAX_GET_DATA + 512  /* size for GET command area length */
#define TIME_BUF_SIZE 128   /* buffer size for date and time string */
#define MAX_OID_STR_LEN   MAX_OID_LEN * 5 /* max OID string size */
/* definitions for 2.6 qeth */
#define QETH_SYSFILE "/sys/bus/ccwgroup/drivers/qeth/notifier_register"
#define SIOC_QETH_ADP_SET_SNMP_CONTROL	(SIOCDEVPRIVATE + 5)
#define SIOC_QETH_GET_CARD_TYPE		(SIOCDEVPRIVATE + 6)

/* some definitions for the linked lists compare and delete functions */
#define OID_FOUND       0
#define OID_NOT_FOUND   1
#define UNEXP_ERROR    -1
#define INDEX_FOUND     0
#define INDEX_NOT_FOUND 1
#define IF_ENTRY        0
#define IND_LIST        1

/* additional access types and data types used by IPAssists */
#define IPA_WRONLY     0xF2
#define IPA_DISPLAYSTR ((u_char)0x09) 

/* IPAssists SNMP subcommand codes */
#define IPA_REG_MIB     0x04
#define IPA_GET_OID     0x10
#define IPA_SET_OID     0x11
/*#define IPA_QUERY_ALERT 0x20*/
/*#define IPA_SET_TRAP    0x21*/

/* IPAssists command return codes */
#define IPA_SUCCESS     0x00
#define IPA_FAILED      0x01
#define IPA_NOT_SUPP    0x04
#define IPA_NO_DATA     0x08

/* IPAssists SNMP subcommand return codes */
#define IPA_SNMP_SUCCESS    0x00
#define IPA_SNMP_INV_TOPOID 0x01
#define IPA_SNMP_INV_GROUP  0x02
#define IPA_SNMP_INV_SUFFIX 0x04
#define IPA_SNMP_INV_INST   0x08
#define IPA_SNMP_OID_NREAD  0x10
#define IPA_SNMP_OID_NWRIT  0x20
#define IPA_SNMP_NOT_SUPP   0x40
#define IPA_SNMP_NO_DATA    0x80

#define PTR_ALIGN4(addr) ((long)((addr))+3)&(~3)   /* align ptr 4-byte bdy */ 


/***************************************************************/ 
/* structure used for getting OSA-Express interfaces via ioctl */
/***************************************************************/ 
#define NAME_FILLED_IN    0x00000001
#define IFINDEX_FILLED_IN 0x00000002

/* version 0 */
typedef struct dev_list
{
  char device_name[IFNAME_MAXLEN]; /* OSA-Exp device name (e.g. eth0) */
  int  if_index;                   /* interface index from kernel */ 
  __u32 flags;                     /* device charateristics */
} __attribute__((packed)) DEV_LIST;

typedef struct osaexp_dev_ver0 
{
  __u32 version;                /* structure version */
  __u32 valid_fields;           /* bitmask of fields that are really filled */
  __u32 qeth_version;           /* qeth driver version */
  __u32 number_of_devices;      /* number of OSA Express devices */
  struct dev_list devices[0]; /* list of OSA Express devices */ 
} __attribute__((packed)) OSAEXP_DEV_VER0;                      


/***************************************************************/
/* ioctl data structure for IPAssists SNMP processing          */
/***************************************************************/
typedef struct ioctl_cmd_hdr
{
  int   data_len;         /* total length of buffer passed to ioctl */
	                  /* following the first 16 bytes */
                          /* in this structure (i.e. starts at token) */
  int	req_len;	  /* length of IPAssists SNMP request */
  int   reserved1;	  /* unused */
  int   reserved2;	  /* unused */

  struct {
    char  token[16];        /* not used */
    int   request;          /* IPA subcommand code */
    int   ifIndex;          /* IF-MIB ifIndex value for interface */
    int   ret_code;         /* IPA return code */
    int   ipa_ver;          /* IPA microcode level (4 hex digits to be shown as xx.yy) */
    int   seq_num;          /* sequence number (currently not used) */
  } ipa_cmd_hdr;
 
} __attribute__((packed)) IOCTL_CMD_HDR;


/***************************************************************/
/* structures for GET/GETNEXT IPAssists processing             */
/***************************************************************/
typedef struct ipa_cmd_get 
{
  IOCTL_CMD_HDR ioctl_cmd;   /* IOCTL command header */
  char        full_oid[0];   /* fully qualified OID for GET/GETNEXT */
} __attribute__((packed)) IPA_CMD_GET;

typedef struct ipa_get_data 
{
  int         len;           /* length of returned data from IPA */
  char        data[0];       /* data returned by IPA */
} __attribute__((packed)) IPA_GET_DATA;


/******************************************************************/
/* struct for IPAssists register MIB data processing              */
/******************************************************************/
typedef struct ipa_cmd_reg
{
  IOCTL_CMD_HDR ioctl_cmd;       /* IPA subcommand header */  
  int        table_cnt;      /* number of table toplevel OIDs */
} __attribute__((packed)) IPA_CMD_REG;


/***************************************************************/
/* linked list for table OID housekeeping                      */
/***************************************************************/
typedef struct table_oid
{
  oid                   *pObjid;         /* registered table OID */ 
  size_t                length;          /* length of subtree OID  */
  struct variable13     *var13ptr;       /* ptr to variable_x list */
  struct reg_indices    *ind_list;       /* ptr to registered indices */
  struct table_oid      *next;           /* ptr to next entry in list */
} TABLE_OID; 


/***************************************************************/
/* linked list for OSA Express interfaces housekeeping         */
/***************************************************************/
typedef struct reg_indices
{
  char                *full_index;     /* full index portion from IPA */
  int                 ifIndex;         /* ifIndex from IF-MIB */
  struct reg_indices  *next;           /* ptr to next entry in list */
} REG_INDICES;


/*******************************************************************/
/* this list keeps information queried from the IF-MIB             */
/*******************************************************************/
typedef struct if_List
{
  int   kerIndex;                    /* Linux kernel ifIndex */
  int   ifIndex;                     /* IF-MIB ifIndex */
  short is_OSAEXP;                   /* TRUE if an OSA Express device */           
  char if_Name[IFNAME_MAXLEN];       /* interface name (e.g. eth0) */
  int  ipa_ver;                      /* IPA microcode level */
} IF_LIST;

