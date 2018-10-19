/*
 * osasnmpd - IBM OSA-Express network card SNMP subagent
 *
 * Basic MIB implementation module for the OSA-E subagent
 *
 * The code in this module is typical for a net-snmp MIB implementation
 * information on how this works because the MIB layout is retrieved during
 * startup of the subagent, the magic identifier is not used within this
 * implementation. The var_ function uses the vp->type instead to distinct
 * the OIDs.
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/zt_common.h"

#include "ibmOSAMibUtil.h"
#include "ibmOSAMib.h"

/* ptr to OSA Express MIB information stored in linked lists */
TABLE_OID* oid_list_head;

/* ptr to interface information on this system */
IF_LIST* if_list;
int ifNumber;



/**********************************************************************
 * init_ibmOSAMib():
 *  Initialization routine. This function is called when the agent  
 *  starts up.
 *  parameters:
 *  IN  uses global MIB data                         
 *  OUT none                                
 *  returns: none                                                     
 *********************************************************************/
void init_ibmOSAMib(void) {

  int i,
    sd,         /* socket descriptor */
    error_code, /* holds errno value */
    osaexp_num, /* number of OSA Express devices */
    retc;       /* return code from register_tables */

  struct ifreq ifr;             /* request structure for ioctl */
  IPA_CMD_REG* ipa_reg_mib;     /* structure for IPA REGISTER MIB command header */ 
  char*        buffer;          /* a data buffer */
  char         time_buf[TIME_BUF_SIZE]; /* date/time buffer */

  /* init head for Toplevel OID linked list */
  oid_list_head = init_oid_list();
  if ( oid_list_head == NULL )
    {
      fprintf( stderr, "init_ibmOSAMib(): "
	       "malloc() for OID list head failed\n"
               "Cannot start subagent...exiting...\n");
      exit(1); 
    }

  /* GET net-snmp ifNumber/ifIndex/ifDescr from IF-MIB for all interfaces */
  /* on this system                                                       */
  ifNumber = query_IF_MIB( &if_list );
  if ( ifNumber < 0 )
    {
      fprintf( stderr, "init_ibmOSAMib(): "
	       "could not obtain interface info from IF-MIB\n"
	       "check if: snmpd daemon is started and subagent "
	       "access control is correct\n"
	       "see agent log file for more details\n"
               "Cannot start subagent...exiting...\n");
      exit(1);
    }
  else if ( ifNumber == 0 ) 
    {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, "%s init_ibmOSAMib(): "
		"SNMP reports no devices within IF-MIB"
		" - starting subagent anyway\n", time_buf );
      return;
    } /* end if */

  /* query OSA-E device driver for OSA-E devices and mark them in IF-MIB interface list */
  osaexp_num = query_OSA_EXP ( &if_list, ifNumber );
  if ( osaexp_num == 0 )
    {
      get_time( time_buf );
      snmp_log( LOG_ERR, "%s init_ibmOSAMib(): none of the %d interfaces is a real "
			 "OSA-E device - starting subagent anyway\n", time_buf, ifNumber);
      return;
    } 
  /* end if */
  
  /* allocate area, that should contain retrieved MIB data for a single interface */
  buffer = (char*) malloc ( MIB_AREA_LEN );
  if ( buffer == NULL )
    {
      fprintf( stderr, "init_ibmOSAMib(): "
	       "malloc() for REGISTER MIB data buffer "
	       "failed\ninit_ibmOSAMib(): requested %d bytes\n"
	       "Cannot start subagent...exiting...\n", 
	       MIB_AREA_LEN );
      exit(1);
    } /* end if */

  /* open socket for ioctl */
  sd = socket( AF_INET, SOCK_STREAM, 0 );
  if ( sd < 0 )
    {
      error_code = errno;
      fprintf( stderr, "init_ibmOSAMIB(): "
	       "error opening socket() - reason %s\n"
	       "Cannot start subagent...exiting...\n", 
	       strerror( error_code ) );
      exit(1);
    } /* end if */
  
  /* walk through interface list and query MIB data for all OSA-E devices */
  /* register MIB data with subagent driving code afterwards              */  
  for ( i=0; i < ifNumber; i++ )
    {
      if ( if_list[i].is_OSAEXP == TRUE )
	{
	  /* clear buffer */
	  memset( buffer, 0, MIB_AREA_LEN ); 

	  /* setup ioctl buffer with request and input parameters */
	  ipa_reg_mib = (IPA_CMD_REG*) buffer;                /* map command structure */
          ipa_reg_mib->ioctl_cmd.data_len  =                  /* length of IPA data area */ 
                       MIB_AREA_LEN - offsetof( IOCTL_CMD_HDR, ipa_cmd_hdr );
          ipa_reg_mib->ioctl_cmd.req_len =                    /* length of IPA subcommand */
                       sizeof( ipa_reg_mib->ioctl_cmd );  

	  ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.request  = IPA_REG_MIB; /* IPA subcommand code */
          ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ifIndex  = if_list[i].ifIndex; /* assign IF-MIB ifIndex */
          ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code = 0;
          ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.seq_num  = 0;           /* sequence number not used */
	  
	  /* do ioctl */
	  strcpy( ifr.ifr_name, if_list[i].if_Name );         /* add interface name */       
	  ifr.ifr_ifru.ifru_data = (char*) buffer;            /* add data buffer    */ 
	  
	  if ( ioctl( sd, SIOC_QETH_ADP_SET_SNMP_CONTROL, &ifr ) < 0 )
	    {
	      error_code = errno;

              /* see if we got a common I/O error */
              if ( error_code == -EIO )
                {
                   get_time( time_buf );
                   snmp_log( LOG_ERR, "%s init_ibmOSAMib(): "
			     "ioctl() failed - reason %s for interface %s\n"
                             "init_ibmOSAMib(): start subagent anyway\n",
                              time_buf, strerror( error_code ), if_list[i].if_Name );
                   close( sd );
                   free( buffer );
                   return;
                   break;     
                } /* end if */

	      /* let's see, if we got a return code from IPAssists */
	      /* or if MIB buffer is exhausted */
	      switch ( ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code ) {
	      case IPA_FAILED:
		fprintf( stderr, "init_ibmOSAMib(): "
			 "ioctl() failed - IPA command failed "
			 "init_ibmOSAMib(): "
			 "Can't get MIB information for network interface %s\n"
			 "Cannot start subagent...exiting...\n", if_list[i].if_Name );
		break;
		
	      case IPA_NOT_SUPP:
		fprintf( stderr, "init_ibmOSAMib(): "
			 "ioctl() failed - IPA command not supported "
			 "init_ibmOSAMib(): "
			 "Can't get MIB information for network interface %s\n"
			 "Cannot start subagent...exiting...\n", if_list[i].if_Name );
		break;
		
	      case IPA_NO_DATA:
		get_time( time_buf );
		snmp_log( LOG_ERR, "%s init_ibmOSAMib(): "
			  "ioctl() failed - valid IPA command, but no"
			  " SNMP data is available for interface %s\n"
			  "init_ibmOSAMib(): start subagent anyway\n", 
			  time_buf, if_list[i].if_Name );
		close( sd );
		free( buffer );
		return;
		break;
		
	      case -ENOMEM: /* should not happen in the near future ;-) */
		fprintf( stderr, "init_ibmOSAMib(): "
			 "ioctl() failed - MIB data size > "
			 "constant MIB_AREA_LEN\n"
			 "init_ibmOSAMib(): "
			 "Enlarge constant for MIB_AREA_LEN within "
			 "ibmOSAMibDefs.h and recompile the subagent\n"
			 "init_ibmOSAMib(): "
			 "Can't get MIB information for network interfaces\n"
			 "Cannot start subagent...exiting...\n" );
		break;
	      default:
		fprintf( stderr, "init_ibmOSAMib(): "
			 "ioctl() failed - reason %s\n"
			 "init_ibmOSAMib(): "
			 "Can't get MIB information for network interface %s\n"
			 "Cannot start subagent...exiting...\n",
			 strerror( error_code ), if_list[i].if_Name );
		break;
	      } /* end switch */

	      exit(1);
	    } 
	  else if( ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code != 0 )
	    {
	      /* now check IPA SNMP subcommand return code */
	      switch ( ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code ) {
		
	      case IPA_SNMP_INV_TOPOID: 
	      case IPA_SNMP_INV_GROUP: 
	      case IPA_SNMP_INV_SUFFIX:
	      case IPA_SNMP_INV_INST:
	      case IPA_SNMP_OID_NREAD:
	      case IPA_SNMP_OID_NWRIT:
		get_time( time_buf );      
		snmp_log( LOG_ERR, "%s init_ibmOSAMib(): "
			  "IPA SNMP subcommand failed\n" 
                          "init_ibmOSAMib(): "
			  "IPA SNMP subcommand  return code 0x%x\n"
			  "init_ibmOSAMib(): "
			  "Can't get MIB information for network interface %s\n"
			  "Cannot start subagent...exiting...\n", time_buf,
			  ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code, 
			  if_list[i].if_Name );
		break;
		
	      case IPA_SNMP_NOT_SUPP:
		get_time( time_buf );
		snmp_log( LOG_ERR, "%s init_ibmOSAMib(): "
			  "IPA SNMP subcommand failed - subcommand 0x%x "
			  "not supported\ninit_ibmOSAMib(): "
			  "Can't get MIB information for network interface %s\n"
			  "Cannot start subagent...exiting...\n", time_buf,
			  ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.request,
			  if_list[i].if_Name );
		break;
		
	      case IPA_SNMP_NO_DATA:
		get_time( time_buf );
		snmp_log( LOG_ERR, "%s init_ibmOSAMib(): "
			  "IPA SNMP subcommand failed - no data available\n"
			  "init_ibmOSAMib(): "
			  "Can't get MIB information for network interface %s\n"
			  "Cannot start subagent...exiting...\n", time_buf,
			  if_list[i].if_Name );
		break;
		
	      default:
		get_time( time_buf );
		snmp_log( LOG_ERR, "%s init_ibmOSAMib(): "
			  "IPA SNMP subcommand failed - undefined return code"
			  " 0x%x\ninit_ibmOSAMib(): "
			  "Can't get MIB information for network interface %s\n"
			  "Cannot start subagent...exiting...\n", time_buf,
			  ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code,
			  if_list[i].if_Name );
		break;
		
	      } /* end switch */

	      exit(1);

	    } /* end if */
	  
          /* save microcode level */
	  if_list[i].ipa_ver = ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ipa_ver;

	  
	  /* register initial table information, that we got from IPAssists */
	  retc = register_tables ( buffer, oid_list_head ); 
	  if ( retc != 0 )
	    {
	      fprintf( stderr, "init_ibmOSAMib(): "
		       "register MIB data with subagent driving "
		       "code failed\ninit_ibmOSAMib(): for ifIndex %d ifDescr %s\n"
		       "check agent log file for more details\n"
		       "Cannot start subagent...exiting...\n", 
		       if_list[i].ifIndex, if_list[i].if_Name );
	      exit(1); 
	    } /* end if */
	} /* end if */
      
    } /* end for */ 

  /* log IPA microcode level per interface */
  for ( i=0; i < ifNumber; i++ )
    {
       if ( if_list[i].is_OSAEXP == TRUE )
	  snmp_log( LOG_INFO, "OSA-E microcode level is %x for interface %s\n",
	                      if_list[i].ipa_ver,
			      if_list[i].if_Name );
    } /* end for */ 

  /* free resources */
  close( sd );
  free( buffer );
  
} /* end init_ibmOSAMib */


/**********************************************************************
 * var_ibmOSAMib():
 *  This function is called every time the agent gets a request for 
 *  any MIB data for the IBM OSA express MIB. It's up to this function
 *  to return the appropriate data back to the subagent driving code.
 *  This function supports all standard SNMIv2 data types.
 *  parameters:
 *  IN  variable vp       - entry in variableN array
 *  INOUT oid    *name    - OID from original request/OID being returned
 *  INOUT size_t *length  - length of orig. OID/length of ret. OID
 *  IN    int    exact    - exact/inexact request
 *  OUT   size_t *var_len - length of answer being returned
 *  OUT   WriteMethod **write_method - unused
 *  returns: NULL - vp entry does not match or instance wrong
 *                - something within ioctl handling failed
 *           else   data returned as answer
 *********************************************************************/
unsigned char* var_ibmOSAMib( struct variable *vp,
    	                         oid         *name,
    	                         size_t      *length,
    	                         int         exact,
    	                         size_t      *var_len,
    	                         WriteMethod **write_method)
{
  /* variables for returning data back to the subagent driving code */
  static long long_ret;
  static unsigned char octetstr_buf[MAX_GET_DATA];
  static oid objid[MAX_OID_LEN];
  static struct counter64 osa_counter64;
  long             *ptr_long;
  int              *ptr_int;
  unsigned char    *ptr_uchar;
  
  int  ifIndex;     /* IF-MIB ifIndex of the OSA device that is queried for data */
  int  offset;      /* offset to returned data portion within GET command area */
  char time_buf[TIME_BUF_SIZE]; /* date/time buffer */

  IPA_CMD_GET  *get_cmd;        /* area for GET command */
  IPA_GET_DATA *get_res;        /* pointer to offset where data portion starts */
  void         *tmp_ptr;        

  /* 
   * This function compares the full OID that is passed in to the registered
   * OIDs from this subagent. 
   * It is the IBM OSA Express specific version of the default 
   * header_simple_table() function, that is normally used in case of a simple
   * table. Place a mutual exlusion lock around this operation to avoid 
   * interfering threads, when updating the internal MIB table thru thread 
   * update_mib_info()  	
   */

  ifIndex = header_osa_table( vp, name, length, exact, var_len, write_method,
			      oid_list_head );

  if ( ifIndex == MATCH_FAILED ) 
    return NULL; 


  /* issue ioctl to query Get/Getnext request data */
  offset = do_GET_ioctl ( ifIndex, name, *length, &get_cmd );
  if ( offset < 0 )
    {
      return NULL; 
    }

  /*
   * return the result to subagent driving code 
   */
  
  /* map data portion returned by IPAssists */
  /* # ptr GET command area + offset returned data portion */
  /* # align PTR to 4 byte bdy where data portion starts   */
  tmp_ptr = (char*) get_cmd;
  tmp_ptr += offset;
  get_res = (IPA_GET_DATA*) (PTR_ALIGN4( tmp_ptr )); 
  
  switch( vp->type ) {

  case ASN_INTEGER: case ASN_COUNTER: case ASN_GAUGE: case ASN_TIMETICKS:  
    /* ASN_UNSIGNED is same as ASN_GAUGE (RFC1902) */
 
    if ( get_res->len == sizeof(int) ) 
      {
	    ptr_int = (int*) get_res->data;
	    long_ret = (long) *ptr_int;
      }
    else	    
      {
	    ptr_long = (long*) get_res->data;
	    long_ret = (long) *ptr_long;
      } /* end if */

    free( get_cmd );

    return (unsigned char *) &long_ret;
    break;

  case ASN_COUNTER64:

    if ( get_res->len > 8 )
    {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, "%s var_ibmOSAMib(): "
		"IPA data length for ASN_COUNTER64 > 8 bytes\n"
		"var_ibmOSAMib(): rejected Get/Getnext request\n", time_buf );
      free( get_cmd );
      return NULL;
    } /* end if */
  
    /* IPA returns 8 bytes for COUNTER64 */ 
    ptr_int = (int*) get_res->data;
    osa_counter64.high = (int) *ptr_int;
    ptr_int++;
    osa_counter64.low  = (int) *ptr_int;
     
    *var_len = sizeof( osa_counter64 );
    free( get_cmd );

    return (unsigned char *) &osa_counter64; 
    break;

  case ASN_OPAQUE:    /* old v1 type/included for compatibility */
  case ASN_OCTET_STR: /* used for Binary data */ 
                      /* case Display String is handled within var_DisplayStr() */
   
    if ( get_res->len > MAX_GET_DATA )
    {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, "%s var_ibmOSAMib(): "
		"IPA data length %d  for ASN_OCTET_STR > "
		"MAX_GET_DATA (%d  bytes)\n"
		"var_ibmOSAMib(): rejected Get/Getnext request\n",
		time_buf, get_res->len, MAX_GET_DATA );
      free( get_cmd );
      return NULL;
    } /* end if */

    *var_len = get_res->len;
    ptr_uchar = (unsigned char*) get_res->data;
    memcpy( octetstr_buf, ptr_uchar, *var_len ); 
    free( get_cmd );

    return (unsigned char *) octetstr_buf;  
    break;

  case ASN_IPADDRESS:

    /* IPA IpAddress within 4 bytes hex data */
    ptr_int = (int*) get_res->data;
    long_ret = (long) *ptr_int;
    free( get_cmd );

    return (unsigned char *) &long_ret;
    break;

  case ASN_OBJECT_ID:
    
    /* IPA returned ObjectId as character string, have to convert... */
    *var_len = str_to_oid_conv ( get_res->data, objid );
    if ( *var_len == 0 )
    {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, "%s var_ibmOSAMib(): IPA returned bad ObjectId - "
		"cannot convert net-snmp oid type\n"
		"var_ibmOSAMib(): rejected Get/Getnext request\n", time_buf );
      free( get_cmd );
      return NULL;
    } /* end if */

    *var_len = (*var_len) * sizeof( oid );
    free( get_cmd );

    return (unsigned char *) &objid;
    break;

  default:
    get_time( time_buf );
    snmp_log( LOG_ERR, "%s var_ibmOSAMib(): "
	      "got a not known ASN data type %x\n"
	      "var_ibmOSAMib(): "
	      "rejected Get/Getnext request\n", time_buf, vp->type );

  } /* end switch */

  free( get_cmd );
 
  return NULL;

} /* end var_ibmOSAMib */


/**********************************************************************
 * var_DisplayStr():
 *  This function handles the special case for Display Strings, which are 
 *  a textual convention to Octet Strings. The binary data case for 
 *  Octet Strings is handled within var_ibmOSAMib(). 
 *  It's up to this function to return the appropriate data back to the 
 *  subagent driving code.
 *  parameters:
 *  IN  variable vp       - entry in variableN array
 *  INOUT oid    *name    - OID from original request/OID being returned
 *  INOUT size_t *length  - length of orig. OID/length of ret. OID
 *  IN    int    exact    - exact/inexact request
 *  OUT   size_t *var_len - length of answer being returned
 *  OUT   WriteMethod **write_method - unused
 *  returns: NULL - vp entry does not match or instance wrong
 *                - something within ioctl handling failed
 *           else   data returned as answer
 *********************************************************************/
unsigned char* var_DisplayStr( struct variable *vp,
    	                       oid         *name,
    	                       size_t      *length,
    	                       int         exact,
    	                       size_t      *var_len,
    	                       WriteMethod **write_method)
{
  /* variables for returning a display string to the subagent driving code */
  static char string[SPRINT_MAX_LEN];
  char                 time_buf[TIME_BUF_SIZE]; /* date/time buffer */
  
  int  ifIndex;     /* IF-MIB ifIndex of the OSA device that is queried for data */
  int  offset;      /* offset to returned data portion within GET command area */

  IPA_CMD_GET  *get_cmd;        /* area for GET command */
  IPA_GET_DATA *get_res;        /* pointer to offset where data portion starts */
  void         *tmp_ptr;

  /* 
   * This function compares the full OID that is passed in to the registered
   * OIDs from this subagent. 
   * It is the IBM OSA Express specific version of the default 
   * header_simple_table() function, that is normally used in case of a simple
   * table. Place a mutual exlusion lock around this operation to avoid 
   * interfering threads, when updating the internal MIB table thru thread 
   * update_mib_info()  	
   */

  ifIndex = header_osa_table( vp, name, length, exact, var_len, write_method,
			      oid_list_head );

  if ( ifIndex == MATCH_FAILED )
    return NULL;


  /* issue ioctl to query Get/Getnext request data */
  offset = do_GET_ioctl ( ifIndex, name, *length, &get_cmd );
  if ( offset < 0 )
    {
      return NULL;
    }
  
  /*
   * return the result to subagent driving code 
   */

  /* map data portion returned by IPAssists */
  /* # ptr GET command area + offset returned data portion */
  /* # align PTR to 4 byte bdy where data portion starts   */
  tmp_ptr = (char*) get_cmd;
  tmp_ptr += offset;
  get_res = (IPA_GET_DATA*) (PTR_ALIGN4( tmp_ptr )); 

  if ( vp->type == ASN_OCTET_STR)  
    {
      if ( get_res->len >= SPRINT_MAX_LEN )
	{
	  get_time( time_buf );	
	  snmp_log( LOG_ERR, "%s var_DisplayStr(): "
		    "IPA data length %d  for Display "
		    "String >= SPRINT_MAX_LEN (%d  bytes)\n"
		    "var_ibmOSAMib(): rejected Get/Getnext request\n"
		    ,time_buf, get_res->len, SPRINT_MAX_LEN );
	  free( get_cmd );
	  return NULL;
	} /* end if */

      strncpy( string, get_res->data, get_res->len );
      string[ get_res->len ] = '\0';
      *var_len = strlen( string ); 
      free( get_cmd );

      return (unsigned char *) string;  
    }
  else
    {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, "%s var_DisplayStr(): "
		"expected a Display String here, "
		"but got a different ASN data type: %x\n"
		"var_DisplayStr(): "
		"rejected Get/Getnext request\n", time_buf, vp->type );
    } /* end if */

  free( get_cmd );
 
  return NULL;

} /* end var_DisplayStr */


/**********************************************************************
 * do_GET_ioctl()
 *  This function handles the communication with an OSA Express Card
 *  to query the appropriate MIB information from IPAssists.
 *  An ioctl is used in order to qet the appropriate information.
 *  parameters:
 *  IN    int ifIndex       - IF-MIB interface index 
 *  IN    oid    *name      - OID being returned
 *  IN    size_t len        - length of ret. OID
 *  INOUT IPA_CMD_GET** cmd - GET command area
 *  returns:  cmd_len - return offset to returned data
 *           -1 -  ioctl() was not successful
 *********************************************************************/
int do_GET_ioctl ( int ifIndex, oid *name, size_t len, IPA_CMD_GET **cmd )
{
  int  sd;                                   /* socket descriptor */
  int  i, error_code;
  char oid_str[MAX_OID_STR_LEN];             /* may hold an OID as string */
  char time_buf[TIME_BUF_SIZE];              /* date/time buffer */
  char device[IFNAME_MAXLEN] = "not_found";  /* device name for ioctl */
  struct ifreq ifr;                          /* request structure for ioctl */
  
  
  /* search device name in in global interface list for ifIndex */
  for ( i=0; i < ifNumber; i++ )
    {
      if ( if_list[i].ifIndex == ifIndex )
	{
	  strcpy( device, if_list[i].if_Name );
	  break;
	}
    } /* end for */
  
  if ( strcmp( device, "not_found" ) == 0 )
    {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
		"ifIndex %d is not recorded in "
		"interface list\n"
		"OSA Subagent MIB information may be incomplete!\n"
		,time_buf, ifIndex );
      return -1;
    } 

  /*
   * query IPAssists for data appropriate to the OID that we just validated
   */

  /* convert Get/GetNext OID to a string used by IPA */
  if( oid_to_str_conv ( name, len, oid_str ) == FALSE )
    {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
		"cannot convert OID to string object\n"
		"do_GET_ioctl(): rejected request\n", time_buf );
      return -1;
    } 

  /* allocate memory for Get/GetNext command area */
  *cmd = ( IPA_CMD_GET* ) malloc( GET_AREA_LEN ); 
  if ( *cmd == NULL ) 
    {
      get_time( time_buf );	     
      snmp_log( LOG_ERR, 
		"%s do_GET_ioctl(): "
		"malloc() for GET command area failed\n"
		"do_GET_ioctl(): rejected request for .%s\n",
		time_buf, oid_str );
      return -1;
    } /* end if */

  /* set up input parameters in Get/GetNext command area */
  /* size of IPA data area */  
  (*cmd)->ioctl_cmd.data_len =             
          GET_AREA_LEN - offsetof( IOCTL_CMD_HDR, ipa_cmd_hdr );

  /* size of IPA GET subcommand padded to 4-byte bdy */
  (*cmd)->ioctl_cmd.req_len =  
    (sizeof((*cmd)->ioctl_cmd) + strlen( oid_str ) + 1 + 3)&(~3); 

  /* set up input parameters in Get/GetNext command area */
  (*cmd)->ioctl_cmd.ipa_cmd_hdr.request  = IPA_GET_OID;  /* IPA subcommand code   */
  (*cmd)->ioctl_cmd.ipa_cmd_hdr.ifIndex  = ifIndex;      /* assign IF-MIB ifIndex */
  (*cmd)->ioctl_cmd.ipa_cmd_hdr.ret_code = 0;               
  (*cmd)->ioctl_cmd.ipa_cmd_hdr.seq_num  = 0;            /* sequence# is not used */ 
  strcpy( (*cmd)->full_oid, oid_str );                   /* requested OID         */
                                                         /* (fully qualified)     */

  /*
   *  issue Get/GetNext command against IPAssists 
   */

  /* create socket for ioctl */
  sd = socket( AF_INET, SOCK_STREAM, 0 );
  if ( sd < 0 )
    {
      error_code = errno;
      get_time( time_buf );
      snmp_log(LOG_ERR, "%s do_GET_ioctl(): "
	       "error opening socket() - reason %s\n"
	       "do_GET_ioctl(): rejected request for .%s\n", 
	       time_buf, strerror( error_code ), oid_str );
      free( *cmd );
      return -1;
    } /* end if */
  
  /* do ioctl */
  strcpy( ifr.ifr_name, device );       
  ifr.ifr_ifru.ifru_data = (char*) (*cmd);
  if ( ioctl( sd, SIOC_QETH_ADP_SET_SNMP_CONTROL, &ifr ) < 0 )
    {
      error_code = errno;
      get_time( time_buf );

      /* see if we got a common I/O error */
      if ( error_code == -EIO )
        {
           snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
		     "ioctl() failed - reason %s\n"
                     "do_GET_ioctl(): rejected request for .%s\n",
                     time_buf, strerror( error_code ), oid_str );
           close( sd );
           free( *cmd );
           return -1;
        } /* end if */
      
      /* let's see, if we got a return code from IPAssists */
      /* or if MIB buffer is exhausted */
      switch ( (*cmd)->ioctl_cmd.ipa_cmd_hdr.ret_code ) {
	
      case IPA_FAILED:
	snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
		  "ioctl() failed - IPA command failed\n"
		  "do_GET_ioctl(): rejected request for .%s\n",
		  time_buf, oid_str );
	break;

      case IPA_NOT_SUPP:
	snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
		  "ioctl() failed - IPA command not supported\n"
		  "do_GET_ioctl(): rejected request for .%s\n",
		  time_buf,  oid_str );
	break;
		
      case IPA_NO_DATA:
	snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
		  "ioctl() failed - valid IPA command, but no "
		  "SNMP data is available\n"
		  "do_GET_ioctl(): rejected request for .%s\n",
		  time_buf, oid_str ); 
	break;

      case -ENOMEM:
        snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
		  "ioctl() failed - response data > "
		  "constant MAX_GET_DATA %d\n"
	          "do_GET_ioctl(): rejected request for .%s\n",
	          time_buf, MAX_GET_DATA, oid_str );	    
	break;

      default:
	snmp_log(LOG_ERR, "%s do_GET_ioctl(): "
		 "ioctl() failed - reason %s\n"
		 "do_GET_ioctl(): rejected request for .%s\n", 
		 time_buf, strerror( error_code ), oid_str );
	break;
      } /* end switch */

      close( sd );
      free( *cmd );
      return -1;

    } /* end if */ 

  /* close socket */
  close( sd );
  
  /* now check IPA SNMP subcommand return code */
  switch ( (*cmd)->ioctl_cmd.ipa_cmd_hdr.ret_code ) {
    
  case IPA_SNMP_SUCCESS:
    /* return offset to data portion */
    return ( sizeof( IPA_CMD_GET ) + strlen( oid_str ) + 1 );
    break;

  case IPA_SNMP_INV_TOPOID: 
  case IPA_SNMP_INV_GROUP: 
  case IPA_SNMP_INV_SUFFIX:
  case IPA_SNMP_INV_INST:
  case IPA_SNMP_OID_NREAD:
  case IPA_SNMP_OID_NWRIT:
    get_time( time_buf );
    snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
	      "IPA SNMP subcommand failed - cannot handle OID\n"
              "do_GET_ioctl(): IPA SNMP subcommand return code 0x%x\n"
              "do_GET_ioctl(): rejected request for .%s\n",
              time_buf, (*cmd)->ioctl_cmd.ipa_cmd_hdr.ret_code, oid_str );
    break;

  case IPA_SNMP_NOT_SUPP:
    get_time( time_buf );
    snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
	      "IPA SNMP subcommand failed - subcommand 0x%x not supported\n"
	      "do_GET_ioctl(): rejected request for .%s\n", 
	      time_buf, (*cmd)->ioctl_cmd.ipa_cmd_hdr.request, oid_str );
    break;
    
  case IPA_SNMP_NO_DATA:
    get_time( time_buf );
    snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
	      "IPA SNMP subcommand failed - no data available\n"
	      "do_GET_ioctl(): rejected request for .%s\n", 
	      time_buf, oid_str );
    break;
    
  default:
    get_time( time_buf );
    snmp_log( LOG_ERR, "%s do_GET_ioctl(): "
	      "IPA SNMP subcommand failed - undefined return code 0x%x\n"
	      "do_GET_ioctl(): rejected request for .%s\n", 
	      time_buf, (*cmd)->ioctl_cmd.ipa_cmd_hdr.ret_code, oid_str );
    break;
    
  } /* end switch */

  /* return error */
  free( *cmd );
  return -1;

} /* end do_GET_ioctl */


/**********************************************************************
 * write_ibmOSAMib():
 *  !!! Set processing is not supported in version 1.0.0 !!!
 *  !!! Function is defind as a skeleton for later use   !!!
 *  This function handles any SET requests raised against the      
 *  ibmOSAMib.                                                      
 *  The flow of actions is to preserve proper transaction handling 
 *  with other transactions in the same set request.
 *  parameters:
 *  IN    int    action       - current action state 
 *  IN    u_char *var_val     - new variable value                      
 *  IN    u_char var_val_type - data type of above variable          
 *  IN    size_t var_val_len  - length of variable value 
 *  IN    u_char *statP       - value that a GET request would return
 *                              for this variable                             
 *  IN    oid    *name        - OID to be set
 *  IN    size_t name_len     - len of OID to be set 
 *  returns: SNMP_ERR_WRONGTYPE  - wrong data type passed in     
 *           SNMP_ERR_GENERR     - general error occurred
 *           SNMP_ERR_UNDOFAILED - undo operation failed
 *           SNMP_ERR_NOERROR    - variable set successful
 *********************************************************************/
int write_ibmOSAMib( int      action,
                        u_char   *UNUSED(var_val),
                        u_char   UNUSED(var_val_type),
                        size_t   UNUSED(var_val_len),
                        u_char   *UNUSED(statP),
                        oid      *UNUSED(name),
                        size_t   UNUSED(name_len) )
{
/*  static unsigned char string[SPRINT_MAX_LEN]; */
/*  int size; */

  switch ( action ) {
        case RESERVE1:
          /* check to see that everything is possible */
          break;


        case RESERVE2:
          /* allocate needed memory here */
          break;


        case FREE:
          /* Release any resources that have been allocated */
          break;


        case ACTION:
          /* Actually make the change requested. Note that anything done
             here must be reversible in the UNDO case */
          break;


        case UNDO:
          /* Back out any changes made in the ACTION case */
          break;


        case COMMIT:
          /* Things are working well, so it's now safe to make the change
             permanently.  Make sure that anything done here can't fail! */
          break;
  }
  return SNMP_ERR_NOERROR;
} /* end write_ibmOSAMib */






