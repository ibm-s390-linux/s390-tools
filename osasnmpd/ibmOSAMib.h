/*
 * osasnmpd - IBM OSA-Express network card SNMP subagent
 *
 * Include file for the OSA-E subagent MIB implementaton module. 
 * Defines function prototypes of the basic functions in the MIB
 * implementation module.
 *
 * Copyright IBM Corp. 2002, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _MIBGROUP_IBMOSAMIB_H
#define _MIBGROUP_IBMOSAMIB_H

/* we may use header_generic and header_simple_table from the util_funcs module */

config_require(util_funcs)


/* function prototypes */

void          init_ibmOSAMib(void);     /* register MIB data */
FindVarMethod var_ibmOSAMib;            /* handle GET and GETNEXT requests */
                                        /* for all SMIv2 standard types */
FindVarMethod var_DisplayStr;           /* handle special case Display String */
WriteMethod   write_ibmOSAMib;          /* handle SET requests             */

/* ioctl for Get/Getnext processing */
int do_GET_ioctl ( int, oid*, size_t, IPA_CMD_GET** ); 

#endif /* _MIBGROUP_IBMOSAMIB_H */
