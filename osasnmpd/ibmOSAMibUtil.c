/*
 * osasnmpd - IBM OSA-Express network card SNMP subagent
 *
 * Collection of utility functions used by the MIB implementation
 * module.
 *
 * Copyright IBM Corp. 2002, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "ibmOSAMibUtil.h"
#include "ibmOSAMib.h"

/* ptr to interface information on this system */
extern IF_LIST* if_list;
extern int ifNumber;
extern TABLE_OID* oid_list_head;

/* proc file filedescriptor. opened in osasnmpd.c */
extern int proc_fd;




/**********************************************************************
 * str_to_oid_conv():
 *  This function converts an OID string in an OID u_long array used
 *  by net-snmp.
 *  parameters:
 *  IN  char* uc_oid: OID string separated by dots  
 *  OUT oid*  ul_oid: OID u_long array
 *  returns: int count - number of OID identifiers found within OID 
 *                       string; 0 if OID string was invalid
 *********************************************************************/
int str_to_oid_conv ( char* uc_oid, oid* ul_oid )
{
  short valid  = TRUE;
  int   count = 0;
  char* pos_strt = uc_oid; 
  char* pos_end;
  
  /* got non-empty oid string */   
  if ( strlen( uc_oid ) > 0 )
    {
      do {  
          /* found a dot, skip it */
          if ( *pos_strt == '.' )
           {    
            pos_strt++; 
            if ( *pos_strt == '\0')   /* found ending dot - valid - */
              break;
           } 
         
          /* found no dot and but expected one, indicate invalid OID */  
	  else if (count > 0)
            {
              valid = FALSE;
              break;
            } /* end if */

          /* convert oid digit into data type oid (unsigned long) */ 
          ul_oid[count] = (oid) strtoul( pos_strt, &pos_end, 10); 
 
          /* check result from conversion */         
          if (pos_strt == pos_end || ul_oid[count] == ULONG_MAX) 
            {
              valid = FALSE;
              break;
            }
        
          /* adjust to next OID digit */  
          pos_strt = pos_end;
          count++;          
         } 
      while ( *pos_end != '\0' && count < MAX_OID_LEN );               
    }
  else
    /* indicate invalid OID */
    valid = FALSE;

  /* if OID was valid, return number of OID identifiers */
  if (!valid)
    return 0;
  else 
    return count;

} /* end str_to_oid_conv() */


/**********************************************************************
 * oid_to_str_conv():
 *  This function converts a net-snmp OID u_long array into an OID
 *  string separated by dots.
 *  parameters:
 *  IN  oid*    ul_oid: OID u_long array
 *  IN  size_t  length: OID length
 *  OUT char*   uc_oid: OID string including dots (no leading dot)   
 *  returns:  TRUE  -  conversion was successful                        
 *            FALSE -  conversion failed
 *********************************************************************/
int oid_to_str_conv (oid* ul_oid, size_t length, char* uc_oid )
{
  #define MAX_CHARS 50           /* size of buffer */
  int i;
  short  valid = TRUE;
  char   buffer[MAX_CHARS];      /* buffer used for conversion */

  /* got invalid OID length */
  if ( length != 0 && length <= MAX_OID_LEN )
    {
      /* init return string */      
      uc_oid[0] = '\0'; 

      for ( i=0; i < (int)length; i++)
        {
          /* convert and append OID digit to return string */ 
          if (i == 0)       
            sprintf( buffer, "%lu", ul_oid[i] );
          else 
            sprintf( buffer, ".%lu", ul_oid[i] );   
         
          strcat( uc_oid, buffer ); 
        } /* end for */
    }
  else
    /* indicate invalid OID */
    valid = FALSE;

  /* if OID conversion was successful, indicate success */
  return valid;

} /* end oid_to_str_conv() */
 

/**********************************************************************
 * init_oid_list():
 *  This function initializes the head of the linked list structure to
 *  maintain the IPAssists MIB information. It is called at subagent
 *  startup.
 *
 *  parameters:
 *  INOUT    none
 *  returns: TABLE_OID* - head of linked list (pseudo node)
 *           NULL       - if malloc() for head failed
 *
 *********************************************************************/
TABLE_OID* init_oid_list ()
{
  TABLE_OID* head;

  /* allocate list head */
  head = (TABLE_OID*) malloc( sizeof *head );

  if ( head != NULL )
    head->next = NULL;

  return head;

} /* init_oid_list() */


/**********************************************************************
 * search_oid():  
 *  This function searches the linked OID list for a given OID and
 *  returns a ptr to the element if it is an exact match, otherwise the 
 *  previous (smaller) OID in the list is returned.
 *                                   
 *  parameters:
 *  IN   oid*   s_oid      - Toplevel OID to search for 
 *  IN   size_t len        - length of this OID 
 *  IN   TABLE_OID*  lhead - ptr to list head
 *  OUT  TABLE_OID** curr  - ptr to entry in list      
 *  returns:  0 - exact match - OID exists in list
 *            1 - not found, curr point to possible insertion point 
 *           -1 - got unexpected return code from snmp_oid_compare()     
 *                                                            
 *********************************************************************/
int search_oid ( oid* s_oid, size_t len, TABLE_OID* lhead, TABLE_OID** curr  )
{

  /* loop through list and compare OIDs */
  /* fyi - snmp_oid_compare() is a function from the net-snmp agent extension API */
  for( *curr=lhead; (*curr)->next != NULL; *curr=(*curr)->next )    
    {
      switch
	( snmp_oid_compare( s_oid, len, (*curr)->next->pObjid, 
			    (*curr)->next->length )) 
	{
	case  0:      /* exact OID match - curr->next points to entry */
          *curr = (*curr)->next;
	  return OID_FOUND;
          break;
	case  1:      /* search OID still greater - goto next entry */
	  break;
	case -1:      /* next entry is greater than search OID */
	  return OID_NOT_FOUND;   
	  break;
	default:      /* unexpected return code from snmp_oid_compare */
	  return UNEXP_ERROR; 
	} /* end switch */

    } /* end for */

  /* we're at the head or the end of linked list */
  /* curr points to head or last element in list, good insertion points */
  return OID_NOT_FOUND;
  
} /* search_oid() */


/**********************************************************************
 * search_top_oid():  
 *  This function searches for a fully qualified OID a matching Toplevel  
 *  OID from the linked list.
 *  It returns a pointer to the element if it is an exact match. 
 *  Otherwise the return OID is set to NULL.
 *                                   
 *  parameters:
 *  IN   oid*   s_oid      - Fully qualified OID 
 *  IN   size_t len        - length of this OID 
 *  IN   TABLE_OID*  lhead - ptr to list head
 *  OUT  TABLE_OID** curr  - ptr to entry in list      
 *  returns:  0 - exact match - appropriate Toplevel OID found
 *            1 - not found, curr set to NULL 
 *           -1 - got unexpected return code from snmp_oid_compare()     
 *                                                            
 *********************************************************************/
int search_top_oid ( oid* s_oid, size_t len, 
		     TABLE_OID* lhead, TABLE_OID** curr  )
{

  /* loop through list and compare OIDs */
  /* snmp_oid_compare() is a taken from the net-snmp agent extension API */
  for( *curr=lhead; (*curr)->next != NULL; *curr=(*curr)->next )    
    {
      /* fully qualified OID must be greater than our Toplevel OID */
      if ( len > (*curr)->next->length ) {

	switch
	  ( snmp_oid_compare( s_oid, (*curr)->next->length , 
			      (*curr)->next->pObjid, (*curr)->next->length )) 
	  {
	  case  0:      /* exact OID match - curr->next points to entry */
	    *curr = (*curr)->next;
	    return OID_FOUND;
	    break;
	  case  1:      /* search OID still greater - goto next entry */
	    break;
	  case -1:      /* next entry is greater than search OID */
	    *curr = NULL;
	    return OID_NOT_FOUND;   
	    break;
	  default:      /* unexpected return code from snmp_oid_compare */
	    *curr = NULL;
	    return UNEXP_ERROR; 
	} /* end switch */

      } /* end if */

    } /* end for */


  /* we're at the head or the end of linked list */
  /* curr points to head or last element in list */
  *curr = NULL;
  return OID_NOT_FOUND;
  
} /* search_top_oid() */


/**********************************************************************
 * oid_insert_after():  
 *  This function initializes and adds a new entry to the OID linked   
 *  list after entry pre_oid.
 *                                   
 *  parameters:
 *  IN   oid* i_oid         - Toplevel OID to add
 *  IN   size_t len         - length of this OID
 *  IN   TABLE_OID* pre_oid - add Toplevel OID after this entry           
 *  returns: TABLE_OID* - PTR to newly inserted entry
 *           NULL       - if malloc() for new entry failed
 *********************************************************************/
TABLE_OID* oid_insert_after ( oid* i_oid, size_t len, TABLE_OID* pre_oid )
{
  TABLE_OID *new_entry;

  new_entry = (TABLE_OID*) malloc( sizeof *new_entry );
  if ( new_entry == NULL )
    return NULL;

  /* allocate head for index list */
  new_entry->ind_list = init_ind_list();
  if ( new_entry->ind_list == NULL )
    { 
      free ( new_entry );   
      return NULL;
    } /* end if */

  /* assign OID and length */
  new_entry->pObjid = i_oid;  
  new_entry->length = len;
  new_entry->var13ptr = NULL;

  /* insert */
  new_entry->next = pre_oid->next;
  pre_oid->next = new_entry;

  return new_entry;
 
} /* oid_insert_after()*/


/**********************************************************************
 * delete_oid():  
 *  This function deletes a Toplevel OID entry from the Toplevel OID 
 *  linked list.
 *                                   
 *  parameters:
 *  IN       oid         *d_oid   - Toplevel OID to delete
 *  IN       size_t      len      - length of this OID 
 *  IN       TABLE_OID   *lhead   - head of Toplevel OID linked list
 *  returns: none
 *                                                            
 *********************************************************************/
int delete_oid( oid* d_oid, size_t len, TABLE_OID* lhead )
{
  TABLE_OID *curr, *del_entry;

  /* loop through list and compare OIDs  */
  /* snmp_oid_compare() is taken from the net-snmp agent extension API */
  for( curr=lhead; curr->next != NULL; curr=curr->next )    
    {
      if ( snmp_oid_compare( d_oid, len, curr->next->pObjid, 
			     curr->next->length ) == 0 ) 
	{
	  del_entry = curr->next;
	  curr->next = curr->next->next;
	  free( del_entry->pObjid );
	  free( del_entry->var13ptr );

	  /* index list not empty, free index list first */
	  if ( del_entry->ind_list->next != NULL )
	    delete_index( del_entry->ind_list, 0, IND_LIST );

	  /* free index list head */
	  free( del_entry->ind_list );

	  free( del_entry );
	  break;
	} /* end if */
    } /* end for */
  
  return 0; 
 
} /* delete_oid() */


/**********************************************************************
 * clear_oid_list():
 *  This function removes all index entries from the Toplevel OID  
 *  linked list.            
 *
 *  parameters:
 *  IN       TABLE_OID   *lhead   - head of Toplevel OID linked list
 *  returns: none
 *
 *********************************************************************/
int clear_oid_list( TABLE_OID* lhead )
{
  TABLE_OID *curr, *clr_entry;
  
  /* loop through list and clean entries */
  for( curr=lhead; curr->next != NULL; curr=curr->next )
    {
       clr_entry = curr->next;
       
       /* index list not empty, free index list first */
       if ( clr_entry->ind_list->next != NULL )
          delete_index( clr_entry->ind_list, 0, IND_LIST );

    } /* end for */

  return 0;

} /* clear_oid_list() */

/**********************************************************************
 * init_ind_list():  
 *  This function initializes the head of the linked list structure to
 *  maintain index portion information. This is called when a new
 *  Toplevel OID is inserted in the Toplevel OID linked list.  
 *                                   
 *  parameters:
 *  INOUT    none 
 *  returns: TABLE_OID* - head of linked list (pseudo node)
 *           NULL       - if malloc() for head failed
 *                                                            
 *********************************************************************/
REG_INDICES* init_ind_list ( )
{
  REG_INDICES* ihead;

  /* allocate list head */
  ihead = (REG_INDICES*) malloc( sizeof *ihead );

  if ( ihead != NULL )  
    ihead->next = NULL;

  return ihead; 
 
} /* init_ind_list() */


/**********************************************************************
 * index_insert_after():  
 *  This function adds a new index entry to the index linked list   
 *                                   
 *  parameters:
 *  IN   char* i_index        - index to add
 *  IN   int   ifIndex        - appropriate IF-MIB ifIndex 
 *  IN   REG_INDICES* pre_ind - add index after this entry           
 *  returns: REG_INDICES*     - PTR to newly inserted entry
 *           NULL             - if malloc() for new entry failed
 *********************************************************************/
REG_INDICES* index_insert_after ( char* i_index, int ifIndex,  
				  REG_INDICES* pre_ind )
{
  REG_INDICES *new_entry;

  new_entry = (REG_INDICES*) malloc( sizeof *new_entry );
  if ( new_entry == NULL )
    return NULL;

  /* assign index and ifIndex */
  new_entry->full_index = i_index;  
  new_entry->ifIndex = ifIndex;

  /* insert */
  new_entry->next = pre_ind->next;
  pre_ind->next = new_entry;

  return new_entry;
 
} /* index_insert_after()*/


/**********************************************************************
 * delete_index():  
 *  This function deletes an entry in the index linked list indexed by
 *  ifIndex or removes the whole index linked list if desired.
 *                                   
 *  parameters:
 *  IN       REG_INDICES *lhead   - head of index linked list
 *  IN       int         ifIndex  - ifIndex to remove from list
 *  IN       int         del_type - deletion type (IF_ENTRY/IND_LIST) 
 *  returns: none
 *                                                            
 *********************************************************************/
int delete_index( REG_INDICES* lhead, int ifIndex, int del_type )
{
  REG_INDICES *curr, *del_entry;

  if (del_type == IF_ENTRY ) {
    
    /* loop through list and compare ifIndex */
    curr = lhead;    
    while ( curr->next != NULL )
      {
	if ( curr->next->ifIndex == ifIndex ) {
	  del_entry = curr->next;
	  curr->next = curr->next->next;
	  free( del_entry->full_index );
	  free( del_entry );
	} /* end if */
	else
	  curr=curr->next;
      } /* end while */
  }
  else if ( del_type == IND_LIST ) {
    
    /* loop through list delete one entry after another */
    curr = lhead;
    while ( curr->next !=NULL )
      {
	del_entry = curr->next;
	curr->next = curr->next->next;
	free( del_entry->full_index );
	free( del_entry );
      } /* end while */
  } /* end if */

  return 0; 
 
} /* delete_index() */


/**********************************************************************
 * search_index():  
 *  This function searches the linked index list for a given index and
 *  returns a ptr to the element if it is an exact match, otherwise the 
 *  previous (smaller) index in the list is returned.
 *                                   
 *  parameters:
 *  IN   index*       s_index    - index to search for 
 *  IN   REG_INDICES* lhead  - ptr to list head
 *  OUT  REG_INDICES** curr  - ptr to entry in list      
 *  returns:  0 - exact match - index exists in list
 *            1 - not found, curr point to possible insertion point 
 *                                                            
 *********************************************************************/
int search_index ( char* s_index, REG_INDICES* lhead, REG_INDICES** curr  )
{

  int  oid_len1, oid_len2;
  oid  ind_oid1[MAX_OID_LEN];           /* temporary net-snmp oids */
  oid  ind_oid2[MAX_OID_LEN];

  /* loop through list and compare indices */
  for( *curr=lhead; (*curr)->next != NULL; *curr=(*curr)->next )    
    {
      oid_len1 = str_to_oid_conv( (char*) s_index, ind_oid1 );
      oid_len2 = str_to_oid_conv( (char*) (*curr)->next->full_index,
				  ind_oid2 );

      switch
        ( snmp_oid_compare( ind_oid1, oid_len1, ind_oid2, oid_len2 ) )
        {
        case  0:      /* exact index match - curr->next points to entry */
          /* exact index match - curr-> points to entry */
          *curr = (*curr)->next;
          return INDEX_FOUND;
          break;
        case  1:      /* search index still greater - goto next entry */
          continue;
          break;
        case -1:      /* next entry is greater than search index */
          /* next entry is greater than search index */
          return INDEX_NOT_FOUND; 
          break;
        default:      /* unexpected return code from snmp_oid_compare */
          return UNEXP_ERROR;
        } /* end switch */
    } /* end for */

  /* we're at the head or the end of linked list */
  /* curr points to head or last element in list, good insertion points */
  return INDEX_NOT_FOUND;
  
} /* search_index() */ 


/**********************************************************************
 * register_tables()
 *  Parses MIB information returned by IPAssists and registers OID 
 *  suffixes with net-snmp subagent driving code using the REGISTER_MIB
 *  macro. Also puts data from the MIB information returned by IPAssists
 *  into local data structures to maintain index information.
 *  
 *  This functions only maps the header of the IPAssists MIB info.
 *  The table data is parsed through the void mib_data_ptr.
 *
 *  IPAssists MIB information layout:
 *  
 *  header information:
 *  INOUT int request  
 *  INOUT int interface number/ifIndex
 *  INOUT int return code from IPAssists
 *  INOUT int IPAssists version
 *  INOUT int sequence number of this response
 *  OUT   int number of returned table information for that interface
 *  
 *  Repeated information:
 *  OUT string Toplevel OID for a table (including dots)
 *  OUT int    number of OID suffixes for that table
 *    
 *  Repeated OID suffix information for a single table and every index: 
 *  OUT int    object access type
 *  OUT int    object data type
 *  OUT string OID suffix for object
 *  OUT string OID index portion                                 
 *                                                                   
 *  parameters:
 *  IN  struct table:     MIB information returned by IPAssists 
 *  IN  TABLE_OID* lhead: head of toplevel OID linked list        
 *  returns: 0 - SUCCESS
 *          -1 - Registration not performed due to error; 
 *               an appropriate log entry is made                        
 *                                                                             
 *********************************************************************/
int register_tables ( void* mib_data,
                      TABLE_OID* lhead ) 
{ 
  int  i, j, suf_def, suf_cnt, src_oid, src_ind;   
  int  oid_len, oid_acc, oid_typ;         

  oid  t_oid[MAX_OID_LEN];           /* temporary net-snmp oid */
  oid  *top_oid;
  char *new_index;                         
  char toid_str[MAX_OID_STR_LEN];
  char time_buf[TIME_BUF_SIZE];   /* date/time buffer */
  
  IPA_CMD_REG *mib_data_hdr;      /* ptr to IPAssists hdr information */   
  char        *last_suffix;       /* last suffix in suffix list */
  void        *mib_data_ptr;      /* ptr to parse IPAssists MIB info */

  TABLE_OID      *oid_ptr, *ins_oid = NULL; /* ptr into Toplevel OID linked list */
  REG_INDICES    *ind_ptr;        /* ptr into index linked list */
 
  /* ptr to net-snmp variable13 structs that will contain the suffix
     information registered with subagent driving code */
  struct variable13 *table_vars, *new_area;

  /* point to beginning of MIB information (header) */
  mib_data_hdr = ( IPA_CMD_REG* ) mib_data;    

  /* set parse ptr behind header information; first Toplevel OID */ 
  mib_data_ptr = ( char* ) mib_data_hdr + sizeof( IPA_CMD_REG ); 

  /************************************/                                       
  /* loop through returned table data */
  /************************************/
  for ( i=0; i < mib_data_hdr->table_cnt; i++ ) {

    /****************************************************/
    /* get Toplevel oid that we want to register under  */
    /****************************************************/
    /* adjust parse ptr to next Toplevel OID (skip padding) */	  
    mib_data_ptr = (int*) (PTR_ALIGN4(mib_data_ptr));	  
    
    /* convert string OID to net-snmp oid type */
    strncpy( toid_str, (char*) mib_data_ptr, MAX_OID_STR_LEN ); 
    toid_str[ MAX_OID_STR_LEN-1 ] = '\0';
    oid_len = str_to_oid_conv( (char*) mib_data_ptr, t_oid ); 
    if ( oid_len == 0 ) {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, 
		"%s register_tables(): str to oid conversion failed "
		"(Toplvl OID) .%s\nOSA Subagent MIB information may be incomplete!\n"
		,time_buf, toid_str ); 
      return -1;
    } /* end if */

    /* save Toplevel OID in order to register it later */
    top_oid = (oid*) malloc ( oid_len * sizeof(oid) );
    if ( top_oid == NULL ) {
      get_time( time_buf );	    
      snmp_log( LOG_ERR, 
		"%s register_tables(): malloc() for variable top_oid failed\n"
		"register_tables(): Toplevel OID .%s\n"
		"OSA Subagent MIB information may be incomplete!\n", 
		time_buf, toid_str ); 
      return -1;
    } /* end if */
    memcpy( top_oid, t_oid, oid_len * sizeof(oid) );
    
    /* is retrieved Toplevel OID already in linked list? */
    src_oid = search_oid( top_oid, oid_len, lhead, &oid_ptr );
    if ( src_oid == UNEXP_ERROR ) { 
      get_time( time_buf );	    
      snmp_log( LOG_ERR, 
		"%s register_tables(): Unexpected return code from"
		" function search_oid() for Toplevel OID .%s\n"
		"OSA Subagent MIB information may be incomplete!\n", 
		time_buf, toid_str );
      free( top_oid ); 
      return -1;
    }

    /* put this Toplevel OID into the linked list, if OID was not found */
    else if ( src_oid == OID_NOT_FOUND ) { 
      ins_oid = oid_insert_after( top_oid, oid_len, oid_ptr );
      if ( ins_oid == NULL ) {
	get_time( time_buf );	      
	snmp_log( LOG_ERR, 
		  "%s register_tables(): malloc() for new entry in "
		  "OID list failed for Toplevel OID .%s\nOSA Subagent "
		  "MIB information may be incomplete!\n", time_buf, toid_str );
	free( top_oid ); 
	return -1;
      } /* end if */
    } /* end if */
    /* if OID was found, set insert OID to exact match OID */
    else   /* src_oid == OID_FOUND */
      ins_oid = oid_ptr;  
    
    /****************************************************************/
    /* add suffixes to variable_x structure for macro REGISTER_MIB  */
    /****************************************************************/
    last_suffix = NULL;                  /* initialize compare ptr */
    table_vars = NULL;                   /* initialize variable_x ptr */ 
    suf_def = 0;                         /* number of suffixes */
    
    /* point to suffix entries */
    mib_data_ptr += (strlen(mib_data_ptr)+1);
    mib_data_ptr = (int*) (PTR_ALIGN4(mib_data_ptr));

    /* get number of attached suffix OIDs */
    suf_cnt = *((int*) mib_data_ptr);       

    /* loop through suffix list */    
    for ( j=0;j < suf_cnt; j++ ) 
      {
	/* adjust parse ptr to access type 
	   (align pointer if it follows a string) */ 
	if ( j == 0 )
	  mib_data_ptr += sizeof( int );    
	else
	  {
	    mib_data_ptr += (strlen(mib_data_ptr)+1);
	    mib_data_ptr = (int*) (PTR_ALIGN4(mib_data_ptr));
	  } /* end if */

	/* save object access type for registering later */
	oid_acc = *((int*) mib_data_ptr); 

	/* adjust ptr and save object data type for registering later */
	mib_data_ptr += sizeof( int );    
	oid_typ = *((int*) mib_data_ptr); 

	/* adjust ptr to OID suffix string */
	mib_data_ptr += sizeof( int );    
        
        /* need to register suffixes only, if I have a new Toplevel OID */
        if ( src_oid == OID_NOT_FOUND ) {     

	  /* init last_suffix here, if loop entered the first time */
	  if ( j==0 )
	    last_suffix = (char*) mib_data_ptr;         

	  /* check wether last and current OID suffixes match */
	  /* yes-don't need to register suffix again, goto register index portion */
	  /* no -add suffix to variable_x list */
	  if ( (strcmp( last_suffix, (char*) mib_data_ptr ) !=0)  || j==0 )
	    {
	      suf_def++;      /* increase count of suffix definitions */
	      last_suffix = (char*) mib_data_ptr; /* save suffix */
            
	      /* allocate one entry within variable_x struct */
	      new_area = (struct variable13*) 
		          realloc( table_vars, suf_def * sizeof( struct variable13));
	      if ( new_area == NULL )
		{
		  get_time( time_buf );	
		  snmp_log( LOG_ERR, "%s register_tables(): "
			    "realloc() for variable_x structure failed\n"
			    "register_tables(): for Toplevel OID .%s\n"
			    "OSA Subagent MIB information may be incomplete!\n", 
			    time_buf, toid_str );
		 
		  /* remove all memory for this Toplevel OID allocated so far */ 
		  free(table_vars);
		  delete_oid( ins_oid->pObjid, ins_oid->length, lhead );
		  return -1;
		} /* end if */
              else
		/* reassign table_vars */
                table_vars = new_area;

	      /* convert suffix OID string to net-snmp oid type */
	      oid_len = str_to_oid_conv( (char*) mib_data_ptr, t_oid ); 
	      if ( oid_len == 0 ) {
		get_time( time_buf );      
		snmp_log( LOG_ERR, "%s register_tables(): "
			  "suffix str to oid conversion failed "
			  "for Toplevel OID .%s\nOSA Subagent MIB information may "
			  "be incomplete!\n", time_buf, toid_str );

		/* remove all memory for this Toplevel OID allocated so far */ 
		free(table_vars);
		delete_oid( ins_oid->pObjid, ins_oid->length, lhead );
		return -1;
	      } /* end if */
               
              /*******************************/
	      /* set up variable_x structure */
	      /*******************************/
	      table_vars[suf_def-1].magic = 0;            /* magic is not used */
                 
	      if ( oid_typ == IPA_DISPLAYSTR )            /* set object type */
		table_vars[suf_def-1].type = ASN_OCTET_STR;
	      else
		table_vars[suf_def-1].type = oid_typ;     

	      if ( oid_acc == IPA_WRONLY )                /* have no WRITE ONLY */
		table_vars[suf_def-1].acl =  RWRITE;      /* set to type RWRITE */
              else
		table_vars[suf_def-1].acl =  oid_acc;     /* set given object type */

	      if ( oid_typ == IPA_DISPLAYSTR )       /* set callback functions */
		table_vars[suf_def-1].findVar = var_DisplayStr;
	      else 
		table_vars[suf_def-1].findVar = var_ibmOSAMib;

	      table_vars[suf_def-1].namelen = oid_len;    /* OID suffix len */
	      if ( oid_len <= SUFFIX_MAXLEN )             /* set OID suffix */ 
	         memcpy( table_vars[suf_def-1].name, t_oid, oid_len * sizeof( oid ));
	      else 
		{
		  get_time( time_buf );	
		  snmp_log( LOG_ERR, 
			    "%s register_tables(): OID suffix length exceeded "
			    "for Toplevel OID .%s\nSuffix OID length %d\n"
			    "OSA Subagent MIB information may be incomplete!\n",
			    time_buf, toid_str, oid_len );

		  /* remove all memory for this Toplevel OID allocated so far */ 
		  free(table_vars);
		  delete_oid( ins_oid->pObjid, ins_oid->length, lhead );
		  return -1;
		} /* end if */
	    } /* end if  */
	} /* end if register_suffix part */

        /****************************************************************/
	/* add index to index linked list under this Toplevel OID entry */
        /****************************************************************/

        /* adjust ptr to index portion */
	mib_data_ptr = (char*) (mib_data_ptr + (strlen(mib_data_ptr)+1));
	
        /* search index list for this index */
	src_ind = search_index( (char*) mib_data_ptr, ins_oid->ind_list, &ind_ptr );

        /* if index is not found in the linked list, add index */
        if ( src_ind == INDEX_NOT_FOUND ) {
	  new_index = (char*) malloc( strlen( (char*) mib_data_ptr ) + 1 ); 
	  if ( new_index == NULL ) {
	    get_time( time_buf );	  
	    snmp_log( LOG_ERR, "%s register_tables(): "
		      "malloc() for new index entry failed\n"
		      "register_tables(): for Toplevel OID .%s\n"
		      "OSA Subagent MIB information may be incomplete!\n", 
		      time_buf, toid_str); 
	    if ( src_oid == OID_NOT_FOUND ) {
	      free(table_vars);
	      delete_oid( ins_oid->pObjid, ins_oid->length, lhead );
	    }
	    return -1;
	  } /* end if */

	  strcpy( new_index, (char*) mib_data_ptr );
	  index_insert_after( new_index,
				mib_data_hdr->ioctl_cmd.ipa_cmd_hdr.ifIndex,
				ind_ptr );
	} /* end if */	  

      } /* end for (j) */

    /* new Toplevel OID?: yes, then register with agent to add this table */
    /* note - register_mib() is taken from the net-snmp agent extension API */
    
    if ( src_oid == OID_NOT_FOUND )  
      {	    
        if ( register_mib( "ibmOSAMib",(struct variable*) table_vars, 
	    		   sizeof(struct variable13), suf_def,
			   top_oid, ins_oid->length ) != MIB_REGISTERED_OK )
	  { 
	    get_time( time_buf );	
	    snmp_log( LOG_ERR, "%s register_tables(): "
		      "API function register_mib() failed\n"
		      "register_tables(): for Toplevel OID .%s\n"
                      "OSA Subagent MIB information may be incomplete!\n",
		      time_buf, toid_str );
	    /* remove all memory for this Toplevel OID allocated so far */ 
	    free(table_vars);
	    delete_oid( ins_oid->pObjid, ins_oid->length, lhead );
	    return -1;
	  } /* end if */
        else
          {
	    get_time( time_buf );	
	    snmp_log( LOG_INFO, "%s registered Toplevel OID .%s\n",
    			    time_buf, toid_str );
          } /* end if */
      } /* end if */

    /* save variable_x ptr to free allocated memory later, if needed */
    ins_oid->var13ptr = table_vars; 
    
    /* adjust ptr to next Toplevel OID */
    mib_data_ptr = (char*) (mib_data_ptr + (strlen(mib_data_ptr)+1));
    
  } /* end for (i) */
  
  return 0;
  
} /* end register_tables() */
 

/************************************************************************
 * header_osa_table()
 * Compare 'name' to vp->name for the best match or an exact match.
 * Store result OID in 'name', including the index that matches best.
 * Return matching net-snmp ifIndex to caller.
 * 
 * parameters:
 * IN    struct variable *vp      - ptr to registered subagent MIB data
 * INOUT oid             *name    - fully instantiated OID name
 * INOUT size_t          *length  - length of this OID
 * IN    int             exact    - TRUE if an GET match is desired
 * OUT   size_t          *var_len - hook for size of returned data type
 * IN    WriteMethod     **write_method - hook for write method (UNUSED)
 * IN    TABLE_OID       *lhead   - ptr to Toplevel OID list head
 *
 * returns:
 *   ifIndex              - ifIndex in this OID 
 *   -1 (MATCH_FAILED)    - no suitable match found
 *
 ************************************************************************/
int header_osa_table( struct variable *vp, oid *name, size_t *length,
		      int exact, size_t *var_len, 
		      WriteMethod **write_method, TABLE_OID *lhead )
{
  int interface = -1;
  int   i, res, conv;
  size_t  index_len;              /* length of index portion */
  oid newname[MAX_OID_LEN];       /* temporary return OID */
  oid buffer[MAX_OID_LEN];        /* temporary converion buffer */
  char name_index[MAX_OID_STR_LEN]; 
  char time_buf[TIME_BUF_SIZE];   /* date/time buffer */
  
  /* ptr into OID and index linked lists */
  TABLE_OID   *ptr_oid;
  REG_INDICES *ptr_ind;

  int found_OID = FALSE;
 
  /* some debugging calls */
  DEBUGMSGTL(("ibmOSAMib-Subagent", "header_osa_table: "));
  DEBUGMSGOID(("ibmOSAMib-Subagent", name, *length));
  DEBUGMSG(("ibmOSAMib-Subagent"," exact=%d\n", exact)); 

  /* OID compare                      */
  /* set 'res' to -1  name < vp->name */
  /*               1  name > vp->name */
  /*               0  exact match     */ 
  for ( i=0, res=0; (i < (int) vp->namelen) && (i < (int) (*length)) && !res; i++ )
    {
      if ( name[i] != vp->name[i] ) {
	if ( name[i] < vp->name[i] )
	  res = -1;
	else 
	  res = 1;
      } /* end if */
    } /* end for */      

  DEBUGMSG(("ibmOSAMib-Subagent", " snmp_oid_compare: %d\n", res));
 
  /* (GETNEXT AND search OID still greater) OR (GET AND not-exact OIDs) */
  /* yes - indicate match failed */ 
  if ( (!exact && (res > 0)) || (exact && (res != 0)) ) {
    if (var_len)
      *var_len = 0;
     return MATCH_FAILED;
  } /* end if */
 
  /* init temporary return OID */
  memset(newname, 0, sizeof(newname));

  /******************************************/
  /* handle GET requests with matching OIDs */
  /******************************************/
  if ( exact && res == 0 )
    {
       /* got a too short OID */
      if ( (*length) <=  vp->namelen ) {
	if (var_len)
	  *var_len = 0;
 	return MATCH_FAILED;
      }
      else 
	/* determine length of attached index */
	index_len = (int) (*length) - (int) vp->namelen;
      
      DEBUGMSG(("ibmOSAMib-Subagent", 
		  " header_osa_table - GET index length: %zd\n", index_len));
 
      /* search our internal linked list for a matching Toplevel OID */
      res = search_top_oid ( (oid*) vp->name, (size_t) vp->namelen,
			     lhead, &ptr_oid );
      
      /* found a matching Toplevel OID, now look for index portion */
      if ( res == OID_FOUND ) {
	DEBUGMSGOID(("ibmOSAMib-Subagent:header_osa_table - Toplevel OID found", 
		     ptr_oid->pObjid, ptr_oid->length));

 	/* convert index portion to string */
	conv = oid_to_str_conv ( (oid*) &name[vp->namelen], 
				 index_len, name_index );
	DEBUGMSG(("ibmOSAMib-Subagent"," index portion=%s\n", name_index));

	if (conv == TRUE) {
	  res = search_index ( name_index,
			       (REG_INDICES*) ptr_oid->ind_list, &ptr_ind );

	  /* found a matching index, OID for GET request exists! */
	  if ( res == INDEX_FOUND ) {
	    DEBUGMSG(("ibmOSAMib-Subagent"," index found in linked list\n"));

 	    /* return appropriate ifIndex responsible for that OID */
	    interface = ptr_ind->ifIndex;
            
	    /* set up return OID */
	    memmove( newname, name, (*length) * sizeof(oid) );
	    
	    found_OID = TRUE;
	  } /* end if */
	} /* end if */
      } /* end if */
    } /* end if */

  /***************************/
  /* handle GETNEXT requests */
  /***************************/
  else if ( !exact && res <= 0 )
    {
      /* OID too short or switched to next suffix */
      /* adjust length and attach first index     */
      if ( (int) (*length) <= (int) vp->namelen || res < 0 )
	{
	  DEBUGMSG(("ibmOSAMib-Subagent", 
		      " GETNEXT - length <= vp->namelen OR snmp_oid_compare < 0"));
	  /* search our internal linked list for a matching Toplevel OID */
	  res = search_top_oid ( (oid*) vp->name, vp->namelen, lhead, &ptr_oid );
      
	  /* found a matching Toplevel OID, now look for index portion */
	  if ( res == OID_FOUND ) {
	    DEBUGMSGOID(("ibmOSAMib-Subagent:header_osa_table - Toplevel OID found", 
			 ptr_oid->pObjid, ptr_oid->length));
	    
	    /* set up return OID */
	    memmove( newname, vp->name, (int) vp->namelen * sizeof(oid) );
	    *length = vp->namelen;
	    
	    /* retrieve first index under this Toplevel OID and attach to newname */
	    if ( ptr_oid->ind_list->next != NULL ) {
	      index_len = str_to_oid_conv ( ptr_oid->ind_list->next->full_index, 
					    buffer );

	      if ( index_len != 0 && ( (vp->namelen + index_len) <= MAX_OID_LEN ) ) {
		memmove ( &newname[vp->namelen], buffer, index_len * sizeof(oid) );
		*length = *length + index_len;
		DEBUGMSG(("ibmOSAMib-Subagent"," index portion to attach=%s\n"
			  ,ptr_oid->ind_list->next->full_index ));

		/* return appropriate ifIndex responsible for that OID */
		interface = ptr_oid->ind_list->next->ifIndex;
	
		found_OID = TRUE;
	      } 
	      else
	      {
	        get_time( time_buf );	      
		snmp_log( LOG_ERR, "%s header_osa_table(): "
			  "(GETNEXT-1) index list corrupted\n"
	                  "OSA Subagent MIB information may be incomplete!\n", 
			  time_buf );
	      } /* end if */	
	    } /* end if */
	  } /* end if */
	} 
      /* 'true' GETNEXT case */
      else  
	{
	  DEBUGMSG(("ibmOSAMib-Subagent", 
		    " GETNEXT - length > vp->namelen"));
	  /* search our internal linked list for a matching Toplevel OID */
	  res = search_top_oid ( (oid*) name, (int) (*length), 
				 lhead, &ptr_oid );

	  /* found a matching Toplevel OID, now look for index portion */
	  if ( res == OID_FOUND ) {
	    DEBUGMSGOID(("ibmOSAMib-Subagent: "
			 "header_osa_table - Toplevel OID found", 
			 ptr_oid->pObjid, ptr_oid->length));
	    
	    /* search the index attached to 'name' in the index list */
	    /* determine length of attached index and convert to a string */
	    index_len = (int) (*length) - (int) vp->namelen;
	    conv = oid_to_str_conv ( (oid*) &name[vp->namelen], 
				     index_len, name_index );

	    if (conv == TRUE) {
	      res = search_index ( name_index, 
				   (REG_INDICES*) ptr_oid->ind_list, &ptr_ind );
	      
	      /* next index is the one we're looking for */
	      /* if next index is NULL; return MATCH FAILED(goto next suffix) */
	      if( ptr_ind->next != NULL ) {
		index_len = str_to_oid_conv( ptr_ind->next->full_index, buffer);

		if ( index_len != 0 && ( (vp->namelen + index_len) <= MAX_OID_LEN ) ) {
		  DEBUGMSG(("ibmOSAMib-Subagent"," index portion to attach=%s\n"
			    ,ptr_ind->next->full_index ));
		  
		  /* set up return OID */
		  *length = vp->namelen;
		  memmove( newname, name, vp->namelen * sizeof(oid) );
		  memmove( &newname[vp->namelen], buffer, index_len * sizeof(oid) );
		  *length = *length + index_len;

		  /* return appropriate ifIndex responsible for that OID */
		  interface = ptr_ind->next->ifIndex;
	
		  found_OID = TRUE;
		} /* end if */
		else
		{
		  get_time( time_buf );	
		  snmp_log( LOG_ERR, "%s header_osa_table(): "
			    "(GETNEXT-2) index list corrupted\n"
			    "OSA Subagent MIB information may be incomplete!\n", 
			    time_buf );
		} /* end if */
	      } /* end if */
	    } /* end */
	  } 
	  else
	  {
	    get_time( time_buf );	    
	    snmp_log( LOG_ERR, "%s header_osa_table(): "
		      "(GETNEXT-2) Toplevel OID not found\n"
		      "OSA Subagent MIB information may be incomplete!\n", 
		      time_buf );
	  } /* end if */
	} /* end if - handle GETNEXT requests */
    }

  /* return MATCH_FAILED, if no appropriate OID was found */
  if ( !found_OID )
    {
      if (var_len)
	*var_len = 0;
      return MATCH_FAILED;
    }
  else
    {
      /* finalize OID to be returned */
      memmove(name, newname, (*length) * sizeof(oid));
      if (write_method)
	*write_method = 0;
      if (var_len)
	*var_len = sizeof(long);   /* default data type long */

      return interface;
    } /* end if */

} /* end header_osa_table */

/************************************************************************
 * update_mib_info()
 * Whenever a network interface appears or disappears the MIB and/or 
 * interface information has to be updated, this fuction is called.
 *
 * parameters:
 *   none
 * returns:
 *   none
 *
 ************************************************************************/
void update_mib_info ()
{
	TABLE_OID *mib_info = oid_list_head;  

	char time_buf[TIME_BUF_SIZE];  /* date/time buffer */
  
	int i, retc,
		sd,           /* socket descriptors */
		error_code,       /* used to save errno */  
		if_num,           /* number of network interfaces */   
		osaexp_num;       /* number of OSA-E devices */

	struct ifreq ifr;             /* request structure for ioctl */
	IPA_CMD_REG* ipa_reg_mib;     /* structure for IPA REGISTER MIB command header */ 
	IF_LIST*     tmp_list;        /* temporary interfaces list */
	char*        buffer;          /* a data buffer */


	/* Retrieve ifNumber/ifIndex/ifDescr newly from IF-MIB for all interfaces */
	/* retrieve data in temporary list first */
	if_num = query_IF_MIB( &tmp_list );
	if ( if_num < 0 )
	{
		get_time( time_buf );        
		snmp_log( LOG_ERR, "%s update_mib_info(): "
			  "could not get interface info from IF-MIB\n"
			  "update_mib_info(): check previous messages for more details\n"
			  "update_mib_info(): keeping original interface lists\n",
			  time_buf );
		return; 
	}

	/* query OSA-E device driver for OSA-E devices 
	 * and mark them in IF-MIB interface list 
	 * */
	osaexp_num = query_OSA_EXP( &tmp_list, if_num );
	if ( osaexp_num == 0 )
	{
		get_time( time_buf );      
		snmp_log( LOG_ERR, "%s update_mib_info(): "
			  "no or bad OSA Express devices reported"
			  " - continue processing\n"
			  "update_mib_info(): "
			  "if available, see previous message for reason\n" 
			  "update_mib_info(): freeing interface lists\n",
			  time_buf );
		free( tmp_list );

		/* remove all index entries from Toplevel OID 
		 * linked list and store ifNumber 
		 * */
		clear_oid_list( mib_info );
		ifNumber = if_num;
	
		return;
	} /* end if */

    
    /* allocate area, that should contain retrieved MIB 
     * data for a single interface 
     * */
    buffer = (char*) malloc( MIB_AREA_LEN );
    if ( buffer == NULL )
      {
	get_time( time_buf );      
	snmp_log( LOG_ERR, "%s update_mib_info(): "
		  "malloc() for REGISTER MIB data buffer "
		  "failed\nupdate_mib_info(): requested %d bytes\n"
		  "update_mib_info(): keeping original interface lists\n",
		  time_buf, MIB_AREA_LEN );
	free( tmp_list );
	return;
      } /* end if */

    /* socket for query MIB information ioctl */
    sd = socket( AF_INET, SOCK_STREAM, 0 );
    if ( sd < 0 )
      {
	error_code = errno;
	get_time( time_buf );
	snmp_log(LOG_ERR, "%s update_mib_info(): "
		 "error opening socket() - reason %s\n"
		 "update_mib_info(): cannot update OSA-E MIB information\n"
		 "update_mib_info(): keeping original interface lists\n",
		 time_buf, strerror( error_code ) );
	free( tmp_list );
	free( buffer );
	return;
      } /* end if */

    /* free original interface list and assign the new one (global data) */
    if ( if_list != NULL )
      free( if_list );
    
    ifNumber = if_num;
    if_list = tmp_list;

    /* free entire MIB lists that we maintain so far */ 
    clear_oid_list( mib_info ); 

    /* walk through interface list and query MIB data 
     * for all OSA-E devices register MIB data with 
     * subagent driving code afterwards               
     * */  
    for ( i=0; i < ifNumber; i++ )
      {
	if ( if_list[i].is_OSAEXP == TRUE )
	  {
	    /* clear buffer */
	    memset( buffer, 0, MIB_AREA_LEN ); 
	    
	    /* setup ioctl buffer with request and input parameters */
	    /* map command structure */
	    ipa_reg_mib = (IPA_CMD_REG*) buffer;
           
	    /* size of IPA data area */
	    ipa_reg_mib->ioctl_cmd.data_len  =                  
	      MIB_AREA_LEN - offsetof( IOCTL_CMD_HDR, ipa_cmd_hdr );

	    /* length of IPA subcommand */	    
	    ipa_reg_mib->ioctl_cmd.req_len =                  
	      sizeof( ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr );  
	    
	    /* set input parameters for IPA Register MIB command */
	    ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.request  = IPA_REG_MIB;        
	    ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ifIndex  = if_list[i].ifIndex; 
	    ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code = 0;
	    ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.seq_num  = 0;                  	    
    
	    /* do ioctl() */
	    strcpy( ifr.ifr_name, if_list[i].if_Name );         /* add interface name */       
	    ifr.ifr_ifru.ifru_data = (char*) buffer;            /* add data buffer    */ 
	
	    if ( ioctl( sd,SIOC_QETH_ADP_SET_SNMP_CONTROL, &ifr ) < 0 )
	      {
		error_code = errno;
		get_time( time_buf );

                /* see if we got a common I/O error */
                if ( error_code == -EIO )
                  {
                     snmp_log( LOG_ERR, "%s update_mib_info(): "
			       "ioctl() failed - reason %s for interface %s\n"
                               "update_mib_info(): "
			       "MIB information may be incomplete\n",
                               time_buf, strerror( error_code ),
			       if_list[i].if_Name );
                     continue;
                     break;
                  } /* end if */
		
		/* let's see, if we got a return code from IPAssists */
		/* or if MIB buffer is exhausted */
		switch ( ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code ) {
		case IPA_FAILED:
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "ioctl() failed - IPA command failed\n"
			    "update_mib_info(): for interface %s\n"
			    "update_mib_info(): MIB information may be incomplete\n",
			    time_buf, if_list[i].if_Name );
		  continue;
		  break;
		  
		case IPA_NOT_SUPP:
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "ioctl() failed - IPA command not supported\n"
			    "update_mib_info(): for interface %s\n"
			    "update_mib_info(): MIB information may be incomplete\n", 
			    time_buf, if_list[i].if_Name );
		  continue;
		  break;
		
		case IPA_NO_DATA:
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "ioctl() failed - valid IPA command, but no"
			    "SNMP data is available for interface %s\n"
			    "update_mib_info(): MIB information may be incomplete\n", 
			    time_buf, if_list[i].if_Name );
		  continue;
		  break;
		  
		case -ENOMEM: /* should not happen in the near future ;-) */
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "ioctl() failed - MIB data size > "
			    "constant MIB_AREA_LEN for interface %s\n"
			    "update_mib_info(): "
			    "Enlarge constant for MIB_AREA_LEN "
			    "within ibmOSAMibDefs.h and "
			    "recompile the subagent\n"
			    "update_mib_info(): MIB information may be incomplete\n",
			    time_buf, if_list[i].if_Name );
		  continue;
		  break;
		  
		default:
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "ioctl() failed - reason %s "
			    "for interface %s\n"
			    "update_mib_info(): MIB information may be incomplete\n",
			    time_buf, strerror( error_code ), if_list[i].if_Name );
		  continue;
		  break;
		} /* end switch */
	      } 
	    else if ( ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code != 0 )
	      {
		get_time( time_buf );      
		
		/* now check IPA SNMP subcommand return code */
		switch ( ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code ) {
		  
		case IPA_SNMP_INV_TOPOID: 
		case IPA_SNMP_INV_GROUP: 
		case IPA_SNMP_INV_SUFFIX:
		case IPA_SNMP_INV_INST:
		case IPA_SNMP_OID_NREAD:
		case IPA_SNMP_OID_NWRIT:
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "IPA SNMP subcommand failed - "
		            "return code 0x%x for interface %s\n"
			    "update_mib_info(): MIB information may be incomplete\n",
			    time_buf, 
			    ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code, 
			    if_list[i].if_Name );
		  continue;
		  break;
		  
		case IPA_SNMP_NOT_SUPP:
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "IPA SNMP subcommand failed - "
			    "subcommand 0x%x for interface %s\n"
			    "update_mib_info(): MIB information may be incomplete\n",
			    time_buf, 
			    ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.request, 
			    if_list[i].if_Name );
		  continue;
		  break;
		
		case IPA_SNMP_NO_DATA:
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "IPA SNMP subcommand failed - "
			    "no data available for interface %s\n"
			    "update_mib_info(): MIB information may be incomplete\n",
			    time_buf, if_list[i].if_Name );
		  continue;
		  break;
		  
		default:
		  snmp_log( LOG_ERR, "%s update_mib_info(): "
			    "IPA SNMP subcommand failed - "
	   		    "undefined return code 0x%x for interface %s\n"
			    "update_mib_info(): MIB information may be incomplete\n",
			    time_buf, 
			    ipa_reg_mib->ioctl_cmd.ipa_cmd_hdr.ret_code, 
			    if_list[i].if_Name );
		  continue;
		  break;
		  
		} /* end switch */
		
	      } /* end if */

	    /* register MIB tables information, that we got from IPAssists */
	    retc = register_tables ( buffer, mib_info );
	    if ( retc != 0 )
	      {
		get_time( time_buf );      
		snmp_log( LOG_ERR, "%s update_mib_info(): "
			  "register MIB data with subagent "
			  "driving code failed\nupdate_mib_info(): for interface %s\n"
			  "update_mib_info(): check previous messages for "
			  "more details\nupdate_mib_info(): MIB information may be "
			  "incomplete\n", time_buf, if_list[i].if_Name );
		continue;
	      } /* end if */
	    
	  } /* end if */
	    
      } /* end for */ 
 
    get_time( time_buf );
    snmp_log( LOG_INFO, "%s *** OSA-E interface change indicated ***\n"
		        "%s *** Reinitialized MIB information ***\n",
			time_buf, time_buf );
    
    close( sd );
    free( buffer );
} /* end update_mib_info */


/**********************************************************************
 * query_IF_MIB():
 *  Retrieve ifIndex values for all OSA devices residing on this    
 *  system. Use SNMP to query the master agent for ifNumber and 
 *  ifIndex/ifDescr values from the standard IF-MIB.
 *  Then figure out which of these devices are OSA Express devices.
 *  parameters:
 *  INOUT IF_LIST** ifList: List of network interfaces on this system  
 *  returns: int if_Number - number of network interfaces on this system 
 *                          system  (>=0)
 *                          -1 -an error occurred , no valid info avail
 *********************************************************************/
int query_IF_MIB ( IF_LIST** ifList )
{
  
  char   time_buf[TIME_BUF_SIZE];  /* date/time buffer */
  
  /* data structures for SNMP API */ 
  struct snmp_session session, *ss;
  struct snmp_pdu *pdu;
  struct snmp_pdu *response;
  struct variable_list *vars;
  void   *sessp;
  int status, have_info, valid;
  
  /* define static OIDs for if_Number, ifIndex and ifDescr from IF-MIB */
  size_t ifNumber_OIDlen   = 9,
         ifIndex_OIDlen    = 11,
         ifDescr_OIDlen    = 11;
  oid    ifNumber_OID[9]   = { 1,3,6,1,2,1,2,1,0 },
         ifIndex_OID[11]   = { 1,3,6,1,2,1,2,2,1,1,0 },
	 ifDescr_OID[11]   = { 1,3,6,1,2,1,2,2,1,2,0 };
	 
  int i, if_Number, count;      

  /* Initialize the SNMP library */
  DEBUGMSGTL(("query_IF_MIB"," about to query IF-MIB information using SNMP\n"));    
  
  /* Initialize a "session" for localhost */
  have_info = TRUE;
  valid = TRUE;
  if_Number = 0;
  snmp_sess_init( &session );                                           
  session.peername  = NET_SNMP_PEERNAME;       
  session.version   = SNMP_VERSION_2c;      /* use SNMPv2c */
  /* SNMPv2c community name */
  session.community = (unsigned char*)NET_SNMP_COMMUNITY;
  session.community_len = strlen((const char*)session.community);
  session.timeout = 300 * 1000000L;
   
  /* Open the session */
  sessp = snmp_sess_open( &session );                               
  if ( sessp == NULL ) {
    get_time( time_buf );	  
    snmp_log(LOG_ERR,
	     "%s query_IF_MIB(): snmp_sess_open() failed\n", time_buf );
    return -1;                                                
  } /* end if */
 
  ss = snmp_sess_session( sessp );
  
  /* Create and send synchronous GET PDU for if_Number */
  pdu = snmp_pdu_create(SNMP_MSG_GET);
  snmp_add_null_var( pdu, ifNumber_OID, ifNumber_OIDlen );
  status = snmp_sess_synch_response( sessp, pdu, &response);
  
  /* Process the response and get ifIndex/ifDescr table entries */
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
    {    
      /* get value for if_Number */
      if ( response->variables->val.integer == NULL )
        {
           get_time( time_buf );
	   snmp_log(LOG_ERR, "%s query_IF_MIB(): Get(if_Number) Error in packet\n"
	                     "Reason: response->variables->val.integer == NULL\n",
			     time_buf);
           snmp_free_pdu(response);
           return -1;	   
        } /* end if */	
      
      count = (int) *(response->variables->val.integer);
      snmp_free_pdu(response);
      
      if ( count == 0 )
	{
	  snmp_sess_close( sessp );
	  return 0;
	} /* end if */

      /* allocate memory for interface list */
      *ifList = (IF_LIST*) malloc((sizeof(IF_LIST) * count));
      if (*ifList == NULL)
	{
	  get_time( time_buf );	
	  snmp_log(LOG_ERR, 
		   "%s query_IF_MIB(): malloc() for ifList structure failed!\n", 
		   time_buf);
	  snmp_sess_close( sessp );
	  return -1;
	} /* end if */
      
      /* if have interfaces, issue GETNEXT PDUs for ifIndex/ifDescr table entries */
      for ( i=0; i < count; i++ )
	{
	  pdu = snmp_pdu_create( SNMP_MSG_GETNEXT );
	  snmp_add_null_var( pdu, ifIndex_OID, ifIndex_OIDlen  );
	  snmp_add_null_var( pdu, ifDescr_OID, ifDescr_OIDlen  );
	  status = snmp_sess_synch_response( sessp, pdu, &response );   
	   
	  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)
	    {
	      /* set device to default value false; 
	       * device type is determined later 
	       * */
	      (*ifList)[i].is_OSAEXP = FALSE;
	      (*ifList)[i].kerIndex = 0;
	      (*ifList)[i].ifIndex = 0;

	      /* get values for ifIndex/ifDescr from response PDU 
	       *  FIXME: (workaround) compare ifDescr values 
	       *  and omit double entries 
	       *  */ 
	      for(vars = response->variables; vars; vars = vars->next_variable)
		{
		  if( vars->type == ASN_INTEGER ) 
		    (*ifList)[if_Number].ifIndex = (int) *(vars->val.integer);
		  else if( vars->type == ASN_OCTET_STR  
			   && vars->val_len <= IFNAME_MAXLEN ) 
	          {
		    if ( if_Number == 0 )
		      {	   
		         strncpy((char*)((*ifList)[0]).if_Name,
				 (const char*)vars->val.string, vars->val_len);
			 (*ifList)[0].if_Name[vars->val_len] = '\0';
		      }
	   	    else
		      {
                        if (strncmp((const char*)(*ifList)[if_Number-1].if_Name,
				    (const char*)vars->val.string,
			  	     vars->val_len) !=0)
		          {
		            strncpy((char*)(*ifList)[if_Number].if_Name,
				    (const char*)vars->val.string,
				     vars->val_len);
	                    (*ifList)[if_Number].if_Name[vars->val_len] = '\0';
			    valid = TRUE;
                          }
		        else 
			  valid = FALSE;	
                      } /* end if */			
   		  }
		  else 
		  {
		    get_time( time_buf );	  
		    snmp_log(LOG_ERR, "%s query_IF_MIB(): GetNext(ifIndex;ifDescr)"
			     " response PDU has invalid data\n", time_buf );
		    free( *ifList ); 
		    snmp_free_pdu(response);
		    snmp_sess_close( sessp );
		    return -1;
		  } /* end if */
		} /* end for */
	      if ( valid == TRUE ) 
		if_Number++;      
	    }
	  else
	    {
	      /* FAILURE GETNEXT */
	      if (status == STAT_SUCCESS)
	      {  
		get_time( time_buf );      
		snmp_log(LOG_ERR, "%s query_IF_MIB(): GetNext(ifIndex,ifDescr) "
			 "Error in packet\n"
			 "Reason: %s\n",time_buf, snmp_errstring(response->errstat));
	      }
	      else
		snmp_sess_perror("query_IF_MIB(): GetNext(ifIndex;ifDescr)", ss);
	      if (response)
		snmp_free_pdu(response);
	      free( *ifList );
	      
	      have_info = FALSE;
	      break;
	    } /* end if */
	  
	  /* store current ifIndex in OIDs for next GetNext request */
	  ifIndex_OID[ifIndex_OIDlen-1] = (*ifList)[i].ifIndex;
	  ifDescr_OID[ifDescr_OIDlen-1] = (*ifList)[i].ifIndex;
	  
	  snmp_free_pdu( response );
	  
	} /* end for */
    }
  else
    { 
      /* FAILURE GET if_Number */
      if (status == STAT_SUCCESS)
      {
	get_time( time_buf );      
	snmp_log(LOG_ERR, "%s query_IF_MIB(): Get(if_Number) Error in packet\n"
		 "Reason: %s\n", time_buf, snmp_errstring(response->errstat));
      }	
      else
	snmp_sess_perror("query_IF_MIB(): Get(if_Number)", ss);
      
      if (response)
	snmp_free_pdu(response);
      have_info = FALSE;
    } /* end if */
  
  /* Cleanup */
  snmp_sess_close( sessp );
  if ( have_info )
    return ( if_Number );
  else
    return -1;

} /* end query_IF_MIB() */


/**********************************************************************
 * query_OSA_EXP():
 *  Retrieve device characteristics for OSA Express devices and mark
 *  OSA Express devices in the interface list from IF-MIB.    
 *  parameters:
 *  INOUT IF_LIST** ifList: List of network interfaces on this system 
 *  IN    int       if_Number: number of network interfaces
 *  returns: int num - number of OSA Express devices found on this 
 *                          system  (>=0)
 *********************************************************************/
unsigned int query_OSA_EXP ( IF_LIST** ifList, int if_Number )
{
  int j, num = 0;  
  char            time_buf[TIME_BUF_SIZE];  /* date/time buffer */
  int sd;
  struct ifreq ifr;
  /*open socket to get information if device is an OSA device*/ 
  if ( (sd = socket(AF_INET,SOCK_STREAM,0)) < 0 ) {
	snmp_log( LOG_ERR,"%s query_OSA_EXP(): " 
			  "socket  failed\n"
			  "query_OSA_EXP(): cancel init or update "
			  "of MIB information\n",time_buf );
	return 0;
  }
  
  /* walk through IF-MIB interface list and mark OSA Express interfaces */
  for ( j=0; j < if_Number; j++ ) {
	int ret=0;

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name, (*ifList)[j].if_Name,IFNAME_MAXLEN);
        ret = ioctl(sd, SIOC_QETH_GET_CARD_TYPE, &ifr);
	if (ret>0) {
      		(*ifList)[j].is_OSAEXP = TRUE;
		(*ifList)[j].kerIndex  = (*ifList)[j].ifIndex;
      		num++;
        }
  } /* end for */
  close(sd);
  
  return num;
} /* end query_OSA_EXP() */ 


/********************************************************************** 
 * get_time():
 *  gets current time of day string and returns it as
 *  MONTH DAY HH:MM:SS
 *  returns: string with date and time 
 *********************************************************************/
int get_time( char* buffer )
{
  
  time_t curtime;
  struct tm *loctime;

  curtime = time(NULL);
  loctime = localtime( &curtime );
  
  strftime( buffer, TIME_BUF_SIZE, "%b %d %T", loctime );
  
  return 0;
  
} /* end get_time () */

static const char* usage_text[] = {
"Usage:  osasnmpd [-h] [-v] [-l LOGFILE] [-A] [-f] [-L] [-P PIDFILE]",
"                 [-x SOCKADDR]",
"",
"-h, --help              This usage message",
"-v, --version           Version information",
"-l, --logfile LOGFILE   Print warnings/messages to LOGFILE",
"-A, --append            Append to the logfile rather than truncating it",
"-L, --stderrlog         Print warnings/messages to stdout/err",
"-f, --nofork            Do not fork() from the calling shell",
"-P, --pidfile PIDFILE   Save the process ID of the subagent in PIDFILE",
"-x, --sockaddr SOCKADDR Bind AgentX port to this address",
""
};

/**********************************************************************
 * usage():
 *  prints help message with descriptions of available parameters    
 *  IN name of subagent                                                
 *  returns: none                                                    
 *********************************************************************/
void usage()
{
	unsigned int i;

	for (i=0; i < sizeof(usage_text) / sizeof(usage_text[0]); i++)
		printf("%s\n", usage_text[i]);
	exit(0);
  
} /* end usage() */
