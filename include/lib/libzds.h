/**
 * \file libzds.h
 * This is the main header file for the internal library libzds.
 * Please note that this library should currently only be used
 * by programs in the s390-tools package. It is not yet meant
 * for external use as interfaces and definitions may change
 * without further notice.
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/**
 * @mainpage
 * The libzds is a s390-tools internal library for use with DASD
 * devices in raw_track_access mode.
 *
 * The regular operation mode of the DASD device driver allows only to
 * access ECKD DASDs that were formatted with a specific record
 * layout.  The raw access mode of the DASD device driver allows to
 * access any kind of ECKD DASD, but requires the correct use of
 * the DIRECT_IO interface and leaves the interpretation of the data
 * format on these devices to the user.
 *
 * This library supports the use of raw DASD devices by providing
 * functions that
 * @li access the device with DIRECT_IO and the correct buffer alignment
 * @li provide access to label and VTOC data on the device
 * @li provide access to simple z/OS data set formats
 *     (physical sequential (PS) and partitioned data sets (PDS))
 *
 *
 * @section interface_groups Library Interface
 *
 * @subsection interface_structures Data Structures
 *
 * The data structures provided by this library can be divided into
 * two types: Structures that represent external hardware and software
 * interfaces, and structures that are defined by libzds itself:
 *
 * @ref external_interfaces
 *
 * @ref libzds_data
 *
 *
 * @subsection interface_functions Functions
 *
 * The functions provided by this library are divided into 5 categories:
 * base, low, mid, and highlevel functions and helper functions.
 *
 * The lower the level, the less dependent are the functions on the data
 * that is stored on the DASDs. The higher the level the more abstract
 * are the implemented concepts.
 *
 * The base level functions are needed to setup the internal data
 * structures which the other functions work on. Otherwise, he use of higher
 * level functions does not require the use of low level functions.
 * For example: To simply read data from a data set, you just need the
 * base and high level functions and can ignore the low and mid level
 * functions.
 *
 * \ref libzds_functions_base
 *
 * \ref libzds_functions_low
 *
 * \ref libzds_functions_mid
 *
 * \ref libzds_functions_high
 *
 * \ref libzds_functions_helper
 *
 *
 * @section naming_scheme Naming Scheme
 *
 * All interface functions start with lzds_ for libzds (could be changed later
 * but libzds_ is quite long). Next is the entity the function works on,
 * for example
 * @li @c lzds_zdsroot_...
 * @li @c lzds_dasd_...
 *
 * So if you know what entity you want to work on, you know where to look.
 *
 * Then follows the operation (add, get, read, alloc, ...).
 * There are several verbs that can mean 'access data'.
 * As a guideline we define the following meaning for use in this library:
 * @li read: Will result in data being read from a device
 * @li get: Get a value from one of the internal structures
 * @li extract: Use the internal data to create higher level data,
 *              e.g. use the VTOC information of a DASD to create data
 *              set structures
 * @li alloc: Create and return a libzds data structure
 *
 * @note For every alloc function there shall be a matching free function to
 * release the memory. However, often the structure is created in the
 * context of a another structure, but when it is freed, that is done in
 * its own context. For example:
 * lzds_zdsroot_alloc_dasditerator is matched by lzds_dasditerator_free
 *
 * Finally the object of the operation, what you want to get or achieve,
 *  e.g lzds_ds_get_is_PDS
 *
 * For the parmeter list, the general rule is:
 * The subject comes first, the object last, further parameters in between.
 */


#ifndef LIB_LIBZDS_H
/**
 * @brief Watchdog for libzds.h inclusion.
 */
#define LIB_LIBZDS_H

#include "lib/util_base.h"
#include "lib/util_list.h"
#include "vtoc.h"
#include <iconv.h>


/**
 *  \defgroup external_interfaces  External constants and structures.
 *  @{
 *  @brief These constants and structures are related to
 *         hardware and software interfaces that are specified outside of
 *         libzds.
 *
 * @li For a description of ECKD data formats see
 * 'IBM 3990/9390 Storage Control Reference', Document Number GA32-0274-05
 * @li For a description of VTOC entries see
 * 'z/OS DFSMSdfp Advanced Services', Document Number SC26-7400-11
 * @li For a description of physical sequential and partitioned data sets see
 * 'z/OS DFSMS Using Data Sets', Document Number SC26-7410-11
 * @li For a description of the Linux on System z DASD device driver see
 * 'Device Drivers, Features, and Commands (kernel 3.7)',
 * Document Number SC33-8411-18
 */


/**
 * @brief The size of one raw track when read via the DASD device driver
 *        with raw_track_access.
 *
 *        When reading from a DASD in raw_track_access mode, you need to
 *        align your I/O to multiples of this size.
 */
#define RAWTRACKSIZE 65536

/**
 * @brief Maximum size of one record on a track
 *
 * This is the maximum size of a single record on a track. If a track contains
 * multiple records, the additional overhead will cause the sum of these
 * multiple records to be smaller than the biggest single record, so MAXRECSIZE
 * is also the upper limit for user data that a single track can hold.
 */
#define MAXRECSIZE 56664


/**
 * @brief Maximum number of extents a data set can hold.
 *
 * We do not handle extended format data sets so we can have a total of 16
 * extents per dataset (3 in the f1 and 13 in the f3 label).
 */
#define MAXEXTENTS 16


/**
 * @brief Maximum size of a data set name string (including one byte for
 * 0-termination)
 */
#define MAXDSNAMELENGTH 45

/**
 * @brief Maximum size of a partitioned data set member name string
 *        (including one byte for 0-termination)
 */
#define MEMBERNAMELENGTH 9

/**
 * @brief The maximum number of volumes (devices) that a multi volume data
 * set can span.
 */
#define MAXVOLUMESPERDS 59

/**
 * @brief Eight bytes of 0xFF are used in several cases to designate the end of data.
 *
 */
#define ENDTOKEN 0xFFFFFFFFFFFFFFFFULL


#define MAX_LINE_LENGTH 512
#define MAX_SERVER 3

/**
 * @brief This structure represents the count field in an ECKD record.
 */
struct eckd_count {
	/** @brief record ID
	 *
	 * In general the record ID is defined as just a 5 byte field.
	 * The interpretation of these 5 bytes as a struct cchhb_t is a common
	 * convention, which we assume here as well.
	 */
	cchhb_t recid;
	/** @brief key length */
	unsigned char kl;
	/** @brief data length */
	unsigned short dl;
} __attribute__ ((packed));

/**
 * @brief A generic structure to describe a data set control block (DSCB)
 *
 * The elements of the VTOC are called DSCBs. All DSCBs have in common that
 * they have a size of 140 bytes, and byte 44 is the identifier that
 * determines the type of DSCB.
 */
struct dscb {
	/** @brief key area
	 *
	 *  This part of the DSCB is usually stored in the key part of an
	 *  ECKD record in the VTOC. The contents depends on the format.
	 */
	char key[44];
	/** @brief Format identifier
	 *
	 *  This identifier determines the data layout of the rest of the
	 *  DSCB. In a format-x DSCB this field is called DSxFMTID.
	 *  The identifiers for format-1 to format-9 are the respective
	 *  EBCDIC characters '1' to '9' (0xf1 to 0xf9).
	 *  An empty DSCB record (format-0 DSCB) contains 140 zeros, so
	 *  here the format id is 0x00.
	 */
	char fmtid;
	/** @brief The residual data part of the DSCB
	 *
	 *  The contents depends on the format.
	 */
	char data[95];
} __attribute__ ((packed));


/**
 * @brief This structure represents a segment descriptor word (SDW),
 * record descriptor word (RDW) or block descriptor word (BDW).
 *
 * These are used to describe data set blocks and records.
 * (see z/OS DFSMS Using Data Sets)
 */
struct segment_header {
	/** @brief Is this an empty segment (valid for SDW) */
	unsigned short nullsegment:1;
	/** @brief Length of the segment */
	unsigned short length:15;
	/** @brief reserved */
	unsigned char reserved1:6;
	/** @brief Segment control code (valid for SDW)
	 *
	 * 0: logical record consists of just this segment,
	 * 1: first segment in the logical record,
	 * 2: last segment in the logical record,
	 * 3: intermediate in the logical record
	 */
	unsigned char position:2;
	/** @brief reserved  */
	unsigned char reserved3:8;
} __attribute__ ((packed));



/**
 * @brief The key length of a PDS directory member record.
 */
#define PDS_DIR_KL 8
/**
 * @brief The data length of a PDS directory member record.
 */
#define PDS_DIR_DL 256

/**
 * @brief This structure represents and entry in the PDS directory and
 * describes a member of the data set.
 *
 * This structure represents only the fixed part of the member
 * entry. The variable size of the user data part is determined
 * by the entry user_data_count.
 * (see z/OS DFSMS Using Data Sets)
 */
struct pds_member_entry {
	/** @brief Member name */
	char name[8];
	/** @brief Start track of the member (relative to start of the PDS) */
	unsigned short track;
	/** @brief Start record of the member */
	unsigned char record;
	/** @brief Is this entry an alias for another entry? */
	unsigned char is_alias:1;
	/** @brief How many TTRN note lists are contained in the user data. */
	unsigned char ttrn_count:2;
	/** @brief The user_data_count value counts 'half words' i.e. shorts! */
	unsigned char user_data_count:5;
} __attribute__ ((packed));


/**  @} */ /* end of group hardware */



/**
 * @defgroup libzds_data libzds data structures
 * @{
 * @brief These are the data structures used by the libzds API.
 *
 * For users of libzds these are opaque data structures and they have
 * no dependency on the implementation details of these structures.
 * All libzds interface functions work on pointers to these structures,
 * so programs that use the library do not need to know them either.
 * This prevents users from accessing the data in unsupported ways
 * allows us to change the implementation without changing the
 * interface.
 */

/**
 * @struct zdsroot
 * @brief The root of all device and data set information.
 *
 *        Note that data sets do not belong to DASDs, as they
 *        may span over more than one DASD.
 */
struct zdsroot;

/**
 * @struct raw_vtoc
 * @brief The VTOC is a directory of data sets on one DASD
 *
 * As the VTOC is the data area on the DASD that describes all data sets,
 * this library will often have to refer to the various records in the VTOC.
 * To make this more efficient, we will read the whole VTOC once and identify
 * all elements (DSCBs). The raw data of the VTOC tracks and the index to the
 * DSCBs is stored.
 */
struct raw_vtoc {
	/** @brief The raw track data  */
	char *rawdata;
	/** @brief This size of the raw track data in bytes */
	unsigned long long rawdatasize;
	/** @brief An array with pointers to the various DSCBs in the rawdata */
	char **vtocindex;
	/** @brief Number of entries in the index */
	unsigned int vtocindexcount;
	/** @brief Number of records per VTOC track
	 *
	 *  @note While the DS4DEVDT field in the format 4 DSCB names the number
	 *  if DSCBs per VTOC track, we count the records, which is DS4DEVDT + 1
	 *  for record 0.
	 */
	unsigned int vtoc_rec_per_track;
	/** @brief The track number at which the vtoc begins on the DASD */
	unsigned int vtoctrackoffset;
	/** @brief Start record of VTOC.
	 *
	 *  The rawdata contains full tracks. This is the number of the first
	 *  record that actually belongs to the VTOC
	 */
	unsigned int vtocrecno;
	/** @brief The DASD this vtoc was read from */
	struct dasd *dasd;
	/** @brief Detailed error messages in case of a problem */
	struct errorlog *log;
};

/**
 * @struct dasd
 * @brief Represents one physical device, may have a vtoc
 */
struct dasd {
	/** @brief List head used to store a list of DASDs in struct zdsroot */
	struct util_list_node list;
	/** @brief Name of the block device, e.g. /dev/dasde */
	char *device;
	/** @brief File descriptor for the block device.
	 *
	 * The device is kept open for as along as the library uses it.
	 * This lets the system know that the device is still in use.
	 */
	int inusefd;
	/* @brief where to find the volume label */
	unsigned int label_block;
	/** @brief Device geometry. How many cylinders does the DASD have. */
	unsigned int cylinders;
	/** @brief Device geometry. How many heads does the DASD have. */
	unsigned int heads;
	/** @brief The VTOC data that has been read from this device */
	struct raw_vtoc *rawvtoc;
	/** @brief The volume label that has been read from this device */
	volume_label_t *vlabel;
	/** @brief Detailed error messages in case of a problem */
	struct errorlog *log;
};

/**
 * @struct dasditerator
 * @brief Allows to iterate over all dasds in the zdsroot
 */
struct dasditerator;

/**
 * @struct dasdhandle
 * @brief Represents the state of a DASD device while it is in use.
 *
 * For applications that need to read data directly from a DASD device.
 * The idea is to have an abstract handle for a DASD that is in
 * use, similar to a FILE pointer
 */
struct dasdhandle;

/**
 * @struct dscbiterator
 * @brief  allows to iterate over all DSCBs in a vtoc
 */
struct dscbiterator;

/**
 * @struct dataset
 * @brief The whole of one data set
 *
 * May refer to one or more dataset parts
 * and may have a list of partitioned dataset members.
 */
struct dataset;

/**
 * @struct dsiterator
 * @brief Allows to iterate over all data sets in the zdsroot
 */
struct dsiterator;

/**
 * @struct pdsmember
 * @brief If a data set is a partitioned data set (PDS) it
 *        may have zero or more PDS members
 */
struct pdsmember;

/**
 * @struct memberiterator
 * @brief Allows to iterate over all members in the dataset
 */
struct memberiterator;

/**
 * @struct dshandle
 * @brief Represents the state of a data set while it is in use
 *
 * This state includes the I/O buffers used for reading,
 * the position within the data set, options used for processing the data,
 * etc. The idea is to have an abstract handle for a data set that is in
 * use, similar to a FILE pointer.
 */
struct dshandle;

/**
 * @struct error_log
 * @brief A stack of error messages that are related to the last error
 */
struct errorlog;

/**  @} */ /* end of group libzds_data */




/**
 * @defgroup libzds_functions_base  Base functions
 * @{
 * @brief These functions are basic setup functions which need to
 *        be used before any of the low, mid or high level functions
 *        can be used. These functions concern the allocation and
 *        initialization of the zdsroot and the basic handling of devices.
 */

/**
 * @brief Allocate a new zdsroot structure.
 */
int lzds_zdsroot_alloc(struct zdsroot **root);

/**
 * @brief Free the memory of the given zdsroot structure.
 */
void lzds_zdsroot_free(struct zdsroot *root);

/**
 * @brief Add a DASD device to the zdsroot.
 */
int lzds_zdsroot_add_device(struct zdsroot *root, const char *devnode,
			    struct dasd **dasd);
/**
 * @brief Get the errorlog.
 */
void lzds_dasd_get_errorlog(struct dasd *dasd, struct errorlog **log);

/**
 * @brief Allocate index that allows to iterate through all DASDs
 *        stored in the root.
 */
int lzds_zdsroot_alloc_dasditerator(struct zdsroot *root,
				    struct dasditerator **it);
/**
 * @brief Free the dasditerator structure.
 */
void lzds_dasditerator_free(struct dasditerator *it);

/**
 * @brief Get the next dasd structure.
 */
int lzds_dasditerator_get_next_dasd(struct dasditerator *it,
				    struct dasd **dasd);

/**
 * @brief Return the device node name that was used for this dasd.
 */
void lzds_dasd_get_device(struct dasd *dasd, char **device);

/**
 * @brief Get the dasd structure that belongs to the given device.
 */
int lzds_zdsroot_get_dasd_by_node_name(struct zdsroot *root, const char *device,
				       struct dasd **dasd);

/**
 * @brief Get the errorlog.
 */
void lzds_zdsroot_get_errorlog(struct zdsroot *root, struct errorlog **log);

int lzds_errorlog_fprint(struct errorlog *log, FILE *stream);

/** @} */ /* end of group libzds_functions_base */





/**
 * @defgroup libzds_functions_low  Low level interface functions.
 * @{
 * @brief    Very basic functions, should all work on every kind DASD.
 *
 * These functions give access to the data on a DASD on a very
 * low abstraction level. They do not dependent on the data on the
 * device itself.
 *
 */

/**
 * @brief Based on the dasd device geometry, compute a track number from a
 *        given cchh_t (cylinder, head) address value.
 */
void lzds_dasd_cchh2trk(struct dasd *dasd, cchh_t *p, unsigned int *track);

/**
 * @brief Get the number of cylinders that this DASD has.
 */
void lzds_dasd_get_cylinders(struct dasd *dasd, unsigned int *cylinders);

/**
 * @brief Get the number of heads, that a cylinder of this DASD has.
 */
void lzds_dasd_get_heads(struct dasd *dasd, unsigned int *heads);

/**
 * @brief Allocate a new dasd context structure for given data set.
 */
int lzds_dasd_alloc_dasdhandle(struct dasd *dasd, struct dasdhandle **dasdh);

/**
 * @brief Free memory that was allocated for a dasdhandle.
 */
void lzds_dasdhandle_free(struct dasdhandle *dasdh);

/**
 * @brief This makes the dasd context ready for read operations.
 */
int lzds_dasdhandle_open(struct dasdhandle *dasdh);

/**
 * @brief This closes the file descriptor connected with the dasdhandle.
 */
int lzds_dasdhandle_close(struct dasdhandle *dasdh);

/**
 *  @brief Read raw tracks from the dasdhandle.
 */
int lzds_dasdhandle_read_tracks_to_buffer(struct dasdhandle *dasdh,
					  unsigned int starttrck,
					  unsigned int endtrck,
					  char *trackdata);

/** @} */ /* end of group libzds_functions_low */



/**
 * @defgroup libzds_functions_mid  Mid level interface functions
 * @{
 * @brief Functions that give access to low level structures like VTOC
 *        records.
 *
 * These functions give access to and rely on the meta data stored on
 * the DASD, in particular the VTOC.
 * These functions take the structure of the data on the
 * device into account, so they may fail if this data is not
 * correct (e.g. if the VTOC is broken).
 *
 * @todo The interface of the mid level functions is not properly structured yet.
 *
 */

/**
 * @brief Read the volume label from device. The data as stored as
 *        part of the struct dasd.
 */
int lzds_dasd_read_vlabel(struct dasd *dasd);

/**
 * @brief Get the previously read volume label data..
 */
int lzds_dasd_get_vlabel(struct dasd *dasd, struct volume_label **vlabel);

/**
 * @brief Read the vtoc data from device. The data as stored as part
 *        of the struct dasd.
 */
int lzds_dasd_read_rawvtoc(struct dasd *dasd, struct raw_vtoc *vtoc);

/**
 * @brief Read the vtoc data from device. The data as stored as part
 *        of the struct dasd.
 */
int lzds_dasd_alloc_rawvtoc(struct dasd *dasd);

/**
 * @brief Get the previously read raw_vtoc data.
 */
int lzds_dasd_get_rawvtoc(struct dasd *dasd, struct raw_vtoc **vtoc);

/**
 * @brief Allocate index that allows to iterate through all DSCB
 *        records stored in the raw_vtoc.
 */
int lzds_raw_vtoc_alloc_dscbiterator(struct raw_vtoc *rawvtoc,
				     struct dscbiterator **it);
/**
 * @brief Free the iterators memory
 */
void lzds_dscbiterator_free(struct dscbiterator *it);

/**
 * @brief Get the next DSCB in the VTOC.
 */
int lzds_dscbiterator_get_next_dscb(struct dscbiterator *it,
				    struct dscb **dscb);
/**
 * @brief Find and get a specific DSCB record by its cylinder, head
 *        and record address (cchhb_t)
 */
int lzds_raw_vtoc_get_dscb_from_cchhb(struct raw_vtoc *rv, cchhb_t *p,
				      struct dscb **dscb);

/** @} */ /* end of group libzds_functions_mid */





/**
 * @defgroup libzds_functions_high  High level interface functions
 * @{
 * @brief These functions give access to the data on a DASD on a
 *        high abstraction level.
 *
 * These functions abstract away most of the low level details.
 * They give access to the user data stored on the DASD using abstract
 * concepts like 'data set' without requiring the user
 * to do any low level analysis.
 */

/**
 * @brief Search zdsroot for a specific data set.
 */
int lzds_zdsroot_find_dataset(struct zdsroot *root, const char *name,
			      struct dataset **ds);

/**
 * @brief Allocate an iterator that will allow to iterate through all
 *        datasets on the index.
 */
int lzds_zdsroot_alloc_dsiterator(struct zdsroot *zdsroot,
				  struct dsiterator **it);
/**
 * @brief Free memory of the given data set iterator.
 */
void lzds_dsiterator_free(struct dsiterator *it);

/**
 * @brief Return the next data set the iterator points to.
 */
int lzds_dsiterator_get_next_dataset(struct dsiterator *it,
				     struct dataset **ds);

/**
 * @brief Get the 'partitioned data set' status of a data set?
 */
void lzds_dataset_get_is_PDS(struct dataset *ds, int *ispds);

/**
 * @brief Are all parts of a multi volume data set available?
 */
void lzds_dataset_get_is_complete(struct dataset *ds, int *iscomplete);

/**
 * @brief Can the data set be opened and read with this library?
 */
void lzds_dataset_get_is_supported(struct dataset *ds, int *issupported);

/**
 * @brief Get the name of a dataset as ASCII string.
 */
void lzds_dataset_get_name(struct dataset *ds, char **name);

/**
 * @brief Get the format 1 DSCB for a data set. In case of a multi volume
 *        data set it returns the DSCB of the first volume.
 */
void lzds_dataset_get_format1_dscb(struct dataset *ds, format1_label_t **f1);

/**
 * @brief Search the data set for a given member name and if a matching
 *        member is found return a struct pdsmember.
 */
int lzds_dataset_get_member_by_name(struct dataset *ds, char *membername,
				    struct pdsmember **member);

/**
 * @brief Allocate an iterator that will allow to iterate through all members
 *        on a datasets.
 */
int lzds_dataset_alloc_memberiterator(struct dataset *ds,
				      struct memberiterator **it);

/**
 * @brief Free memory of the given member iterator.
 */
void lzds_memberiterator_free(struct memberiterator *it);

/**
 * @brief Return the next data set member the iterator points to.
 */
int lzds_memberiterator_get_next_member(struct memberiterator *it,
					struct pdsmember **member);

/**
 * @brief Allocate a new data set context structure for given data set.
 */
int lzds_dataset_alloc_dshandle(struct dataset *ds,
				unsigned int tracks_per_frame,
				struct dshandle **dsh);

/**
 * @brief Free the memory of the given dshandle structure.
 */
void lzds_dshandle_free(struct dshandle *dsh);

/**
 * @brief If the dsh points to a partitioned data set, this function will
 *        set which member of that PDS is read via the dsh.
 */
int lzds_dshandle_set_member(struct dshandle *dsh, char *membername);

/**
 * @brief Read out the member pointer that has been set on this dshandle.
 */
void lzds_dshandle_get_member(struct dshandle *dsh,
			      struct pdsmember **member);

/**
 * @brief Set the flag that causes the library to keep the record descriptor
 * word (RDW) of variable records in the data stream.
 */
int lzds_dshandle_set_keepRDW(struct dshandle *dsh, int keepRDW);

/**
 * @brief Read out the current setting of the RDW flag.
 */
void lzds_dshandle_get_keepRDW(struct dshandle *dsh, int *keepRDW);

/**
 * @brief Prepares the dsh and the related devices for read operations.
 */
int lzds_dshandle_open(struct dshandle *dsh);

/**
 * @brief Matching close operation for the data set context.
 */
void lzds_dshandle_close(struct dshandle *dsh);

/**
 * @brief Read data from the data set to which the dsh points.
 */
int lzds_dshandle_read(struct dshandle *dsh, char *buf,
		       size_t size, ssize_t *rcsize);

/**
 * @brief Move buffer position of dsh to offset.
 */
int lzds_dshandle_lseek(struct dshandle *dsh, long long offset,
			long long *rcoffset);

/**
 * @brief Get the current buffer position.
 */
void lzds_dshandle_get_offset(struct dshandle *dsh, long long *offset);

/**
 * @brief Get the errorlog.
 */
void lzds_dshandle_get_errorlog(struct dshandle *dsh, struct errorlog **log);

/**
 * @brief Set an upper limit for the seek buffer.
 */
int lzds_dshandle_set_seekbuffer(struct dshandle *dsh,
				 unsigned long long seek_buffer_size);

/**
 * @brief Set iconv handle for codepage conversion.
 */
int lzds_dshandle_set_iconv(struct dshandle *dsh, iconv_t *iconv);

/**
 * @brief Get the size of the data set in number of tracks (sum of all extents).
 */
void lzds_dataset_get_size_in_tracks(struct dataset *ds,
				     unsigned long long *tracks);

/**
 * @brief Get the name of a partitioned dataset member.
 */
void lzds_pdsmember_get_name(struct pdsmember *member, char **name);


/**
 * @brief Extract the data set information from the rawvtoc stored in the
 *        dasd and add it to the list of data sets stored in the zdsroot.
 */
int lzds_zdsroot_extract_datasets_from_dasd(struct zdsroot *root,
					    struct dasd *dasd);


void lzds_dslist_free(struct zdsroot *root);

int lzds_ping_rest(struct dshandle *dsh, char *server);

/** @} */ /* end of group libzds_functions_high */



/**
 * @defgroup libzds_functions_helper  Helper functions
 * @{
 *
 * @brief These functions do not fit in the hierarchy of the other
 *        libzds functions, but are useful helpers.
 */

/**
 * @brief Translates a DS1RECFM byte to a recfm format string.
 */
void lzds_DS1RECFM_to_recfm(char DS1RECFM, char *buffer);


int lzds_analyse_open_count(struct zdsroot *root, int warn);

/** @} */ /* end of group libzds_functions_helper */


int lzds_rest_get_enq(struct dshandle *dsh, char *server);
int lzds_rest_release_enq(struct dshandle *dsh, char *server);
int lzds_rest_ping(struct dshandle *dsh, char *server);

#endif /* LIB_LIBZDS_H */
