/**
 * @file libzds.c
 * This is the implementation of the internal library libzds.
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

#include <errno.h>
#include <linux/types.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_CURL
#include <curl/curl.h>
#endif /* HAVE_CURL */

#include "lib/util_libc.h"
#include "lib/dasd_base.h"
#include "lib/dasd_sys.h"
#include "lib/libzds.h"
#include "lib/vtoc.h"

/** @cond PRIVATE */


/******************************************************************************/
/*     libzds structure definitions					      */
/******************************************************************************/

/**
 * @brief Maximum size of a volume serial string (NOT including one byte for
 * 0-termination)
 */
#define MAXVOLSER  6


/*
 * The following structures are declared in libzds.h but defined here in
 * the .c file to keep them opaque to the user of the library.
 */


struct errorlog {
	struct util_list *entries;
};

/**
 * @brief Size of the message buffer in errormsg
 *
 */
#define ERRORMSG  240

#define BUSIDSIZE  8

#define EBCDIC_SP 0x40
#define EBCDIC_LF 0x25

/**
 * @brief An internal structure that represents an entry in the error log.
 */
struct errormsg {
	/** @brief List head to store a list of errormsg in struct errorlog */
	struct util_list_node list;
	/** @brief error code that was associated with this message*/
	int error;
	/** @brief a descriptive message text */
	char text[ERRORMSG];
};

struct dscbiterator {
	/** @brief The raw_vtoc this iterator refers to */
	struct raw_vtoc *rawvtoc;
	/** @brief Index to the vtocindex array in rawvtoc */
	unsigned int i;
};

struct dasdhandle {
	/** @brief The struct dasd this context relates to */
	struct dasd *dasd;
	/** @brief File descriptor for the block device.
	 *  Should be -1 when the device not open */
	int fd;
	/** @brief Detailed error messages in case of a problem */
	struct errorlog *log;
};

struct pdsmember {
	/** @brief List head that is used to store a list of members in
	 * struct dataset */
	struct util_list_node list;

	/** @brief Member name, converted from EBCDIC to ASCII */
	char name[MEMBERNAMELENGTH];
	/** @brief The track the member starts in, relative to the data set.
	 *
	 *  @note This number is relative to the data set, with track 0
	 *  being the first track of the data set. It is independent
	 *  of the DASD geometry or extent location. */
	unsigned short track;
	/** @brief First record of the member starts in, relative to the
	 *  start track.*/
	unsigned char record;
	/** @brief Marks if pdsmember is an alias (we make no distinction
	 *  between a regular member and an alias). */
	unsigned char is_alias;
	/** @brief Detailed error messages in case of a problem */
	struct errorlog *log;
};


/**
 * @brief An internal structure that represents part of a multi volume data set
 *
 * Data sets can be spread over several DASD devices (multi volume data set),
 * and this structure represents one such part. Each data set has at least one
 * datasetpart.
 */
struct datasetpart {
	/** @brief The dasd that this part resides on */
	struct dasd *dasdi;
	/** @brief Pointer to the respective format 1 DSCB in the raw_vtoc
	 *  of that dasd */
	format1_label_t *f1;
	/** @brief Each part can consist of up to MAXEXTENTS (16) extents */
	extent_t ext[MAXEXTENTS];
};


struct dataset {
	/** @brief List head that is used to store a list of data sets in
	 * struct zdsroot */
	struct util_list_node list;

	/** @brief Data set name, translated from EBCDIC to ASCII, 0-terminated
	 *  and with any blank padding removed */
	char name[MAXDSNAMELENGTH];
	/** @brief Array of data set parts this data set consists of.
	 *
	 *  We use just an regular array as the number of parts is limited.
	 *  Each part has a specific position, as defined by the DS1VOLSQ
	 *  value in the parts format 1 label.
	 */
	struct datasetpart *dsp[MAXVOLUMESPERDS];
	/** @brief Number of parts this data set has
	 *
	 *  @note This is the number of data set parts we have already found.
	 *  As long as there are still gaps in the dsp array, dspcount may be
	 *  smaller than the largest index of an element in the dsp array.
	 */
	int dspcount;
	/** @brief Flag that is set to 1 if we have all parts
	 *
	 * @note: In cases where a dataset consists of only one part, the
	 * the fist part should be flagged as last part as well in DS1DSIND,
	 * but this seems not to be reliable. So, as long as we only have only
	 * found one part in position 0, we may set iscomplete, even if we
	 * have no 'last part' marker found.
	 */
	int iscomplete;
	/** @brief If a data set is a partitioned data set (PDS), then this
	 *  contains a list of members, otherwise the list is empty */
	struct util_list *memberlist;
	/** @brief Detailed error messages in case of a problem */
	struct errorlog *log;
};

struct memberiterator {
	/** @brief Data set that holds the members */
	struct dataset *ds;
	/** @brief The last selected member. */
	struct pdsmember *memberi;
};

struct dsiterator {
	/** @brief zdsroot that holds the data sets */
	struct zdsroot *zdsroot;
	/** @brief The last selected data set */
	struct dataset *dsi;
};

struct dasditerator {
	/** @brief zdsroot that holds the dasds */
	struct zdsroot *zdsroot;
	/** @brief The last selected dasd */
	struct dasd *dasdi;
};

struct zdsroot {
	/** @brief list of dasds */
	struct util_list *dasdlist;
	/** @brief list of data sets */
	struct util_list *datasetlist;
	/** @brief Detailed error messages in case of a problem */
	struct errorlog *log;
};

/**
 * @brief Internal structure to keep track of offsets in the data set
 */
struct seekelement {
	/** @brief Data set part this element refers to */
	unsigned char dsp_no;
	/** @brief The extent on that part/dasd */
	unsigned char ext_seq_no;
	/** @brief The starting track on that part/dasd */
	unsigned int bufstarttrk;
	/** @brief The absolute offset in the data set */
	long long databufoffset;
};

/**
 * @brief Default value for the tracks value in dshandle
 */
#define TRACK_BUFFER_DEFAULT 128

struct dshandle {
	/** @brief Data set this context relates to */
	struct dataset *ds;
	/** @brief Pointer to member, only applicable to PDS */
	struct pdsmember *member;
	/** @brief One dasdhandle per data set part
	 *
	 *  The dshandle functions do not read directly from the devices,
	 *  instead they use the dasdhandle interfacesw.
	 */
	struct dasdhandle *dasdhandle[MAXVOLUMESPERDS];

	/** @brief A multiplier that is used to determine the various
	    buffer sizes. Number of tracks in one track frame. */
	unsigned int tracks_per_frame;

	/** @brief Flag: While interpreting the data, keep the record
	 *  descriptor words in the data stream */
	int keepRDW;
	/** @brief Flag that is set between open and close */
	int is_open;
	/** @brief This flag is set when during interpretation of the track
	 *  buffer the end of the data is found	 */
	int eof_reached;


	/* The following values describe our current position within the data
	 * set */

	/** @brief Index number of the current data set part */
	int dsp_no;
	/** @brief The sequence number of the current extent in the current
	 *  data set part */
	int ext_seq_no;
	/** @brief Start buffer interpretation at this record.
	 *
	 *  Data set members may start in the middle of a track. So we need
	 *  to know with which record to start.
	 */
	unsigned char startrecord;
	/** @brief The first track of the extent that dsp_no and ext_seq_no
	 *  point to */
	unsigned int extstarttrk;
	/** @brief The last track of the extent that dsp_no and ext_seq_no
	 *  point to */
	unsigned int extendtrk;
	/** @brief Start of the area that is currently in the rawbuffer */
	unsigned int bufstarttrk;
	/** @brief End of the area that is currently in the rawbuffer */
	unsigned int bufendtrk;
	/** @brief Running number of the current track frame */
	long long frameno;

	/** @brief Buffer for the raw track images  */
	char *rawbuffer;
	/** @brief Buffer for the extracted user data */
	char *databuffer;
	/** @brief Size of the rawbuffer */
	long long rawbufmax;
	/** @brief Size of the databuffer */
	long long databufmax;
	/** @brief Size of the currently used part of the rawbuffer */
	long long rawbufsize;
	/** @brief Size of the currently used part of the databuffer */
	long long databufsize;
	/** @brief Current position of the databuffer relative to the begin
	 *  of the data set */
	long long databufoffset;
	/** @brief Current position in the databuffer */
	long long bufpos;


	/** @brief Buffer for seek data points */
	struct seekelement *seekbuf;
	/** @brief Total number of elements in seekbuf */
	unsigned long long seek_count;
	/** @brief Number of used elements in seekbuf */
	unsigned long long seek_current;
	/** @brief Modulo that determines which track frame is stored in the
	 *  seek buffer
	 *
	 *  Example: If skip is 2, then every 2'nd frame is stored.
	 */
	unsigned long long skip;
	/** @brief Detailed error messages in case of a problem */
	struct errorlog *log;

	char *session_ref;
	iconv_t *iconv;
	char *convbuffer;
};

/** @endcond */


/******************************************************************************/
/*     BASIC level functions						      */
/******************************************************************************/

static void dasd_free(struct dasd *dasd);
static void dataset_free_memberlist(struct dataset *ds);
static void errorlog_free(struct errorlog *log);
static void errorlog_clear(struct errorlog *log);
static int errorlog_add_message(struct errorlog **log,
				struct errorlog *oldlog,
				int error_code,
				const char *message_format,
				...) __attribute__ ((format (printf, 4, 5)));





/**
 * Since the zdsroot is the root for all the other data structures,
 * this should be one of the first functions to call.
 * @param[out] root Reference to a pointer variable in which the newly
 *             allocated structure will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
int lzds_zdsroot_alloc(struct zdsroot **root)
{
	struct zdsroot *tmproot;

	*root = NULL;
	tmproot = malloc(sizeof(*tmproot));
	if (!tmproot)
		return ENOMEM;
	memset(tmproot, 0, sizeof(*tmproot));

	tmproot->dasdlist = util_list_new(struct dasd, list);
	tmproot->datasetlist = util_list_new(struct dataset, list);

	*root = tmproot;

	return 0;
}


/**
 * It should be noted that this frees all structures that are owned by the
 * root structure as well. For example, a pointer to a struct dasd that
 * has been returned by lzds_zdsroot_add_device is not valid anymore.
 *
 * @param[in] root Reference to the zdsroot structure that is to be freed.
 */
void lzds_dslist_free(struct zdsroot *root)
{
	struct dataset *ds, *nextds;
	int i;

	util_list_iterate_safe(root->datasetlist, ds, nextds) {
		util_list_remove(root->datasetlist, ds);
		dataset_free_memberlist(ds);
		for (i = 0; i < MAXVOLUMESPERDS; ++i)
			free(ds->dsp[i]);
		errorlog_free(ds->log);
		free(ds);
	}
}

/**
 * It should be noted that this frees all structures that are owned by the
 * root structure as well. For example, a pointer to a struct dasd that
 * has been returned by lzds_zdsroot_add_device is not valid anymore.
 *
 * @param[in] root Reference to the zdsroot structure that is to be freed.
 */
void lzds_zdsroot_free(struct zdsroot *root)
{
	struct dasd *dasd, *nextdasd;

	if (!root)
		return;

	util_list_iterate_safe(root->dasdlist, dasd, nextdasd) {
		util_list_remove(root->dasdlist, dasd);
		dasd_free(dasd);
	}
	util_list_free(root->dasdlist);
	lzds_dslist_free(root);
	util_list_free(root->datasetlist);
	errorlog_free(root->log);
	free(root);
}

/**
 * @brief Subroutine of lzds_zdsroot_add_device
 *
 * This function determines some basic DASD geometry information and stores
 * it in the struct dasd for later use.
 *
 * @param[in] dasd Reference to the dasd to work on.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EIO     Some error prevented us from gaining this information
 *
 */
static int dasd_read_geometry(struct dasd *dasd)
{
	unsigned long long size_in_bytes;

	errorlog_clear(dasd->log);

	if (dasd_get_blocksize_in_bytes(dasd->device, &size_in_bytes) != 0)
		return errorlog_add_message(
			&dasd->log, NULL, EIO,
			"read geometry: could not get size from device %s\n",
			dasd->device);

	/* label_block and heads are simply hard coded with the correct values
	 * for ECKD DASDs. This makes us independent from any DASD specific
	 * ioctls like BIODASDINFO and allows us to work on DASD images via
	 * loopback device.
	 */
	dasd->label_block = 2;
	dasd->heads = 15;
	dasd->cylinders = (size_in_bytes / (dasd->heads * RAWTRACKSIZE));
	return 0;
}


/**
 * @brief Subroutine of lzds_zdsroot_add_device
 *
 * This function goes through the list of dasds in root and verifies that
 * the a dasd with the given device name is not yet present.
 * @param[in] root Reference to the zdsroot structure the new struct dasd
 *                 is to be added to.
 * @param[in] devnode String that holds the name of the device node,
 *                    e.g. "/dev/dasdb".
 * @return    true if matching dasd has been found, false if not
 */
static int zdsroot_is_duplicate_device(struct zdsroot *root,
				       const char *devnode)
{
	struct dasd *dasd;

	dasd = NULL;
	lzds_zdsroot_get_dasd_by_node_name(root, devnode, &dasd);
	return !(dasd == NULL);
}

/**
 * This function creates a new struct dasd and adds it to the root.
 * It can later be traversed using the dasditerator functions.
 *
 * @param[in] root Reference to the zdsroot structure the new struct dasd
 *                 is to be added to.
 * @param[in] devnode String that holds the name of the device node,
 *                    e.g. "/dev/dasdb".
 * @param[out] dasd Reference to a pointer variable in which the newly
 *                allocated structure will be returned.
 *                This pointer is returned for the convenience of the user,
 *                to be used with follow on calls, e.g to lzds_dasd_read_vlabel.
 *
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 *   - ENOTTY  The used ioctl is not supported by the device (i.e. the
 *             device is not a DASD.)
 *   - EIO     Some other error prevented us from gaining this information
 *
 * @note It is not guaranteed that ENOTTY is returned when the device is
 *       not a DASD. It depends on the device whether ENOTTY or EIO is returned.
 */
int lzds_zdsroot_add_device(struct zdsroot *root, const char *devnode,
			    struct dasd **dasd)
{
	struct dasd *dasdtmp;
	int rc;

	errorlog_clear(root->log);
	if (zdsroot_is_duplicate_device(root, devnode)) {
		return errorlog_add_message(
			&root->log, NULL, EINVAL,
			"add device: duplicate device %s\n",
			devnode);
	}
	dasdtmp = malloc(sizeof(*dasdtmp));
	if (!dasdtmp)
		return ENOMEM;
	memset(dasdtmp, 0, sizeof(*dasdtmp));
	dasdtmp->device = strdup(devnode);
	dasdtmp->inusefd = open(dasdtmp->device, O_RDONLY);
	if (dasdtmp->inusefd < 0) {
		errorlog_add_message(
			&root->log, dasdtmp->log, EIO,
			"add device: could open device %s\n",
			dasdtmp->device);
		dasd_free(dasdtmp);
		return EIO;
	}
	rc = dasd_read_geometry(dasdtmp);
	if (rc) {
		errorlog_add_message(
			&root->log, dasdtmp->log, EIO,
			"add device: could not read device data from %s\n",
			dasdtmp->device);
		close(dasdtmp->inusefd);
		dasd_free(dasdtmp);
		return EIO;
	}
	util_list_add_tail(root->dasdlist, dasdtmp);
	if (dasd)
		*dasd = dasdtmp;
	return 0;
}

/**
 * @param[in]  dasd   A dasd on which an error occurred.
 * @param[out] log    Reference to a variable in which the errorlog
 *                    is returned.
 */
void lzds_dasd_get_errorlog(struct dasd *dasd, struct errorlog **log)
{
	*log = dasd->log;
}

/**
 * @brief Subroutine of lzds_zdsroot_free. Frees the struct dasd and everything
 *        that belogns to it.
 *
 * @param[in] dasd Pointer to the struct dasd that is to be freed.
 */
static void dasd_free(struct dasd *dasd)
{
	free(dasd->device);
	free(dasd->vlabel);
	if (dasd->rawvtoc) {
		free(dasd->rawvtoc->rawdata);
		free(dasd->rawvtoc->vtocindex);
		errorlog_free(dasd->rawvtoc->log);
		free(dasd->rawvtoc);
	}
	errorlog_free(dasd->log);
	close(dasd->inusefd);
	free(dasd);
}

/**
 * @param[in] zdsroot  Reference to struct zdsroot that the iterator will be
 *                     bound to. The iterator will traverse the dasds stored
 *                     in this zdsroot.
 * @param[out] it Reference to a pointer variable in which the newly allocated
 *                structure will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
int lzds_zdsroot_alloc_dasditerator(struct zdsroot *zdsroot,
				   struct dasditerator **it)
{
	*it = malloc(sizeof(struct dasditerator));
	if (*it) {
		(*it)->dasdi = NULL;
		(*it)->zdsroot = zdsroot;
		return 0;
	}
	return ENOMEM;
}

/**
 * @param[in]  it  Pointer to the struct dasditerator that is to be freed.
 */
void lzds_dasditerator_free(struct dasditerator *it)
{
	free(it);
}

/**
 * @param[out] it    Reference to the struct dasditerator we use to traverse the
 *                   dasd list.
 * @param[out] dasd  Reference to a pointer variable in which the next dasd in
 *                   the sequence will be returned. If there is no next DASD,
 *                   this variable will be set to NULL.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPERM  The end of the list has been reached. There is no further dasd.
 */
int lzds_dasditerator_get_next_dasd(struct dasditerator *it, struct dasd **dasd)
{
	struct dasd *dasdtmp;

	if (!it->dasdi)
		dasdtmp = util_list_start(it->zdsroot->dasdlist);
	else
		dasdtmp = util_list_next(it->zdsroot->dasdlist, it->dasdi);
	*dasd = dasdtmp;
	if (!dasdtmp)
		return EPERM;
	it->dasdi = dasdtmp;
	return 0;
}

/**
 * @param[in]  dasd    The struct dasd we want to know the device of.
 * @param[out] device  Reference to a pointer variable in which the device
 *                     string will be returned. This string holds the device
 *                     name as it was given to lzds_zdsroot_add_device.
 */
void lzds_dasd_get_device(struct dasd *dasd, char **device)
{
	*device = dasd->device;
}

/**
 * @param[in]  root  Reference to the zdsroot that holds the dasd.
 * @param[in]  device  Pointer to a character string that holds the device node
 *                     name that we are looking for. It must be the same name as
 *                     previously given to lzds_zdsroot_add_device
 * @param[out] dasd  Reference to a pointer variable in which the found struct
 *                   dasd will be returned. If no dasd was found,
 *                   this will be set to NULL
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structures due to lack of memory.
 *   - ENODEV  No matching struct dasd was found.
 */
int lzds_zdsroot_get_dasd_by_node_name(struct zdsroot *root, const char *device,
				       struct dasd **dasd)
{
	struct dasditerator *dasdit;
	int rc;
	struct dasd *tempdasd;
	char *dasddev;

	errorlog_clear(root->log);
	rc = lzds_zdsroot_alloc_dasditerator(root, &dasdit);
	if (rc)
		return ENOMEM;
	rc = ENODEV;
	*dasd = NULL;
	while (!lzds_dasditerator_get_next_dasd(dasdit, &tempdasd)) {
		lzds_dasd_get_device(tempdasd, &dasddev);
		if (!strcmp(device, dasddev)) {
			rc = 0;
			*dasd = tempdasd;
			break;
		}
	}
	lzds_dasditerator_free(dasdit);
	return rc;
}

/**
 * @param[in]  root   A zdsroot on which an error occurred.
 * @param[out] log    Reference to a variable in which the errorlog
 *                    is returned.
 */
void lzds_zdsroot_get_errorlog(struct zdsroot *root, struct errorlog **log)
{
	*log = root->log;
}


/**
 * @brief free storage for a single error message
 *
 * @param[in] msg The message to be freed
 */
static void errormsg_free(struct errormsg *msg)
{
	free(msg);
}

/**
 * @brief allocate storage for a single error message
 *
 * @param[out] msg Reference to a pointer variable in which the newly allocated
 *                structure will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
static int errormsg_alloc(struct errormsg **msg)
{
	struct errormsg *tmpmsg;

	*msg = NULL;
	tmpmsg = malloc(sizeof(*tmpmsg));
	if (!tmpmsg)
		return ENOMEM;
	memset(tmpmsg, 0, sizeof(*tmpmsg));
	*msg = tmpmsg;
	return 0;
}

/**
 * @brief remove and free all messages from a given errolog
 *
 * After this operation new messages can be added to the log.
 *
 * @param[in] log The message log to be cleared. This may be NULL.
 */
static void errorlog_clear(struct errorlog *log)
{
	struct errormsg *msg, *nextmsg;

	if (!log)
		return;
	util_list_iterate_safe(log->entries, msg, nextmsg) {
		util_list_remove(log->entries, msg);
		errormsg_free(msg);
	}
}

/**
 * @brief free storage for an error log, including all messages
 *
 * @param[in] log The error log to be freed. This may be NULL.
 */
static void errorlog_free(struct errorlog *log)
{
	if (!log)
		return;
	errorlog_clear(log);
	util_list_free(log->entries);
	free(log);
}

/**
 * @brief allocate storage for an error log
 *
 * @param[out] log Reference to a pointer variable in which the newly allocated
 *                structure will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
static int errorlog_alloc(struct errorlog **log)
{
	struct errorlog *tmplog;

	*log = NULL;
	tmplog = malloc(sizeof(*tmplog));
	if (!tmplog)
		return ENOMEM;
	memset(tmplog, 0, sizeof(*tmplog));
	tmplog->entries = util_list_new(struct errormsg, list);
	*log = tmplog;
	return 0;
}

/**
 * @brief add a new message to the front of a log.
 *
 * @param[out] log A reference to a errorlog pointer variable. If a log already
 *                exists, old messages are cleared, otherwise a new log will
 *                be created.
 * @param[in] oldlog A log that already contains messages, usually from a call
 *                   to a subordinate function. This may be the same errorlog as
 *                   referenced by log, in which case the existing messages
 *                   are retained. This may also be NULL.
 * @param[in] error_code  The error code that will be stored in the new errormsg.
 *                   This is also the return value.
 * @param[in] message_format A format string for the message string
 *                  (see vsnprintf man page).
 * @param[in] ... A variable number of further parameters.
 *                Must match the message_format string.
 */
static int errorlog_add_message(struct errorlog **log,
				struct errorlog *oldlog,
				int error_code,
				const char *message_format,
				...)
{
	struct errormsg *msg, *nextmsg;
	struct errorlog *tmplog;
	va_list ap;
	int rc;

	if (!log)
		return error_code;
	if (log && !*log) {
		errorlog_alloc(&tmplog);
		if (!tmplog)
			return error_code;
		*log = tmplog;
	} else {
		tmplog = *log;
	}

	if (tmplog != oldlog) {
		errorlog_clear(tmplog);
		if (oldlog) {
			util_list_iterate_safe(oldlog->entries, msg, nextmsg) {
				util_list_remove(oldlog->entries, msg);
				util_list_add_tail(tmplog->entries, msg);
			}
		}
	}

	if (!message_format)
		return error_code;

	rc = errormsg_alloc(&msg);
	if (rc)
		return error_code;

	va_start(ap, message_format);
	vsnprintf(msg->text, ERRORMSG - 1, message_format, ap);
	va_end(ap);
	msg->error = error_code;
	util_list_add_head(tmplog->entries, msg);

	return error_code;
}

/**
 * This is pretty a very simple implementation that just goes through
 * the list of messages in the log and for each message it prints
 * "rc <error>: <text>"
 *
 * @param[in] log A log that contains messages.
 * @param[in] stream  The stream that these messages will be printed to.
 */
int lzds_errorlog_fprint(struct errorlog *log, FILE *stream)
{
	struct errormsg *msg;
	int rc;

	if (!log)
		return 0;
	util_list_iterate(log->entries, msg) {
		rc = fprintf(stream, "rc %d: %s", msg->error, msg->text);
		if (rc < 0)
			return -rc;
	}
	return 0;
}



/******************************************************************************/
/*      LOW  level functions                                                  */
/******************************************************************************/


/**
 * @param[in]  dasd The DASD to whose geometry we refer to.
 * @param[in]  p    Cylinder and head address
 * @param[out] track The sequential track number for the given
 *                   cylinder and head address.
 */
void lzds_dasd_cchh2trk(struct dasd *dasd, cchh_t *p, unsigned int *track)
{
	*track = vtoc_get_cyl_from_cchh(p) * dasd->heads +
		vtoc_get_head_from_cchh(p);
}

/**
 * @param[in]  dasd The DASD to whose geometry we refer to.
 * @param[out] cylinders The number of cylinders that DASD has
 */
void lzds_dasd_get_cylinders(struct dasd *dasd, unsigned int *cylinders)
{
	*cylinders = dasd->cylinders;
}

/**
 * @param[in]  dasd The DASD to whose geometry we refer to
 * @param[out] heads The number of heads that DASD has
 */
void lzds_dasd_get_heads(struct dasd *dasd, unsigned int *heads)
{
	*heads = dasd->heads;
}

/**
 * @param[in] dasd Reference to struct dasd that represents
 *                 the DASD that we want to read from.
 * @param[out] dasdh Reference to a pointer variable in which the newly
 *                   allocated structure will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
int lzds_dasd_alloc_dasdhandle(struct dasd *dasd, struct dasdhandle **dasdh)
{
	struct dasdhandle *dasdhtmp;

	dasdhtmp = malloc(sizeof(*dasdhtmp));
	if (!dasdhtmp)
		return ENOMEM;
	memset(dasdhtmp, 0, sizeof(*dasdhtmp));
	dasdhtmp->fd = -1;
	dasdhtmp->dasd = dasd;
	*dasdh = dasdhtmp;
	return 0;
}

/**
 * @param[in] dasdh Pointer to the struct dasdhandle that is to be freed.
 */
void lzds_dasdhandle_free(struct dasdhandle *dasdh)
{
	if (!dasdh)
		return;
	/* we close the file descriptor in case it wasn't done properly */
	lzds_dasdhandle_close(dasdh);
	errorlog_free(dasdh->log);
	free(dasdh);
}

/**
 * @param[in]  dasdh The dasd handle for the dasd that is to be opened.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EIO  Could not open underlying device.
 */
int lzds_dasdhandle_open(struct dasdhandle *dasdh)
{
	errorlog_clear(dasdh->log);
	dasdh->fd = open(dasdh->dasd->device, O_RDONLY | O_DIRECT);
	if (dasdh->fd < 0) {
		dasdh->fd = -1;
		return errorlog_add_message(
			&dasdh->log, NULL, EIO,
			"dasdhandle: could not open %s, errno %d\n",
			dasdh->dasd->device, errno);
	}
	return 0;
}

/**
 * @param[in]  dasdh The dasdhandle that has to be closed
 * @return     0 on success, otherwise one of the following error codes:
 *   - EIO  Error when closing underlying dasd device.
 */
int lzds_dasdhandle_close(struct dasdhandle *dasdh)
{
	int rc;
	errorlog_clear(dasdh->log);
	rc = 0;
	if (dasdh->fd >= 0)
		rc = close(dasdh->fd);
	dasdh->fd = -1;
	if (rc)
		return errorlog_add_message(
			&dasdh->log, NULL, EIO,
			"dasdhandle: could not close %s\n",
			dasdh->dasd->device);
	return 0;
}

/**
 * @param[in]  dasdh The dasdhandle we are reading from
 * @param[in]  starttrck First track to read
 * @param[in]  endtrck Last track to read
 * @param[out] trackdata Target buffer we read into, must have at least the
 *                       size (endtrk - starttrk + 1) * RAWTRACKSIZE
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  starttrck or endtrck are not within the boundaries of the
 *             underlying DASD device.
 *   - EPROTO  Could not read a full track image
 *   - EIO     Other I/O error
 */
int lzds_dasdhandle_read_tracks_to_buffer(struct dasdhandle *dasdh,
					  unsigned int starttrck,
					  unsigned int endtrck,
					  char *trackdata)
{
	off_t trckseek;
	ssize_t residual;
	off_t rc;
	ssize_t count;

	unsigned int cylinders;
	unsigned int heads;

	errorlog_clear(dasdh->log);
	/* verify that endtrck is not beyond the end of the dasd */
	lzds_dasd_get_cylinders(dasdh->dasd, &cylinders);
	lzds_dasd_get_heads(dasdh->dasd, &heads);
	if (starttrck > endtrck || endtrck >= cylinders * heads)
		return errorlog_add_message(
			&dasdh->log, NULL, EINVAL,
			"dasdhandle read tracks: start %u, end %u is"
			" out of bounds for device %s\n",
			starttrck, endtrck, dasdh->dasd->device);
	/*
	 * Compute seek address of the first track and number of tracks
	 * to be read. Please note that geo.sectors does not match our raw
	 * track size of 16*4KB, so we use the RAWTRACKSIZE explicitly
	 */
	trckseek = (off_t)starttrck * RAWTRACKSIZE;
	/* residual is the number of bytes we still have to read */
	residual = (off_t)(endtrck - starttrck + 1) * RAWTRACKSIZE;
	rc = lseek(dasdh->fd, trckseek, SEEK_SET);
	if (rc < 0)
		return errorlog_add_message(
			&dasdh->log, NULL, EINVAL,
			"dasdhandle read tracks: seek to %llu, failed"
			" for device %s\n",
			(unsigned long long)trckseek, dasdh->dasd->device);

	while (residual) {
		count = read(dasdh->fd, trackdata, residual);
		if (count < 0)
			return errorlog_add_message(
				&dasdh->log, NULL, EIO,
				"dasdhandle read tracks: read failed"
				" for device %s, start %u, end %u\n",
				dasdh->dasd->device, starttrck, endtrck);
		if (count % RAWTRACKSIZE) /* No full track read */
			return errorlog_add_message(
				&dasdh->log, NULL, EPROTO,
				"dasdhandle read tracks: read returned "
				"unaligned data for device %s,"
				"start %u, end %u\n",
				dasdh->dasd->device, starttrck, endtrck);
		residual -= count;
		trackdata += count;
	}
	return 0;
}


/******************************************************************************/
/*      MID  level functions                                                  */
/******************************************************************************/
/**
 * @brief Helper function that iterates through the records in a track buffer.
 *
 * @param[in]     buffer    Address of the track buffer
 * @param[in]     size      Size of the buffer
 * @param[in,out] record Pointer that has the current record pointer as input
 *                       and gets a pointer to the next record as output.
 *                       If it the current record pointer is null, then the
 *                       pointer to the first record is returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOENT  If we have reached the end of the buffer and there are no
 *             further records
 */
static int buffer_get_next_record(char *buffer, size_t size, char **record)
{
	char *data, *next_record;
	unsigned long offset;
	unsigned int record_size;
	struct eckd_count *ecount;

	/* If *record contains no record yet, then we return the first record */
	if (!*record) {
		*record = buffer;
		return 0;
	}
	data = *record;
	ecount = (struct eckd_count *)data;
	record_size = sizeof(*ecount) + ecount->kl + ecount->dl;
	data += record_size;
	next_record = NULL;
	while (!next_record) {
		/* check if we have reached the end of the buffer */
		if (data >= buffer + size) {
			*record = NULL;
			return ENOENT;
		}
		/* If the 'next' record is the pseudo record, then we have
		 * reached the end of data in this track and we have to jump
		 * to the start of the next track to find the next record.
		 */
		if ((*(unsigned long long *)data) == ENDTOKEN) {
			offset = (unsigned long)data - (unsigned long)buffer;
			offset &= ~(RAWTRACKSIZE - 1);
			offset += RAWTRACKSIZE;
			data = buffer + offset;
			continue;
		}
		next_record = data;
	}
	*record = next_record;
	return 0;
}

/**
 * @brief Helper function that does the whole open/read/close cycle in one go.
 *
 * @param[in]  dasd Pointer to struct dasd that represents
 *                  the DASD that we want to read from.
 * @param[in]  starttrck First track to read
 * @param[in]  endtrck   Last track to read
 * @param[out] trackdata Target buffer we read into, must have at least the
 *                       size (endtrk - starttrk + 1) * RAWTRACKSIZE
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structure due to lack of memory.
 *   - EINVAL  starttrck or endtrck are not within the boundaries of the
 *             underlying DASD device.
 *   - EPROTO  Could not read a full track image
 *   - EIO     Other I/O error
 */
static int dasd_read_tracks(struct dasd *dasd,
			    unsigned int starttrck,
			    unsigned int endtrck,
			    char *trackdata)
{
	struct dasdhandle *dasdh;
	int rc, rc2;

	rc = lzds_dasd_alloc_dasdhandle(dasd, &dasdh);
	if (rc)
		return errorlog_add_message(
			&dasd->log, dasd->log, rc,
			"dasd read tracks: could not allocate dasdhandle\n");

	rc = lzds_dasdhandle_open(dasdh);
	if (rc) {
		errorlog_add_message(
			&dasd->log, dasdh->log, rc,
			"dasd read tracks: could not open dasdhandle\n");
		lzds_dasdhandle_free(dasdh);
		return rc;
	}
	rc = lzds_dasdhandle_read_tracks_to_buffer(dasdh, starttrck,
						   endtrck, trackdata);
	if (rc)
		errorlog_add_message(
			&dasd->log, dasdh->log, rc,
			"dasd read tracks: read error\n");
	rc2 = lzds_dasdhandle_close(dasdh);
	/* report close error only if we had no read error */
	if (rc2 && !rc) {
		errorlog_add_message(
			&dasd->log, dasdh->log, rc,
			"dasd read tracks: could not close dasdhandle\n");
		rc = rc2;
	}
	lzds_dasdhandle_free(dasdh);
	return rc;
}

/**
 * @brief Helper function that reads a volume label from a DASD.
 *
 * @param[in]  dasd  Pointer to struct dasd that represents
 *                   the DASD that we want to read from.
 * @param[out] vlabel Buffer to read the label into.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structure due to lack of memory.
 *   - EIO     Other I/O error
 */
static int dasd_read_vlabel_to_buffer(struct dasd *dasd,
				      struct volume_label *vlabel)
{
	int rc;
	unsigned int i;
	char *trackdata, *record;
	struct volume_label *label;
	struct eckd_count *ecount;
	unsigned long labelend, trackend;
	size_t label_size;

	trackdata = memalign(4096, RAWTRACKSIZE); /* page align for O_DIRECT */
	if (!trackdata)
		return ENOMEM;

	rc = dasd_read_tracks(dasd, 0, 0, trackdata);
	if (rc) {
		free(trackdata);
		return errorlog_add_message(
			&dasd->log, dasd->log, EIO,
			"read vlabel: could not read track 0\n");
	}
	/* fist step, find label record */
	record = NULL;
	label = NULL;
	ecount = NULL;
	i = 0;
	while (!buffer_get_next_record(trackdata, RAWTRACKSIZE, &record)) {
		if (i == (dasd->label_block + 1)) {
			ecount = (struct eckd_count *)record;
			label = (struct volume_label *)(ecount + 1);
			break;
		}
		++i;
	}
	if (!ecount || !label) {
		free(trackdata);
		return errorlog_add_message(
			&dasd->log, dasd->log, EPROTO,
			"read vlabel: could not find label record\n");
	}
	/* verify record layout */
	memset(vlabel, 0, sizeof(*vlabel));
	labelend = (unsigned long)label + ecount->kl + ecount->dl;
	trackend = (unsigned long)trackdata + RAWTRACKSIZE;
	if ((ecount->kl + ecount->dl == 84) && (labelend <= trackend)) {
		/* VOL1 label */
		memcpy(vlabel, label, ecount->kl + ecount->dl);
	} else if ((ecount->kl == 0) && (labelend <= trackend)) {
		/* LNX1 / CMS1 label */
		label_size = MIN(ecount->dl, sizeof(*vlabel) - 4);
		memcpy(&vlabel->vollbl, label, label_size);
	} else {
		free(trackdata);
		return errorlog_add_message(
			&dasd->log, dasd->log, EPROTO,
			"read vlabel: record layout does not match VOL1"
			" label\n");
	}
	free(trackdata);
	return 0;
}

/**
 * @param[in]  dasd  Pointer to struct dasd that represents
 *                   the DASD that we want to read from.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structure due to lack of memory.
 *   - EIO     Other I/O error
 */
int lzds_dasd_read_vlabel(struct dasd *dasd)
{
	struct volume_label *vlabel;
	int rc;

	errorlog_clear(dasd->log);
	free(dasd->vlabel);
	dasd->vlabel = NULL;
	vlabel = malloc(sizeof(*vlabel));
	if (!vlabel)
		return ENOMEM;
	rc = dasd_read_vlabel_to_buffer(dasd, vlabel);
	if (rc)
		free(vlabel);
	else
		dasd->vlabel = vlabel;
	return rc;
}

/**
 * @param[in]  dasd   Reference to struct dasd that we want to get the label
 *                    from.
 * @param[out] vlabel Reference to a pointer variable in which the struct
 *                    volume_label will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  The volume lable has not yet been read from the device.
 */
int lzds_dasd_get_vlabel(struct dasd *dasd, struct volume_label **vlabel)
{
	*vlabel = dasd->vlabel;
	if (*vlabel)
		return 0;
	else
		return EINVAL;
}

/**
 * @param[in] rawvtoc  Reference to struct raw_vtoc that the iterator will be
 *                     bound to. The iterator will traverse the DSCBs stored
 *                     in this raw_vtoc.
 * @param[out] it Reference to a pointer variable in which the newly allocated
 *                structure will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
int lzds_raw_vtoc_alloc_dscbiterator(struct raw_vtoc *rawvtoc,
				     struct dscbiterator **it)
{
	*it = malloc(sizeof(**it));
	if (*it) {
		(*it)->i = rawvtoc->vtocrecno - 1;
		(*it)->rawvtoc = rawvtoc;
		return 0;
	}
	return ENOMEM;
}

/**
 * @param[in]  it Pointer to the struct dscbiterator that is to be freed.
 */
void lzds_dscbiterator_free(struct dscbiterator *it)
{
	free(it);
}

/**
 * @param[out] it    Reference to the struct dscb iterator we use to traverse
 *                   the VTOC.
 * @param[out] dscb  Reference to a pointer variable in which the next dscb in
 *                   the sequence will be returned. If there is no next dscb,
 *                   this variable will be set to NULL.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPERM   There is no further DSCB in the VTOC.
 */
int lzds_dscbiterator_get_next_dscb(struct dscbiterator *it, struct dscb **dscb)
{
	struct eckd_count *ecount;
	unsigned int i;

	i = it->i + 1;
	while (i < it->rawvtoc->vtocindexcount) {
		ecount = (struct eckd_count *)(it->rawvtoc->vtocindex[i]);
		if (ecount && (ecount->kl == 44) && (ecount->dl == 96))
			break;
		else
			++i;
	}
	if (i < it->rawvtoc->vtocindexcount) {
		it->i = i;
		*dscb = (struct dscb *)(it->rawvtoc->vtocindex[it->i]
					+ sizeof(*ecount));
		return 0;
	} else {
		*dscb = NULL;
		return EPERM;
	}
}

/**
 *  @brief Subroutine of lzds_raw_vtoc_get_dscb_from_cchhb
 *
 * This function takes a cylinder, head, block address as it can be
 * found in DSCBs and returns an index to the matching entry in the
 * raw_vtoc vtocindex.
 *
 * The cchhb2blk function of the libvtoc does not work for raw devices
 * as the 'sectors per track' value in the geo structure has no meaning
 * for a raw DASD. We need to take this value from the context,
 * e.g. from the format 4 label of the VTOC.
 * Since this computation is very specialized, we can go all the way and
 * just compute the index to the vtoc array.
 *
 * @param[in]  rv The raw_vtoc we refer to.
 * @param[in]  p  The cylinder, head, block address structure.
 * @return     index to the vtocindex array
 */
static long long vtocindex_from_cchhb(struct raw_vtoc *rv, cchhb_t *p)
{
	long long recno;

	recno = (long long) vtoc_get_cyl_from_cchhb(p) *
		rv->dasd->heads * rv->vtoc_rec_per_track +
		vtoc_get_head_from_cchhb(p) * rv->vtoc_rec_per_track +
		p->b;
	return recno - (rv->vtoctrackoffset * rv->vtoc_rec_per_track);
}

/**
 * @note A cchhb address within a VTOC dscb is often set to zero to
 * indicate that this entry does not point anywhere. For example this
 * is the case at the end of a format 3 dscb chain.  This special case
 * is handled by setting the dscb pointer to NULL and having a return
 * value of 0 (no error).
 *
 * @param[in]  rv The raw_vtoc we refer to.
 * @param[in]  p  The cylinder, head, block address of the DSCB.
 * @param[out] dscb Reference to a pointer variable in which a pointer to
 *                  the respective dscb in the raw_vtoc will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  The address in *p refers to a record that is not a valid DSCB.
 *   - ERANGE  The cylinder, head, block address lies not within the VTOC.
 */
int lzds_raw_vtoc_get_dscb_from_cchhb(struct raw_vtoc *rv, cchhb_t *p,
				      struct dscb **dscb)
{
	long long index;
	char *record;

	errorlog_clear(rv->log);
	index = vtocindex_from_cchhb(rv, p);
	*dscb = NULL;
	if (!p->cc && !p->hh && !p->b)
		return 0;
	/* record zero is part of the track image, but not a dscb */
	if (!p->b)
		return errorlog_add_message(
			&rv->log, NULL, EINVAL,
			"raw vtoc: DSCB address is empty\n");
	if (index < rv->vtocrecno || index >= rv->vtocindexcount)
		return errorlog_add_message(
			&rv->log, NULL, ERANGE,
			"raw vtoc: DSCB address is outside VTOC\n");
	record = rv->vtocindex[vtocindex_from_cchhb(rv, p)];
	if (!record)
		return errorlog_add_message(
			&rv->log, NULL, EINVAL,
			"raw vtoc: DSCB address points to nonexistent DSCB\n");
	*dscb = (struct dscb *)(record + sizeof(struct eckd_count));
	return 0;
}

/**
 * @param[in]  dasd The struct dasd that represents the device we want to read
 *                  the VTOC from.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structure due to lack of memory.
 *   - EINVAL  The volume label has not yet been read or it is not valid.
 *   - EPROTO  The VTOC data is not in a valid format.
 *   - EIO     Other I/O error
 */
int lzds_dasd_read_rawvtoc(struct dasd *dasd, struct raw_vtoc *rawvtoc)
{
	unsigned long long vtoctrckno, vtocrecno;
	unsigned int vtoctrack_start, vtoctrack_end, vtocindexsize;
	unsigned int vtoc_rec_per_track;
	unsigned int i;
	int rc;
	char *record;
	struct eckd_count *ecount;
	format4_label_t *f4;
	unsigned long long rawvtocsize;

	volume_label_t *vlabel = NULL;
	char *trackdata = NULL;
	char vol1[] = {0xe5, 0xd6, 0xd3, 0xf1, 0x00}; /* "VOL1" in EBCDIC */

	errorlog_clear(dasd->log);

	rc = lzds_dasd_get_vlabel(dasd, &vlabel);
	if (rc) {
		errorlog_add_message(
			&dasd->log, NULL, rc,
			"read VTOC: there is no volume label data available\n");
		goto cleanup;
	}
	/* verify that we have a proper VOL1 label */
	if (strncmp(vlabel->volkey, vol1, 4) ||
	    strncmp(vlabel->vollbl, vol1, 4)) {
		rc = EINVAL;
		errorlog_add_message(
			&dasd->log, NULL, rc,
			"read VTOC: volume label is not a VOL1 label\n");
		goto cleanup;
	}

	/* The label contains the address of the first block of the vtoc. */
	vtoctrckno = (unsigned long long) vtoc_get_cyl_from_cchhb(&vlabel->vtoc)
		* dasd->heads + vtoc_get_head_from_cchhb(&vlabel->vtoc);
	vtocrecno = vlabel->vtoc.b;

	/* We do not know how large the VTOC is, yet. So first, we read only
	 * one track of the VTOC to access the format 4 DSCB in the first record
	 * of the VTOC.
	 */
	trackdata = memalign(4096, RAWTRACKSIZE); /* page align for O_DIRECT */
	if (!trackdata) {
		rc = ENOMEM;
		goto cleanup;
	}
	rc = dasd_read_tracks(dasd, vtoctrckno, vtoctrckno, trackdata);
	if (rc) {
		errorlog_add_message(
			&dasd->log, dasd->log, rc,
			"read VTOC: error when reading VTOC start\n");
		goto cleanup;
	}
	record = NULL;
	f4 = NULL;
	i = 0;
	while (!buffer_get_next_record(trackdata, RAWTRACKSIZE, &record)) {
		if (i == vtocrecno) {
			f4 = (format4_label_t *)(record + 8);
			ecount = (struct eckd_count *)record;
			break;
		}
		++i;
	}
	/* verify that the found record has the expected format */
	if (!(f4 &&
	      (ecount->kl == 44) && (ecount->dl == 96) &&
	      (f4->DS4KEYCD[0] == 0x04) &&
	      (f4->DS4KEYCD[43] == 0x04) &&
	      (f4->DS4IDFMT == 0xf4))) {
		rc = EPROTO;
		errorlog_add_message(
			&dasd->log, NULL, rc,
			"read VTOC: could not find format 4 DSCB\n");
		goto cleanup;
	}
	/* We have found a format 4 label at the position indicated by the
	 * label.
	 * How to determine the size of the VTOC:
	 *  - DS4VTOCE contains the VTOC extent, or in other words, lower and
	 *             uper boundary of the VTOC
	 *
	 * Searching through the VTOC tracks record by record is tedious, so
	 * we build an array of pointers to the DSCBs, our VTOC index:
	 * Number of entries in the index is the number of tracks times the
	 * number of DSCBS per track plus one for record zero
	 */
	lzds_dasd_cchh2trk(dasd, &f4->DS4VTOCE.llimit, &vtoctrack_start);
	lzds_dasd_cchh2trk(dasd, &f4->DS4VTOCE.ulimit, &vtoctrack_end);
	vtoc_rec_per_track = (f4->DS4DEVCT.DS4DEVDT + 1);
	/* A VTOC consists of whole tracks, so the index size is number of
	 * tracks multiplied by records per track
	 */
	vtocindexsize = (vtoctrack_end - vtoctrack_start + 1) *
		vtoc_rec_per_track;

	rawvtocsize = ((unsigned long long)vtoctrack_end - vtoctrack_start + 1)
		* RAWTRACKSIZE;

	f4 = NULL;
	record = NULL;
	free(trackdata);
	trackdata = memalign(4096, rawvtocsize); /* page align for O_DIRECT */
	if (!trackdata) {
		rc = ENOMEM;
		goto cleanup;
	}

	/* read in the full VTOC from disk into memory */
	rc = dasd_read_tracks(dasd, vtoctrack_start, vtoctrack_end, trackdata);
	if (rc) {
		errorlog_add_message(
			&dasd->log, dasd->log, rc,
			"read VTOC: error when reading VTOC\n");
		goto cleanup;
	}

	rawvtoc->rawdata = trackdata;
	rawvtoc->rawdatasize = rawvtocsize;
	rawvtoc->vtoc_rec_per_track = vtoc_rec_per_track;
	rawvtoc->vtoctrackoffset = vtoctrack_start;
	rawvtoc->vtocrecno = vtocrecno;
	rawvtoc->vtocindexcount = vtocindexsize;

	/* Now parse all VTOC tracks in memory and create an index of
	 * all records (including record 0)
	 */
	rawvtoc->vtocindex = malloc(sizeof(char *) * vtocindexsize);
	if (!rawvtoc->vtocindex) {
		rc = ENOMEM;
		goto cleanup;
	}
	memset(rawvtoc->vtocindex, 0, (sizeof(char *) * vtocindexsize));

	record = NULL;
	f4 = NULL;
	i = 0;
	while (!buffer_get_next_record(trackdata, rawvtocsize, &record)) {
		/* verify that we do not get too many records */
		if (i >= vtocindexsize) {
			rc = EPROTO;
			errorlog_add_message(
				&dasd->log, NULL, rc,
				"read VTOC: too many records in VTOC\n");
			goto cleanup;
		}
		rawvtoc->vtocindex[i] = record;
		++i;
	}

	return 0;

cleanup:
	free(trackdata);
	return rc;
}

/**
 * @param[in]  dasd The struct dasd that represents the device we want to read
 *                  the VTOC from.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structure due to lack of memory.
 *   - EINVAL  The volume label has not yet been read or it is not valid.
 *   - EPROTO  The VTOC data is not in a valid format.
 *   - EIO     Other I/O error
 */
int lzds_dasd_alloc_rawvtoc(struct dasd *dasd)
{
	struct raw_vtoc *rawvtoc = NULL;
	int rc;

	/* cleanup the old rawvtoc structures before we read new ones */
	rawvtoc = dasd->rawvtoc;
	dasd->rawvtoc = NULL;
	if (rawvtoc) {
		free(rawvtoc->rawdata);
		free(rawvtoc->vtocindex);
		free(rawvtoc);
	}

	rawvtoc = malloc(sizeof(*rawvtoc));
	if (!rawvtoc)
		return ENOMEM;
	memset(rawvtoc, 0, sizeof(*rawvtoc));
	rawvtoc->dasd = dasd;

	rc = lzds_dasd_read_rawvtoc(dasd, rawvtoc);
	if (rc) {
		free(rawvtoc->vtocindex);
		free(rawvtoc);
	} else {
		dasd->rawvtoc = rawvtoc;
	}
	return rc;
}

/**
 * @param[in]  dasd Pointer to the struct dasd we want to get the raw_vtoc from.
 * @param[out] vtoc Reference to a pointer variable in which a pointer to
 *                  the previously read struct raw_vtoc will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  The VTOC has not yet been read.
 */
int lzds_dasd_get_rawvtoc(struct dasd *dasd, struct raw_vtoc **vtoc)
{
	errorlog_clear(dasd->log);
	*vtoc = dasd->rawvtoc;
	if (!*vtoc)
		return EINVAL;
	else
		return 0;
}


/******************************************************************************/
/*      HIGH level functions                                                  */
/******************************************************************************/

/**
 * @param[in] zdsroot  Reference to struct zdsroot that the iterator will be
 *                     bound to. The iterator will traverse the data sets stored
 *                     in this zdsroot.
 * @param[out] it Reference to a pointer variable in which the newly allocated
 *                structure will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
int lzds_zdsroot_alloc_dsiterator(struct zdsroot *zdsroot,
				  struct dsiterator **it)
{
	*it = malloc(sizeof(struct dsiterator));
	if (*it) {
		(*it)->dsi = NULL;
		(*it)->zdsroot = zdsroot;
		return 0;
	}
	return ENOMEM;
}

/**
 * @param[in]  it  Pointer to the struct dsiterator that is to be freed.
 */
void lzds_dsiterator_free(struct dsiterator *it)
{
	free(it);
}

/**
 * @param[in] it   Reference to the struct dsiterator we use to traverse the
 *                 data set list.
 * @param[out] ds  Reference to a pointer variable in which the next
 *                 data set in the sequence will be returned. If there
 *                 is no next data set, this variable will be set to NULL.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPERM  The end of the list has been reached. There is no further dataset.
 */
int lzds_dsiterator_get_next_dataset(struct dsiterator *it, struct dataset **ds)
{
	struct dataset *dstmp;

	if (!it->dsi)
		dstmp = util_list_start(it->zdsroot->datasetlist);
	else
		dstmp = util_list_next(it->zdsroot->datasetlist, it->dsi);
	*ds = dstmp;
	if (!dstmp)
		return EPERM;
	it->dsi = dstmp;
	return 0;
}


/**
 * @param[in] root  Reference to struct zdsroot that holds the list of data
 *                  sets that this function shall search through.
 * @param[in] name  Name of the data set.
 * @param[out] ds   Reference to a pointer variable in which the found dataset
 *                  structure will be returned. If no data set was found, this
 *                  variable will be set to NULL
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not internal structure due to lack of memory.
 *   - ENOENT  A dataset with the given name was not found.
 */
int lzds_zdsroot_find_dataset(struct zdsroot *root, const char *name,
			      struct dataset **ds)
{
	struct dsiterator *dsit;
	struct dataset *tempds;
	int rc;

	errorlog_clear(root->log);
	*ds = NULL;
	rc = lzds_zdsroot_alloc_dsiterator(root, &dsit);
	if (rc)
		return ENOMEM;
	while (!lzds_dsiterator_get_next_dataset(dsit, &tempds)) {
		if (!strcmp(tempds->name, name)) {
			*ds = tempds;
			break;
		}
	}
	lzds_dsiterator_free(dsit);
	if (!*ds)
		return ENOENT;
	return 0;
}

/**
 * @param[in] ds  Reference to the struct dataset that the iterator will be
 *                bound to. The iterator will traverse the members stored
 *                in this data set.
 * @param[out] it Reference to a pointer variable in which the newly allocated
 *                structure will be returned.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 *   - EINVAL  Failed to allocate a memberiterator because the data set does
 *             not support members (is not a PDS).
 */
int lzds_dataset_alloc_memberiterator(struct dataset *ds,
				      struct memberiterator **it)
{
	if (!ds->memberlist) {
		*it = NULL;
		return errorlog_add_message(
			&ds->log, NULL, EINVAL,
			"alloc memberiterator: this data set has no members\n");

	}
	*it = malloc(sizeof(struct memberiterator));
	if (*it) {
		(*it)->memberi = NULL;
		(*it)->ds = ds;
		return 0;
	}
	return ENOMEM;
}

/**
 * @param[in]  it  Pointer to the struct meberiterator that is to be freed.
 */
void lzds_memberiterator_free(struct memberiterator *it)
{
	free(it);
}

/**
 * @param[out] it    Reference to the struct memberiterator we use to traverse
 *                   the member list.
 * @param[out] member Reference to a pointer variable in which the next member
 *                    in the sequence will be returned. If there is no next
 *                    member, this variable will be set to NULL.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPERM  The end of the list has been reached. There is no further dasd.
 */
int lzds_memberiterator_get_next_member(struct memberiterator *it,
					struct pdsmember **member)
{
	struct pdsmember *memtmp;

	if (!it->memberi)
		memtmp = util_list_start(it->ds->memberlist);
	else
		memtmp = util_list_next(it->ds->memberlist, it->memberi);
	*member = memtmp;
	if (!memtmp)
		return EPERM;
	it->memberi = memtmp;
	return 0;
}


/**
 * @brief Subroutine of raw_vtoc_get_datasetpart_from_dscb
 *
 * Check the validity of the extent and copy it to the extent array in the
 * datasetpart.
 * @param[in] extent Pointer to the extent that is to be copied.
 * @param[in] dsp   The target datasetpart.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPROTO  The extent is not valid.
 */
static int copy_extent_to_datasetpart(extent_t *extent, struct datasetpart *dsp)
{
	/* sanity check: if the extent is valid then make sure that seqno
	 * will not cause us to go beyond the array limits
	 */
	if (extent->typeind && extent->seqno >= MAXEXTENTS)
		return EPROTO;
	if (extent->typeind)
		dsp->ext[extent->seqno] = *extent;
	return 0;
}

/**
 * @brief Subroutine of raw_vtoc_get_datasetpart_from_dscb
 */
static int raw_vtoc_add_extent_error_message(struct raw_vtoc *rv)
{
	return errorlog_add_message(
		&rv->log, NULL, EPROTO,
		"vtoc: an extent descriptor is not valid \n");
}

/**
 * @brief Subroutine of create_dataset_from_dscb
 *
 * This function copies the necessary data from a format 1/8 DSCB
 * into a given datasetpart structure.
 * @param[in] rv  The raw_vtoc that f1 belongs to.
 * @param[in] f1  The f1/f8 DSCB that the datasetpart is based on.
 * @param[in] dsp The target datasetpart.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPROTO  Invalid data in the DSCB or dependent DSCBs.
 */
static int raw_vtoc_get_datasetpart_from_dscb(struct raw_vtoc *rv,
					      format1_label_t *f1,
					      struct datasetpart *dsp)
{
	format3_label_t *f3;
	format9_label_t *f9;
	struct dscb *dscb;
	int rc, j;

	errorlog_clear(rv->log);
	memset(dsp, 0, sizeof(*dsp));
	dsp->f1 = f1;

	/* Find the first format 3 DSCB that is chained format 1 or 8 DSCB.
	 * In a format 8 dscb we will first have one or more format 9
	 * DSCBs that we need to pass over.
	 */
	rc = lzds_raw_vtoc_get_dscb_from_cchhb(rv, &f1->DS1PTRDS, &dscb);
	while (!rc && dscb && dscb->fmtid == 0xf9) {
		f9 = (format9_label_t *)dscb;
		rc = lzds_raw_vtoc_get_dscb_from_cchhb(rv, &f9->DS9PTRDS,
						       &dscb);
	}
	if (rc)
		return errorlog_add_message(
			&rv->log, rv->log, EPROTO,
			"vtoc: format 9 DSCB chain not valid \n");
	/* We may or may not have a format 3 DSCB */
	f3 = (dscb && dscb->fmtid == 0xf3) ? (format3_label_t *)dscb : NULL;

	/* In any case we have three extents in the f1/8 label itself */
	rc = copy_extent_to_datasetpart(&f1->DS1EXT1, dsp);
	if (rc)
		return raw_vtoc_add_extent_error_message(rv);
	rc = copy_extent_to_datasetpart(&f1->DS1EXT2, dsp);
	if (rc)
		return raw_vtoc_add_extent_error_message(rv);
	rc = copy_extent_to_datasetpart(&f1->DS1EXT3, dsp);
	if (rc)
		return raw_vtoc_add_extent_error_message(rv);
	/* now follow the f3 chain */
	while (f3) {
		if (f3->DS3FMTID != 0xf3)
			return errorlog_add_message(
				&rv->log, rv->log, EPROTO,
				"vtoc: format 3 DSCB not valid \n");
		for (j = 0; j < 4; ++j) {
			rc = copy_extent_to_datasetpart(&f3->DS3EXTNT[j], dsp);
			if (rc)
				return raw_vtoc_add_extent_error_message(rv);
		}
		for (j = 0; j < 9; ++j) {
			rc = copy_extent_to_datasetpart(&f3->DS3ADEXT[j], dsp);
			if (rc)
				return raw_vtoc_add_extent_error_message(rv);
		}
		rc = lzds_raw_vtoc_get_dscb_from_cchhb(rv, &f3->DS3PTRDS,
						       (struct dscb **)&f3);
		if (rc)
			return errorlog_add_message(
				&rv->log, rv->log, EPROTO,
				"vtoc: format 3 DSCB reference not valid\n");
	}
	return 0;
}

/**
 * @brief Subroutine of lzds_zdsroot_extract_datasets_from_dasd
 *
 * This functions takes the data of a format 1/8 label, fills in
 * a given struct dataset and creates exactly one dataset part.
 * In case of a multi volume data set this part may not be the the
 * first in the ds->dsp array, but is placed according to its
 * volume sequence number!
 * @param[in] dasd  The dasd the data set belongs to.
 * @param[in] f1    The f1/f8 DSCB that the dataset(part) is based on.
 * @param[in] ds    A dataset structure that will be filled with data,
 *                  in particular a data set part.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 *   - EPROTO  Invalid data in the DSCB: An extent is not valid.
 */
static int create_dataset_from_dscb(struct dasd *dasd, format1_label_t *f1,
				    struct dataset *ds)
{
	struct datasetpart *dsp;
	char *end;
	int rc;
	int dspindex;

	errorlog_clear(dasd->log);
	memset(ds, 0, sizeof(*ds));

	dsp = malloc(sizeof(*dsp));
	if (!dsp)
		return ENOMEM;

	/* convert EBCDIC fixed length name into ascii 0-terminated string */
	strncpy(ds->name, f1->DS1DSNAM, MAXDSNAMELENGTH - 1);
	vtoc_ebcdic_dec(ds->name, ds->name, MAXDSNAMELENGTH - 1);
	end = strchr(ds->name, ' ');
	if (end)
		*end = 0;

	rc = raw_vtoc_get_datasetpart_from_dscb(dasd->rawvtoc, f1, dsp);
	if (rc) {
		free(dsp);
		return errorlog_add_message(
			&dasd->log, dasd->rawvtoc->log, rc,
			"create data sets: get data set part failed for %s\n",
			ds->name);
	}
	dsp->dasdi = dasd;
	dspindex = f1->DS1VOLSQ - 1;
	if (dspindex < 0 || dspindex >= MAXVOLUMESPERDS) {
		free(dsp);
		return errorlog_add_message(
			&dasd->log, NULL, EPROTO,
			"create data sets: data set sequence number "
			"out of bounds failed for %s\n",
			ds->name);
	}
	ds->dsp[dspindex] = dsp;
	ds->dspcount = 1;
	/* Note: we cannot tell the difference between the first volume of
	 * a multi volume data set and a single volume data set,
	 * so the following is just a first assumption
	 */
	if (dspindex == 0)
		ds->iscomplete = 1;
	else
		ds->iscomplete = 0;

	return 0;
}


/**
 * @brief Subroutine of extract_members_from_track
 *
 * Take the information from a pds_member_entry, create a new pdsmember
 * and add it to the datasets memberlist
 * @param[in] ds  The dataset that the new struct pdsmember will be added to.
 * @param[in] memberentry The PDS directory entry that describes the member.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
static int dataset_add_member(struct dataset *ds,
			      struct pds_member_entry *memberentry)
{
	char name[9];
	char *end;
	struct pdsmember *member;

	/* convert name to ascii and truncate trailing spaces */
	strncpy(name, memberentry->name, 8);
	name[8] = 0;
	vtoc_ebcdic_dec(name, name, 8);
	end = strchr(name, ' ');
	if (end)
		*end = 0;

	member = malloc(sizeof(*member));
	if (!member)
		return ENOMEM;
	memset(member, 0, sizeof(*member));
	strcpy(member->name, name);
	member->track = memberentry->track;
	member->record = memberentry->record;
	member->is_alias = memberentry->is_alias;
	util_list_add_tail(ds->memberlist, member);
	return 0;
}

/**
 * @brief Helper function that removes and frees all elements in the
 *        member list in a struct dataset.
 *
 * @param[in] ds  The dataset whose memberlist is to be freed.
 */
static void dataset_free_memberlist(struct dataset *ds)
{
	struct pdsmember *member, *next;

	if (!ds->memberlist)
		return;
	util_list_iterate_safe(ds->memberlist, member, next) {
		util_list_remove(ds->memberlist, member);
		errorlog_free(member->log);
		free(member);
	}
	util_list_free(ds->memberlist);
	ds->memberlist = NULL;
}

/**
 * @brief Helper function that just checks if the type of an extend
 * indicates that it contains user data or not.
 *
 * @param[in] ext The extent that gets evaluated.
 * @return     1 if the extent contains user data, 0 otherwise.
 */
static int extent_contains_userdata(extent_t *ext)
{
	return ((ext->typeind == 0x01) || (ext->typeind == 0x81));
}

/**
 * @brief Subroutine of dataset_member_analysis.
 *
 * This function parses one track of a PDS directory and adds all found
 * members to the dataset. A PDS directory may span more than one track.
 * The variable dirend is used to indicate the end of the directory.
 *
 * @note In case of an error there is no cleanup done for the data set.
 *
 * @param[in] trackdata  The raw track that contains the PDS directory.
 * @param[in]  ds        The dataset the found members will be added to.
 * @param[out] dirend    If the end of the directory is found, dirend is
 *                       set to 1, else it is 0.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 *   - EPROTO  The track layout is not valid.
 */
static int extract_members_from_track(char *trackdata, struct dataset *ds,
				      int *dirend)
{
	char *record, *data;
	int r;
	struct eckd_count *ecount;
	int used_bytes, residual, user_data_size;
	struct pds_member_entry *member;
	int rc;

	*dirend = 0;
	record = NULL;
	r = 0;
	while (!buffer_get_next_record(trackdata, RAWTRACKSIZE, &record)) {
		/* jump over record zero */
		if (r == 0) {
			++r;
			continue;
		}
		data = record;
		ecount = (struct eckd_count *)data;
		/* sanity check: do key and data length match the format of
		 * a directory record? */
		if ((ecount->kl != PDS_DIR_KL) || (ecount->dl != PDS_DIR_DL))
			return errorlog_add_message(
				&ds->log, NULL, EPROTO,
				"member analysis: directory record layout"
				" not valid, offset %lu\n",
			      (unsigned long)ecount - (unsigned long)trackdata);
		data += sizeof(*ecount);
		/* compare key to directory end token */
		if ((*(unsigned long long *)data) == ENDTOKEN)
			*dirend = 1;
		data += ecount->kl;
		/* First element in the data area are two bytes that denote how
		 * may bytes of the data area are used for directory entries.
		 * This number includes the first two bytes.
		 */
		used_bytes = (*(unsigned short *)data);
		residual = used_bytes - sizeof(unsigned short);
		data += sizeof(unsigned short);
		/* Loop over directory entries in record */
		while (residual > 0) {
			/* A pseudo directory entry marks directory end */
			if ((*(unsigned long long *)data) == ENDTOKEN) {
				*dirend = 1; /* should already be set */
				break;
			}
			member = (struct pds_member_entry *)data;
			rc = dataset_add_member(ds, member);
			if (rc)
				return rc;
			/* A directory entry may contain a user data part
			 * that follows the pds_member_entry structure.
			 */
			user_data_size = 2 * member->user_data_count;
			data += sizeof(*member) + user_data_size;
			residual -= (sizeof(*member) + user_data_size);
		}
		++r;
		if (*dirend)
			break;
	}
	return 0;
}

/**
 * @brief Subroutine of lzds_zdsroot_extract_datasets_from_dasd.
 *
 * This function checks if a data set is a PDS, analyzes the PDS directory
 * and creates a corresponding list of struct pdsmember in the dataset.
 *
 * @param[in]  ds  The dataset that is to be analyzed and the found
 *                 members will be added to.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 *   - EPROTO  The track layout is not valid.
 *   - EINVAL  An internal error happened.
 *   - EIO     An error happened while reading data from disk.
 */
static int dataset_member_analysis(struct dataset *ds)
{
	char *trackdata;
	unsigned int extstarttrk, extendtrk, currenttrack;
	int j;
	int dirend;
	struct datasetpart *dsp;
	struct dasd *dasd;
	struct dasdhandle *dasdh;
	int rc, rc2;
	int issupported;

	errorlog_clear(ds->log);
	rc2 = 0;
	/* a partitioned data set has only one volume, so we only need dsp[0] */
	dsp = ds->dsp[0];
	/* if it is not a partitioned data set, do nothing */
	if (!dsp || !(dsp->f1->DS1DSRG1 & 0x02))
		return 0;
	/* do not do member analysis if we do not support the format (PDSE) */
	lzds_dataset_get_is_supported(ds, &issupported);
	if (!issupported)
		return 0;

	dasd = dsp->dasdi;

	dataset_free_memberlist(ds);
	ds->memberlist = util_list_new(struct pdsmember, list);

	/* track buffer must be page aligned for O_DIRECT */
	trackdata = memalign(4096, RAWTRACKSIZE);
	if (!trackdata)
		return ENOMEM;

	rc = lzds_dasd_alloc_dasdhandle(dasd, &dasdh);
	if (rc)
		goto out1;
	rc = lzds_dasdhandle_open(dasdh);
	if (rc) {
		errorlog_add_message(
			&ds->log, dasdh->log, rc,
			"member analysis: could not open dasdhandle\n");
		goto out2;
	}
	dirend = 0;
	/* loop over all extents in dataset*/
	for (j = 0; j < MAXEXTENTS; ++j) {
		if (!extent_contains_userdata(&dsp->ext[j]))
			continue;
		lzds_dasd_cchh2trk(dasd, &dsp->ext[j].llimit, &extstarttrk);
		lzds_dasd_cchh2trk(dasd, &dsp->ext[j].ulimit, &extendtrk);
		currenttrack = extstarttrk;
		/* loop over tracks in extent */
		while (currenttrack <= extendtrk) {
			rc = lzds_dasdhandle_read_tracks_to_buffer(
				dasdh, currenttrack, currenttrack, trackdata);
			if (rc) {
				errorlog_add_message(
					&ds->log, dasdh->log, rc,
					"member analysis: read error\n");
				goto out4;
			}
			rc = extract_members_from_track(trackdata, ds, &dirend);
			if (rc) {
				errorlog_add_message(
					&ds->log, ds->log, rc,
					"member analysis: error "
					"extracting members from track %u\n",
					currenttrack);
				goto out4;
			}
			currenttrack++;
			if (dirend)
				break;
		}
		if (dirend)
			break;
	}

	rc = 0;
	goto out3;

out4:
	dataset_free_memberlist(ds);
out3:
	rc2 = lzds_dasdhandle_close(dasdh);
	/* report close error only if we had no read error */
	if (rc2 && !rc) {
		errorlog_add_message(
			&ds->log, dasdh->log, rc,
			"member analysis: could not close dasdhandle\n");
		rc = rc2;
	}
out2:
	lzds_dasdhandle_free(dasdh);
out1:
	free(trackdata);
	rc = rc ? rc : rc2;
	return rc;
}

/**
 * @brief Subroutine of zdsroot_merge_dataset
 *
 * Merge two dataset structures that are two halves of a multi volume data set.
 * All datasetparts of the second dataset are copied to the first dataset.
 *
 * @param[in]  baseds  The dataset that the data will be merged into.
 * @param[in]  newds   The dataset that will be merged with baseds.
 *                     This strucure can be freed after the merge, but do not
 *                     free the data set parts it contained, as those belong
 *                     to baseds now.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPROTO  The data is not mergable because of conflicting entries.
 */
static int dataset_merge_dataset(struct dataset *baseds, struct dataset *newds)
{
	int k, l, dspcount;

	for (k = 0; k < MAXVOLUMESPERDS; ++k) {
		/* if both datasets have a part in position k,
		 * then something is wrong */
		if (baseds->dsp[k] && newds->dsp[k])
			return errorlog_add_message(
				&baseds->log, NULL, EPROTO, "merge dataset: "
				"part %d was previously found on device %s\n",
				k, baseds->dsp[k]->dasdi->device);
		/* if the new data set has a part that is not present in the
		 * base data set, than copy the dsp pointer to the base
		 */
		if (!baseds->dsp[k] && newds->dsp[k]) {
			/* Each format 1/8 DSCB of a part in a multi volume data
			 * set has a reference to the volume serial of the first
			 * volume. Need to verify that the new data set parts
			 * refer to the correct volume serial in f1->DS1DSSN.
			 * Since dsp[0] may not be set yet, we loop over the
			 * base dsp array until we find an entry.
			 */
			for (l = 0; l < MAXVOLUMESPERDS; ++l) {
				if (!baseds->dsp[l])
					continue;
				if (memcmp(baseds->dsp[l]->f1->DS1DSSN,
					   newds->dsp[k]->f1->DS1DSSN,
					   MAXVOLSER))
					return errorlog_add_message(
						&baseds->log, NULL, EPROTO,
						"merge dataset: part %d has incompatible base volume serial\n",
						k);
				else
					break;
			}

			baseds->dsp[k] = newds->dsp[k];
			baseds->dspcount++;

		}
	}
	/* check for completeness:
	 * If element (dspcount - 1) exists and is the last part in a multi
	 * volume data set, then all other parts must have been found as well.
	 */
	dspcount = baseds->dspcount;
	if (baseds->dsp[dspcount - 1] &&
	    (baseds->dsp[dspcount - 1]->f1->DS1DSIND & 0x80))
		baseds->iscomplete = 1;
	else
		baseds->iscomplete = 0;
	/* The last statement is only true for a correct multi volume data set.
	 * Since the data on the DASDs may be incorrect and we will rely later
	 * on the fact that the first dspcount elements of the dsp array are
	 * valid, we must make sure that they are all filled.
	 */
	if (baseds->iscomplete)
		for (l = 0; l < baseds->dspcount; ++l)
			if (!baseds->dsp[l]) {
				baseds->iscomplete = 0;
				return errorlog_add_message(
					&baseds->log, NULL, EPROTO,
					"merge dataset: inconsistent data set"
					" part list at index %d\n", l);
			}

	return 0;
}

/**
 * @brief Subroutine of lzds_zdsroot_extract_datasets_from_dasd
 *
 * Takes the data from newds and merges it with a matching dataset in
 * root. If no matching dataset exists yet, a new struct dataset is
 * created, so that the caller of this function can release newds in
 * any case.
 * It is important to note that while newds is just a temporary
 * structure that can be released after the function returns, the
 * elements and structures that are contained by newds (e.g the
 * datasetparts) are transferred to the struct dataset in root and must
 * not be released.
 *
 * @param[in]  root    The zdsroot that the dataset will be merged into.
 * @param[in]  newds   The dataset that will be merged.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structure due to lack of memory.
 *   - EPROTO  The data is not mergable because of conflicting entries.
 */
static int zdsroot_merge_dataset(struct zdsroot *root, struct dataset *newds)
{
	struct dataset *rootds;
	int rc;

	/* first, try to find a matching data set in the old list */
	rc = lzds_zdsroot_find_dataset(root, newds->name, &rootds);
	if (!rc) { /* match found */
		rc = dataset_merge_dataset(rootds, newds);
		if (rc)
			return errorlog_add_message(
				&root->log, rootds->log, rc,
				"merge dataset: "
				"merge with existing data set failed\n");
	} else if (rc == ENOENT) { /* no match found */
		rootds = malloc(sizeof(*rootds));
		if (!rootds)
			return ENOMEM;
		memcpy(rootds, newds, sizeof(*rootds));
		util_list_add_tail(root->datasetlist, rootds);
	} else
		return rc;
	return 0;
}

/**
 * This function finds all data set descriptions in the VTOC of the
 * dasd and creates respective struct dataset representations. These
 * struct dataset are stored in the zdsroot and can later be traversed
 * using a dsiterator.  In case that it finds a dataset that is
 * already present in the zdsroot, it verifies that both are parts of
 * the same multivolume data set and then merges the new data with the
 * existing struct dataset.  If the conflicting data sets are indeed
 * individual data sets and not parts of a single one, the function
 * returns an error.
 *
 * @param[in]  root    The zdsroot that the dataset will be merged into.
 * @param[in]  dasd    The datasets found in this dasd will be merged.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 *   - EPROTO  The data is not mergable because of conflicting entries,
 *             or invalid data in the VTOC of the dasd.
 */
int lzds_zdsroot_extract_datasets_from_dasd(struct zdsroot *root,
					    struct dasd *dasd)
{
	format1_label_t *f1;
	struct dscb *dscb;
	struct dscbiterator *it;
	int rc;
	struct dataset tmpds;
	int i;

	errorlog_clear(root->log);
	memset(&tmpds, 0, sizeof(tmpds));
	rc = lzds_raw_vtoc_alloc_dscbiterator(dasd->rawvtoc, &it);
	if (rc)
		return ENOMEM;
	while (!lzds_dscbiterator_get_next_dscb(it, &dscb)) {
		if (dscb->fmtid == 0xf1 || dscb->fmtid == 0xf8) {
			f1 = (format1_label_t *)dscb;
			rc = create_dataset_from_dscb(dasd, f1, &tmpds);
			if (rc) {
				errorlog_add_message(
					&root->log, dasd->log, rc,
					"extract data sets: "
					"creating dataset failed for %s\n",
					dasd->device);
				break;
			}
			rc = dataset_member_analysis(&tmpds);
			if (rc) {
				errorlog_add_message(
					&root->log, tmpds.log, rc,
					"extract data sets: "
					"member analysis failed for %s\n",
					tmpds.name);
				break;
			}
			rc = zdsroot_merge_dataset(root, &tmpds);
			if (rc) {
				errorlog_add_message(
					&root->log, root->log, rc,
					"extract data sets: "
					"merge dataset failed for %s\n",
					tmpds.name);
				break;
			}
		}
	}
	if (rc) {
		dataset_free_memberlist(&tmpds);
		for (i = 0; i < MAXVOLUMESPERDS; ++i)
			free(tmpds.dsp[i]);
		errorlog_free(tmpds.log);
	}
	lzds_dscbiterator_free(it);
	return rc;
}

/**
 * @brief Subroutine of lzds_dataset_get_size_in_tracks
 *
 * Computes the number of tracks in a given extent.
 * Returns 0 for anything but user data.
 * @param[in]  ext    The extent we want to know the size of.
 * @param[in]  dasd   The dasd that the extent is located on.
 * @return     Number of tracks the extent contains
 */
static unsigned int get_extent_size_in_tracks(extent_t *ext, struct dasd *dasd)
{
	unsigned int starttrck, endtrck;

	if (!extent_contains_userdata(ext))
		return 0;

	lzds_dasd_cchh2trk(dasd, &ext->llimit, &starttrck);
	lzds_dasd_cchh2trk(dasd, &ext->ulimit, &endtrck);

	return endtrck - starttrck + 1;
}

/**
 * @param[in]  ds     The dataset we we want to know the size of.
 * @param[out] tracks Reference to a return buffer for the number of tracks.
 */
void lzds_dataset_get_size_in_tracks(struct dataset *ds,
				     unsigned long long *tracks)
{
	unsigned long long sumtracks;
	int i, j;

	*tracks = 0;
	sumtracks = 0;
	for (i = 0; i < MAXVOLUMESPERDS; ++i)
		if (ds->dsp[i])
			for (j = 0; j < MAXEXTENTS; ++j)
				sumtracks += get_extent_size_in_tracks(
					&ds->dsp[i]->ext[j], ds->dsp[i]->dasdi);
	*tracks = sumtracks;
}

/**
 * @param[in]  member The PDS member we want to know the name of.
 * @param[out] name   Reference to a pointer variable in which a pointer to
 *                    the name string will be returned.
 */
void lzds_pdsmember_get_name(struct pdsmember *member, char **name)
{
	*name = member->name;
}

/**
 * @param[in]  ds     The dataset we want to know the name of.
 * @param[out] name   Reference to a pointer variable in which a pointer to
 *                    the name string will be returned.
 */
void lzds_dataset_get_name(struct dataset *ds, char **name)
{
	*name = ds->name;
}

/**
 * @param[in]  ds     Is this dataset a PDS?
 * @param[out] ispds  Reference to a pointer variable in which
 *                    1 (true) or 0 (false) is returned.
 */
void lzds_dataset_get_is_PDS(struct dataset *ds, int *ispds)
{

	if (ds->dsp[0]->f1->DS1DSRG1 & 0x02) /* is PDS */
		*ispds = 1;
	else
		*ispds = 0;
}

/**
 * The returned DSCB belongs always to the first volume of a data set.
 *
 * @param[in]  ds   The dataset we want to know the DSCB of.
 * @param[out] f1   Reference to a pointer variable in which a pointer to
 *                  the format 1 DSCB will be returned.
 */
void lzds_dataset_get_format1_dscb(struct dataset *ds, format1_label_t **f1)
{
	*f1 = ds->dsp[0]->f1;
}

/**
 * @param[in]  ds          Is this dataset complete?
 * @param[out] iscomplete  Reference to a pointer variable in which
 *                         1 (true) or 0 (false) is returned.
 */
void lzds_dataset_get_is_complete(struct dataset *ds, int *iscomplete)
{
	*iscomplete = ds->iscomplete;
}

/**
 * @param[in]  ds           Is this dataset supported?
 * @param[out] issupported  Reference to a pointer variable in which
 *                          1 (true) or 0 (false) is returned.
 */
void lzds_dataset_get_is_supported(struct dataset *ds, int *issupported)
{
	int complete, org_supported, format_supported, not_ext_fmt;
	char DS1RECFM;

	if (!ds->dsp[0]) {
		*issupported = 0;
		return;
	}
	/* do we have all parts of the data set? */
	lzds_dataset_get_is_complete(ds, &complete);

	/* is this a supported organisation (PS or PDS)?*/
	org_supported = 0;
	if ((ds->dsp[0]->f1->DS1DSRG1 & 0x40) || /* PS */
	    (ds->dsp[0]->f1->DS1DSRG1 & 0x02))   /* PDS */
		org_supported = 1;
	/* extended format datasets are not supported */
	not_ext_fmt = 0;
	if (!(ds->dsp[0]->f1->DS1SMSFG & 0x0C))
		not_ext_fmt = 1;
	/* fixed, variable or undefined length records are supported */
	DS1RECFM = ds->dsp[0]->f1->DS1RECFM;
	format_supported = 0;
	if (DS1RECFM & 0xC0)
		format_supported = 1;
	/* track overflow (legacy) is not supported */
	if ((DS1RECFM & 0x20))
		format_supported = 0;
	/* all other RECFM flags are modifiers of the above and are supported */
	*issupported = complete && org_supported && format_supported
		&& not_ext_fmt;
	return;
}

/**
 * @param[in]  ds          The dataset that is searched for the member.
 * @param[in]  membername  The name of the member (ASCII string).
 * @param[out] member      Reference to a pointer variable in which the found
 *                         pdsmember is returned. If no member is found, this
 *                         is set to NULL.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structure due to lack of memory.
 *   - ENOENT  No matching member was found.
 */
int lzds_dataset_get_member_by_name(struct dataset *ds, char *membername,
				    struct pdsmember **member)
{
	struct memberiterator *it;
	struct pdsmember *tmpmember;
	int rc;

	errorlog_clear(ds->log);
	*member = NULL;
	rc = lzds_dataset_alloc_memberiterator(ds, &it);
	if (rc)
		return ENOMEM;
	while (!lzds_memberiterator_get_next_member(it, &tmpmember)) {
		if (!strcmp(tmpmember->name, membername)) {
			*member = tmpmember;
			break;
		}
	}
	lzds_memberiterator_free(it);
	if (!*member)
		return ENOENT;
	return 0;
}

/**
 * @param[in] dsh Pointer to structure that is to be freed.
 */
void lzds_dshandle_free(struct dshandle *dsh)
{
	int i;

	if (!dsh)
		return;
	for (i = 0; i < MAXVOLUMESPERDS; ++i)
		if (dsh->dasdhandle[i])
			lzds_dasdhandle_free(dsh->dasdhandle[i]);
	free(dsh->databuffer);
	free(dsh->rawbuffer);
	if (dsh->seekbuf)
		free(dsh->seekbuf);
	errorlog_free(dsh->log);
	free(dsh);
}

/**
 * @param[in] ds   The dataset  we want to read from.
 * @param[in] tracks_per_frame  The number of tracks that the internal buffers
 *                 can hold. If 0, then the default value 128 is used.
 * @param[out] dsh Reference to a pointer variable which will be used
 *                 to store the new dshandle.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
int lzds_dataset_alloc_dshandle(struct dataset *ds,
				unsigned int tracks_per_frame,
				struct dshandle **dsh)
{
	struct dshandle *dshtmp;
	int i, rc;

	dshtmp = malloc(sizeof(*dshtmp));
	if (!dshtmp)
		return ENOMEM;
	memset(dshtmp, 0, sizeof(*dshtmp));
	for (i = 0; i < ds->dspcount; ++i) {
		rc = lzds_dasd_alloc_dasdhandle(ds->dsp[i]->dasdi,
						&dshtmp->dasdhandle[i]);
		if (rc) {
			lzds_dshandle_free(dshtmp);
			return rc;
		}
	}
	if (tracks_per_frame)
		dshtmp->tracks_per_frame = tracks_per_frame;
	else
		dshtmp->tracks_per_frame = TRACK_BUFFER_DEFAULT;
	dshtmp->rawbufmax = dshtmp->tracks_per_frame * RAWTRACKSIZE;
	/* track buffer must be page aligned for O_DIRECT */
	dshtmp->rawbuffer = memalign(4096, dshtmp->rawbufmax);
	if (!dshtmp->rawbuffer) {
		lzds_dshandle_free(dshtmp);
		return ENOMEM;
	}

	dshtmp->databufmax = dshtmp->tracks_per_frame * MAXRECSIZE;
	dshtmp->databuffer = malloc(dshtmp->databufmax);
	if (!dshtmp->databuffer) {
		lzds_dshandle_free(dshtmp);
		return ENOMEM;
	}

	dshtmp->ds = ds;
	*dsh = dshtmp;
	return 0;
}

/**
 * The number of user data bytes per track is not predictable as record
 * sizes and number of records per track may vary. Seeking forward will
 * always require us to read all the data between the current position
 * and the seek target. To improve performance of seeking backwards
 * we can buffer previous positions in the data set.
 * For a given seek buffer size and the known number of tracks of the
 * data set, we can compute how many track frames we need to skip if
 * we and to store track frames in regular intervals.
 *
 * @param[in] dsh   The dshandle we want to modify.
 * @param[in] seek_buffer_size  The maximum number of bytes to be allocated
 *                  for the seek buffer.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate structure due to lack of memory.
 */
int lzds_dshandle_set_seekbuffer(struct dshandle *dsh,
				 unsigned long long seek_buffer_size)
{
	unsigned long long totaltracks;
	size_t entries, frames;
	unsigned int extents, skip;
	struct dataset *ds;
	int i, j;
	unsigned long long buf_count;

	errorlog_clear(dsh->log);
	if (dsh->seekbuf)
		free(dsh->seekbuf);
	dsh->seekbuf = NULL;
	dsh->seek_count = 0;
	dsh->seek_current = 0;
	dsh->skip = 0;

	if (!seek_buffer_size)
		return 0;

	ds = dsh->ds;
	lzds_dataset_get_size_in_tracks(ds, &totaltracks);

	/* compute the total number of extents */
	extents = 0;
	for (i = 0; i < ds->dspcount; ++i)
		for (j = 0; j < MAXEXTENTS; ++j)
			if (ds->dsp[i]->ext[j].typeind != 0x00)
				++extents;

	entries = seek_buffer_size / sizeof(struct seekelement);

	/* track frames at the end of an extent may be shorter,
	 * increasing the maximum number of frames we need to read */
	frames = (totaltracks / dsh->tracks_per_frame) + 1 + extents;
	skip = (frames / entries) + 1;
	buf_count = (frames / skip) + 1;

	dsh->seekbuf = malloc(buf_count * sizeof(struct seekelement));
	if (!dsh->seekbuf)
		return ENOMEM;
	memset(dsh->seekbuf, 0, buf_count * sizeof(struct seekelement));
	dsh->seek_count = buf_count;
	dsh->skip = skip;
	return 0;
}


/**
 * If dsh points to a partitioned data set, the library needs to know
 * which member of that PDS should be read. So this function must be
 * called before lzds_dshandle_open.  This setting cannot be changed
 * for open dsh, so this function must not be used after
 * lzds_dshandle_open, unless the dsh has been closed with
 * lzds_dsh_close again.
 *
 * @pre The dsh must not be open when this function is called.
 *
 * @param[in] dsh         The dshandle we want to modify.
 * @param[in] membername  The name of the member that shall be read via
 *                        this handle.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOMEM  Could not allocate internal structure due to lack of memory.
 *   - ENOENT  No matching member was found.
 *   - EBUSY   The handle is already open.
 *   - EINVAL  The data set is not a PDS.
 */
int lzds_dshandle_set_member(struct dshandle *dsh, char *membername)
{
	int ispds, rc;
	struct pdsmember *member;

	errorlog_clear(dsh->log);
	if (dsh->is_open)
		return errorlog_add_message(
			&dsh->log, NULL, EBUSY,
			"dshandle: cannot set member while handle is open\n");
	dsh->member = NULL;
	lzds_dataset_get_is_PDS(dsh->ds, &ispds);
	if (!ispds)
		return errorlog_add_message(
			&dsh->log, NULL, EINVAL,
			"dshandle: cannot set member, not a PDS\n");

	rc = lzds_dataset_get_member_by_name(dsh->ds, membername, &member);
	if (rc)
		return errorlog_add_message(
			&dsh->log, NULL, rc,
			"dshandle: could not find member %s in dataset %s\n",
			membername, dsh->ds->name);

	dsh->member = member;
	return 0;
}

/**
 * @param[in]  dsh    The dshandle that we want to know the member of.
 * @param[out] member Reference to a pointer variable in which the found
 *                    pdsmember is returned. If no member has been set
 *                    before, this is set to NULL.
 */
void lzds_dshandle_get_member(struct dshandle *dsh, struct pdsmember **member)
{
	*member = dsh->member;
}

/**
 * @pre The dsh must not be open when this function is called.
 *
 * @param[in] dsh      The dshandle we want to modify.
 * @param[in] keepRDW  Set this to 1 to enable the keep RDW feature or
 *                     0 to disable it.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EBUSY   The handle is already open.
 */
int lzds_dshandle_set_keepRDW(struct dshandle *dsh, int keepRDW)
{
	errorlog_clear(dsh->log);
	if (dsh->is_open)
		return errorlog_add_message(
			&dsh->log, NULL, EBUSY,
			"dshandle: cannot set RDW while handle is open\n");
	dsh->keepRDW = keepRDW;
	return 0;
}

/**
 * @pre The dsh must not be open when this function is called.
 *
 * @param[in] dsh      The dshandle we want to modify.
 * @param[in] iconv_t  The iconv handle for codepage conversion.
 *
 * @return     0 on success, otherwise one of the following error codes:
 *   - EBUSY   The handle is already open.
 */
int lzds_dshandle_set_iconv(struct dshandle *dsh, iconv_t *iconv)
{
	errorlog_clear(dsh->log);
	if (dsh->is_open)
		return errorlog_add_message(
			&dsh->log, NULL, EBUSY,
			"dshandle: cannot set iconv while handle is open\n");

	/*
	 * if conversion is enabled the returned data might in worst case
	 * be 4 times the size of the input buffer. So realloc the buffer.
	 * If for whatever very unlikely reason the converted size is still
	 * larger the conversion will fail.
	 */
	if (iconv) {
		dsh->databufmax *= 4;
		dsh->databuffer = util_realloc(dsh->databuffer,
					       dsh->databufmax);
	}
	dsh->iconv = iconv;
	return 0;
}

/**
 * @param[in]  dsh     The dshandle that we want to know the member of.
 * @param[out] keepRDW Reference to a variable in which the previously
 *                     set keepRDW value is returned.
 */
void lzds_dshandle_get_keepRDW(struct dshandle *dsh, int *keepRDW)
{
	*keepRDW = dsh->keepRDW;
}

/**
 * @brief Helper function that initializes the given handle so that it
 *        points to the beginning of the dataset or member.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPROTO  The dataset data is inconsistent.
 */
static int initialize_buffer_positions_for_first_read(struct dshandle *dsh)
{

	unsigned long long tracksum, extentsize;
	unsigned int starttrck, endtrck;
	int j;

	/* make sure that read knows that we have no ready data in our buffer */
	dsh->bufpos = 0;
	dsh->databufsize = 0;
	dsh->databufoffset = 0;
	dsh->eof_reached = 0;

	/* we need to set the bufendtrk and sequence number so,
	 * that the current track buffer seems to end with the
	 * track that comes before the first track of the
	 * data set or member
	 */

	/* When we read the first track frame this will be incremented to 0 */
	dsh->frameno = -1;

	/* We allways start with data set part 0. Partitioned
	 * data sets have only one part, so this correct for
	 * both partitioned and non partitioned data sets.
	 */
	dsh->dsp_no = 0;

	/* for a non partitioned data set we just need to set the
	 * extentsequence number to -1 so read will start with the
	 * first track of extent number 0
	 */
	if (!dsh->member) {
		dsh->ext_seq_no = -1;
		dsh->bufstarttrk = 0;
		dsh->bufendtrk = 0;
		dsh->extstarttrk = 0;
		dsh->extendtrk = 0;
		return 0;
	}

	/* sanity check: a partitioned data set cannot be a multi volume data
	 * set.
	 */
	if (dsh->ds->dspcount != 1)
		return errorlog_add_message(
			&dsh->log, NULL, EPROTO,
			"initialize read buffer: dataset %s is inconsistent,"
			" PDS must not span more than one volume\n",
			dsh->ds->name);
	/* For a partitioned data set we need to find the correct start
	 * track and point the current buffer just before it.
	 * As we always need to read full tracks, any additional
	 * record offset will be set explicitly and handled during
	 * track interpretation.
	 */
	dsh->startrecord = dsh->member->record;

	/* member->track is an offset based on the start of the data set
	 * I will have to add up extents until I have got the right number
	 * of tracks
	 */
	tracksum = 0;
	/* Note: No need to loop over all data set parts, a PDS has only one */
	for (j = 0; j < MAXEXTENTS; ++j) {
		if (!extent_contains_userdata(&dsh->ds->dsp[0]->ext[j]))
			continue;
		lzds_dasd_cchh2trk(dsh->ds->dsp[0]->dasdi,
				 &dsh->ds->dsp[0]->ext[j].llimit, &starttrck);
		lzds_dasd_cchh2trk(dsh->ds->dsp[0]->dasdi,
				 &dsh->ds->dsp[0]->ext[j].ulimit, &endtrck);
		extentsize = endtrck - starttrck + 1;

		/* If offset in the extent (member->track - tracksum) == 0,
		 * then we must set the dsh buffer to the end of the previous
		 * extent, so that rdf_read will start with the first track
		 * of the next extent.
		 * However, since rdf_read checks for bufendtrk < extendtrk
		 * we can set both to 0 and do not need a special case for the
		 * first extend.
		 */
		if (dsh->member->track == tracksum) {
			dsh->ext_seq_no = j - 1;
			dsh->bufendtrk = 0;
			dsh->extendtrk = 0;
			break;
		}
		/* If the offset is within the current extent an not the
		 * special case above, then we can need to adjust the dsh so,
		 * as if we have just already read data up to the track before
		 * our target track
		 */
		if (dsh->member->track < tracksum + extentsize) {
			dsh->ext_seq_no = j;
			dsh->extstarttrk = starttrck;
			dsh->extendtrk = endtrck;
			dsh->bufstarttrk = dsh->extstarttrk;
			dsh->bufendtrk = dsh->bufstarttrk +
				(dsh->member->track - tracksum) - 1;
			break;
		}
		tracksum += extentsize;
	}
	return 0;
}


/**
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 */
void lzds_dshandle_close(struct dshandle *dsh)
{
	int i;
	for (i = 0; i < MAXVOLUMESPERDS; ++i)
		if (dsh->dasdhandle[i])
			lzds_dasdhandle_close(dsh->dasdhandle[i]);
	free(dsh->convbuffer);
	free(dsh->iconv);
	dsh->is_open = 0;
}

#ifdef HAVE_CURL

struct response_data {
	char *session_ref;
	unsigned long statuscode;
};

static size_t
parse_response_callback(void *data, size_t size, size_t member, void *target)
{
	struct response_data *response = target;

	if (strstr(data, "HTTP/1.1 500 Internal Server Error")) {
		response->statuscode = 500;
	} else if (strstr(data, "HTTP/1.1 200 OK")) {
		response->statuscode = 200;
	} else
		sscanf(data, "X-IBM-Session-Ref: %m[^\n]\n",
		       &response->session_ref);

	return size*member;
}

static size_t write_discard_callback(void *UNUSED(data), size_t size, size_t member,
				     void *UNUSED(target))
{
	/* do nothing just pretend all data has been processed */
	return size*member;
}

CURL *lzds_prepare_curl(char *url)
{
	CURL *curl;

	curl = curl_easy_init();
	if (!curl)
		return NULL;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 0L);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_discard_callback);

	return curl;
}

/**
 * Ping the z/OSMS REST server.
 * Used to check if the server is responding and accessible and to prevent
 * the ENQ from timing out. If not used it would be automatically released
 * after 10 minutes.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 *             server The URL to the z/OSMF REST services
 * @return     1 on success, 0 otherwise
 */
int lzds_rest_ping(struct dshandle *dsh, char *server)
{
	struct curl_slist *list = NULL;
	char *release;
	CURLcode res;
	size_t size;
	CURL *curl;
	char *url;

	url = util_strcat_realloc(NULL, server);
	url = util_strcat_realloc(url, "restfiles/ping");

	curl = lzds_prepare_curl(url);
	if (!curl) {
		free(url);
		return 0;
	}

	list = curl_slist_append(list, "X-CSRF-ZOSMF-HEADER: none");
	if (dsh && dsh->session_ref) {
		size = sizeof("X-IBM-Session-Ref: ") + strlen(dsh->session_ref);
		release = util_zalloc(size);
		snprintf(release, size, "X-IBM-Session-Ref: %s",
			 dsh->session_ref);
		list = curl_slist_append(list, release);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	res = curl_easy_perform(curl);
	curl_slist_free_all(list);
	curl_easy_cleanup(curl);

	if (res == CURLE_OK) {
		free(url);
		return 1;
	}

	fprintf(stderr, "URL: %s\n", url);
	fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
	free(url);
	return 0;
}

/**
 * Mark the dataset as in use for z/OS.
 * Use z/OSMF REST services to read a small amount of data and get an exclusive
 * ENQ that prevents z/OS applications from writing to the dataset in parallel
 * until the ENQ is released.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 *             server The URL to the z/OSMF REST services
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOTSUP Unable to setup curl and therefore no further access possible.
 *   - EPERM ENQ not obtained and therefore access is not allowed.
 */
int lzds_rest_get_enq(struct dshandle *dsh, char *server)
{
	struct curl_slist *list = NULL;
	struct response_data response;
	int first_run;
	CURLcode res;
	CURL *curl;
	char *url;
	int rc;

	url = util_strcat_realloc(NULL, server);
	url = util_strcat_realloc(url, "restfiles/ds/");
	url = util_strcat_realloc(url, dsh->ds->name);

	memset(&response, 0, sizeof(response));
	/*
	 * in the first run provide a range statement to read only 1 record of
	 * the dataset to get an ENQ.
	 * For the unlikely case that the dataset is empty
	 * "500 Internal Server Error" will be returned.
	 * If this is the case give it a second try without a range statement
	 */
	first_run = 1;
	list = curl_slist_append(list, "X-IBM-Record-Range: 0-1");
retry:
	rc = 1;
	curl = lzds_prepare_curl(url);
	if (!curl) {
		free(url);
		return errorlog_add_message(
			&dsh->log,
			NULL, ENOTSUP,
			"curl handle not established for dataset %s\n",
			dsh->ds->name);
	}

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, parse_response_callback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
	list = curl_slist_append(list, "X-CSRF-ZOSMF-HEADER: none");
	list = curl_slist_append(list, "X-IBM-Obtain-ENQ: EXCLU");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		rc = errorlog_add_message(&dsh->log, NULL, ECONNREFUSED,
					  "Error: %s\n",
					  curl_easy_strerror(res));
	} else {
		if (first_run && response.statuscode == 500) {
			curl_slist_free_all(list);
			curl_easy_cleanup(curl);
			first_run = 0;
			list = NULL;
			goto retry;
		}
		/* expect that the callback function found a reference string, double check */
		if (response.statuscode == 200 && response.session_ref) {
			dsh->session_ref = response.session_ref;
			rc = 0;
		} else {
			rc = errorlog_add_message(
				&dsh->log,
				NULL, EPERM,
				"no session ref obtained for dataset %s rest rc %ld\n",
				dsh->ds->name, response.statuscode);
		}
	}

	free(url);
	curl_slist_free_all(list);
	curl_easy_cleanup(curl);

	return rc;
}

/**
 * Mark the dataset as no longer in use for z/OS.
 * Use z/OSMF REST services to read a small amount of data and release the exclusive
 * ENQ that was previously obtained.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 *             server The URL to the z/OSMF REST services
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOTSUP Unable to release the ENQ.
 */
int lzds_rest_release_enq(struct dshandle *dsh, char *server)
{
	struct curl_slist *list = NULL;
	struct response_data response;
	char *release;
	int first_run;
	CURLcode res;
	CURL *curl;
	char *url;


	if (!dsh->session_ref) {
		fprintf(stderr, "No ENQ to release.\n");
		return 0;
	}

	url = util_strcat_realloc(NULL, server);
	url = util_strcat_realloc(url, "restfiles/ds/");
	url = util_strcat_realloc(url, dsh->ds->name);

	release = util_strcat_realloc(NULL, "X-IBM-Session-Ref: ");
	release = util_strcat_realloc(release, dsh->session_ref);

	memset(&response, 0, sizeof(response));
	/*
	 * in the first run provide a range statement to read only 1 record of
	 * the dataset to release the ENQ.
	 * For the unlikely case that the dataset is empty
	 * "500 Internal Server Error" will be returned.
	 * If this is the case give it a second try without a range statement
	 */
	first_run = 1;
	list = curl_slist_append(list, "X-IBM-Record-Range: 0-1");
retry:
	curl = lzds_prepare_curl(url);
	if (!curl) {
		free(url);
		free(release);
		return errorlog_add_message(
			&dsh->log,
			NULL, ENOTSUP,
			"curl handle not established for dataset %s\n",
			dsh->ds->name);
	}

	list = curl_slist_append(list, "X-CSRF-ZOSMF-HEADER: none");
	list = curl_slist_append(list, "X-IBM-Release-ENQ: true");
	list = curl_slist_append(list, release);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, parse_response_callback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
	res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		errorlog_add_message(&dsh->log, NULL, ENOTSUP, "Error: %s\n",
				     curl_easy_strerror(res));
	} else if (first_run && response.statuscode == 500) {
		curl_slist_free_all(list);
		curl_easy_cleanup(curl);
		first_run = 0;
		list = NULL;
		goto retry;
	}

	curl_slist_free_all(list);
	curl_easy_cleanup(curl);
	free(dsh->session_ref);
	free(release);
	free(url);
	dsh->session_ref = NULL;

	return res;
}

#endif /* HAVE_CURL */


/**
 * This makes the data set context ready for read operations.
 * All settings on the dsh must be done before it is opened.
 * @pre For a partitioned data set a member must be set before
 *      this function is called.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 * @return     0 on success, otherwise one of the following error codes:
 *   - ENOTSUP The dataset is of a type that is not supported.
 *   - EINVAL  Tried to open a PDS without setting a member before..
 *   - EIO     Could not open underlying device.
 */
int lzds_dshandle_open(struct dshandle *dsh)
{
	int i, rc;
	int ispds, issupported;

	/* sanity check: Open will fail if the data set type is not supported.
	 * We do this check here and not during dshandle creation, as it may
	 * depend on settings on the dshandle that the user has to make
	 * between creation and open.
	 */
	errorlog_clear(dsh->log);
	lzds_dataset_get_is_supported(dsh->ds, &issupported);
	if (!issupported)
		return errorlog_add_message(
			&dsh->log,
			NULL, ENOTSUP,
			"data set open: data set %s is not supported\n",
			dsh->ds->name);
	lzds_dataset_get_is_PDS(dsh->ds, &ispds);
	if (ispds && !dsh->member)
		return errorlog_add_message(
			&dsh->log,
			NULL, EINVAL,
			"data set open: a member must be set"
			" before PDS %s can be opened\n", dsh->ds->name);
	rc = initialize_buffer_positions_for_first_read(dsh);
	if (rc)
		return errorlog_add_message(
			&dsh->log,
			dsh->log, rc,
			"data set open: error when initializing buffers"
			" for data set %s\n", dsh->ds->name);
	for (i = 0; i < dsh->ds->dspcount; ++i) {
		rc = lzds_dasdhandle_open(dsh->dasdhandle[i]);
		if (rc) {
			errorlog_add_message(
				&dsh->log,
				dsh->dasdhandle[i]->log, rc,
				"data set open: error opening DASD "
				"for data set %s\n", dsh->ds->name);
			lzds_dshandle_close(dsh);
			return rc;
		}
	}
	if (dsh->iconv)
		dsh->convbuffer = util_zalloc(dsh->databufmax);

	dsh->is_open = 1;
	return 0;
}

/**
 * @brief subroutine of parse_fixed_record for codepage conversion
 *
 * Converts the provided data from one codepage to another using iconv.
 * Stores converted data directly in the target buffer.
 * Adds a linebreak at the end of each record to end the line.
 * Also remove trailing spaces.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 * @param[in]  rec         Pointer to the record buffer.
 * @param[in]  targetdata  Pointer to the data buffer.
 * @return     Number of copied data bytes on success,
 *             otherwise one of the following (negative) error codes:
 *   - -EPROTO  The record is malformed.
 */
static ssize_t convert_fixed_record(struct dshandle *dsh,
				    char *rec, char *targetdata)
{
	struct eckd_count *ecount = (struct eckd_count *)rec;
	size_t in_count, out_count, max_count;
	int reclen, blocksize, reccount;
	char *inbuf, *outbuf;
	char *src, *target;
	size_t rc;
	int i;

	blocksize = ecount->dl;
	reclen = dsh->ds->dsp[0]->f1->DS1LRECL;
	reccount = blocksize / reclen;

	outbuf = targetdata;
	out_count =  max_count =
		(unsigned long)dsh->databuffer + dsh->databufmax -
		(unsigned long)targetdata;
	in_count = 0;
	inbuf = dsh->convbuffer;

	/* skip block header */
	src = (rec + sizeof(*ecount) + ecount->kl);
	target = inbuf;
	/* for each record aka line */
	for (i = 0; i < reccount; i++) {
		/* remove trailing spaces */
		while (reclen && (*(src + reclen - 1) == EBCDIC_SP))
			reclen--;
		/* move remaining data and add linebreak at end of record */
		memcpy(target, src, reclen);
		target += reclen;
		*target = EBCDIC_LF;
		target++;
		/* count how much chars remain after whitespace cleanup */
		in_count += reclen + 1;

		/* reset for next line */
		reclen = dsh->ds->dsp[0]->f1->DS1LRECL;
		src += reclen;
	}
	/* convert directly into target buffer */
	rc = iconv(*(dsh->iconv), &inbuf, &in_count, &outbuf, &out_count);
	if ((rc == (size_t) -1) || (in_count != 0))
		return -errorlog_add_message(
			&dsh->log, NULL, EPROTO,
			"fixed record parser: codepage conversion failed\n");
	/* return how much was written in the target buffer */
	return max_count - out_count;
}

/**
 * @brief subroutine of parse_variable_record for codepage conversion
 *
 * Converts the record data from one codepage to another using iconv.
 * Stores converted data directly in the target buffer
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 * @param[in]  reclen      Length of the record.
 * @param[in]  rec         Pointer to the record buffer.
 * @param[in]  targetdata  Pointer to the data buffer.
 * @return     Number of copied data bytes on success,
 *             otherwise one of the following (negative) error codes:
 *   - -EPROTO  The record is malformed.
 */
static ssize_t convert_variable_record(struct dshandle *dsh, int reclen,
				       char *rec, char *targetdata)
{
	size_t in_count, out_count, max_count;
	char *inbuf, *outbuf;
	size_t rc;

	inbuf = rec;
	outbuf = targetdata;
	in_count = reclen + 1;
	out_count = max_count =
		(unsigned long)dsh->databuffer + dsh->databufmax -
		(unsigned long)targetdata;
	/*
	 * we can not overwrite the track end marker since it is still used
	 * for this case we have to make a copy of the source data to add the
	 * linebreak
	 */
	if (inbuf[reclen] == 0xFF) {
		inbuf = dsh->convbuffer;
		memcpy(inbuf, rec, reclen);
	}

	/* add linebreak */
	inbuf[reclen] = 0x25;

	rc = iconv(*(dsh->iconv), &inbuf, &in_count, &outbuf, &out_count);
	if ((rc == (size_t) -1) || (in_count != 0))
		return -errorlog_add_message(
			&dsh->log, NULL, EPROTO,
			"variable record parser: codepage conversion failed\n");

	/* return how much was written in the target buffer */
	return max_count - out_count;
}

/**
 * @brief subroutine of dshandle_extract_data_from_trackbuffer
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 * @param[in]  rec         Pointer to the raw record.
 * @param[in]  targetdata  Pointer to the data buffer.
 * @return     Number of copied data bytes on success,
 *             otherwise one of the following (negative) error codes:
 *   - -EPROTO  The record is malformed.
 */
static ssize_t parse_fixed_record(struct dshandle *dsh,
				  char *rec, char *targetdata)
{
	struct eckd_count *ecount;
	int count;

	ecount = (struct eckd_count *)rec;
	/* Make sure that we do not copy data beyond the end of
	 * the data buffer
	 */
	if ((unsigned long)targetdata + ecount->dl >
	    (unsigned long)dsh->databuffer + dsh->databufmax)
		return - errorlog_add_message(
			&dsh->log, NULL, EPROTO,
			"fixed record to long for target buffer\n");
	if (dsh->iconv) {
		count = convert_fixed_record(dsh, rec, targetdata);
	} else {
		memcpy(targetdata, (rec + sizeof(*ecount) + ecount->kl), ecount->dl);
		count = ecount->dl;
	}
	return count;
}

/**
 * @brief subroutine of dshandle_extract_data_from_trackbuffer
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 * @param[in]  rec         Pointer to the raw record.
 * @param[in]  targetdata  Pointer to the data buffer.
 * @param[in]  keepRDW     Flag that specifies if the RDW should be copied to
 *                         the data buffer or or not.
 * @return     Number of copied data bytes on success,
 *             otherwise one of the following (negative) error codes:
 *   - -EPROTO  The record is malformed.
 */
static ssize_t parse_variable_record(struct dshandle *dsh, char *rec,
				     char *targetdata, int keepRDW)
{
	struct eckd_count *ecount;
	unsigned int blocklength, segmentlength, residual;
	char *data;
	struct segment_header *blockhead;
	struct segment_header *seghead;
	size_t totaldatalength;
	int count;

	/* We must not rely on the data in rec, as it was read from disk and
	 * may be broken. Wherever we interprete the data we must have sanity
	 * checks.
	 */
	ecount = (struct eckd_count *)rec;
	totaldatalength = 0;
	/* An empty record is expected at the end of dataset or member */
	if (ecount->dl == 0)
		return 0;
	/* If the data area is not zero but to small to contain a segment header
	 * then the record contents cannot be valid.
	 */
	if (ecount->dl < sizeof(struct segment_header))
		return - errorlog_add_message(
			&dsh->log, NULL, EPROTO,
			"variable record parser: record length to small\n");
	data = (rec + sizeof(*ecount) + ecount->kl);
	blockhead = (struct segment_header *)data;
	blocklength = blockhead->length;
	/* If the length in the block descriptor is 0, then the block contains
	 * no data. Not sure if this is a valid case, but we tolerate it. */
	if (!blocklength)
		return totaldatalength;
	/* If blocklength is to small to contain the block descriptor or to
	 * large to fit in the data area, then the block descriptor is broken */
	if ((blocklength < sizeof(*blockhead)) || (blocklength > ecount->dl))
		return - errorlog_add_message(
			&dsh->log, NULL, EPROTO,
			"variable record parser: block length to small\n");
	data += sizeof(*blockhead);
	residual = blocklength - sizeof(*blockhead);
	while (residual) {
		seghead = (struct segment_header *)data;
		segmentlength = seghead->length;
		if (seghead->nullsegment || !segmentlength) {
			/* null segment found -> end of data in block */
			return totaldatalength;
		}
		/* If segmentlength is to small to contain the record descriptor
		 * descriptor or to large to fit in the residual data area, then
		 * the record descriptor is broken
		 */
		if ((residual < segmentlength) ||
		    (segmentlength < sizeof(*seghead)))
			return - errorlog_add_message(
				&dsh->log, NULL, EPROTO,
				"variable record parser: segment length %d "
				"inconsistent at offset %lu\n",
				segmentlength,
				(unsigned long)seghead - (unsigned long)rec);
		residual -= segmentlength;
		if (!keepRDW) {
			data += sizeof(*seghead);
			segmentlength -= sizeof(*seghead);
		}
		/* Make sure that we do not copy data beyond the end of
		 * the data buffer
		 */
		if ((unsigned long)targetdata + segmentlength >
		    (unsigned long)dsh->databuffer + dsh->databufmax)
			return - errorlog_add_message(
				&dsh->log, NULL, EPROTO,
				"variable record parser: "
				"record to long for target buffer\n");
		if (dsh->iconv) {
			count = convert_variable_record(dsh, segmentlength,
							data, targetdata);
			if (count < 0)
				return count;

			totaldatalength += count;
			targetdata += count;
		} else {
			memcpy(targetdata, data, segmentlength);
			totaldatalength += segmentlength;
			targetdata += segmentlength;
		}
		data += segmentlength;
	}
	return totaldatalength;
}

/**
 * @brief subroutine of lzds_dshandle_read
 *
 * Parses the raw track buffer in dsh and copies the user data to
 * the databuffer in dsh.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPROTO  The raw track data is malformed.
 */
static int dshandle_extract_data_from_trackbuffer(struct dshandle *dsh)
{
	char *track;
	size_t i, trckcount;
	struct eckd_count *ecount;
	char *rawdata, *targetdata;
	unsigned int record;
	char DS1RECFM;
	ssize_t tdsize;

	DS1RECFM = dsh->ds->dsp[0]->f1->DS1RECFM;
	trckcount = dsh->rawbufsize / RAWTRACKSIZE;
	track = dsh->rawbuffer;
	targetdata = dsh->databuffer;
	dsh->databufsize = 0;
	/* Record zero is not part of the regular data, so I must not copy its
	 * data. In case of a PDS member, we may need to skip a few extra
	 * records on the first track. In this case startrecord is already set
	 * and will be reset to 1 after the first track has been read.
	 */
	if (!dsh->startrecord)
		dsh->startrecord = 1;
	for (i = 0; i < trckcount && !dsh->eof_reached; ++i) {
		record = 0;
		rawdata = track;
		while (!dsh->eof_reached) {
			tdsize = 0;
			if (record >= dsh->startrecord) {
				/* fixed or undefined record size */
				if ((DS1RECFM & 0x80))
					tdsize = parse_fixed_record(dsh,
								    rawdata,
								    targetdata);
				/* variable records */
				if (!(DS1RECFM & 0x80) && (DS1RECFM & 0x40))
					tdsize = parse_variable_record(dsh,
								       rawdata,
								    targetdata,
								  dsh->keepRDW);
				if (tdsize < 0)
					return errorlog_add_message(
						&dsh->log, dsh->log, EPROTO,
						"data extraction: error at "
						"record %u, offset %lu\n",
						record,
						(unsigned long)rawdata
						- (unsigned long)dsh->rawbuffer);
				targetdata += tdsize;
				dsh->databufsize += tdsize;
			}
			ecount = (struct eckd_count *)rawdata;
			rawdata += sizeof(*ecount) + ecount->kl + ecount->dl;
			/* An empty record marks the end of a member / data set
			 * We need to take startrecord into account or we might
			 * find the end marker of the previous member.
			 */
			if ((record >= dsh->startrecord) &&
			    (!ecount->kl) && (!ecount->dl))
				dsh->eof_reached = 1;
			++record;
			if ((*(unsigned long long *)rawdata) == ENDTOKEN)
				break;
			if ((unsigned long)rawdata >=
			    (unsigned long)track + RAWTRACKSIZE)
				return errorlog_add_message(
					&dsh->log, NULL, EPROTO,
					"data extraction: run over end of"
					" track buffer\n");
		}
		dsh->startrecord = 1;
		track += RAWTRACKSIZE;
	}
	return 0;
}


/**
 * @brief subroutine of lzds_dshandle_read
 *
 * Find the next range of extents and prepare dsh for the next read.
 * The return value indicates whether there is more data to read or not.
 *
 * @pre: For the first call to this function, dsh should be set to the
 *       last track before the first track to read.
 *       If the first track to read is the first track in the dataset
 *       then set dsh->ext_seq_no to -1.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 *
 * @return
 *   0 when there is no further raw data available,
 *   1 when there is more data available and dsh is prepared
 */
static int dshandle_prepare_for_next_read_tracks(struct dshandle *dsh)
{
	int found, dsp_no, ext_seq_no;

	/* If there are still unread tracks in the current extent, we just need
	 * to point dsh to the next range of tracks
	 */
	if (dsh->bufendtrk < dsh->extendtrk) {
		dsh->bufstarttrk = dsh->bufendtrk + 1;
		dsh->bufendtrk = dsh->bufstarttrk +
			(dsh->rawbufmax / RAWTRACKSIZE) - 1;
		dsh->bufendtrk = MIN(dsh->bufendtrk, dsh->extendtrk);
		dsh->rawbufsize = (dsh->bufendtrk - dsh->bufstarttrk + 1)
			* RAWTRACKSIZE;
		dsh->databufoffset = dsh->databufoffset + dsh->databufsize;
		dsh->databufsize = 0;
		dsh->bufpos = 0;
		dsh->frameno++;
		return 1;
	}
	/* There are no more tracks left in the current extent.
	 * Loop over data set parts and extends in these parts until a valid
	 * extent is found or the end of the data set is reached
	 */
	ext_seq_no = dsh->ext_seq_no;
	dsp_no = dsh->dsp_no;
	found = 0;
	while (!found) {
		++ext_seq_no;
		if (ext_seq_no >= MAXEXTENTS) {
			ext_seq_no = 0;
			++dsp_no;
		}
		if (dsp_no >= dsh->ds->dspcount)
			break;
		if (extent_contains_userdata(
			    &dsh->ds->dsp[dsp_no]->ext[ext_seq_no]))
			found = 1;
	}
	if (!found)
		return 0;
	/* We have found the next valid extent. Get lower and upper track
	 * limits and set dsh to the first range of tracks */
	dsh->ext_seq_no = ext_seq_no;
	dsh->dsp_no = dsp_no;
	lzds_dasd_cchh2trk(dsh->ds->dsp[dsp_no]->dasdi,
			&dsh->ds->dsp[dsp_no]->ext[ext_seq_no].llimit,
			&dsh->extstarttrk);
	lzds_dasd_cchh2trk(dsh->ds->dsp[dsp_no]->dasdi,
			&dsh->ds->dsp[dsp_no]->ext[ext_seq_no].ulimit,
			&dsh->extendtrk);
	dsh->bufstarttrk = dsh->extstarttrk;
	dsh->bufendtrk = dsh->bufstarttrk + (dsh->rawbufmax / RAWTRACKSIZE) - 1;
	dsh->bufendtrk = MIN(dsh->bufendtrk, dsh->extendtrk);
	dsh->rawbufsize = (dsh->bufendtrk - dsh->bufstarttrk + 1)
			   * RAWTRACKSIZE;
	dsh->databufoffset = dsh->databufoffset + dsh->databufsize;
	dsh->databufsize = 0;
	dsh->bufpos = 0;
	dsh->frameno++;
	return 1;
}

/**
 * @brief subroutine of lzds_dshandle_read
 *
 * As we progress in reading data from the dataset, we store
 * track/data offsets in the dshandle for late use by the
 * lzds_dshandle_lseek and related operations.
 *
 * @param[in]  dsh  The dshandle that keeps track of the I/O operations.
 *
 * @return     0 on success, otherwise one of the following error codes:
 *   - EPROTO  The existing seek buffer data is inconsistent.
 *   - EINVAL  The existing seek buffer data is inconsistent.
 *   - ERANGE  We try to add more elements than the prepared buffer can hold.
 */
static int dshandle_store_trackframe(struct dshandle *dsh)
{
	unsigned long long index;

	/* if we have no skip or seekbuf we cannot store anything */
	if (!dsh->skip || !dsh->seekbuf)
		return 0;

	/* if this is a frame we want to skip, just return 0 */
	if (dsh->frameno % dsh->skip)
		return 0;
	/* make sure we do not access elements beyond the end of the buffer */
	if (dsh->seek_current >= dsh->seek_count)
		return errorlog_add_message(
			&dsh->log,
			NULL, ERANGE,
			"store track frame: frame list size is inconsistent\n");

	/* our seek code relies on the fact that element n refers to frame
	 * n * skip, so we need to make sure we that we do not leave gaps */
	index = dsh->frameno / dsh->skip;
	if (index > dsh->seek_current)
		return errorlog_add_message(
			&dsh->log,
			NULL, EPROTO,
			"store track frame: frame list inconsistent\n");

	/* if we have visited this frame before, return */
	if (index < dsh->seek_current) {
		if (dsh->seekbuf[index].dsp_no != dsh->dsp_no ||
		    dsh->seekbuf[index].ext_seq_no != dsh->ext_seq_no ||
		    dsh->seekbuf[index].bufstarttrk != dsh->bufstarttrk ||
		    dsh->seekbuf[index].databufoffset != dsh->databufoffset)
			return errorlog_add_message(
				&dsh->log,
				NULL, EINVAL,
				"store track frame: frame data inconsistent\n");
		else
			return 0;
	}
	/* the seek_current = index case */
	dsh->seekbuf[index].dsp_no = dsh->dsp_no;
	dsh->seekbuf[index].ext_seq_no = dsh->ext_seq_no;
	dsh->seekbuf[index].bufstarttrk = dsh->bufstarttrk;
	dsh->seekbuf[index].databufoffset = dsh->databufoffset;
	dsh->seek_current++;
	return 0;
}

/**
 * @param[in]  dsh    The dshandle that keeps track of the I/O operations.
 * @param[in]  buf    The target buffer for the read data.
 * @param[in]  size   The number of bytes that are to be read.
 * @param[out] rcsize Reference to a variable in which the actual number
 *                    of read bytes is returned.
 *                    If this is 0, the end of the file is reached.
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  The data in dsh is inconsistent.
 *   - ERANGE  The data in dsh is inconsistent.
 *   - EPROTO  The data read from the disk does not conform to the
 *             expected format.
 *   - EIO     I/O error when reading from device.
 */
int lzds_dshandle_read(struct dshandle *dsh, char *buf,
		       size_t size, ssize_t *rcsize)
{
	ssize_t copysize;
	int rc;

	errorlog_clear(dsh->log);
	if (!dsh->is_open)
		return errorlog_add_message(
			&dsh->log, NULL, EINVAL,
			"data set read: dshandle is not open\n");
	*rcsize = 0;
	while (*rcsize < (long long)size) {
		if (dsh->bufpos >= dsh->databufsize) {
			/* need to fill dsh data buffer */
			if (dsh->eof_reached)
				break; /* end of data in data set reached */
			if (!dshandle_prepare_for_next_read_tracks(dsh))
				break; /* end of data set extents reached */
			rc = lzds_dasdhandle_read_tracks_to_buffer(
				dsh->dasdhandle[dsh->dsp_no], dsh->bufstarttrk,
				dsh->bufendtrk, dsh->rawbuffer);
			if (rc)
				return errorlog_add_message(
					&dsh->log,
					dsh->dasdhandle[dsh->dsp_no]->log, rc,
					"data set read: error reading data set"
					" %s\n", dsh->ds->name);
			rc = dshandle_extract_data_from_trackbuffer(dsh);
			if (rc)
				return errorlog_add_message(
					&dsh->log,
					dsh->log,
					rc,
					"data set read: extracting data set "
					"%s from %s, tracks %u to %u\n",
					dsh->ds->name,
					dsh->dasdhandle[dsh->dsp_no]->dasd->device,
					dsh->bufstarttrk,
					dsh->bufendtrk);
			rc = dshandle_store_trackframe(dsh);
			if (rc)
				return errorlog_add_message(
					&dsh->log,
					dsh->log, rc,
					"data set read: storing track frame "
					"%s\n", dsh->ds->name);
		}
		/* if databuf has data to copy */
		if (dsh->bufpos < dsh->databufsize) {
			/*  copy data from databuf to buf */
			copysize = MIN(((long long)size - *rcsize),
				       (dsh->databufsize - dsh->bufpos));
			memcpy(buf, &dsh->databuffer[dsh->bufpos], copysize);
			buf += copysize;
			dsh->bufpos += copysize;
			*rcsize += copysize;
		}
	}
	return 0;
}

/**
 * @brief subroutine of lzds_dshandle_lseek
 *
 * Find the closest buffered seekelement that starts before offset
 *
 * @param[in]  dsh      The dshandle that keeps track of the I/O operations.
 * @param[in]  offset   The data offset in the dataset that we want to reach.
 * @param[out] se_index Reference to a variable in which the found index
 *                      to dsh->seekbuf is returned.
 *
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  There is no seekbuffer available.
 */
static int dshandle_find_seekelement(struct dshandle *dsh, off_t offset,
				      long long *se_index)
{
	unsigned long long low, high, index;

	if (!dsh->seek_current)
		return EINVAL;

	/* special case for the last element in the list */
	if (dsh->seekbuf[dsh->seek_current - 1].databufoffset <= offset) {
		*se_index = dsh->seek_current - 1;
		return 0;
	}
	/* search starts with 'high' set to the second to last element */
	index = 0;
	high = dsh->seek_current - 2;
	low = 0;
	*se_index = 0;
	index = (high + low) / 2;
	while (low != high) {
		if (dsh->seekbuf[index].databufoffset <= offset) {
			low = index;
			index = (high + low + 1) / 2;
		} else {
			high = index - 1;
			index = (high + low) / 2;
		}
	}
	*se_index = low;
	return 0;
}

/**
 * @brief subroutine of lzds_dshandle_lseek
 *
 * Reset the internel buffers etc, so that the next read will read
 * the track frame pointed to by the seekelement.
 *
 * @param[in]  dsh      The dshandle that keeps track of the I/O operations.
 * @param[out] se_index Index to the seekelement in dsh->seekbuf.
 */
static void dshandle_reset_buffer_position_to_seekelement(
				      struct dshandle *dsh, long long se_index)
{
	/* make sure that read knows that we have no ready data in our buffer */
	dsh->bufpos = 0;
	dsh->databufsize = 0;
	dsh->eof_reached = 0;

	/* we need to set the bufendtrk and sequence number so,
	 * that the current track buffer seems to end with the
	 * track that comes before the first track of the
	 * data set or member
	 */

	/* framno will be incremented during read, so do a -1 here */
	dsh->frameno = (se_index * dsh->skip) - 1;
	dsh->databufoffset = dsh->seekbuf[se_index].databufoffset;
	dsh->dsp_no = dsh->seekbuf[se_index].dsp_no;

	/* For a partitioned data set we need to find the correct start
	 * track and point the current buffer just before it.
	 * As we always need to read full tracks, any additional
	 * record offset will be set explicitly and handled during
	 * track interpretation.
	 */
	if (dsh->member && (dsh->frameno == -1))
		dsh->startrecord = dsh->member->record;

	/* In most cases our track frame will be in the middle of the
	 * disk, so we set bufendtrk to the last track before our track
	 * frame. In the special case that the track frame begins
	 * on track 0, we set the ext_seq_no to that of the frame -1,
	 * so that the read code will advance to the next extend and
	 * the first track of that extent
	 */
	if (!dsh->seekbuf[se_index].bufstarttrk) {
		dsh->ext_seq_no = dsh->seekbuf[se_index].ext_seq_no - 1;
		dsh->bufendtrk = 0;
		dsh->extendtrk = 0;
		return;
	}

	dsh->ext_seq_no = dsh->seekbuf[se_index].ext_seq_no;

	lzds_dasd_cchh2trk(dsh->ds->dsp[dsh->dsp_no]->dasdi,
			&dsh->ds->dsp[dsh->dsp_no]->ext[dsh->ext_seq_no].llimit,
			&dsh->extstarttrk);
	lzds_dasd_cchh2trk(dsh->ds->dsp[dsh->dsp_no]->dasdi,
			&dsh->ds->dsp[dsh->dsp_no]->ext[dsh->ext_seq_no].ulimit,
			&dsh->extendtrk);

	dsh->bufstarttrk = 0;
	dsh->bufendtrk = dsh->seekbuf[se_index].bufstarttrk - 1;

	dsh->rawbufsize = 0;
	dsh->databufoffset = dsh->seekbuf[se_index].databufoffset;
	dsh->databufsize = 0;
	dsh->bufpos = 0;
	return;
}

/**
 * It is not possible to seek beyond the end of the data, but an
 * attempt to do so is a common occurrence as we may not know the
 * actual data size beforehand. In this case, the returned rcoffset
 * is smaller than offset and points to the offset directly following
 * the last data byte.
 *
 * @param[in]  dsh      The dshandle that keeps track of the I/O operations.
 * @param[in]  offset   The data offset in the dataset that we want to reach.
 * @param[out] rcoffset Reference to a variable in which the actual offset
 *                      is returned.
 *
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  The data in dsh is inconsistent.
 *   - ERANGE  The data in dsh is inconsistent.
 *   - EPROTO  The data read from the disk does not conform to the
 *             expected format.
 *   - EIO     I/O error when reading from device.
 */
int lzds_dshandle_lseek(struct dshandle *dsh, long long offset,
			long long *rcoffset)
{
	char foo;
	ssize_t rcsize;
	int rc;
	long long se_index;

	errorlog_clear(dsh->log);
	if (dsh->databufoffset <= offset &&
	    offset < dsh->databufoffset + dsh->databufsize) {
		/* offset is within the current track frame */
		dsh->bufpos = offset - dsh->databufoffset;
		*rcoffset = offset;
		return 0;
	}
	/* need to seek to some other track frame */
	if (!dshandle_find_seekelement(dsh, offset, &se_index)) {
		/* do not reset our context if we can seek forward from
		 * our current position */
		if (!(dsh->seekbuf[se_index].databufoffset < dsh->databufoffset
		      && dsh->databufoffset <= offset)) {
			dshandle_reset_buffer_position_to_seekelement(dsh,
								      se_index);
		}
	} else if (offset < dsh->databufoffset) {
		/* if we have no seekbuffer, we can only reset to the
		 * start of the data set */
		rc = initialize_buffer_positions_for_first_read(dsh);
		if (rc)
			return errorlog_add_message(
				&dsh->log,
				dsh->log, rc,
				"data set seek: error when initializing buffers"
				" for data set %s\n", dsh->ds->name);
	}
	/* from here on we just need to go forward by reading track
	 * frames until we find a frame that contains the offset
	 */
	while (dsh->databufoffset + dsh->databufsize <= offset) {
		dsh->bufpos = dsh->databufsize;
		rc = lzds_dshandle_read(dsh, &foo, sizeof(foo), &rcsize);
		if (rc || !rcsize) {
			*rcoffset = dsh->databufoffset + dsh->databufsize;
			if (rc)
				errorlog_add_message(
					&dsh->log,
					dsh->log, rc,
					"data set seek: error reading data from"
					" data set %s\n", dsh->ds->name);
			return rc;
		}
	}
	dsh->bufpos = offset - dsh->databufoffset;
	*rcoffset = offset;
	return 0;
}

/**
 * @param[in]  dsh    The dshandle that keeps track of the I/O operations.
 * @param[out] offset Reference to a variable in which the current offset
 *                    is returned.
 */
void lzds_dshandle_get_offset(struct dshandle *dsh, long long *offset)
{
	*offset = dsh->databufoffset + dsh->bufpos;
}

/**
 * @param[in]  dsh    The dshandle that keeps track of the I/O operations.
 * @param[out] log    Reference to a variable in which the errorlog
 *                    is returned.
 */
void lzds_dshandle_get_errorlog(struct dshandle *dsh, struct errorlog **log)
{
	*log = dsh->log;
}


/******************************************************************************/
/*   libzds helper functions                                                  */
/******************************************************************************/

/**
 * This function takes the DS1RECFM byte as defined for the format 1 DSCB, and
 * creates a string of the usual characters F, V, U, T, B, S, A, and M.
 *
 * @param[in]  DS1RECFM  Input byte.
 * @param[out] buffer    Buffer for the output string.
 *                       The buffer must be at least 7 characters long.
 */
void lzds_DS1RECFM_to_recfm(char DS1RECFM, char *buffer)
{
	if ((DS1RECFM & 0x80) && !(DS1RECFM & 0x40))
		*buffer++ = 'F'; /* fixed records */

	if (!(DS1RECFM & 0x80) && (DS1RECFM & 0x40))
		*buffer++ = 'V'; /* variable records */

	if ((DS1RECFM & 0x80) && (DS1RECFM & 0x40))
		*buffer++ = 'U'; /* undefined length records */

	if ((DS1RECFM & 0x20))
		*buffer++ = 'T'; /* track overflow (legacy) */

	if ((DS1RECFM & 0x10))
		*buffer++ = 'B'; /* blocked */

	if ((DS1RECFM & 0x08))
		*buffer++ = 'S'; /* standard records */

	if ((DS1RECFM & 0x04) && !(DS1RECFM & 0x02))
		*buffer++ = 'A'; /* ISO / ANSI control characters */

	if (!(DS1RECFM & 0x04) && (DS1RECFM & 0x02))
		*buffer++ = 'M'; /* machine control characters */
	*buffer = 0;

	/* The combinations ((DS1RECFM & 0x04) && (DS1RECFM & 0x02))
	 * and (DS1RECFM & 0x01) are reserved
	 *
	 * If we count only one byte for the mutual exclusive F, V and U,
	 * three bytes for T, B and S,
	 * one byte for the mutual exclusive A and M,
	 * one byte for a possible future definition of 0x01, and
	 * one byte for the zero termination,
	 * then we get a required buffer length of 7 bytes
	 */
}

int lzds_analyse_open_count(struct zdsroot *root, int warn)
{
	struct dasd *dasd;
	int value;
	int rc = 0;

	util_list_iterate(root->dasdlist, dasd) {
		value = dasd_get_host_access_count(dasd->device);

		if (value < 0) {
			fprintf(stderr,
				"Hosts access information not available for disk %s.\n",
				dasd->device);
			rc = value;
			continue;
		}

		if (value == 1)
			continue;

		if (warn)
			fprintf(stderr,
				"\nWARNING:\n"
				"Disk %s is online on operating system instances in %d different LPARs.\n"
				"Ensure that the disk is not being used by a system outside your LPAR.\n"
				"Note: Your installation might include z/VM systems that are configured to\n"
				"automatically vary on disks, regardless of whether they are subsequently used.\n",
				dasd->device, value);
		else {
			fprintf(stderr,
				"\nERROR:\n"
				"Disk %s is online on operating system instances in %d different LPARs.\n"
				"Ensure that the disk is not being used by a system outside your LPAR.\n"
				"Note: Your installation might include z/VM systems that are configured to\n"
				"automatically vary on disks, regardless of whether they are subsequently used.\n",
				dasd->device, value);
			rc = -EACCES;
		}
	}

	return rc;
}

