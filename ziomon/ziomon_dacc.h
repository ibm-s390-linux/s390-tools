/*
 * FCP adapter trace utility
 *
 * Data access library
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <linux/types.h>
#include <stdio.h>

#ifndef ZIOMON_DACC_H
#define ZIOMON_DACC_H



#define DATA_MGR_MAGIC		0x64616d67
#define DATA_MGR_MAGIC_AGGR	0x61676772
#define DATA_MGR_V2		2u
#define DATA_MGR_V3		3u


/**
 * Library to access the data files.
 * Does not perform any endianness conversions.
 * Assumes that messages are provided in BE.
 */


/**
 * Message as handled by this library.
 * NOTE: The very first entry of the data member _must_ be
 * a timestamp of type __u64!!!
 */
struct message {
	__u32	length;	/* length of the message,
			   excluding the 'length' and 'type' attributes.
			   Or, in other word, length of 'data' */
	__u32	type;
	void   *data;
} __attribute__ ((packed));

/**
 * Preview version of a message. Has timestamp included,
 * but not the actual content.
 */
struct message_preview {
	__u32	length;	/* length of the message in Bytes,
			   excluding the 'length' and 'type' attributes.
			   Or, in other word, length of 'data' */
	__u32	type;
	__u64   timestamp;
	__u32   is_blkiomon_v2; /* message is a v2 blkiomon msg */
	long	pos;	/* position in file where msg starts */
};

#define DACC_FILE_EXT_LOG	".log"
struct file_header {
	__u32	magic;
	__u32	version;
	__u64	size_limit;
	__u64	end_time;	/* AUTOSET
			timestamp of last message,
			set automatically by API */
	__u64	first_msg_offset;	/* AUTOSET
			offset of first message. 0 if all
			messages in sequence, fseek-able offset otherwise.
			Set automatically by API. */
	__u32	interval_length;
	/* In case you wonder why the msg-ids are dynamic at all:
	blkiomon was/is an external tool, which would not have been accepted
	with a fixed msg-id. So since the blkiomon msg id is dynamic, everyone
	has to do it dynamic. We *could* have used the wrapper-script ziomon
	to assign a fixed msg-id for blkiomon, but went all the way instead.
	*/
	__u32	msgid_utilization;
	__u32	msgid_ioerr;
	__u32	msgid_blkiomon;
	__u32	msgid_zfcpdd;

	/* NOT WRITTEN TO DISK!!! */
	/* Since we might move messages from .log to .agg in a round-robin
	 * fashion, it is not trivial to get the timestamp of the first message
	 * in .log - each time we write a new message, we would have to read
	 * the next one and rewind again.
	 * Hence we figure this one out only when we open a finished .log file,
	 * but do not actually write it to disk.
	*/
	__u64	begin_time;
} __attribute__ ((packed));


#define DACC_AGGR_FILE_HDR_LEN	40
#define DACC_FILE_EXT_AGG	".agg"
struct aggr_data {
	__u32	magic;
	__u32	version;
	__u64	begin_time;	/* start time of aggregated data */
	__u64	end_time;	/* timestamp of latest message */
	__u64	num_zfcpdd;	/* number of zfcpdd messages */
	__u64	num_blkiomon;	/* number of blkiomon messages */
	struct message *util_aggr;
	struct message **blkio_aggr;
	struct message *ioerr_aggr;
	struct message **zfcpdd_aggr;	/* multiple msgs */
} __attribute__ ((packed));


/**
 * Write the initial file header and forward to place where first message would
 * go init_size gives the total size of the header block in the file.
 * fp is assumed to have been opened.
 */
int init_file(FILE *fp, struct file_header *f_hdr, long version);


/**
 * Open an existing .log file and read its header.
 * Returns <0 in case of error, >0 if file doesn't exist.
 * 'filename' is assumed to NOT carry the .log extension.
 * ONLY USE IF YOU KNOW WHAT YOU DO, i.e. in case you want to access
 * the as-is data. Anyone else should rather use open_data().
 * NOTE: Use close_log_file() when finished! */
int open_log_file(FILE **fp, const char *filename, struct file_header *fhdr);


/**
 * Must be called to close fp and reset internals */
void close_log_file(FILE *fp);

/**
 * Open the data files. This function will not only open the .log and .agg
 * files, but also
 * - read and aggregate the first few messages from .log in case they are
 *   missing in the 'agg' data to complete the respective frame.
 * - adjust the boundaries of both, .log and .agg so that .agg has the
 *   complete content of the last frame it scratched upon and the next message
 *   read from .log will be the first message of the first frame not in .agg
 * Returns <0 in case of error, >0 if file doesn't exist.
 * 'filename' is assumed to NOT carry the .log or .agg extension.
 * Note that, consistent with all other API calls, the messages inside 'agg'
 * are still in BE format!
 * NOTE: Use close_data_files() when finished! */
int open_data_files(FILE **fp, const char *filename, struct file_header *fhdr,
	      struct aggr_data **agg);


/**
 * Must be called to close fp and reset internals */
void close_data_files(FILE *fp);

/**
 * Put a message into the file. Will automatically wrap around.
 * If existing messages have to be deleted to add the new message,
 * the messages that were overwritten are returned via del_msgs and num_del_msgs.
 * del_msgs must be free'd, and the messages within have to be discarded
 * and free'd.
 * via discard_msg()
 * fp is assumed to have been opened.
 */
int add_msg(FILE *fp, struct message *msg, struct file_header *f_hdr,
	    struct message ***del_msgs, int *num_del_msgs);

/**
 * Retrieve the next message from the file. Note that the returned message has
 * to be discarded!
 * Returns 0 if successful, >0 if end of file reached, <0 in case of error.
 * fp is assumed to have been opened.
 */
int get_next_msg(FILE *fp, struct message *msg, struct file_header *f_hdr);

/**
 * Retrieve preview of next message from the file.
 * Note that fp will be forwarded to the next message!
 * If you want the actual message, use get_complete_msg().
 * If you want to stay at the message, use rewind_to().
 * Returns 0 if successful, >0 if end of file reached, <0 in case of error.
 * fp is assumed to have been opened.
 */
int get_next_msg_preview(FILE *fp, struct message_preview *msg,
			 struct file_header *f_hdr);

/**
 * Rewinds to the start of the provided message preview.
 * Handy in case you could not process the message preview on the
 * first time and want to make sure that you read it again next time. */
void rewind_to(FILE *fp, struct message_preview *msg);

/**
 * Get complete message for a preview. Rewinds back to where it was at.
 */
int get_complete_msg(FILE *fp, struct message_preview *msg_prev,
		     struct message *msg);

/**
 * Frees the alloc'd portion of a message.
 */
void discard_msg(struct message *msg);

/**
 * Initialize.
 */
void init_aggr_data_struct(struct aggr_data *data);

/**
 * Open an existing .agg file and read its header.
 * Returns <0 in case of error, >0 if file doesn't exist.
 * 'filename' is assumed to NOT carry the .log extension.
 * ONLY USE IF YOU KNOW WHAT YOU DO, i.e. in case you want to access
 * the as-is data. Anyone else should rather use open_data().
 * NOTE: Use close_agg_file() when finished! */
int open_agg_file(FILE **fp, const char *filename, struct aggr_data *agg);

/**
 * Must be called to close fp and reset internals */
void close_agg_file(FILE *fp);

/**
 * Frees the alloc'd portion of the struct.
 */
void discard_aggr_data_struct(struct aggr_data *data);

/**
 * Write aggregated data to file.
 * fp is assumed to have been opened.
 */
int write_aggr_file(FILE *fp, struct aggr_data *data);


#endif

