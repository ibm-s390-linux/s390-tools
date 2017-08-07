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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ziomon_dacc.h"
#include "ziomon_msg_tools.h"
#include "ziomon_util.h"


#define ZIOMON_DACC_GARBAGE_MSG	-1U

extern const char *toolname;
extern int verbose;

/*
 * Structure of binary file:
 *                                                                          |
 * +-----+---+---+-----+---+---+---------+---+---+---------+-      -+-----+ |
 * | hdr | l | t | dat | l | t |   dat   | l | t |   dat   |        | dat | |
 * +-----+---+---+-----+---+---+---------+---+---+---------+- .... -+-----+ |
 *                                                                          |
 *                                                                        limit
 * NOTES:
 * The messages might differ in length, depending how many monitored devices
 * were available in each interval. When we *would* exceed the limit, we wrap
 * around, overwriting old messages. Hence it is utterly important that we keep
 * the lengths 'l' intact, since we will have random garbage after one of the
 * messages once we wrapped around for the first time.
 * 't' denotes the type of the message, 'dat' is the (variable length) data.
 * The length is specified as __u32 and specifies the length of the variable
 * part of the message entry, beginning after the message type.
 * 'length' will always specify the length of the variable part of the message
 *
 * Aggregated statistics are put into a separate file.
 * Messages inside the aggregated file are written in fixed order (so we do not
 * need struct file_header to figure out what is where).
 * Note that we write a single garbage message for any message that might have
 * not been used yet!
 */


/* indicates whether we already wrapped or not */
static int wrapped = -1;

#ifndef NDEBUG
static int open_count = 0;
#endif


/**
 * Calculate size of the message. In contrast to the message's
 * length attribute, this also includes the header */
static __u32 get_total_msg_size(struct message *msg) {
	return (msg->length + 8);
}


/**
 * Position at first _physical_ message, not necessarily the first
 * logical message */
static int position_at_first_msg(FILE * fp)
{
	return fseek(fp, sizeof(struct file_header) - sizeof(__u64), SEEK_SET);
}


static void swap_header(struct file_header *f_hdr)
{
	swap_32(f_hdr->magic);
	swap_32(f_hdr->version);
	swap_64(f_hdr->size_limit);
	swap_32(f_hdr->interval_length);
	swap_32(f_hdr->msgid_utilization);
	swap_32(f_hdr->msgid_ioerr);
	swap_32(f_hdr->msgid_blkiomon);
	swap_32(f_hdr->msgid_zfcpdd);
	swap_64(f_hdr->end_time);
	swap_64(f_hdr->first_msg_offset);
	swap_64(f_hdr->begin_time);
}


static void swap_msg_header(struct message *msg)
{
	swap_32(msg->length);
	swap_32(msg->type);
}


static int write_f_header(FILE *fp, struct file_header *f_hdr)
{
	int rc = 0;

	rewind(fp);
	swap_header(f_hdr);
	if (fwrite(f_hdr, sizeof(struct file_header)
		   - sizeof(__u64), 1, fp) != 1) {
		fprintf(stderr, "%s: Failed to write"
			" header\n", toolname);
		rc = -1;
	}
	swap_header(f_hdr);

	return rc;
}

/**
 * write garbage of specified length to file, where 'length' is the total
 * length of the garbage message.
 * Note: This is only done for consistency, we rewind to start of garbage
 * immediately so we may overwrite it next time again
 */
static int write_garbage_message(FILE *fp, int length)
{
	struct message msg;

	vverbose_msg("writing garbage at pos=%ld, total size=%d\n", ftell(fp), length);
	msg.type = ZIOMON_DACC_GARBAGE_MSG;
	msg.length = length - 8;

	swap_msg_header(&msg);
	if (!fwrite(&msg, 8, 1, fp)) {
		fprintf(stderr, "%s: Error writing"
			" garbage\n", toolname);
		return -1;
	}

	return 0;
}


static int read_message_header(FILE *fp, __u32 *length, __u32 *type)
{
#ifndef NDEBUG
	long pos = ftell(fp);
#endif

	if (fread(length, 4, 1, fp) != 1) {
		if (feof(fp))
			return 1;	/* end of file reached */
		else {
			fprintf(stderr, "%s: Error reading"
				" message length\n", toolname);
			return -1;
		}
	}
	if (fread(type, 4, 1, fp) != 1) {
		fprintf(stderr, "%s: Error reading message"
			" type\n", toolname);
		return -1;
	}
	swap_32(*type);
	swap_32(*length);

	vverbose_msg("read %smsg at pos=%ld, data size=%d\n",
		     (*type == ZIOMON_DACC_GARBAGE_MSG ? "garbage " : ""), pos, *length);

	return 0;
}

/**
 * Read the next message.
 * @param msgid_blkiomon: ID of blkiomon messages or IS_NO_BLKIOMON_MSG if we
 *                        already know that it is none, or IS_BLKIOMON_MSG
 *                        if we know it is.
 */
#define IS_NO_BLKIOMON_MSG	0xfffffffe
#define IS_BLKIOMON_MSG		0xffffffff

static int read_message(FILE *fp, struct message *msg, __u32 ver,
			__u32 msgid_blkiomon)
{
	int rc;

	if ( (rc = read_message_header(fp, &msg->length, &msg->type)) )
		return rc;

	if (msg->type == ZIOMON_DACC_GARBAGE_MSG) {
		fseek(fp, msg->length, SEEK_CUR);
		msg->data = NULL;
	}
	else {
		msg->data = malloc(msg->length);
		if (fread(msg->data, msg->length, 1, fp) != 1) {
			fprintf(stderr, "%s: Error reading %u Bytes message"
				" content\n", toolname, msg->length);
			return -1;
		}
		if (ver == DATA_MGR_V2 && msgid_blkiomon != IS_NO_BLKIOMON_MSG
		    && (msg->type == IS_BLKIOMON_MSG || msg->type == msgid_blkiomon))
			conv_blkiomon_v2_to_v3(msg);
	}

	return 0;
}


static int read_message_preview(FILE *fp, struct message_preview *msg,
				struct file_header *f_hdr)
{
	int rc;

	msg->pos = ftell(fp);
	if ( (rc = read_message_header(fp, &msg->length, &msg->type)) )
		return rc;

	/* Eventually read timestamp and fforward to next msg */
	if (msg->type != ZIOMON_DACC_GARBAGE_MSG) {
		/* per convention, the first 8 bytes of the actual message
		 * is the timestamp. */
		assert(msg->length >= 8);
		if (fread(&msg->timestamp, 8, 1, fp) != 1) {
			fprintf(stderr, "%s: Error reading"
				" message timestamp\n", toolname);
			return -1;
		}
		swap_64(msg->timestamp);
		fseek(fp, msg->length - 8, SEEK_CUR);
		msg->is_blkiomon_v2 = (f_hdr->version == DATA_MGR_V2
				       && msg->type == f_hdr->msgid_blkiomon);
	}
	else
		fseek(fp, msg->length, SEEK_CUR);

	return 0;
}


/**
 * Add msg to the bunch of aggregated messages.
 */
static int aggregate_message(FILE *fp, struct message ***del_msg,
			     int *num_del_msg, struct file_header *f_hdr)
{
	struct message tmp_msg;
	long cur_pos = ftell(fp);
	struct message **tmp = *del_msg;
	int i;

	/* read message and rewind */
	if (read_message(fp, &tmp_msg, f_hdr->version, f_hdr->msgid_blkiomon))
		return -1;
	fseek(fp, cur_pos, SEEK_SET);

	/* append the message that we read to the array */
	if (tmp_msg.type != ZIOMON_DACC_GARBAGE_MSG) {
		*del_msg = malloc((*num_del_msg + 1)*sizeof(struct message*));
		for (i = 0; i < *num_del_msg; ++i)
			(*del_msg)[i] = tmp[i];
		if (*num_del_msg > 0)
			free(tmp);
		// add new msg at end
		(*del_msg)[*num_del_msg] = malloc(sizeof(struct message));
		*(*del_msg)[*num_del_msg] = tmp_msg;
		(*num_del_msg)++;
	}

	return 0;
}


/**
 * Calculate next message's size, including header, then rewind to current position
 */
static int get_next_msg_size(FILE *fp, int *length) {
	if (fread(length, 4, 1, fp) != 1)
		return -1;
	fseek(fp, -4, SEEK_CUR);
	swap_32(*length);
	(*length) += 8;

	return 0;
}


/**
 * Position at the right place in the file.
 * Returns 0 on success, <0 on error and >0 if an additional gargabe message
 * has to be written after this message. If so, the value returned
 * is length of the garbage message.
 */
static __s32 position_in_file(FILE *fp, struct message *msg,
			      struct file_header *f_hdr,
			      struct message ***del_msg, int *num_del_msg)
{
	__s32 next_msg_length;
	long start_pos;
	__s32 rc = 0;
	long cum_size = 0;

	/*
	 * Are we at the end of the file?
	 */
	if (get_next_msg_size(fp, &next_msg_length)) {
		/* end of file reached - size limit also reached? */
		if ((__u64)ftell(fp) + get_total_msg_size(msg) > f_hdr->size_limit) {
			if (position_at_first_msg(fp) < 0)
				return -1;
			vverbose_msg("end reached - WRAP\n");
			/* we have rewound, but need to aggregate first few messages now,
			   so we better go on... */
		}
		else
			return 0; /* still enough space left - finished */
	}

	/*
	 * Is there still enough room for our message?
	 */
	if ((__u64)ftell(fp) + get_total_msg_size(msg) > f_hdr->size_limit) {
		/* doesn't fit in anymore - wrap around */
		vverbose_msg("msg doesn't fit anymore - WRAP\n");
		/* aggregate final message so all msgs are still in sequence */
		if (get_next_msg_size(fp, &next_msg_length))
			return -1;
		if (aggregate_message(fp, del_msg, num_del_msg, f_hdr))
			return -1;
		if (write_garbage_message(fp, next_msg_length) < 0
		    || position_at_first_msg(fp) < 0)
			return -1;
	}

	/*
	 * Aggregate messages that will be overwritten
	 */
	vverbose_msg("make room for new message\n");
	start_pos = ftell(fp);
	while (cum_size < (long)get_total_msg_size(msg)) {
		if (get_next_msg_size(fp, &next_msg_length)) {
			/*  end of file reached, but we checked before
			    that it will fit in */
			cum_size = get_total_msg_size(msg);; /* prevents garbage msg */
			break;
		}
		if (aggregate_message(fp, del_msg, num_del_msg, f_hdr))
			return -1;
		cum_size += next_msg_length;
		fseek(fp, next_msg_length, SEEK_CUR);
		vverbose_msg("    read msg, cum_size=%ld, needed=%d\n", cum_size, get_total_msg_size(msg));
	}
	if (cum_size - get_total_msg_size(msg) > 0
	    && cum_size - get_total_msg_size(msg) < 8) {
		/* garbage message required, but even minimum size
		   would overwrite start of next msg - aggregate one more! */
		if (get_next_msg_size(fp, &next_msg_length)) {
			/* corner case: we are at EOF, but our message
			   doesn't delete everything from the previous one.
			   So we write the minimum garbage possible*/
			vverbose_msg("garbage needed, but end of file reached\n");
			cum_size += 8;
		}
		else {
			vverbose_msg("garbage needed, but doesn't fit - aggregate one more\n");
			if (aggregate_message(fp, del_msg, num_del_msg, f_hdr))
				return -1;
			cum_size += next_msg_length;
		}
	}

	rc = cum_size - get_total_msg_size(msg);
	fseek(fp, start_pos, SEEK_SET);

	return rc;
}


static int write_message(FILE *fp, struct message *msg)
{
	vverbose_msg("write msg at pos=%ld, total size=%d\n", ftell(fp),
		     get_total_msg_size(msg));
	swap_msg_header(msg);
	if (!fwrite(&msg->length, 4, 1, fp)) {
		fprintf(stderr, "%s: Writing of length"
			" failed\n", toolname);
		swap_msg_header(msg);
		return -1;
	}
	if (!fwrite(&msg->type, 4, 1, fp)) {
		fprintf(stderr, "%s: Writing of type failed\n", toolname);
		swap_msg_header(msg);
		return -2;
	}
	swap_msg_header(msg);

	if (!fwrite(msg->data, msg->length, 1, fp)) {
		fprintf(stderr, "%s: Writing of message data"
			" failed\n", toolname);
		return -3;
	}

	return 0;
}


int add_msg(FILE *fp, struct message *msg, struct file_header *f_hdr,
	    struct message ***del_msg, int *num_del_msg)
{
	__s32 add_garbage;
	long cur_pos, old_pos = ftell(fp);

	*num_del_msg = 0;
	add_garbage = position_in_file(fp, msg, f_hdr, del_msg, num_del_msg);
	if (add_garbage < 0)
		return -1;

	if (write_message(fp, msg) < 0)
		return -2;

	if (add_garbage > 0) {
		cur_pos = ftell(fp);
		if (write_garbage_message(fp, add_garbage) < 0)
			return -3;
		fseek(fp, cur_pos, SEEK_SET);
	}

	f_hdr->end_time = *(__u64*)(msg->data);
	swap_64(f_hdr->end_time);	/* msg content is BE by convention */
	cur_pos = ftell(fp);
	if (f_hdr->first_msg_offset != 0 || cur_pos < old_pos)
		f_hdr->first_msg_offset = ftell(fp);
	if (write_f_header(fp, f_hdr))
		return -4;
	fseek(fp, cur_pos, SEEK_SET);

	return 0;
}


int init_file(FILE *fp, struct file_header *f_hdr, long version)
{
	f_hdr->magic = DATA_MGR_MAGIC;
	if (version == 2)
		f_hdr->version = DATA_MGR_V2;
	else if (version == 3)
		f_hdr->version = DATA_MGR_V3;
	else {
		fprintf(stderr, "%s: Unsupported version: %ld\n",
	                        toolname, version);
		return -2;
	}
	f_hdr->first_msg_offset = 0;
	f_hdr->end_time = 0;
	f_hdr->begin_time = 0;

	if (write_f_header(fp, f_hdr))
		return -1;

	return 0;
}


static int check_version(__u32 ver) {
	if (ver != DATA_MGR_V2 && ver != DATA_MGR_V3) {
		fprintf(stderr, "%s: Wrong version: .log data is in version %u"
			" format, while this tool only supports version %u"
			" and %u.\n"
			" Get the matching tool version and try again.\n",
			toolname, ver, DATA_MGR_V2, DATA_MGR_V3);
		return -2;
	}
	
	return 0;
}


static int get_header(FILE *fp, struct file_header *hdr)
{
	rewind(fp);
	if (fread(hdr, sizeof(struct file_header)
		  - sizeof(__u64), 1, fp) != 1) {
		fprintf(stderr, "%s: Could not read header\n", toolname);
		return -1;
	}
	swap_header(hdr);
	if (hdr->magic != DATA_MGR_MAGIC) {
		fprintf(stderr, "%s: Unregocgnized data in .log file.\n",
			toolname);
		return -2;
	}
	if (check_version(hdr->version))
		return -2;
	hdr->begin_time = 0;

	return 0;
}


int open_log_file(FILE **fp, const char *filename, struct file_header *fhdr)
{
	int rc = 0;
	char *fname = NULL;
	struct message_preview msg_prev;

	fname = (char*)malloc(strlen(filename) + strlen(DACC_FILE_EXT_LOG) + 1);
	sprintf(fname, "%s%s", filename, DACC_FILE_EXT_LOG);
	*fp = fopen(fname, "r");
	if (!*fp) {
		fprintf(stderr, "%s: Could not open %s"
			" - file not accessible?", toolname, fname);
		rc = 1;
		goto out;
	}
	if (get_header(*fp, fhdr)) {
		rc = -2;
		goto out;
	}
	if (get_next_msg_preview(*fp, &msg_prev, fhdr)) {
		rc = -3;
		goto out;
	}
	rewind_to(*fp, &msg_prev);
	fhdr->begin_time = msg_prev.timestamp;

out:
	free(fname);
	if (rc < 0)
		fclose(*fp);

	return rc;
}


void close_log_file(FILE *fp)
{
	wrapped = -1;
	if (fp)
		fclose(fp);
}


void close_data_files(FILE *fp)
{
#ifndef NDEBUG
	open_count--;
	assert(open_count == 0);
#endif
	close_log_file(fp);
}


static void swap_agg_header(struct aggr_data *hdr)
{
	swap_32(hdr->magic);
	swap_32(hdr->version);
	swap_64(hdr->begin_time);
	swap_64(hdr->num_zfcpdd);
	swap_64(hdr->num_blkiomon);
	swap_64(hdr->end_time);
}


static void conv_agg_header_from_BE(struct aggr_data *hdr) {
	swap_agg_header(hdr);
}


static void conv_agg_header_to_BE(struct aggr_data *hdr) {
	swap_agg_header(hdr);
}


static int read_aggr_file(FILE *fp, struct aggr_data *data)
{
	__u64 i;
	int rc;
	struct message msg;

	rewind(fp);
	if (fread(data, DACC_AGGR_FILE_HDR_LEN, 1, fp) != 1) {
		fprintf(stderr, "%s: Error reading aggregation"
			" content\n", toolname);
		return -1;
	}
	conv_agg_header_from_BE(data);
	if (data->magic != DATA_MGR_MAGIC_AGGR) {
		fprintf(stderr, "%s: Unregocgnized data in .agg file.\n",
			toolname);
		return -1;
	}
	if (check_version(data->version))
		return -1;

	data->util_aggr = NULL;
	if ( (rc = read_message(fp, &msg, data->version, IS_NO_BLKIOMON_MSG)) < 0)
		return -2;

	if (msg.type != ZIOMON_DACC_GARBAGE_MSG) {
		data->util_aggr = malloc(sizeof(struct message));
		*(data->util_aggr) = msg;
	}

	data->ioerr_aggr = NULL;
	if ( (rc = read_message(fp, &msg, data->version, IS_NO_BLKIOMON_MSG)) < 0)
		return -3;
	if (msg.type != ZIOMON_DACC_GARBAGE_MSG) {
		data->ioerr_aggr = malloc(sizeof(struct message));
		*(data->ioerr_aggr) = msg;
	}

	if (data->num_blkiomon > 0) {
		data->blkio_aggr = calloc(data->num_blkiomon, sizeof(struct message*));
		for (i=0; i<data->num_blkiomon; ++i) {
			if ( (rc = read_message(fp, &msg, data->version, IS_BLKIOMON_MSG)) < 0)
				return -4;
			data->blkio_aggr[i] = malloc(sizeof(struct message));
			*(data->blkio_aggr[i]) = msg;
		}
	}
	else {
		/* this _must_ be a garbage message */
		data->blkio_aggr = NULL;
		if ( (rc = read_message(fp, &msg, data->version, IS_NO_BLKIOMON_MSG)) < 0)
			return -1;
	}

	if (data->num_zfcpdd > 0) {
		data->zfcpdd_aggr = calloc(data->num_zfcpdd, sizeof(struct message*));
		for (i=0; i<data->num_zfcpdd; ++i) {
			if ( (rc = read_message(fp, &msg, data->version, IS_BLKIOMON_MSG)) < 0)
				return -4;
			data->zfcpdd_aggr[i] = malloc(sizeof(struct message));
			*(data->zfcpdd_aggr[i]) = msg;
		}
	}
	else {
		/* this _must_ be a garbage message */
		data->zfcpdd_aggr = NULL;
		if ( (rc = read_message(fp, &msg, data->version, IS_NO_BLKIOMON_MSG)) < 0)
			return -1;
	}

	return 0;
}


int open_agg_file(FILE **fp, const char *filename, struct aggr_data *agg)
{
	int rc = 0;
	char *fname = NULL;

	fname = (char*)malloc(strlen(filename) + strlen(DACC_FILE_EXT_AGG) + 1);
	sprintf(fname, "%s%s", filename, DACC_FILE_EXT_AGG);

	/* test the water */
	if (access(fname, F_OK) != 0) {
		rc = 1;
		goto out;
	}
	*fp = fopen(fname, "r");
	if (!*fp) {
		fprintf(stderr, "%s: Could not open %s"
			" - file not accessible?", toolname, fname);
		rc = 1;
		goto out;
	}
	if (read_aggr_file(*fp, agg)) {
		fclose(*fp);
		rc = -1;
		goto out;
	}

out:
	free(fname);

	return rc;
}


void close_agg_file(FILE *fp)
{
	if (fp)
		fclose(fp);
}


static int seek_initial_file_pos(FILE *fp, struct file_header *f_hdr)
{
	int rc = 0;
	long pos;

	if (f_hdr->first_msg_offset)
		pos = f_hdr->first_msg_offset;
	else {
		pos = sizeof(struct file_header) - sizeof(__u64);
		rc = 1;	/* no need to wrap */
	}
	fseek(fp, pos, SEEK_SET);

	return rc;
}


int get_next_msg(FILE *fp, struct message *msg, struct file_header *f_hdr)
{
	int rc;

	if (wrapped < 0)
		wrapped = seek_initial_file_pos(fp, f_hdr);

	do {
		if (f_hdr->first_msg_offset != 0 && wrapped
		    && ftell(fp) >= (long long)f_hdr->first_msg_offset)
			return 1;	/* final msg read */

		rc = read_message(fp, msg, f_hdr->version, f_hdr->msgid_blkiomon);
		if (rc > 0 && !wrapped) {
			position_at_first_msg(fp);
			rc = read_message(fp, msg, f_hdr->version, f_hdr->msgid_blkiomon);
			wrapped++;
		}
	} while (!rc && msg->type == ZIOMON_DACC_GARBAGE_MSG);

	return rc;
}


int get_next_msg_preview(FILE *fp, struct message_preview *msg,
			 struct file_header *f_hdr)
{
	int rc;

	if (wrapped < 0)
		wrapped = seek_initial_file_pos(fp, f_hdr);

	do {
		if (f_hdr->first_msg_offset != 0 && wrapped
		    && ftell(fp) >= (long long)f_hdr->first_msg_offset)
			return 1;	/* final msg read */

		rc = read_message_preview(fp, msg, f_hdr);
		if (rc > 0 && !wrapped) {
			position_at_first_msg(fp);
			rc = read_message_preview(fp, msg, f_hdr);
			wrapped++;
		}
	} while (!rc && msg->type == ZIOMON_DACC_GARBAGE_MSG);

	return rc;
}


void rewind_to(FILE *fp, struct message_preview *msg)
{
	assert(msg->pos > 0);
	fseek(fp, msg->pos, SEEK_SET);
}


int get_complete_msg(FILE *fp, struct message_preview *msg_prev,
		     struct message *msg)
{
	long pos = ftell(fp);
	int rc;

	fseek(fp, msg_prev->pos, SEEK_SET);
	if (msg_prev->is_blkiomon_v2)
		// make sure message is converted
		rc = read_message(fp, msg, DATA_MGR_V2, msg_prev->type);
	else
		// use an arbitrary version != V2
		rc = read_message(fp, msg, DATA_MGR_V3, msg_prev->type);
	fseek(fp, pos, SEEK_SET);

	return rc;
}


void discard_msg(struct message *msg)
{
	if (msg) {
		free(msg->data);
		msg->data = NULL;
	}
}


int write_aggr_file(FILE *fp, struct aggr_data *data)
{
	__u64 i;

	conv_agg_header_to_BE(data);
	rewind(fp);
	i = fwrite(data, DACC_AGGR_FILE_HDR_LEN, 1, fp);
	conv_agg_header_from_BE(data);
	if (i != 1)
		return -1;

	if (data->util_aggr) {
		if (write_message(fp, data->util_aggr))
			return -2;
	}
	else if (write_garbage_message(fp, 8))
			return -3;

	if (data->ioerr_aggr) {
		if (write_message(fp, data->ioerr_aggr))
			return -4;
	}
	else if (write_garbage_message(fp, 8))
		return -5;

	if (data->num_blkiomon > 0) {
		for (i = 0; i<data->num_blkiomon; ++i) {
			if (write_message(fp, data->blkio_aggr[i]))
				return -6;
		}
	}
	else if (write_garbage_message(fp, 8))
		return -7;

	if (data->num_zfcpdd > 0) {
		for (i=0; i<data->num_zfcpdd; ++i) {
			if (write_message(fp, data->zfcpdd_aggr[i]))
				return -8;
		}
	}
	else if (write_garbage_message(fp, 8))
		return -9;

	return 0;
}


void init_aggr_data_struct(struct aggr_data *data)
{
	data->magic = DATA_MGR_MAGIC_AGGR;
	data->version = DATA_MGR_V2;
	data->num_zfcpdd = 0;
	data->num_blkiomon = 0;
	data->end_time = 0;
	data->begin_time = 0;
	data->util_aggr = NULL;
	data->ioerr_aggr = NULL;
	data->blkio_aggr = NULL;
	data->zfcpdd_aggr = NULL;
}


void discard_aggr_data_struct(struct aggr_data *data)
{
	unsigned int i;

	if (data) {
		discard_msg(data->util_aggr);
		discard_msg(data->ioerr_aggr);
		for (i=0; i<data->num_blkiomon; ++i) {
			discard_msg(data->blkio_aggr[i]);
			free(data->blkio_aggr[i]);
		}
		for (i=0; i<data->num_zfcpdd; ++i) {
			discard_msg(data->zfcpdd_aggr[i]);
			free(data->zfcpdd_aggr[i]);
		}
		free(data->util_aggr);
		free(data->ioerr_aggr);
		free(data->blkio_aggr);
		free(data->zfcpdd_aggr);
	}
}


int open_data_files(FILE **fp, const char *filename, struct file_header *f_hdr,
	      struct aggr_data **agg)
{
	struct message_preview msg_prev;
	struct message msg;
	int rc = 0;
	int i;
	__u64 end_of_agg;
	time_t t;

#ifndef NDEBUG
	assert(open_count == 0);
	open_count++;
#endif

	verbose_msg("open data\n");

	/*
	 * Open .agg file if exists
	 */

	*agg = (struct aggr_data*)malloc(sizeof(struct aggr_data));
	if ( (rc = open_agg_file(fp, filename, *agg)) < 0 ) {
		free(*agg);
		return -1;
	}
	if (rc == 0) {
		verbose_msg("  found .agg file\n");
		close_agg_file(*fp);
	}
	else {
		verbose_msg("  no .agg file found\n");
		free(*agg);
		*agg = NULL;
	}

	/*
	 * Open .log file
	 */
	if ( (rc = open_log_file(fp, filename, f_hdr)) )
		return -1;

	/*
	 * Eventually add messages from final frame of .agg file and adjust
	 * respective boundaries
	 */

	if (*agg) {
		conv_aggr_data_msg_data_from_BE(*agg);

		/* We use the first message that we have as the basis to
		   calculate when the final timeframe of the .agg data
		   would have ended. Note that we always add all messages
		   that are interval/2 after that timestamp! */
		end_of_agg = ((*agg)->end_time - (*agg)->begin_time -
			f_hdr->interval_length / 2) % f_hdr->interval_length;
		if (end_of_agg)
			end_of_agg = (*agg)->end_time
				+ (f_hdr->interval_length - end_of_agg);

		i = 0;
		while ( (rc = get_next_msg_preview(*fp, &msg_prev, f_hdr)) == 0
			 && msg_prev.timestamp <= end_of_agg) {
			if (get_complete_msg(*fp, &msg_prev, &msg))
			    return -1;
			rc = add_to_agg(*agg, &msg, f_hdr);
			discard_msg(&msg);
			if (rc)
				return -1;
			++i;
		}
		if (rc < 0) {
			fprintf(stderr, "%s: Could not read"
				" any messages in %s%s\n", toolname, filename,
				DACC_FILE_EXT_LOG);
			return -1;
		}
		// condition of the check impossible to fail, but still...
		if (msg_prev.timestamp > end_of_agg)
			rewind_to(*fp, &msg_prev);

		// finally, adjust boundaries
		(*agg)->end_time = end_of_agg - f_hdr->interval_length / 2;
		f_hdr->begin_time = (*agg)->end_time + f_hdr->interval_length;
		if (verbose > 0) {
			t = (*agg)->end_time;
			verbose_msg("  adjust agg end time to  : %s",
				    ctime(&t));
			t = (*agg)->begin_time;
			verbose_msg("  adjust log begin time to: %s",
				    ctime(&t));
		}

		conv_aggr_data_msg_data_to_BE(*agg);
		verbose_msg("  added %d messages to aggregated structure\n",
			    i);
	}

	verbose_msg("open data finished\n");

	return 0;
}



