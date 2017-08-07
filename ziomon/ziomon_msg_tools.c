/*
 * FCP adapter trace facility
 *
 * Common utility functions to handle message structs
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ziomon_msg_tools.h"
#include "ziomon_util.h"
#include "ziomon_zfcpdd.h"
#include "blkiomon.h"


extern const char *toolname;




void conv_blkiomon_v2_to_v3(struct message *msg) {
	struct blkiomon_stat_v2 stat_v2 = *(struct blkiomon_stat_v2*)msg->data;
	struct blkiomon_stat    *stat = msg->data;

	stat->device = stat_v2.device;
	stat->size_r = stat_v2.size_r;
	stat->size_w = stat_v2.size_w;
	stat->d2c_r = stat_v2.d2c_r;
	stat->d2c_w = stat_v2.d2c_w;
	stat->thrput_r = stat_v2.thrput_r;
	stat->thrput_w = stat_v2.thrput_w;
	stat->bidir = stat_v2.bidir;
}

void conv_msg_data_to_BE(struct message *msg,
			 const struct file_header *hdr)
{
	if (msg->type == hdr->msgid_utilization)
		conv_overall_result_to_BE(msg->data);
	else if (msg->type == hdr->msgid_ioerr)
		conv_ioerr_data_to_BE(msg->data);
	else if (msg->type == hdr->msgid_blkiomon)
		blkiomon_conv_to_BE(msg->data);
	else if (msg->type == hdr->msgid_zfcpdd)
		conv_dstat_to_BE(msg->data);
	else
		fprintf(stderr, "%s: Unknown message encountered\n", toolname);
}

void conv_msg_data_from_BE(struct message *msg,
			   const struct file_header *hdr)
{
	if (msg->type == hdr->msgid_utilization)
		conv_overall_result_from_BE(msg->data);
	else if (msg->type == hdr->msgid_ioerr)
		conv_ioerr_data_from_BE(msg->data);
	else if (msg->type == hdr->msgid_blkiomon)
		blkiomon_conv_from_BE(msg->data);
	else if (msg->type == hdr->msgid_zfcpdd)
		conv_dstat_from_BE(msg->data);
	else
		fprintf(stderr,"%s: Unknown message encountered\n", toolname);
}

void conv_aggr_data_msg_data_to_BE(struct aggr_data *hdr)
{
	__u64 i;

	if (hdr->util_aggr)
		conv_overall_result_to_BE(hdr->util_aggr->data);
	if (hdr->ioerr_aggr)
		conv_ioerr_data_to_BE(hdr->ioerr_aggr->data);
	for (i=0; i<hdr->num_blkiomon; ++i)
		blkiomon_conv_to_BE(hdr->blkio_aggr[i]->data);
	for (i=0; i<hdr->num_zfcpdd; ++i)
		conv_dstat_to_BE(hdr->zfcpdd_aggr[i]->data);
}

void conv_aggr_data_msg_data_from_BE(struct aggr_data *hdr)
{
	__u64 i;

	if (hdr->util_aggr)
		conv_overall_result_from_BE(hdr->util_aggr->data);
	if (hdr->ioerr_aggr)
		conv_ioerr_data_from_BE(hdr->ioerr_aggr->data);
	for (i=0; i<hdr->num_blkiomon; ++i)
		blkiomon_conv_to_BE(hdr->blkio_aggr[i]->data);
	for (i=0; i<hdr->num_zfcpdd; ++i)
		conv_dstat_from_BE(hdr->zfcpdd_aggr[i]->data);
}

void copy_msg(struct message *src, struct message **tgt)
{
	*tgt = malloc(sizeof(struct message));
	(*tgt)->type = src->type;
	(*tgt)->length = src->length;
	(*tgt)->data = malloc(src->length);
	memcpy((*tgt)->data, src->data, src->length);
}

time_t get_timestamp_from_BE_msg(const struct message *msg)
{
	time_t timestamp = get_timestamp_from_msg(msg);
	swap_64(timestamp);

	return timestamp;
}

time_t get_timestamp_from_msg(const struct message *msg)
{
	return *(__u64*)(msg->data);
}

static void aggregate_blkiomon(struct aggr_data *agg_data, struct message *msg)
{
	__u64 i;
	struct message **tmp;
	struct blkiomon_stat *stat = msg->data;

	for (i = 0; i < agg_data->num_blkiomon; ++i)
		if ((((struct blkiomon_stat*)(agg_data->blkio_aggr[i]->data))->device)
			== stat->device)
			break;
	if (i >= agg_data->num_blkiomon) {
		/* messages for this device not aggregated yet
		   - add a new entry */
		tmp = agg_data->blkio_aggr;
		++(agg_data->num_blkiomon);
		agg_data->blkio_aggr =
			malloc(agg_data->num_blkiomon * sizeof(struct message*));
		for (i = 0; i < agg_data->num_blkiomon - 1; ++i)
			agg_data->blkio_aggr[i] = tmp[i];
		copy_msg(msg, &agg_data->blkio_aggr[i]);
		free(tmp);
	}
	else
		blkiomon_stat_merge(agg_data->blkio_aggr[i]->data, msg->data);
}


static void aggregate_zfcpdd(struct aggr_data *agg_data, struct message *msg)
{
	__u64 i;
	struct message **tmp;
	struct zfcpdd_dstat *stat = msg->data;

	for (i = 0; i < agg_data->num_zfcpdd; ++i)
		if ((((struct zfcpdd_dstat*)(agg_data->zfcpdd_aggr[i]->data))->device)
			== stat->device)
			break;
	if (i >= agg_data->num_zfcpdd) {
		/* messages for this device not aggregated yet
		   - add a new entry */
		tmp = agg_data->zfcpdd_aggr;
		++(agg_data->num_zfcpdd);
		agg_data->zfcpdd_aggr =
			malloc(agg_data->num_zfcpdd * sizeof(struct message*));
		for (i = 0; i < agg_data->num_zfcpdd - 1; ++i)
			agg_data->zfcpdd_aggr[i] = tmp[i];
		copy_msg(msg, &agg_data->zfcpdd_aggr[i]);
		free(tmp);
	}
	else
		aggregate_dstat(msg->data, agg_data->zfcpdd_aggr[i]->data);
}


int add_to_agg(struct aggr_data *agg_data, struct message *msg,
	       const struct file_header *f_hdr)
{
	assert(agg_data->magic == DATA_MGR_MAGIC_AGGR);

	conv_msg_data_from_BE(msg, f_hdr);

	if (msg->type == f_hdr->msgid_utilization) {
		if (agg_data->util_aggr)
			aggregate_utilization_data(msg->data,
				    agg_data->util_aggr->data);
		else
			copy_msg(msg, &agg_data->util_aggr);
	} else if (msg->type == f_hdr->msgid_ioerr) {
		if (agg_data->ioerr_aggr)
			aggregate_ioerr_data(msg->data,
				    agg_data->ioerr_aggr->data);
		else
			copy_msg(msg, &agg_data->ioerr_aggr);
	} else if (msg->type == f_hdr->msgid_blkiomon)
		aggregate_blkiomon(agg_data, msg);
	else if (msg->type == f_hdr->msgid_zfcpdd)
		aggregate_zfcpdd(agg_data, msg);
	else {
		fprintf(stderr, "%s: Unknow msg id: %d,"
			" discarding\n", toolname, msg->type);
		return -1;
	}
	agg_data->end_time = get_timestamp_from_msg(msg);
	if (agg_data->begin_time == 0)
		agg_data->begin_time = agg_data->end_time;

	return 0;
}


