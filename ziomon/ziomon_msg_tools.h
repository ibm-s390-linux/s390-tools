/*
 * FCP adapter trace utility
 *
 * Common utility functions to handle message structs
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZIOMON_MSG__TOOLS_H
#define ZIOMON_MSG__TOOLS_H

#include <time.h>

#include "ziomon_dacc.h"

void conv_blkiomon_v2_to_v3(struct message *msg);

void conv_msg_data_to_BE(struct message *msg, const struct file_header *hdr);

void conv_msg_data_from_BE(struct message *msg, const struct file_header *hdr);

void conv_aggr_data_msg_data_to_BE(struct aggr_data *hdr);

void conv_aggr_data_msg_data_from_BE(struct aggr_data *hdr);

void copy_msg(struct message *src, struct message **tgt);

/**
 * Retrieve the timestamp from a message in BE format.
 * The timestamp is returned in regular format */
time_t get_timestamp_from_BE_msg(const struct message *msg);

/**
 * Retrieve the timestamp from a message in regular format.
 * The timestamp is returned in regular format */
time_t get_timestamp_from_msg(const struct message *msg);

/**
 * Add 'msg' to the 'hdr' struct.
 * The aggregated header is assumed to be in regular format,
 * while the message should be in BE format.
 * The message will be left converted to BE for performance
 * reasons */
int add_to_agg(struct aggr_data *hdr, struct message *msg,
	       const struct file_header *f_hdr);

#endif

