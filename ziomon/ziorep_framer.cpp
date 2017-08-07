/*
 * FCP report generators
 *
 * Class for reading messages into frames.
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <unistd.h>
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <stdlib.h>

#include "ziorep_framer.hpp"
#include "ziorep_utils.hpp"

extern "C" {
#include "ziomon_msg_tools.h"
}

extern const char *toolname;
extern int verbose;


Framer::Framer(__u64 begin, __u64 end, __u32 interval_length,
	       list<MsgTypes> *filter_types, DeviceFilter *devFilter,
	       const char *filename, int *rc)
	: m_interval_length(interval_length), m_type_filter(NULL),
	m_device_filter(devFilter), m_filename(filename), m_fp(NULL),
	m_agg_read(false)
{
	m_begin = begin;
	m_end = end;
	assert(m_begin <= m_end);

	// set up .log file on first time
	if (open_data_files(&m_fp, m_filename, &m_fhdr, &m_agg_data)) {
		*rc = -2;
		return;
	}
	if (m_agg_data)
		conv_aggr_data_msg_data_from_BE(m_agg_data);

	if (filter_types) {
		m_type_filter = new MsgTypeFilter;
		for (list<MsgTypes>::const_iterator i = filter_types->begin();
		      i != filter_types->end(); ++i) {
			switch (*i) {
			case utilization:
				m_type_filter->add_type(m_fhdr.msgid_utilization);
				break;
			case ioerr:
				m_type_filter->add_type(m_fhdr.msgid_ioerr);
				break;
			case blkiomon:
				m_type_filter->add_type(m_fhdr.msgid_blkiomon);
				break;
			case zfcpdd:
				m_type_filter->add_type(m_fhdr.msgid_zfcpdd);
				break;
			}
		}
	}

	*rc = 0;
}

Framer::~Framer()
{
	close_data_files(m_fp);

	if (m_type_filter)
		delete m_type_filter;

	if (m_agg_data) {
		discard_aggr_data_struct(m_agg_data);
		free(m_agg_data);
	}
}

bool Framer::handle_agg_data(Frameset &frameset) const
{
	// Initial test - if we pass, we still have to check
	// the messages individually later on!
	if (m_begin > m_agg_data->end_time || m_end < m_agg_data->begin_time)
		return false;

	/* collate all messages */
	list<struct message *> agg_msgs;
	if (m_agg_data->util_aggr)
		agg_msgs.insert(agg_msgs.end(), m_agg_data->util_aggr);
	if (m_agg_data->ioerr_aggr)
		agg_msgs.insert(agg_msgs.end(), m_agg_data->ioerr_aggr);
	for (unsigned int i = 0; i<m_agg_data->num_blkiomon; ++i)
		agg_msgs.insert(agg_msgs.end(), m_agg_data->blkio_aggr[i]);
	for (unsigned int i = 0; i<m_agg_data->num_zfcpdd; ++i)
		agg_msgs.insert(agg_msgs.end(), m_agg_data->zfcpdd_aggr[i]);

	/* loop over collated msgs */
	for (list<struct message*>::iterator i=agg_msgs.begin();
	      i != agg_msgs.end(); ++i) {
		// we do an all-or-nothing approach - anything else would be
		// too confusing
		/*
		__u64 t = get_timestamp_from_msg(*i);
		if (m_begin > t || m_end < t) {
			vverbose_msg("message not in timeframe\n");
			continue;
		} */
		if (m_type_filter && !m_type_filter->is_eligible(*i)) {
			vverbose_msg("message type not eligible\n");
			continue;
		}
		vverbose_msg("adding msg\n");
		handle_msg(*i, frameset);
	}
	verbose_msg("    found eligible data in aggregated messages: %d\n",
		    frameset.is_aggregated());

	return (!frameset.is_empty());
}

void Framer::handle_msg(struct message *msg, Frameset &frameset) const
{
	if (msg->type == m_fhdr.msgid_utilization) {
		struct utilization_data *res = (struct utilization_data*)msg->data;
		struct adapter_utilization *a_res;
		for (int i = 0; i < res->num_adapters; ++i) {
			a_res = &res->adapt_utils[i];
			if (m_device_filter && !m_device_filter->is_eligible(a_res)) {
				vverbose_msg("message not for eligible device\n");
				continue;
			}
			vverbose_msg("adding utilization msg\n");
			frameset.add_data(a_res);
		}
	}
	else if (msg->type == m_fhdr.msgid_ioerr) {
		struct ioerr_data *data = (struct ioerr_data*)msg->data;
		struct ioerr_cnt *cnt;
		for (unsigned int i = 0; i < data->num_luns; ++i) {
			cnt = &data->ioerrors[i];
			if (m_device_filter && !m_device_filter->is_eligible(cnt)) {
				vverbose_msg("message not for eligible device\n");
				continue;
			}
			vverbose_msg("adding ioerr msg\n");
			frameset.add_data(cnt);
		}
	}
	else {
		if (m_device_filter && !m_device_filter->is_eligible(msg, &m_fhdr)) {
			vverbose_msg("message not for eligible device\n");
			return;
		}
		if (msg->type == m_fhdr.msgid_blkiomon) {
			vverbose_msg("adding blkiomon msg\n");
			frameset.add_data((struct blkiomon_stat*)msg->data);
		}
		else {
			assert(msg->type == m_fhdr.msgid_zfcpdd);
			vverbose_msg("adding zfcpdd msg\n");
			frameset.add_data((struct zfcpdd_dstat*)msg->data);
		}
	}
}

int Framer::get_next_frameset(Frameset &frameset, bool replace_missing)
{
	int rc = 0;
	int msgs_read = 0;
	__u64 shifted_begin;
	__u64 shifted_end;
	__u64 frame_begin = 0;

	frameset.reinit();

	if (m_begin > m_end)
		return 1;

	if (verbose >= 2) {
#ifndef NDEBUG
		time_t t = m_begin;
#endif
		vverbose_msg("retrieving next frameset for: %s", ctime(&t));
	}

	// did we check out .agg yet?
	if (!m_agg_read) {
		m_agg_read = true;
		if (m_agg_data) {
			verbose_msg("    found aggregated data, check if eligible\n");
			handle_agg_data(frameset);
			if (!frameset.is_empty()) {
				if (m_interval_length != 0) {
					verbose_msg(".agg data processed, wrap up frame\n");
					frameset.set_aggregated(true);
					frameset.set_timeframe(
						m_agg_data->begin_time
							- m_fhdr.interval_length / 2,
						m_agg_data->end_time
							+ m_fhdr.interval_length / 2,
						m_agg_data->end_time);
					// just bump it to the next frame
					m_begin += m_fhdr.interval_length;
					if (replace_missing)
						frameset.replace_missing_datasets(m_fhdr.interval_length);

					return 0;
				}
				verbose_msg(".agg data processed, add all of the rest to it\n");
				frame_begin = m_agg_data->begin_time - m_fhdr.interval_length / 2;
			}
		}
		else
			verbose_msg("    no aggregated data found\n");
	}

	// down to real business
	struct message		msg;
	struct message_preview	msg_preview;

	shifted_begin = m_begin - m_fhdr.interval_length / 2;
	shifted_end = shifted_begin + m_interval_length;
	if (m_interval_length == 0 || shifted_end > m_end)
		shifted_end = m_end + m_fhdr.interval_length / 2;
	MsgTimeFilter timeFilter(shifted_begin, shifted_end);

	if (frame_begin == 0)
		frame_begin = timeFilter.get_begin_time();

	while( (rc = get_next_msg_preview(m_fp, &msg_preview, &m_fhdr)) == 0 ) {
		vverbose_msg("checking out next msg\n");
		++msgs_read;
		if (msg_preview.timestamp > timeFilter.get_end_time()) {
			vverbose_msg("timeframe exceeded\n");
			rewind_to(m_fp, &msg_preview);
			break;
		}
		// is this necessary at all?!?
		if (!timeFilter.is_eligible(&msg_preview))
			continue;
		vverbose_msg("timestamp: OK\n");
		if (m_type_filter && !m_type_filter->is_eligible(&msg_preview)) {
			vverbose_msg("wrong type (%u)\n", msg_preview.type);
			continue;
		}
		vverbose_msg("type     : OK\n");
		if (get_complete_msg(m_fp, &msg_preview, &msg) < 0) {
			fprintf(stderr, "%s: Error retrieving next message, aborting"
				" - file corrupt?\n", toolname);
			return -5;
		}
		conv_msg_data_from_BE(&msg, &m_fhdr);
		handle_msg(&msg, frameset);
		discard_msg(&msg);
	}

	if (rc < 0) {
		fprintf(stderr, "%s: Error retrieving next message, aborting"
			" - file corrupt?\n", toolname);
		return -4;
	}

	/* if we read some messages, though not the right ones,
	   we pass on an empty frame still. Will indicate EOF next time */
	if (rc > 0 && msgs_read)
		rc = 0;

	if (rc == 0) {
		frameset.set_timeframe(frame_begin, timeFilter.get_end_time(),
                              timeFilter.get_end_time() - m_fhdr.interval_length / 2);
		if (m_interval_length == 0)
			m_begin = m_end + 1;	// we're done
		else
			m_begin += m_interval_length;
		if (replace_missing)
			frameset.replace_missing_datasets(m_fhdr.interval_length);
	}

	return rc;
}

