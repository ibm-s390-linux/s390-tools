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

#ifndef ZIOREP_FRAMER
#define ZIOREP_FRAMER

#include <list>

#include "ziorep_filters.hpp"
#include "ziorep_frameset.hpp"


using std::list;


extern "C" {
#include "ziomon_dacc.h"
}


class Framer {
public:
	/**
	 * Note: Filter parameters transfer memory ownership to class.
	 * 'filter_types' is an optional list of message types that should
	 * be processed exclusively, anything else will be ignored. If not set,
	 * all messages will be processed.
	 */
	Framer(__u64 begin, __u64 end, __u32 interval_length,
	       list<MsgTypes> *filter_types, DeviceFilter *devFilter,
	       const char *filename, int *rc);

	~Framer();

	/**
	 * Retrieve the next set of messages.
	 * Returns 0 in case of success, <0 in case of failure
	 * and >0 in case end of data has been reached.
	 * Set 'replace_missing' to fill in for non-present datasets.
	 * E.g. if no utilization data was found in the interval (since there
	 * was no traffic), a dataset with the expected number of samples
	 * (but all 0s for the values) will be generated.
	 */
	int get_next_frameset(Frameset &frameset, bool replace_missing = false);

private:
	void handle_msg(struct message *msg, Frameset &frameset) const;
	bool handle_agg_data(Frameset &frameset) const;

	/* timestamps of samples to consider
	 * These are exact timestamps, we shift them a bit to make sure that
	 * we catch any late or early messages as well */
	__u64		 	 m_begin;
	__u64		 	 m_end;
	/// user-specified interval length
	__u32		 	 m_interval_length;

	/* Criteria to identify the right messages */
	MsgTypeFilter		*m_type_filter;
	DeviceFilter		*m_device_filter;

	// filename without extension
	const char		*m_filename;
	FILE			*m_fp;
	struct file_header	 m_fhdr;
	struct aggr_data	*m_agg_data;
	/// indicates whether the .agg file was already read or not
	bool			 m_agg_read;
};


#endif

