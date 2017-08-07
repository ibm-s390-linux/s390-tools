/*
 * FCP report generators
 *
 * Class to hold information of a single frame.
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>

#include "ziorep_frameset.hpp"

extern "C" {
	#include "ziomon_tools.h"
}

extern const char *toolname;
extern int verbose;


Frameset::Frameset(const Collapser *col, bool normalize) :
m_empty(true), m_aggregated(false),
	m_collapser(col), m_normalize(normalize)
{
	reinit();

	/* We set everything up for aggregation collapsers */
	if (m_collapser->get_criterion() != none
	    && m_collapser->get_criterion() != all) {
		unsigned int len = 0;

		AggregationCollapser *col = (AggregationCollapser*)m_collapser;
		switch (m_collapser->get_criterion()) {
		case chpid: len = col->get_reference_chpids().size();
			break;
		case devno: len = col->get_reference_devnos().size();
			break;
		case wwpn: len = col->get_reference_wwpns().size();
			break;
		case multipath_device: len = col->get_reference_mp_mms().size();
			break;
		default:
			assert(false);
		}
		m_util_stats.resize(len);
		m_ioerr_stats.resize(len);
		m_blkiomon_stats.resize(len);
		m_zfcpdd_stats.resize(len);
		for (unsigned int i = 0; i < len; ++i) {
			init_utilization_wrapper(&m_util_stats[i]);
			m_ioerr_stats[i] = NULL;
			m_blkiomon_stats[i] = NULL;
			init_zfcpdd_wrapper(&m_zfcpdd_stats[i]);
		}
	}
}

Frameset::~Frameset()
{
	reinit();
}

void Frameset::reinit()
{
	for (vector<struct utilization_wrapper>::iterator i=m_util_stats.begin();
	      i != m_util_stats.end(); i++) {
		delete (*i).stat;
		init_utilization_wrapper(&(*i));
	}

	for (vector<struct ioerr_cnt*>::iterator i=m_ioerr_stats.begin();
	      i != m_ioerr_stats.end(); i++) {
		delete *i;
		*i = NULL;
	}

	for (vector<struct zfcpdd_wrapper>::iterator i=m_zfcpdd_stats.begin();
	      i != m_zfcpdd_stats.end(); i++) {
		delete (*i).stat;
		init_zfcpdd_wrapper(&(*i));
	}

	for (vector<struct blkiomon_stat*>::iterator i=m_blkiomon_stats.begin();
	      i != m_blkiomon_stats.end(); i++) {
		delete *i;
		*i = NULL;
	}

	if (m_collapser->get_criterion() == none
		|| m_collapser->get_criterion() == all) {
		m_util_stats.clear();
		m_ioerr_stats.clear();
		m_zfcpdd_stats.clear();
		m_blkiomon_stats.clear();
	}

	m_aggregated = false;
	m_start_time = 0;
	m_end_time = 0;
	m_empty = true;
	m_timestamp = 0;
}

const Collapser* Frameset::get_collapser() const
{
	return m_collapser;
}


void Frameset::add_zero_frames(struct utilization_wrapper *wrp,
			     int num_expected, int interval_length)
{
	// found a (probable) kernel bug that cause a violation of this
	// assertion. There might be other reasons (exzessive steal times)
	// that could cause a violation as well.
	//assert(!wrp || wrp->counter <= num_expected);

	if (wrp
	    && wrp->counter > 0
	    && wrp->counter < num_expected
	    && wrp->stat->valid) {
		vverbose_msg("Correcting util stat from %d to %d datasets\n",
			     wrp->counter, num_expected);
		transform_abbrev_stat(&wrp->stat->stats.adapter,
				  wrp->stat->stats.count,
				  wrp->counter);
		transform_abbrev_stat(&wrp->stat->stats.bus,
				  wrp->stat->stats.count,
				  wrp->counter);
		transform_abbrev_stat(&wrp->stat->stats.cpu,
				  wrp->stat->stats.count,
				  wrp->counter);
		wrp->stat->stats.queue_util_interval += interval_length * 1000000
				* (num_expected - wrp->counter);
		wrp->stat->stats.count = num_expected;
		wrp->counter = num_expected;
	}
}


/**
 * Only fix utilization and the qdio portion of util
 * datasets - the rest doesn't matter */
void Frameset::replace_missing_datasets(int interval_length)
{
	int num_expected_datasets;

	assert(m_start_time != 0);
	assert(m_end_time != 0);
	assert(interval_length > 0);

	num_expected_datasets = (m_end_time - m_start_time) /interval_length;
	for (vector<struct utilization_wrapper>::iterator i = m_util_stats.begin();
	      i != m_util_stats.end(); ++i)
		add_zero_frames(&(*i), num_expected_datasets, interval_length);
}

void Frameset::set_timeframe(__u64 begin, __u64 end, __u64 timestamp)
{
	m_start_time = begin;
	m_end_time = end;
	m_timestamp = timestamp;
}

__u64 Frameset::get_begin_time() const
{
	return m_start_time;
}

__u64 Frameset::get_end_time() const
{
	return m_end_time;
}

__u64 Frameset::get_timestamp() const
{
	return m_timestamp;
}

__u64 Frameset::get_duration() const
{
	return (m_end_time - m_start_time);
}


void Frameset::normalize_stat(struct abbrev_stat *stat, __u64 count)
{
	stat->sum = (__u64)calc_avg(stat->sum, count);
	stat->sos = (__u64)calc_avg(stat->sos, count);
}


void Frameset::normalize_util_stat(struct utilization_stats *stats)
{
	if (stats->count > 1) {
		normalize_stat(&stats->adapter, stats->count);
		normalize_stat(&stats->bus, stats->count);
		normalize_stat(&stats->cpu, stats->count);
		stats->count = 1;
	}
}


void Frameset::add_data(struct adapter_utilization *res)
{
	unsigned int idx = m_collapser->get_index_by_host_id(res->adapter_no);

	m_empty = false;

	if (idx >= m_util_stats.size()) {
		unsigned int old_size = m_util_stats.size();
		m_util_stats.resize(idx + 1);
		for (unsigned int i = old_size; i < idx + 1; ++i)
			init_utilization_wrapper(&m_util_stats[i]);
	}

	if (m_normalize)
		normalize_util_stat(&res->stats);

	if (m_util_stats[idx].counter) {
		aggregate_adapter_result(res, m_util_stats[idx].stat);
		m_util_stats[idx].counter++;
	}
	else {
		m_util_stats[idx].stat = new struct adapter_utilization;
		*m_util_stats[idx].stat = *res;
		m_util_stats[idx].counter = 1;
	}
}


void Frameset::add_data(struct ioerr_cnt *cnt)
{
	unsigned int idx = m_collapser->get_index(&cnt->identifier);

	m_empty = false;

	if (idx >= m_ioerr_stats.size()) {
		unsigned int old_size = m_ioerr_stats.size();
		m_ioerr_stats.resize(idx + 1);
		for (unsigned int i = old_size; i < idx + 1; ++i)
			m_ioerr_stats[i] = NULL;
	}

	if (m_ioerr_stats[idx])
		aggregate_ioerr_cnt(cnt, m_ioerr_stats[idx]);
	else {
		m_ioerr_stats[idx] = new struct ioerr_cnt;
		*m_ioerr_stats[idx] = *cnt;
	}
}


void Frameset::add_data(struct blkiomon_stat *stat)
{
	unsigned int idx = m_collapser->get_index(stat->device);

	m_empty = false;

	if (idx >= m_blkiomon_stats.size()) {
		unsigned int old_size = m_blkiomon_stats.size();
		m_blkiomon_stats.resize(idx + 1);
		for (unsigned int i = old_size; i < idx + 1; ++i)
			m_blkiomon_stats[i] = NULL;
	}

	if (m_blkiomon_stats[idx])
		blkiomon_stat_merge(m_blkiomon_stats[idx], stat);
	else {
		m_blkiomon_stats[idx] = new struct blkiomon_stat;
		*m_blkiomon_stats[idx] = *stat;
	}
}


void Frameset::normalize_zfcpdd_stat(struct zfcpdd_dstat *stat)
{
	stat->chan_lat.min /= 1000;
	stat->chan_lat.max /= 1000;
	stat->chan_lat.sum /= 1000;
	stat->chan_lat.sos /= (1000 * 1000);
}


void Frameset::add_data(struct zfcpdd_dstat *stat)
{
	unsigned int idx = m_collapser->get_index(stat->device);

	m_empty = false;

	normalize_zfcpdd_stat(stat);

	if (idx >= m_zfcpdd_stats.size()) {
		unsigned int old_size = m_zfcpdd_stats.size();
		m_zfcpdd_stats.resize(idx + 1);
		for (unsigned int i = old_size; i < idx + 1; ++i)
			init_zfcpdd_wrapper(&m_zfcpdd_stats[i]);
	}

	if (m_zfcpdd_stats[idx].counter) {
		aggregate_dstat(stat, m_zfcpdd_stats[idx].stat);
		m_zfcpdd_stats[idx].counter++;
	}
	else {
		m_zfcpdd_stats[idx].stat = new struct zfcpdd_dstat;
		*m_zfcpdd_stats[idx].stat = *stat;
		m_zfcpdd_stats[idx].counter = 1;
	}
}

void Frameset::set_aggregated(bool aggr)
{
	m_aggregated = aggr;
}

bool Frameset::is_aggregated() const
{
	return m_aggregated;
}

bool Frameset::is_empty() const
{
	return m_empty;
}

const vector<struct ioerr_cnt*>& Frameset::get_ioerr_stats() const
{
	return m_ioerr_stats;
}

const struct zfcpdd_dstat* Frameset::get_first_zfcpdd_stat() const
{
	assert(m_zfcpdd_stats.size() <= 1);

	if (m_zfcpdd_stats.size() > 0)
		return m_zfcpdd_stats[0].stat;
	else
		return NULL;
}

const struct blkiomon_stat* Frameset::get_first_blkiomon_stat() const
{
	assert(m_blkiomon_stats.size() <= 1);

	if (m_blkiomon_stats.size() > 0)
                return m_blkiomon_stats[0];
	else
		return NULL;
}

void Frameset::init_utilization_wrapper(struct utilization_wrapper *wrp)
{
	wrp->counter = 0;
	wrp->stat = NULL;
}

void Frameset::init_zfcpdd_wrapper(struct zfcpdd_wrapper *wrp)
{
	wrp->counter = 0;
	wrp->stat = NULL;
}

int Frameset::get_by_chpid(__u32 chp) const
{
	assert(m_collapser->get_criterion() == chpid);

	int idx = find_index(((AggregationCollapser*)m_collapser)->get_reference_chpids(), chp);
	assert(idx >= 0);

	return idx;
}

int Frameset::get_by_devno(__u32 d) const
{
	assert(m_collapser->get_criterion() == devno);

	int idx = find_index(((AggregationCollapser*)m_collapser)->get_reference_devnos(), d);
	assert(idx >= 0);

	return idx;
}

int Frameset::get_by_mp_mm(__u32 mp_mm) const
{
	assert(m_collapser->get_criterion() == multipath_device);

	int idx = find_index(((AggregationCollapser*)m_collapser)->get_reference_mp_mms(), mp_mm);
	assert(idx >= 0);

	return idx;
}

int Frameset::get_by_mm(__u32 mm) const
{
	assert(m_collapser->get_criterion() == none
	       || m_collapser->get_criterion() == all);

	int idx = m_collapser->get_index(mm);
	assert(idx >= 0);

	return idx;
}

int Frameset::get_by_wwpn(__u64 w) const
{
	assert(m_collapser->get_criterion() == wwpn);

	int idx = find_index(((AggregationCollapser*)m_collapser)->get_reference_wwpns(), w);
	assert(idx >= 0);

	return idx;
}

const struct adapter_utilization* Frameset::get_utilization_stat_by_host_id(
	__u32 h_id) const
{
	for (vector<struct utilization_wrapper>::const_iterator i = m_util_stats.begin();
	      i != m_util_stats.end(); ++i) {
		if ((*i).counter && (*i).stat->adapter_no == h_id)
			return (*i).stat;
	}

	return NULL;
}

const struct adapter_utilization* Frameset::get_utilization_stat_by_chpid(
	__u32 chpid) const
{
	int idx = get_by_chpid(chpid);

	assert(idx < (int)m_util_stats.size());

	if (idx >= (int)m_util_stats.size())
		return NULL;

	return m_util_stats[idx].stat;
}

const struct ioerr_cnt* Frameset::get_ioerr_stat_by_chpid(__u32 chpid) const
{
	int idx = get_by_chpid(chpid);

	assert(idx < (int)m_ioerr_stats.size());

	if (idx >= (int)m_ioerr_stats.size())
		return NULL;

	return m_ioerr_stats[idx];
}

const struct blkiomon_stat* Frameset::get_blkiomon_stat_by_chpid(__u32 chpid) const
{
	int idx = get_by_chpid(chpid);

	if (idx >= (int)m_blkiomon_stats.size())
		return NULL;

	return m_blkiomon_stats[idx];
}

const struct blkiomon_stat* Frameset::get_blkiomon_stat_by_devno(__u32 devno) const
{
	int idx = get_by_devno(devno);

	if (idx >= (int)m_blkiomon_stats.size())
		return NULL;

	return m_blkiomon_stats[idx];
}

const struct blkiomon_stat* Frameset::get_blkiomon_stat_by_wwpn(__u64 wwpn) const
{
	int idx = get_by_wwpn(wwpn);

	if (idx >= (int)m_blkiomon_stats.size())
		return NULL;

	return m_blkiomon_stats[idx];
}

const struct blkiomon_stat* Frameset::get_blkiomon_stat_by_mp_mm(__u32 mp_mm) const
{
	int idx = get_by_mp_mm(mp_mm);

	if (idx >= (int)m_blkiomon_stats.size())
		return NULL;

	return m_blkiomon_stats[idx];
}

const struct blkiomon_stat* Frameset::get_blkiomon_stat_by_mm(__u32 mm) const
{
	int idx = get_by_mm(mm);

	if (idx >= (int)m_blkiomon_stats.size())
		return NULL;

	return m_blkiomon_stats[idx];
}

const struct zfcpdd_dstat* Frameset::get_zfcpdd_stat_by_chpid(__u32 chpid) const
{
	int idx = get_by_chpid(chpid);

	if (idx >= (int)m_zfcpdd_stats.size())
		return NULL;

	return m_zfcpdd_stats[idx].stat;
}

const struct zfcpdd_dstat* Frameset::get_zfcpdd_stat_by_devno(__u32 devno) const
{
	int idx = get_by_devno(devno);

	if (idx >= (int)m_zfcpdd_stats.size())
		return NULL;

	return m_zfcpdd_stats[idx].stat;
}

const struct zfcpdd_dstat* Frameset::get_zfcpdd_stat_by_wwpn(__u64 wwpn) const
{
	int idx = get_by_wwpn(wwpn);

	if (idx >= (int)m_zfcpdd_stats.size())
		return NULL;

	return m_zfcpdd_stats[idx].stat;
}

const struct zfcpdd_dstat* Frameset::get_zfcpdd_stat_by_mp_mm(__u32 mp_mm) const
{
	int idx = get_by_mp_mm(mp_mm);

	if (idx >= (int)m_zfcpdd_stats.size())
		return NULL;

	return m_zfcpdd_stats[idx].stat;
}

const struct zfcpdd_dstat* Frameset::get_zfcpdd_stat_by_mm(__u32 mm) const
{
	int idx = get_by_mm(mm);

	if (idx >= (int)m_zfcpdd_stats.size())
		return NULL;

	return m_zfcpdd_stats[idx].stat;
}

const struct adapter_utilization* Frameset::get_utilization_stat_by_devno(
	__u32 subchnl) const
{
	int idx = get_by_devno(subchnl);

	assert(idx < (int)m_util_stats.size());

	if (idx >= (int)m_util_stats.size())
		return NULL;

	return m_util_stats[idx].stat;
}

const struct ioerr_cnt* Frameset::get_ioerr_stat_by_devno(
	__u32 devno) const
{
	int idx = get_by_devno(devno);

	assert(idx < (int)m_ioerr_stats.size());

	if (idx >= (int)m_ioerr_stats.size())
		return NULL;

	return m_ioerr_stats[idx];
}

int Frameset::find_index(const list<__u32> &lst, __u32 val) const
{
	unsigned int idx = 0;

	for (list<__u32>::const_iterator i = lst.begin();
	      i != lst.end(); ++i, ++idx) {
		if (*i == val)
			return idx;
	}

	return -1;
}

int Frameset::find_index(const list<__u64> &lst, __u64 val) const
{
	unsigned int idx = 0;

	for (list<__u64>::const_iterator i = lst.begin();
	      i != lst.end(); ++i, ++idx) {
		if (*i == val)
			return idx;
	}

	return -1;
}





