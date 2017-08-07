/*
 * FCP report generators
 *
 * Classes implementing various filters
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

#include "ziorep_filters.hpp"

extern "C" {
#include "ziomon_msg_tools.h"
}

extern const char *toolname;
extern int verbose;



MsgFilter::MsgFilter()
{
}


MsgFilter::~MsgFilter()
{
}


MsgTypeFilter::MsgTypeFilter()
{
}


MsgTypeFilter::~MsgTypeFilter()
{
}


void MsgTypeFilter::add_type(__u32 type)
{
	m_types.insert(type);
}


bool MsgTypeFilter::is_eligible(const struct message_preview *msg) const
{
	return is_eligible(msg->type);
}


bool MsgTypeFilter::is_eligible(const struct message *msg) const
{
	return is_eligible(msg->type);
}


bool MsgTypeFilter::is_eligible(__u32 type) const
{
	return (m_types.find(type) != m_types.end());
}


MsgTimeFilter::MsgTimeFilter(__u64 begin, __u64 end) :
m_begin(begin), m_end(end)
{
	assert(m_end >= m_begin);
}


MsgTimeFilter::~MsgTimeFilter()
{
}


bool MsgTimeFilter::is_eligible(__u64 timestamp) const
{
	return (timestamp >= m_begin && timestamp <= m_end);
}


__u64 MsgTimeFilter::get_begin_time() const
{
	return m_begin;
}


__u64 MsgTimeFilter::get_end_time() const
{
	return m_end;
}


bool MsgTimeFilter::is_eligible(const struct message_preview *msg) const
{
	return is_eligible(msg->timestamp);
}


bool MsgTimeFilter::is_eligible(const struct message *msg) const
{
	return is_eligible(get_timestamp_from_msg(msg));
}


void DeviceFilter::add_device(__u32 device, const struct hctl_ident *id) {
	add_device(device);
	add_device(id);
	add_host(id->host);
}


void DeviceFilter::add_device(__u32 device)
{
	list<__u32>::iterator i;

	for (i = m_devices.begin(); i != m_devices.end() && device > *i; ++i) ;

	if (m_devices.size() == 0 || *i != device)
		m_devices.insert(i, device);
}


void DeviceFilter::add_device(const struct hctl_ident *id)
{
	list<struct hctl_ident>::iterator i;

	for (i = m_idents.begin(); i != m_idents.end()
	      && compare_hctl_idents(id, &(*i)) > 0; ++i) ;

	if (m_idents.size() == 0 || i == m_idents.end()
	    || compare_hctl_idents(&(*i), id) != 0)
		m_idents.insert(i, *id);
}


void DeviceFilter::add_host(__u32 host)
{
	list<__u32>::iterator i;

	for (i = m_host_ids.begin(); i != m_host_ids.end() && host > *i; ++i) ;

	if (m_host_ids.size() == 0 || i == m_host_ids.end() || *i != host)
		m_host_ids.insert(i, host);
}


const list<__u32>& DeviceFilter::get_host_id_list() const
{
	return m_host_ids;
}


const list<__u32>& DeviceFilter::get_mm_list() const
{
	return m_devices;
}


bool DeviceFilter::is_eligible(const struct message *msg,
				  const struct file_header *hdr) const
{
	if (msg->type == hdr->msgid_blkiomon)
		return is_eligible_mm(((struct blkiomon_stat *)msg->data)->device);

	assert(msg->type == hdr->msgid_zfcpdd);

	return is_eligible_mm(((struct zfcpdd_dstat *)msg->data)->device);
}


bool DeviceFilter::is_eligible(const struct adapter_utilization *res) const
{
	return is_eligible_host_id(res->adapter_no);
}


bool DeviceFilter::is_eligible(const struct ioerr_cnt *cnt) const
{
	return is_eligible_ident(&cnt->identifier);
}


bool DeviceFilter::is_eligible_mm(__u32 mm) const
{
	for (list<__u32>::const_iterator i = m_devices.begin();
	      i != m_devices.end() && mm >= *i; ++i) {
		if (mm == *i)
			return true;
	}

	return false;
}


bool DeviceFilter::is_eligible_ident(const struct hctl_ident *ident) const
{
	int rc;

	for (list<struct hctl_ident>::const_iterator i = m_idents.begin();
	      i != m_idents.end(); ++i) {
		rc = compare_hctl_idents(ident, &(*i));
		if (rc == 0)
			return true;
		if (rc < 0)
			break;
	}

	return false;
}


bool DeviceFilter::is_eligible_host_id(__u32 host) const
{
	for (list<__u32>::const_iterator i = m_host_ids.begin();
	      i != m_host_ids.end() && host >= (*i); ++i) {
		if (host == (*i))
			return true;
	}

	return false;
}


void DeviceFilter::get_eligible_chpids(ConfigReader &cfg, list<__u32> &lst) const
{
	int rc = 0;

	lst.clear();
	for (list<__u32>::const_iterator i = m_host_ids.begin();
	      i != m_host_ids.end(); ++i) {
		lst.push_back(cfg.get_chpid_by_host_id(*i, &rc));
		assert(rc == 0);
	}
}


void DeviceFilter::get_eligible_devnos(ConfigReader &cfg, list<__u32> &lst) const
{
	if (m_host_ids.size() == 0)
		cfg.get_unique_devnos(lst);
	else {
		lst.clear();
		list<__u32> tmp;
		for (list<__u32>::const_iterator i = m_host_ids.begin();
		      i != m_host_ids.end(); ++i) {
			cfg.get_devnos_by_host_id(tmp, *i);
			lst.insert(lst.begin(), tmp.begin(), tmp.end());
		}
		lst.sort();
		lst.unique();
	}
}

void DeviceFilter::get_eligible_wwpns(ConfigReader &cfg, list<__u64> &lst) const
{
	if (m_devices.size() == 0)
		cfg.get_unique_wwpns(lst);
	else {
		int rc = 0;

		lst.clear();
		for (list<__u32>::const_iterator i = m_devices.begin();
		      i != m_devices.end(); ++i) {
			lst.push_back(cfg.get_wwpn_by_mm_internal(*i, &rc));
			assert(rc == 0);
		}
		lst.sort();
		lst.unique();
	}
}

void DeviceFilter::get_eligible_mp_mms(ConfigReader &cfg, list<__u32> &lst) const
{
	if (m_devices.size() == 0)
		cfg.get_unique_mp_mms(lst);
	else {
		int rc = 0;
		__u32 mp_mm;

		lst.clear();
		for (list<__u32>::const_iterator i = m_devices.begin();
		      i != m_devices.end(); ++i) {
			mp_mm = cfg.get_mp_mm_by_mm_internal(*i, &rc);
			assert(rc == 0);
			if (mp_mm)
				lst.push_back(mp_mm);
		}
		lst.sort();
		lst.unique();
	}
}


void StagedDeviceFilter::stage_wwpn(__u64 w)
{
	list<__u64>::iterator i;

	for (i = m_wwpns.begin(); i != m_wwpns.end() && w > *i; ++i) ;

	if (m_wwpns.size() == 0 || i == m_wwpns.end() || w != *i)
		m_wwpns.insert(i, w);
}


void StagedDeviceFilter::stage_mp_mm(__u32 mp_mm)
{
	list<__u32>::iterator i;

	for (i = m_mp_mms.begin(); i != m_mp_mms.end() && mp_mm > *i; ++i) ;

	if (m_mp_mms.size() == 0 || i == m_mp_mms.end() || mp_mm != *i)
		m_mp_mms.insert(i, mp_mm);
}


void StagedDeviceFilter::stage_devno(__u32 d)
{
	list<__u32>::iterator i;

	for (i = m_devnos.begin(); i != m_devnos.end() && d > *i; ++i) ;

	if (m_devnos.size() == 0 || i == m_devnos.end() || d != *i)
		m_devnos.insert(i, d);
}


void StagedDeviceFilter::stage_chpid(__u32 c)
{
	list<__u32>::iterator i;

	for (i = m_chpids.begin(); i != m_chpids.end() && c > *i; ++i) ;

	if (m_chpids.size() == 0 || i == m_chpids.end() || c != *i)
		m_chpids.insert(i, c);
}


const list<__u64>& StagedDeviceFilter::get_filter_wwpns()
{
	return m_wwpns;
}


const list<__u32>& StagedDeviceFilter::get_filter_chpids()
{
	return m_chpids;
}


const list<__u32>& StagedDeviceFilter::get_filter_devnos()
{
	return m_devnos;
}


const list<__u32>& StagedDeviceFilter::get_filter_mp_mms()
{
	return m_mp_mms;
}


void StagedDeviceFilter::add_mm_with_host(ConfigReader &cfg, __u32 mm, int *rc)
{
	const struct hctl_ident *ident = cfg.get_ident_by_mm_internal(mm, rc);
	assert(*rc == 0);

	add_device(mm, ident);
	add_host(ident->host);
}


void StagedDeviceFilter::add_mms_with_host(ConfigReader &cfg, list<__u32> &mms, int *rc)
{
	for (list<__u32>::const_iterator i = mms.begin();
	      i != mms.end(); ++i)
		add_mm_with_host(cfg, *i, rc);
}


bool StagedDeviceFilter::check_wwpn(__u32 mm, ConfigReader &cfg, int *rc)
{
	if (m_wwpns.size() == 0)
		return true;

	__u64	wwpn = cfg.get_wwpn_by_mm_internal(mm, rc);
	for (list<__u64>::const_iterator i = m_wwpns.begin();
	      i != m_wwpns.end(); ++i) {
		if (*i == wwpn)
			return true;
	}

	return false;
}


bool StagedDeviceFilter::check_mm(__u32 mm)
{
	if (m_devices.size() == 0)
		return true;

	for (list<__u32>::const_iterator i = m_devices.begin();
	      i != m_devices.end(); ++i) {
		if (*i == mm)
			return true;
	}

	return false;
}


bool StagedDeviceFilter::check_devno(__u32 mm, ConfigReader &cfg, int *rc)
{
	if (m_devnos.size() == 0)
		return true;

	__u32	devno = cfg.get_devno_by_mm_internal(mm, rc);
	for (list<__u32>::const_iterator i = m_devnos.begin();
	      i != m_devnos.end(); ++i) {
		if (*i == devno)
			return true;
	}

	return false;
}


bool StagedDeviceFilter::check_chpid(__u32 mm, ConfigReader &cfg, int *rc)
{
	if (m_chpids.size() == 0)
		return true;

	__u32	chpid = cfg.get_chpid_by_mm_internal(mm, rc);
	for (list<__u32>::const_iterator i = m_chpids.begin();
	      i != m_chpids.end(); ++i) {
		if (*i == chpid)
			return true;
	}

	return false;
}


bool StagedDeviceFilter::check_mp_device(__u32 mm, ConfigReader &cfg, int *rc)
{
	if (m_mp_mms.size() == 0)
		return true;

	__u32 mp = cfg.get_mp_mm_by_mm_internal(mm, rc);
	assert(mp);
	for (list<__u32>::const_iterator i = m_mp_mms.begin();
	      i != m_mp_mms.end(); ++i) {
		if (*i == mp)
			return true;
	}

	return false;
}


int StagedDeviceFilter::finish(ConfigReader &cfg, bool intersect)
{
	int rc = 0;
	list<__u32> mm_lst;

	if (intersect) {
		bool found_something = false;
		cfg.get_unique_mms(mm_lst);
		for (list<__u32>::const_iterator i = mm_lst.begin();
		      i != mm_lst.end(); ++i) {
			if (   check_chpid(*i, cfg, &rc)
			    && check_mp_device(*i, cfg, &rc)
			    && check_devno(*i, cfg, &rc)
			    && check_wwpn(*i, cfg, &rc)
			    && check_mm(*i)) {
				found_something = true;
				add_mm_with_host(cfg, *i, &rc);
			}
		}
		if (!rc && !found_something)
			rc = 1;
	}
	else {
		for (list<__u64>::const_iterator i = m_wwpns.begin();
		      i != m_wwpns.end(); ++i) {
			cfg.get_mms_by_wwpn(mm_lst, *i);
			add_mms_with_host(cfg, mm_lst, &rc);
		}
		for (list<__u32>::const_iterator i = m_mp_mms.begin();
		      i != m_mp_mms.end(); ++i) {
			cfg.get_mms_by_mp_mm(mm_lst, *i);
			add_mms_with_host(cfg, mm_lst, &rc);
		}
		for (list<__u32>::const_iterator i = m_devnos.begin();
		      i != m_devnos.end(); ++i) {
			cfg.get_mms_by_devno(mm_lst, *i);
			add_mms_with_host(cfg, mm_lst, &rc);
		}
		for (list<__u32>::const_iterator i = m_chpids.begin();
		      i != m_chpids.end(); ++i) {
			cfg.get_mms_by_chpid(mm_lst, *i);
			add_mms_with_host(cfg, mm_lst, &rc);
		}
	}

	return rc;
}


