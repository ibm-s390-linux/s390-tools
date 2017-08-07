/*
 * FCP report generators
 *
 * Utility classes to get indices for collapsing data by
 * variable criteria
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>
#include <assert.h>

#include "ziorep_collapser.hpp"

extern "C" {
	#include "lib/zt_common.h"
	#include "ziomon_tools.h"
}

extern const char *toolname;
extern int verbose;


Collapser::Collapser(Aggregator criterion)
: m_criterion(criterion) {
}


Collapser::~Collapser()
{
}


Aggregator Collapser::get_criterion() const
{
	return m_criterion;
}


void Collapser::add_to_index(struct ident_mapping *new_mapping) const
{
	list<struct ident_mapping>::iterator i;

	for (i = m_idents.begin(); i != m_idents.end()
	      && compare_hctl_idents(&new_mapping->ident, &(*i).ident) >= 0;
	      ++i) ;
	if (i == m_idents.end() || compare_hctl_idents(&new_mapping->ident, &(*i).ident) != 0)
		m_idents.insert(i, *new_mapping);
}


void Collapser::add_to_index(struct device_mapping *new_mapping) const
{
	list<struct device_mapping>::iterator i;

	for (i = m_devices.begin(); i != m_devices.end()
	      && new_mapping->device >= (*i).device;
	      ++i) ;
	if (i == m_devices.end() || (*i).device != new_mapping->device)
		m_devices.insert(i, *new_mapping);
}


void Collapser::add_to_index(struct host_id_mapping *new_mapping) const
{
	list<struct host_id_mapping>::iterator i;

	for (i = m_host_ids.begin(); i != m_host_ids.end()
	      && new_mapping->h >= (*i).h;
	      ++i) ;
	if (i == m_host_ids.end() || (*i).h != new_mapping->h)
		m_host_ids.insert(i, *new_mapping);
}


int Collapser::lookup_index(struct hctl_ident *identifier) const
{
	int rc;

	for (list<struct ident_mapping>::const_iterator i = m_idents.begin();
	      i != m_idents.end() && (rc = compare_hctl_idents(identifier, &(*i).ident)) >= 0; ++i ) {
		if (rc == 0)
			return (*i).idx;
	}

	return -1;
}


int Collapser::lookup_index(__u32 device) const
{
	for (list<struct device_mapping>::const_iterator i = m_devices.begin();
	      i != m_devices.end() && device >= (*i).device; ++i ) {
		if ((*i).device == device)
			return (*i).idx;
	}

	return -1;
}


int Collapser::lookup_index_by_host_id(__u32 h) const
{
	for (list<struct host_id_mapping>::const_iterator i = m_host_ids.begin();
	      i != m_host_ids.end() && h >= (*i).h; ++i ) {
		if ((*i).h == h)
			return (*i).idx;
	}

	return -1;
}


NoopCollapser::NoopCollapser()
: Collapser(none) {
	m_criterion = none;
}


unsigned int NoopCollapser::get_index(struct hctl_ident *identifier) const
{
	int rc;

	rc = lookup_index(identifier);
	if (rc < 0) {
		struct ident_mapping new_mapping;
		new_mapping.ident = *identifier;
		new_mapping.idx   = m_idents.size();
		add_to_index(&new_mapping);
		rc = new_mapping.idx;
	}

	return rc;
}


unsigned int NoopCollapser::get_index(__u32 device) const
{
	int rc;

	rc = lookup_index(device);
	if (rc < 0) {
		struct device_mapping new_mapping;
		new_mapping.device = device;
		new_mapping.idx    = m_devices.size();
		add_to_index(&new_mapping);
		rc = new_mapping.idx;
	}

	return rc;
}



unsigned int NoopCollapser::get_index_by_host_id(__u32 h) const
{
	int rc;

	rc = lookup_index_by_host_id(h);
	if (rc < 0) {
		struct host_id_mapping new_mapping;
		new_mapping.h	= h;
		new_mapping.idx	= m_host_ids.size();
		add_to_index(&new_mapping);
		rc = new_mapping.idx;
	}

	return rc;
}


TotalCollapser::TotalCollapser()
: Collapser(all)
{
}


unsigned int TotalCollapser::get_index(struct hctl_ident* UNUSED(identifier)) const
{
	return 0;
}


unsigned int TotalCollapser::get_index(__u32 UNUSED(device)) const
{
	return 0;
}


unsigned int TotalCollapser::get_index_by_host_id(__u32 UNUSED(h)) const
{
	return 0;
}


AggregationCollapser::AggregationCollapser(ConfigReader &cfg,
		     Aggregator &criterion, DeviceFilter &dev_filt, int *rc)
: Collapser(criterion)
{
	*rc = 0;
	/*
	 * setup everything so we won't ever have a miss when looking up
	 */
	verbose_msg("AggregationCollapser initializing\n");

	switch(m_criterion) {
	case chpid:
		setup_by_chpid(cfg, dev_filt);
		break;
	case devno:
		setup_by_devno(cfg, dev_filt);
		break;
	case wwpn:
		setup_by_wwpn(cfg, dev_filt);
		break;
	case multipath_device:
		*rc = setup_by_multipath(cfg, dev_filt);
		break;
	default:
		assert(false);
	}

	verbose_msg("AggregationCollapser type %d constructed, mapping by:\n", m_criterion);
	verbose_msg("    %zu host ids\n", m_host_ids.size());
	verbose_msg("    %zu hctl devices\n", m_idents.size());
	verbose_msg("    %zu devices\n", m_devices.size());
}


int AggregationCollapser::get_index_u32(list<__u32> &lst, __u32 chpid)
{
	int idx = 0;

	for (list<__u32>::const_iterator i = lst.begin();
	      i != lst.end(); ++i, ++idx) {
		if (chpid == *i)
			return idx;
	}

	return -1;
}


int AggregationCollapser::get_index_u64(list<__u64> &lst, __u64 chpid)
{
	int idx = 0;

	for (list<__u64>::const_iterator i = lst.begin();
	      i != lst.end(); ++i, ++idx) {
		if (chpid == *i)
			return idx;
	}

	return -1;
}


void AggregationCollapser::setup_by_chpid(ConfigReader &cfg,
					  DeviceFilter &dev_filt)
{
	list<__u32>			mms;
	list<struct hctl_ident>		idents;
	list<__u32>			host_ids;
	struct host_id_mapping		host_id_mapping;
	struct device_mapping		dev_mapping;
	struct ident_mapping		ide_mapping;
	__u32				chpid;
	int				rc = 0;

	// this is our master list for collapsing
	dev_filt.get_eligible_chpids(cfg, m_reference_values_u32);

	cfg.get_unique_mms(mms);
	for (list<__u32>::const_iterator i = mms.begin();
	      i != mms.end(); ++i) {
		if (!dev_filt.is_eligible_mm(*i))
			continue;
		dev_mapping.device = *i;
		dev_mapping.idx = -1;
		chpid = cfg.get_chpid_by_mm_internal(*i, &rc);
		assert(rc == 0);
		dev_mapping.idx = get_index_u32(m_reference_values_u32, chpid);
		assert(dev_mapping.idx >= 0);
		add_to_index(&dev_mapping);
		vverbose_msg("    map mm %d to chpid %x (index %d)\n", *i,
			     chpid, dev_mapping.idx);
	}

	cfg.get_unique_host_ids(host_ids);
	for (list<__u32>::const_iterator i = host_ids.begin();
	      i != host_ids.end(); ++i) {
		if (!dev_filt.is_eligible_host_id(*i))
			continue;
		host_id_mapping.h = *i;
		host_id_mapping.idx = -1;
		chpid = cfg.get_chpid_by_host_id(*i, &rc);
		assert(rc == 0);
		host_id_mapping.idx = get_index_u32(m_reference_values_u32,
						    chpid);
		assert(host_id_mapping.idx >= 0);
		add_to_index(&host_id_mapping);
		vverbose_msg("    map host id %d to chpid %x (index %d)\n", *i,
			     chpid, host_id_mapping.idx);
	}

	cfg.get_unique_devices(idents);
	for (list<struct hctl_ident>::iterator i = idents.begin();
	      i != idents.end(); ++i) {
		if (!dev_filt.is_eligible_ident(&(*i)))
			continue;
		ide_mapping.ident = *i;
		ide_mapping.idx = -1;
		chpid = cfg.get_chpid_by_ident(&(*i), &rc);
		assert(rc == 0);
		ide_mapping.idx = get_index_u32(m_reference_values_u32, chpid);
		assert(ide_mapping.idx >= 0);
		add_to_index(&ide_mapping);
		vverbose_msg("    map device [%d:%d:%d:%d] to chpid %x (index %d)\n",
			    (*i).host, (*i).channel, (*i).target, (*i).lun,
			    chpid, ide_mapping.idx);
	}
}


void AggregationCollapser::setup_by_devno(ConfigReader &cfg,
					  DeviceFilter &dev_filt)
{
	list<__u32>			mms;
	list<struct hctl_ident>		idents;
	list<__u32>			host_ids;
	struct host_id_mapping		host_id_mapping;
	struct device_mapping		dev_mapping;
	struct ident_mapping		ide_mapping;
	__u32				devno;
	int				rc = 0;

	/* this is our master list for collapsing
	*/
	dev_filt.get_eligible_devnos(cfg, m_reference_values_u32);

	cfg.get_unique_mms(mms);
	for (list<__u32>::const_iterator i = mms.begin();
	      i != mms.end(); ++i) {
		if (!dev_filt.is_eligible_mm(*i))
			continue;
		dev_mapping.device = *i;
		dev_mapping.idx = -1;
		devno = cfg.get_devno_by_mm_internal(*i, &rc);
		assert(rc == 0);
		dev_mapping.idx = get_index_u32(m_reference_values_u32, devno);
		assert(dev_mapping.idx >= 0);
		add_to_index(&dev_mapping);
		vverbose_msg("    map mm %d to bus id %x.%x.%04x (index %d)\n", *i,
			     ZIOREP_BUSID_UNPACKED(devno), dev_mapping.idx);
	}

	cfg.get_unique_host_ids(host_ids);
	for (list<__u32>::const_iterator i = host_ids.begin();
	      i != host_ids.end(); ++i) {
		if (!dev_filt.is_eligible_host_id(*i))
			continue;
		host_id_mapping.h = *i;
		host_id_mapping.idx = -1;
		devno = cfg.get_devno_by_host_id(*i, &rc);
		assert(rc == 0);
		host_id_mapping.idx = get_index_u32(m_reference_values_u32,
						    devno);
		assert(host_id_mapping.idx >= 0);
		add_to_index(&host_id_mapping);
		vverbose_msg("    map host id %d to bus id %x.%x.%04x"
			     " (index %d)\n", *i, ZIOREP_BUSID_UNPACKED(devno),
			     host_id_mapping.idx);
	}

	cfg.get_unique_devices(idents);
	for (list<struct hctl_ident>::iterator i = idents.begin();
	      i != idents.end(); ++i) {
		if (!dev_filt.is_eligible_ident(&(*i)))
			continue;
		ide_mapping.ident = *i;
		ide_mapping.idx = -1;
		devno = cfg.get_devno_by_ident(&(*i), &rc);
		assert(rc == 0);
		ide_mapping.idx = get_index_u32(m_reference_values_u32, devno);
		assert(ide_mapping.idx >= 0);
		add_to_index(&ide_mapping);
		vverbose_msg("    map device [%d:%d:%d:%d] to bus id %x.%x.%04x"
			     " (index %d)\n",
			    (*i).host, (*i).channel, (*i).target, (*i).lun,
			    ZIOREP_BUSID_UNPACKED(devno), ide_mapping.idx);
	}
}


void AggregationCollapser::setup_by_wwpn(ConfigReader &cfg,
					 DeviceFilter &dev_filt)
{
	list<__u32>			mms;
	list<struct hctl_ident>		idents;
	struct device_mapping		dev_mapping;
	struct ident_mapping		ide_mapping;
	__u64				wwpn;
	int				rc = 0;

	// this is our master list for collapsing
	dev_filt.get_eligible_wwpns(cfg, m_reference_values_u64);

	cfg.get_unique_mms(mms);
	for (list<__u32>::const_iterator i = mms.begin();
	      i != mms.end(); ++i) {
		if (!dev_filt.is_eligible_mm(*i))
			continue;
		dev_mapping.device = *i;
		dev_mapping.idx = -1;
		wwpn = cfg.get_wwpn_by_mm_internal(*i, &rc);
		assert(rc == 0);
		dev_mapping.idx = get_index_u64(m_reference_values_u64, wwpn);
		assert(dev_mapping.idx >= 0);
		add_to_index(&dev_mapping);
		vverbose_msg("    map mm %d to wwpn %016Lx (index %d)\n", *i,
			     (long long unsigned int)wwpn, dev_mapping.idx);
	}

	cfg.get_unique_devices(idents);
	for (list<struct hctl_ident>::iterator i = idents.begin();
	      i != idents.end(); ++i) {
		if (!dev_filt.is_eligible_ident(&(*i)))
			continue;
		ide_mapping.ident = *i;
		ide_mapping.idx = -1;
		wwpn = cfg.get_wwpn_by_ident(&(*i), &rc);
		assert(rc == 0);
		ide_mapping.idx = get_index_u64(m_reference_values_u64, wwpn);
		assert(ide_mapping.idx >= 0);
		add_to_index(&ide_mapping);
		vverbose_msg("    map device [%d:%d:%d:%d] to wwpn %016Lx"
			     " (index %d)\n",
			    (*i).host, (*i).channel, (*i).target, (*i).lun,
			    (long long unsigned int)wwpn, ide_mapping.idx);
	}
}


int AggregationCollapser::setup_by_multipath(ConfigReader &cfg,
					     DeviceFilter &dev_filt)
{
	list<__u32>			mms;
	list<struct hctl_ident>		idents;
	struct device_mapping		dev_mapping;
	struct ident_mapping		ide_mapping;
	__u32			        mp_mm;
	int				rc = 0, grc = 0;

	// this is our master list for collapsing
	dev_filt.get_eligible_mp_mms(cfg, m_reference_values_u32);

	if (m_reference_values_u32.size() == 0) {
		fprintf(stderr, "%s: No multipath devices in configuration"
			" found. Aggregation by multipath devices not"
			" possible with this data.\n", toolname);
		return -1;
	}

	cfg.get_unique_mms(mms);
	for (list<__u32>::const_iterator i = mms.begin();
	      i != mms.end(); ++i) {
		if (!dev_filt.is_eligible_mm(*i))
			continue;
		dev_mapping.device = *i;
		dev_mapping.idx = -1;
		mp_mm = cfg.get_mp_mm_by_mm_internal(*i, &rc);
		if (mp_mm == 0) {
			fprintf(stderr, "%s: Device %s is not in a multipath "
				"group. Please remove via command line options "
				"and try again.\n", toolname, cfg.get_dev_by_mm_internal(*i, &rc));
			grc = -1;
			continue;
		}
		dev_mapping.idx = get_index_u32(m_reference_values_u32, mp_mm);
		assert(dev_mapping.idx >= 0);
		add_to_index(&dev_mapping);
		vverbose_msg("    map mm %d to mp_mm %x (index %d)\n", *i,
			     mp_mm, dev_mapping.idx);
	}
	if (grc)
		return grc;

	cfg.get_unique_devices(idents);
	for (list<struct hctl_ident>::iterator i = idents.begin();
	      i != idents.end(); ++i) {
		if (!dev_filt.is_eligible_ident(&(*i)))
			continue;
		ide_mapping.ident = *i;
		ide_mapping.idx = -1;
		mp_mm = cfg.get_mp_mm_by_ident(&(*i), &rc);
		assert(rc == 0);
		ide_mapping.idx = get_index_u32(m_reference_values_u32, mp_mm);
		assert(ide_mapping.idx >= 0);
		add_to_index(&ide_mapping);
		vverbose_msg("    map device [%d:%d:%d:%d] to mp_mm %x"
			     " (index %d)\n",
			     (*i).host, (*i).channel, (*i).target, (*i).lun,
			     mp_mm, ide_mapping.idx);
	}

	return grc;
}


unsigned int AggregationCollapser::get_index(struct hctl_ident *identifier) const
{
	int rc = lookup_index(identifier);

	assert(rc >= 0);

	return rc;
}


unsigned int AggregationCollapser::get_index(__u32 device) const
{
	int rc = lookup_index(device);

	assert(rc >= 0);

	return rc;
}


unsigned int AggregationCollapser::get_index_by_host_id(__u32 h) const
{
	int rc;

	// since a host_id can host multiple wwpns and multipath devices,
	// no mapping is possible in these cases.
	assert(m_criterion != wwpn);
	assert(m_criterion != multipath_device);

	rc = lookup_index_by_host_id(h);

	assert(rc >= 0);

	return rc;
}


const list<__u32>& AggregationCollapser::get_reference_chpids() const
{
	return m_reference_values_u32;
}


const list<__u64>& AggregationCollapser::get_reference_wwpns() const
{
	return m_reference_values_u64;
}


const list<__u32>& AggregationCollapser::get_reference_devnos() const
{
	return m_reference_values_u32;
}


const list<__u32>& AggregationCollapser::get_reference_mp_mms() const
{
	return m_reference_values_u32;
}



