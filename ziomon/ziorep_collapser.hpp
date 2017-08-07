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

#ifndef ZIOMON_COLLAPSER
#define ZIOMON_COLLAPSER

#include <list>

#include <linux/types.h>

#include "ziorep_cfgreader.hpp"
#include "ziorep_filters.hpp"

using std::list;


enum Aggregator {
	none,
	chpid,
	devno,
	wwpn,
	multipath_device,
	all
};


/**
 * A collapser is basically a mapper that maps a given device to an index.
 * The interesting part is the AggregationCollapser, which maps devices that
 * share a certain property to the same index.
 * NOTE: There is no guarantee that all indices will be used! E.g. the first
 * index received might be 0, but the next one could be 5. In that case, it is
 * the caller's responsibility to make sure that indices 1 to 4 are handled
 * appropriately.
 */
class Collapser {
public:
	Collapser(Aggregator criterion);
	virtual ~Collapser();

	/// get index by device identifier
	virtual unsigned int get_index(struct hctl_ident *identifier) const = 0;

	/// get index by major/minor
	virtual unsigned int get_index(__u32 device) const = 0;

	/// get index by host_id
	virtual unsigned int get_index_by_host_id(__u32 h) const = 0;

	Aggregator get_criterion() const;

protected:
	struct host_id_mapping {
		__u32		h;
		int		idx;
	};
	struct device_mapping {
		__u32		device;
		int		idx;
	};
	struct ident_mapping {
		struct hctl_ident	ident;
		int			idx;
	};
	/// Lookup list for matching a host id to an index, sorted ascending
	mutable list<struct host_id_mapping>	m_host_ids;

	/// Lookup list for matching a device to an index, sorted ascending
	mutable list<struct device_mapping>	m_devices;

	/// Lookup list for matching an identifier to an index, sorted ascending
	mutable list<struct ident_mapping>	m_idents;

	/// add entry, skips duplicates.
	void add_to_index(struct ident_mapping *new_mapping) const;

	/// add entry, skips duplicates.
	void add_to_index(struct device_mapping *new_mapping) const;

	/// add entry, skips duplicates.
	void add_to_index(struct host_id_mapping *new_mapping) const;

	/// search for device, returns <0 if not found
	int lookup_index(struct hctl_ident *identifier) const;

	/// search for device, returns <0 if not found
	int lookup_index(__u32 device) const;

	/// search for device, returns <0 if not found
	int lookup_index_by_host_id(__u32 h) const;

	Aggregator			m_criterion;
};

/**
 * Collapser that doesn't do any collapsing (ooops) - it merely assigns
 * an individual index to each device.
 */
class NoopCollapser : public Collapser {
public:
	NoopCollapser();

	virtual unsigned int get_index(struct hctl_ident *identifier) const;

	virtual unsigned int get_index(__u32 device) const;

	virtual unsigned int get_index_by_host_id(__u32 h) const;
};


/**
 * Collapser that collapses everything into a single element. That is,
 * all devices will be mapped to the same index of 0.
 */
class TotalCollapser : public Collapser {
public:
	TotalCollapser();

	virtual unsigned int get_index(struct hctl_ident *identifier) const;

	virtual unsigned int get_index(__u32 device) const;

	virtual unsigned int get_index_by_host_id(__u32 h) const;
};


/**
 * Collapser that collapses by a given criterion. For instance, if the
 * criterion used is wwpn, then all devices that have the same wwpn will
 * be matched to the same index.
 */
class AggregationCollapser : public Collapser {
public:
	/**
	 * 'filt' must hold all available devices */
	AggregationCollapser(ConfigReader &cfg,
			     Aggregator &criterion,
			     DeviceFilter &dev_filt,
			     int *rc);

	virtual unsigned int get_index(struct hctl_ident *identifier) const;
	virtual unsigned int get_index(__u32 device) const;
	virtual unsigned int get_index_by_host_id(__u32 h) const;

	/// Reference chpids as used for collapsing.
	const list<__u32>& get_reference_chpids() const;

	/// Reference wwpns as used for collapsing.
	const list<__u64>& get_reference_wwpns() const;

	/// Reference devnos as used for collapsing.
	const list<__u32>& get_reference_devnos() const;

	/// Reference multipathes as used for collapsing.
	const list<__u32>& get_reference_mp_mms() const;

private:
	/** list of all unique __u32 values of the criterion we were
	  * collapsing by. */
	list<__u32>		m_reference_values_u32;
	list<__u64>		m_reference_values_u64;

	int get_index_u32(list<__u32> &lst, __u32 chpid);
	int get_index_u64(list<__u64> &lst, __u64 chpid);

	void setup_by_chpid(ConfigReader &cfg, DeviceFilter &dev_filt);
	void setup_by_devno(ConfigReader &cfg, DeviceFilter &dev_filt);
	void setup_by_wwpn(ConfigReader &cfg, DeviceFilter &dev_filt);
	int setup_by_multipath(ConfigReader &cfg, DeviceFilter &dev_filt);
};



#endif




