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

#ifndef ZIOREP_FILTERS
#define ZIOREP_FILTERS

#include <list>
#include <set>


#include "ziorep_cfgreader.hpp"


using std::list;
using std::set;

extern "C" {
#include "blkiomon.h"
#include "ziomon_zfcpdd.h"
}


enum MsgTypes {
	utilization,
	ioerr,
	blkiomon,
	zfcpdd
};


class MsgFilter {
protected:
	virtual ~MsgFilter();

	MsgFilter();

public:
	/** Returns 'true' if the message should be kept,
	 * 'false' in case it should be filtered
	 */
	virtual bool is_eligible(const struct message_preview *msg) const = 0;

	/** Returns 'true' if the message should be kept,
	 * 'false' in case it should be filtered
	 */
	virtual bool is_eligible(const struct message *msg) const = 0;
};


class MsgTypeFilter : public MsgFilter {
public:
	virtual ~MsgTypeFilter();

	MsgTypeFilter();

	/// add type that should be kept
	void add_type(__u32 type);

	virtual bool is_eligible(const struct message_preview *msg) const;

	virtual bool is_eligible(const struct message *msg) const;

private:
	bool is_eligible(__u32 type) const;

	/// types to keep
	set<__u32>	m_types;
};


class MsgTimeFilter : public MsgFilter {
public:
	virtual ~MsgTimeFilter();

	/// add type that should be kept
	MsgTimeFilter(__u64 begin, __u64 end);

	virtual bool is_eligible(const struct message_preview *msg) const;

	/**
	 * NOTE: Message must be in native endianness! */
	virtual bool is_eligible(const struct message *msg) const;

	__u64	get_begin_time() const;
	__u64	get_end_time() const;

private:
	bool is_eligible(__u64 timestamp) const;

	__u64		m_begin;
	__u64		m_end;
};


/**
 * Class to filter messages by the device they refer to, where
 * the device can be of any type.
 */
class DeviceFilter {
public:
	void add_device(__u32 device, const struct hctl_ident *id);

	const list<__u32>& get_host_id_list() const;
	const list<__u32>& get_mm_list() const;

	/** Returns 'true' if the message should be kept,
	 * 'false' in case it should be filtered
	 */
	bool is_eligible(const message *msg, const struct file_header *hdr) const;
	bool is_eligible(const struct adapter_utilization *res) const;
	bool is_eligible(const struct ioerr_cnt *cnt) const;

	bool is_eligible_mm(__u32 mm) const;
	bool is_eligible_ident(const struct hctl_ident *ident) const;
	bool is_eligible_host_id(__u32 host) const;

	/** Returns a list of all chpids that are eligible according to
	 * the filter criteria. */
	void get_eligible_chpids(ConfigReader &cfg, list<__u32> &lst) const;

	/** Returns a list of all devnos that are eligible according to
	 * the filter criteria. */
	void get_eligible_devnos(ConfigReader &cfg, list<__u32> &lst) const;

	/** Returns a list of all wwpns that are eligible according to
	 * the filter criteria. */
	void get_eligible_wwpns(ConfigReader &cfg, list<__u64> &lst) const;

	/** Returns a list of all mp_mms that are eligible according to
	 * the filter criteria. */
	void get_eligible_mp_mms(ConfigReader &cfg, list<__u32> &lst) const;

protected:
	void add_host(__u32 host_id);
	/// ascending list of devices to keep - in sync with m_idents
	list<__u32>			m_devices;

private:
	void add_device(__u32 device);
	void add_device(const struct hctl_ident *id);

	/// ascending list of HBAs to keep
	list<__u32>			m_host_ids;
	/// ascending list of devices to keep - in sync with m_devices
	list<struct hctl_ident>		m_idents;
};

/**
 * Special kind of DeviceFilter: Add all criteria to it and finally
 * decide whether devices should be filtered by (a) either criterion
 * or (b) only the intersection of the criteria.
 * Internally, we store all submitted data in separate structures. When
 * the user hits 'finished', the data will be analyzed and transferred to
 * the base class.
 */
class StagedDeviceFilter : public DeviceFilter {
public:
	void stage_wwpn(__u64 wwpn);
	void stage_mp_mm(__u32 mp_mm);
	void stage_devno(__u32 sub);
	void stage_chpid(__u32 chpid);

	/**
	  * retrieve an ordered list of the wwpns as they were specified
	  * for filtering. */
	const list<__u64>& get_filter_wwpns();
	/**
	  * retrieve an ordered list of the chpids as they were specified
	  * for filtering. */
	const list<__u32>& get_filter_chpids();
	/**
	  * retrieve an ordered list of the devnos as they were specified
	  * for filtering. */
	const list<__u32>& get_filter_devnos();
	/**
	  * retrieve an ordered list of the mp_mms as they were specified
	  * for filtering. */
	const list<__u32>& get_filter_mp_mms();

	/**
	 * Call this method prior to actually using the class.
	 * If 'intersect' is enabled, a positive return code indicates
	 * that the intersection is empty. <0 means error, 0 in success.
	 */
	int finish(ConfigReader &cfg, bool intersect);

private:
	void add_mm_with_host(ConfigReader &cfg, __u32 mm, int *rc);
	void add_mms_with_host(ConfigReader &cfg, list<__u32> &mms, int *rc);
	/// check if 'mm's wwpn is eligible
	bool check_wwpn(__u32 mm, ConfigReader &cfg, int *rc);
	/// check if 'mm' is eligible
	bool check_mm(__u32 mm);
	/// check if 'mm's devo is eligible
	bool check_devno(__u32 mm, ConfigReader &cfg, int *rc);
	/// check if 'mm's chpid is eligible
	bool check_chpid(__u32 mm, ConfigReader &cfg, int *rc);
	/// check if 'mm's mp is eligible
	bool check_mp_device(__u32 mm, ConfigReader &cfg, int *rc);

	list<__u64>		m_wwpns;
	list<__u32>		m_devnos;
	list<__u32>		m_chpids;
	list<__u32>		m_mp_mms;
};

#endif

