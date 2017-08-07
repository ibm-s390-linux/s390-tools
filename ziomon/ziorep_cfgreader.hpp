/*
 * FCP report generators
 *
 * Utility classes to read and access FCP configuration information
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZIOMON_CFGREADER
#define ZIOMON_CFGREADER

#include <stdio.h>
#include <list>

#include <linux/types.h>

extern "C" {
	#include "ziomon_util.h"
}



using std::list;


/**
 * Parses a file holding the system-wide available devices. Since this
 * is more than what is in the data, the devices are filtered, stripping
 * it down to devices only actually used in the data.
 */
class ConfigReader {
public:
	ConfigReader(int *rc, const char *filename);
	~ConfigReader();

	/// rc is only set on error!
	__u32 get_chpid_by_host_id(__u32 h, int *rc) const;
	/// rc is only set on error!
	__u32 get_chpid_by_devno(__u32 devno, int *rc) const;
	/// rc is only set on error!
	__u32 get_chpid_by_ident(const struct hctl_ident *ident, int *rc) const;
	/// rc is only set on error!
	__u32 get_chpid_by_mm_internal(__u32 mm, int *rc) const;

	/// rc is only set on error!
	__u32 get_host_id_by_chpid(__u32 chpid, int *rc) const;

	/// rc is only set on error!
	__u32 get_devno_by_host_id(__u32 h, int *rc) const;
	/// rc is only set on error!
	__u32 get_devno_by_ident(const struct hctl_ident *ident, int *rc) const;

	/// rc is only set on error!
	__u32 get_devno_by_mm_internal(__u32 mm, int *rc) const;

	/// rc is only set on error!
	__u32 get_mp_mm_by_multipath(const char* mp, int *rc) const;
	/// rc is only set on error!
	const char* get_multipath_by_mp_mm(__u32 mp_mm, int *rc) const;

	/// rc is only set on error!
	__u64 get_wwpn_by_ident(const struct hctl_ident *ident, int *rc) const;
	/// rc is only set on error!
	__u64 get_wwpn_by_mm_internal(__u32 mm, int *rc) const;

	/// rc is only set on error!
	__u32 get_mp_mm_by_ident(const struct hctl_ident *ident, int *rc) const;
	/// rc is only set on error!
	__u32 get_mp_mm_by_mm_internal(__u32 mm, int *rc) const;

	/// rc is only set on error!
	__u64 get_lun_by_mm_internal(__u32 mm_internal, int *rc) const;

	/// rc is only set on error!
	const char* get_dev_by_mm_internal(__u32 mm_internal, int *rc) const;

	/// rc is only set on error!
	__u32 get_mm_by_ident(const struct hctl_ident *id, int *rc) const;

	/// rc is only set on error!
	__u32 get_mm_by_device(const char *dev, int *rc) const;

	/// rc is only set on error!
	const struct hctl_ident* get_ident_by_mm_internal(__u32 mm, int *rc) const;

	void get_unique_wwpns(list<__u64> &lst) const;

	void get_unique_devnos(list<__u32> &lst) const;

	void get_unique_chpids(list<__u32> &lst) const;

	void get_unique_mp_mms(list<__u32> &lst) const;

	void get_unique_mms(list<__u32> &mms) const;

	void get_unique_devices(list<struct hctl_ident> &idents) const;

	void get_unique_host_ids(list<__u32> &host_ids) const;

	void get_devnos_by_chpid(list<__u32> &devnos, __u32 chpid) const;

	void get_devnos_by_host_id(list<__u32> &devnos, __u32 host_id) const;

	void get_mms_by_chpid(list<__u32> &mms, __u32 chpid) const;

	void get_mms_by_mp_mm(list<__u32> &mms, __u32 mp_mm) const;

	void get_mms_by_wwpn(list<__u32> &mms, __u64 wwpn) const;

	void get_mms_by_devno(list<__u32> &mms, __u32 devno) const;

	void get_mms_by_lun(list<__u32> &mms, __u64 lun) const;

	/// returns 'true' in case it exists, 'false' otherwise
	bool verify_chpid(__u32 chpid) const;

	/// returns 'true' in case it exists, 'false' otherwise
	bool verify_device(const char *) const;

	/// returns 'true' in case it exists, 'false' otherwise
	bool verify_mp_device(const char *) const;

	/// returns 'true' in case it exists, 'false' otherwise
	bool verify_wwpn(__u64 wwpn) const;

	/// returns 'true' in case it exists, 'false' otherwise
	bool verify_devno(__u32 devno) const;

	/// returns 'true' in case it exists, 'false' otherwise
	bool verify_lun(__u64 lun) const;

	/// debugging
	void dump(FILE *fp) const;

private:
	/** compare currently held devices with devices as found
	 * in the actual data, and remove anything that is unused */
	int filter_unused_devices(const char *filename);

	int check_config_file(const char *fname) const;

	int extract_config_data(const char *fname);

	int extract(const char *fname);

	int extract_tmp(const char *fname);

	int extract_cached(const char *fname);

	bool cached_config_exists(const char *fname);

	struct device_info {
		// chpid, e.g. 43 (hex)
		__u32	chpid;

		// kernel-internal major/minor representation, e.g. 2096 (number)
		__u32	mm_internal;

		// fcp device identifier, e.g. 0:0:17:1075920929
		struct hctl_ident	hctl_identifier;

		// subchannel bus-ID and device bus-ID are packed into 32 bits:
		// channel subsystem (1 byte), subchannel set (1 byte),
		// subchannel or device number (2 bytes)
		// use accessors ZIOREP_BUSID_PACKED and ZIOREP_BUSID_UNPACKED
		__u32	subchannel;
		__u32	devno;
		__u64	wwpn;
		__u64	lun;

		// multipath device, e.g. /dev/mapper/2376878489249234
		char   *multipath_device;

		// maj/min of multipath device, e.g. 0:0
		__u32	mp_major;
		__u32	mp_minor;

		__u32	mp_mm;	// NOT IN INPUT-DATA!!!

		// device node, e.g. /dev/sda
		char   *device;

		// major/minor, e.g. 8:48
		__u32	major;
		__u32	minor;

		// device type, e.g. "Disk"
		char   *type;
	};
	list<struct device_info>	m_devices;

	/**
	 * File holding the internal representation of the configuration
	 * data. If m_cfg_cached is false, then it must be removed once
	 * we are done. Otherwise we can leave as is for successive runs. */
	char 			       *m_tmp_file;

	/**
	 * If this is set, then we didn't extract the configuration data to
	 * /tmp but rather created an additional .config file which we leave
	 * for successive runs. */
	bool				m_cfg_cached;

	/**
	 * Returns the offset of the first appearance of 'c'
	 * within p. */
	int get_index_to(char *p, char c) const;

	void init_device_info(struct device_info *info);

	void free_device_info(struct device_info *info);

	int extract_adapter_info(char *p, struct device_info *info);

	int extract_adapter_info_sub(char **tgt, char *p, char delim);

	void host_id_not_found_error(__u32 h, int *rc) const;

	void devno_not_found_error(__u32 d, int *rc) const;

	void chpid_not_found_error(__u32 chpid, int *rc) const;

	void lun_not_found_error(__u64 lun, int *rc) const;

	void ident_not_found_error(const struct hctl_ident *ident, int *rc) const;

	void mm_internal_not_found_error(__u32 mm, int *rc) const;

	void device_not_found_error(const char*, int *rc) const;

	void mp_not_found_error(const char* mp, int *rc) const;

	void mp_mm_not_found_error(__u32 mp_mm, int *rc) const;
};


#endif

