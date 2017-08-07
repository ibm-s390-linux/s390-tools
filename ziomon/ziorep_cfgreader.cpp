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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "ziorep_cfgreader.hpp"
#include "ziorep_filters.hpp"
#include "ziorep_utils.hpp"

#define	ZIOREP_CFG_EXTENSION	".cfg"
#define ZIOREP_CONFIG		"ziorep_config"

extern const char *toolname;
extern int verbose;


ConfigReader::ConfigReader(int *rc, const char *filename)
: m_tmp_file(NULL), m_cfg_cached(false)
{
	FILE			*fp = NULL;
	struct device_info	 new_elem;
	char			*line = NULL;
	size_t			 line_len;
	int			 lrc;
	int			 line_idx = 1;
	long long unsigned int	 tmp_lun;
	long long unsigned int	 tmp_wwpn;
	unsigned int		 subch1, subch2, subch3, devno1, devno2, devno3;

	*rc = 0;

	if (check_config_file(filename)) {
		*rc = -1;
		return;
	}

	if (extract_config_data(filename)) {
		*rc = -2;
		return;
	}

	init_device_info(&new_elem);

	verbose_msg("ConfigReader: reading from %s\n", m_tmp_file);

	fp = fopen(m_tmp_file, "r");
	if (!fp) {
		fprintf(stderr, "%s: Could not open config file %s\n", toolname, m_tmp_file);
		*rc = -1;
		goto out_fp_not_opened;
	}
	while ( (lrc = getline(&line, &line_len, fp)) >= 0) {
		// allocation could be improved...
		init_device_info(&new_elem);
		new_elem.device = (char*)malloc(lrc + 1);
		new_elem.type = (char*)malloc(lrc + 1);
		new_elem.multipath_device = (char*)malloc(lrc + 1);
		lrc = sscanf(line, "%x %u:%u:%u:%u %x.%x.%x:%x.%x.%x:%Lx:%Lx %s %u %u:%u %s %u %u:%u %s",
		       &new_elem.chpid,
		       &new_elem.hctl_identifier.host,
		       &new_elem.hctl_identifier.channel,
		       &new_elem.hctl_identifier.target,
		       &new_elem.hctl_identifier.lun,
		       &subch1, &subch2, &subch3,
		       &devno1, &devno2, &devno3,
		       &tmp_wwpn,
		       &tmp_lun,
		       new_elem.multipath_device, &new_elem.mp_mm,
		       &new_elem.mp_major,
		       &new_elem.mp_minor, new_elem.device,
		       &new_elem.mm_internal,
		       &new_elem.major, &new_elem.minor,
		       new_elem.type);
		free(line);
		line = NULL;
		if (lrc != 22) {
			fprintf(stderr, "%s: Could not parse line %d"
				" - configuration file broken?\n", toolname, line_idx);
			*rc = -1;
			goto out;
		}
		/* complete bus-IDs packed in u32 to avoid filter code changes */
		new_elem.subchannel = ZIOREP_BUSID_PACKED(subch1, subch2, subch3);
		new_elem.devno = ZIOREP_BUSID_PACKED(devno1, devno2, devno3);
		new_elem.wwpn = tmp_wwpn;
		new_elem.lun = tmp_lun;

		if (strcmp(new_elem.multipath_device, "n/a") == 0) {
			free(new_elem.multipath_device);
			new_elem.multipath_device = NULL;
			new_elem.mp_major = 0;
			new_elem.mp_minor = 0;
		}
		m_devices.push_back(new_elem);
		++line_idx;
	}
	init_device_info(&new_elem);

	if (filter_unused_devices(filename)) {
		*rc = -2;
		goto out;
	}

	verbose_msg("ConfigReader: done\n");

out:
	fclose(fp);
out_fp_not_opened:
	free_device_info(&new_elem);
	free(line);

	if (m_tmp_file) {
		if (!m_cfg_cached || *rc)
			remove(m_tmp_file);
		free(m_tmp_file);
		m_tmp_file = NULL;
	}
}


ConfigReader::~ConfigReader()
{
	for (list<struct device_info>::iterator i = m_devices.begin();
	      i != m_devices.end(); ++i)
		free_device_info(&(*i));
}


int ConfigReader::filter_unused_devices(const char *filename)
{
	DeviceFilter dev_filt;
        int j = 0;

	if (get_all_devices(filename, dev_filt, *this))
		return -1;

	for (list<struct device_info>::iterator i = m_devices.begin();
	      i != m_devices.end();) {
		if (!dev_filt.is_eligible_mm((*i).mm_internal)) {
			verbose_msg("  device %u:%u not in data, remove\n",
				    (*i).major, (*i).minor);
			free_device_info(&(*i));
			i = m_devices.erase(i);
			j++;
		}
		else
			++i;
	}
	verbose_msg("removed %d of %lu devices\n", j,
			(long unsigned int)(m_devices.size() + j));

	return 0;
}


int ConfigReader::check_config_file(const char *fname) const
{
	char *tmp;
	int rc = 0;

	tmp = (char*)malloc(strlen(fname) +  strlen(ZIOREP_CFG_EXTENSION) + 1);
	sprintf(tmp, "%s%s", fname, ZIOREP_CFG_EXTENSION);

	if (access(tmp, F_OK | R_OK)) {
		fprintf(stderr, "%s: Cannot access config file %s."
			" Please make sure that you get the matching .cfg"
			" file for your data.\n", toolname, tmp);
		rc = -1;
	}
	free(tmp);

	return rc;
}

#define ZIOREP_TMP_TEMPLATE	"/tmp/ziorepXXXXXX"
#define ZIOREP_CONFIG_EXT	".config"


int ConfigReader::extract_config_data(const char *fname)
{
	verbose_msg("Check config data...\n");
	if (cached_config_exists(fname)) {
		verbose_msg("Cached file found, reusing.\n");
		m_cfg_cached = true;
		return 0;
	}

	// Try to extract to .config first, which will be permanently cached
	verbose_msg("No data cached, extract\n");

	fprintf(stdout, "Extracting config data...");
	fflush(stdout);
	if (extract_cached(fname)) {
		verbose_msg("Could not create %s file, create tmp file\n",
			    ZIOREP_CONFIG_EXT);
		if (extract_tmp(fname)) {
			fprintf(stderr, "%s: Could not extract"
				" configuration data. Check the integrity of"
				" %s%s with %s and retry.\n", toolname, fname,
				ZIOREP_CFG_EXTENSION, ZIOREP_CONFIG);
			return -1;
		}
	}

	fprintf(stdout, "done\n");

	verbose_msg("Check config data finished\n");

	return 0;
}


int ConfigReader::extract_cached(const char *fname)
{
	assert(m_tmp_file == NULL);

	m_tmp_file = (char*)malloc(strlen(fname) + strlen(ZIOREP_CONFIG_EXT)
				   + 1);
	sprintf(m_tmp_file, "%s%s", fname, ZIOREP_CONFIG_EXT);

	if (extract(fname)) {
		// we can't guarantee that something was not written,
		// hence we remove the file anyway to avoid stumbling
		// over a broken .config file next time
		remove(m_tmp_file);
		free(m_tmp_file);
		m_tmp_file = NULL;
		return -1;
	}
	m_cfg_cached = true;

	return 0;
}


int ConfigReader::extract_tmp(const char *fname)
{
	int rc = 0;

	assert(m_tmp_file == NULL);

	m_tmp_file = (char*)malloc(strlen(ZIOREP_TMP_TEMPLATE) + 1);
	strcpy(m_tmp_file, ZIOREP_TMP_TEMPLATE);

	if (mkstemp(m_tmp_file) == -1) {
		fprintf(stdout, "Error: Could not create temporary"
			" filename: %s\n", strerror(errno));
		rc = -1;
		goto out;
	}

	rc = extract(fname);

out:
	if (rc) {
		free(m_tmp_file);
		m_tmp_file = NULL;
	}

	return rc;
}


int ConfigReader::extract(const char *fname)
{
	int rc = 0;
	char *cmd = NULL;

	// /sbin/ziorep_config -I -i <fname.cfg> > <file> 2>/dev/null
	cmd = (char*)malloc(strlen(ZIOREP_CONFIG) + 7 + strlen(fname)
		     + strlen(ZIOREP_CFG_EXTENSION) + 3 + strlen(m_tmp_file)
		     + 12 + 1);

	sprintf(cmd, "%s -I -i %s%s > %s 2>/dev/null", ZIOREP_CONFIG, fname,
		ZIOREP_CFG_EXTENSION, m_tmp_file);

	verbose_msg("Issue command: %s\n", cmd);

	if (system(cmd)) {
		rc = -1;
		goto out;
	}
	verbose_msg("Data extracted to %s\n", m_tmp_file);

out:
	free(cmd);
	return rc;
}


bool ConfigReader::cached_config_exists(const char *fname)
{
	int rc = true;

	m_tmp_file = (char*)malloc(strlen(fname) + strlen(ZIOREP_CONFIG_EXT)
				   + 1);
	sprintf(m_tmp_file, "%s%s", fname, ZIOREP_CONFIG_EXT);

	if (access(m_tmp_file, R_OK)) {
		verbose_msg("No cached file found.\n");
		free(m_tmp_file);
		m_tmp_file = NULL;
		rc = false;
	}

	return rc;
}


int ConfigReader::extract_adapter_info_sub(char **tgt, char *p, char delim)
{
	int offset;

	offset = get_index_to(p, delim);
	if (offset <=0)
		return -1;
	*tgt = (char*)malloc(offset + 1);
	strncpy(*tgt, p, offset);
	(*tgt)[offset] = '\0';

	return 0;
}


void ConfigReader::init_device_info(struct device_info *info)
{
	info->multipath_device = NULL;
	info->device = NULL;
	info->type = NULL;
}


void ConfigReader::free_device_info(struct device_info *info)
{
	free(info->multipath_device);
	info->multipath_device = NULL;
	free(info->device);
	info->device = NULL;
	free(info->type);
	info->type = NULL;
}


int ConfigReader::get_index_to(char *p, char c) const
{
	int i;

	for (i = 0; *p != c && *p != '\0'; ++p, ++i) ;

	return i;
}


void ConfigReader::host_id_not_found_error(__u32 h, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find host index %u in configuration"
		" file. Please check if you have the right .cfg file and try"
		" again\n", toolname, h);
}

void ConfigReader::devno_not_found_error(__u32 devno, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find bus id %x.%x.%04x in configuration"
		" file. Please check if you have the right .cfg file and try"
		" again\n", toolname, ZIOREP_BUSID_UNPACKED(devno));
}


void ConfigReader::chpid_not_found_error(__u32 chpid, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find chpid %x in configuration"
		" file. Please check if you have the right .cfg file and try"
		" again\n", toolname, chpid);
}


void ConfigReader::lun_not_found_error(__u64 lun, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find LUN %016Lx in configuration"
		" file. Please check if you have the right .cfg file and try"
		" again\n", toolname, (long long unsigned int)lun);
}


void ConfigReader::ident_not_found_error(const struct hctl_ident *ident, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find identifier [%d:%d:%d:%d] in"
		" configuration file. Please check if you have the right .cfg"
		" file and try again\n", toolname, ident->host, ident->channel,
		ident->target, ident->lun);
}


void ConfigReader::mm_internal_not_found_error(__u32 mm, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find device with internal mm %u in"
		" configuration file. Please check if you have the right .cfg"
		" file and try again\n", toolname, mm);
}


void ConfigReader::device_not_found_error(const char *dev, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find device %s in"
		" configuration file. Please check if you have the right .cfg"
		" file and try again\n", toolname, dev);
}


void ConfigReader::mp_not_found_error(const char *mp, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find multipath device %s in"
		" configuration file. Please check if you have the right .cfg"
		" file and try again\n", toolname, mp);
}


void ConfigReader::mp_mm_not_found_error(__u32 mp_mm, int *rc) const
{
	*rc = -1;
	fprintf(stderr, "%s: Could not find multipath device %ud in"
		" configuration file. Please check if you have the right .cfg"
		" file and try again\n", toolname, mp_mm);
}


#define	search_for(att, crit, ret)	for (list<struct device_info>::const_iterator i = m_devices.begin(); \
							i != m_devices.end(); ++i) { \
						if ((*i).att == crit) \
							return (*i).ret; \
					}

#define	search_for_by_dev(crit, ret)	for (list<struct device_info>::const_iterator i = m_devices.begin(); \
							i != m_devices.end(); ++i) { \
						if (compare_hctl_idents(&(*i).hctl_identifier, crit) == 0) \
							return (*i).ret; \
					}

__u32 ConfigReader::get_chpid_by_host_id(__u32 host, int *rc) const
{
	search_for(hctl_identifier.host, host, chpid);

	host_id_not_found_error(host, rc);

	return 0;
}


__u32 ConfigReader::get_chpid_by_devno(__u32 d, int *rc) const
{
	search_for(devno, d, chpid);

	devno_not_found_error(d, rc);

	return 0;
}


__u32 ConfigReader::get_chpid_by_ident(const struct hctl_ident *ident, int *rc) const
{
	search_for_by_dev(ident, chpid);

	ident_not_found_error(ident, rc);

	return 0;
}


__u32 ConfigReader::get_chpid_by_mm_internal(__u32 mm, int *rc) const
{
	search_for(mm_internal, mm, chpid);

	mm_internal_not_found_error(mm, rc);

	return 0;
}


__u32 ConfigReader::get_host_id_by_chpid(__u32 chpid, int *rc) const
{
	search_for(chpid, chpid, hctl_identifier.host);

	chpid_not_found_error(chpid, rc);

	return 0;
}


__u32 ConfigReader::get_devno_by_host_id(__u32 host, int *rc) const
{
	search_for(hctl_identifier.host, host, devno);

	host_id_not_found_error(host, rc);

	return 0;
}


__u32 ConfigReader::get_devno_by_ident(const struct hctl_ident *ident,
				       int *rc) const
{
	search_for_by_dev(ident, devno);

	ident_not_found_error(ident, rc);

	return 0;
}


__u32 ConfigReader::get_devno_by_mm_internal(__u32 mm, int *rc) const
{
	search_for(mm_internal, mm, devno);

	mm_internal_not_found_error(mm, rc);

	return 0;
}


__u32 ConfigReader::get_mp_mm_by_multipath(const char* mp, int *rc) const
{
	for (list<struct device_info>::const_iterator i = m_devices.begin();
	    i != m_devices.end(); ++i) {
		if ((*i).multipath_device
		    && strcmp((*i).multipath_device + strlen("/dev/mapper/"),
			      mp) == 0)
			return (*i).mp_mm;
	}

	mp_not_found_error(mp, rc);

	return 0;
}


const char* ConfigReader::get_multipath_by_mp_mm(__u32 mp_mm, int *rc) const
{
	search_for(mp_mm, mp_mm, multipath_device);

	mp_mm_not_found_error(mp_mm, rc);

	return NULL;
}


__u64 ConfigReader::get_wwpn_by_mm_internal(__u32 dev, int *rc) const
{
	search_for(mm_internal, dev, wwpn);

	mm_internal_not_found_error(dev, rc);

	return 0;
}


__u64 ConfigReader::get_wwpn_by_ident(const struct hctl_ident *ident, int *rc) const
{
	search_for_by_dev(ident, wwpn);

	ident_not_found_error(ident, rc);

	return 0;
}


__u32 ConfigReader::get_mp_mm_by_mm_internal(__u32 mm, int *rc) const
{
	search_for(mm_internal, mm, mp_mm);

	mm_internal_not_found_error(mm, rc);

	return 0;
}


__u32 ConfigReader::get_mp_mm_by_ident(const struct hctl_ident *ident, int *rc) const
{
	search_for_by_dev(ident, mp_mm);

	ident_not_found_error(ident, rc);

	return 0;
}


__u64 ConfigReader::get_lun_by_mm_internal(__u32 mm, int *rc) const
{
	search_for(mm_internal, mm, lun);

	mm_internal_not_found_error(mm, rc);

	return 0;
}

const char* ConfigReader::get_dev_by_mm_internal(__u32 mm, int *rc) const
{
	search_for(mm_internal, mm, device);

	mm_internal_not_found_error(mm, rc);

	return "<invalid device>";
}

__u32 ConfigReader::get_mm_by_ident(const struct hctl_ident *id, int *rc) const
{
	search_for_by_dev(id, mm_internal);

	ident_not_found_error(id, rc);

	return 0;
}

__u32 ConfigReader::get_mm_by_device(const char *dev, int *rc) const
{
	for (list<struct device_info>::const_iterator i = m_devices.begin();
	    i != m_devices.end(); ++i) {
		if (strcmp((*i).device + strlen("/dev/"), dev) == 0)
			return (*i).mm_internal;
	}

	device_not_found_error(dev, rc);

	return 0;
}

const struct hctl_ident* ConfigReader::get_ident_by_mm_internal(__u32 mm, int *rc) const
{
	for (list<struct device_info>::const_iterator i = m_devices.begin();
		i != m_devices.end(); ++i) {
		if ((*i).mm_internal == mm)
			return &(*i).hctl_identifier;
	}

	mm_internal_not_found_error(mm, rc);

	return NULL;
}


#define	get_uniq(tgt, a, type)		tgt.clear(); \
	for (list<struct device_info>::const_iterator i = m_devices.begin(); \
	      i != m_devices.end(); ++i) { \
		list<type>::iterator j; \
		for (j = tgt.begin(); j != tgt.end() && (*i).a != (*j); ++j) \
			; \
		if (j == tgt.end()) \
			tgt.push_back((*i).a); \
	}


void ConfigReader::get_unique_wwpns(list<__u64> &wwpns) const
{
	get_uniq(wwpns, wwpn, __u64);
}


void ConfigReader::get_unique_devnos(list<__u32> &devnos) const
{
	get_uniq(devnos, devno, __u32);
}


void ConfigReader::get_unique_chpids(list<__u32> &chpids) const
{
	get_uniq(chpids, chpid, __u32);
}


void ConfigReader::get_unique_host_ids(list<__u32> &host_ids) const
{
	get_uniq(host_ids, hctl_identifier.host, __u32);
}


void ConfigReader::get_unique_mp_mms(list<__u32> &mp_mms) const
{
	mp_mms.clear();
	for (list<struct device_info>::const_iterator i = m_devices.begin();
	      i != m_devices.end(); ++i) {
		list<__u32>::iterator j;
		for (j = mp_mms.begin();
		      j != mp_mms.end() && (*i).mp_mm != (*j); ++j) ;
		/* Watch out: Always check the multipath_device attribute
		   to see whether the mp_mm is valid or not! */
		if (j == mp_mms.end() && (*i).multipath_device != NULL)
			mp_mms.push_back((*i).mp_mm);
	}
}


void ConfigReader::get_unique_mms(list<__u32> &lst) const
{
	lst.clear();
	for (list<struct device_info>::const_iterator i = m_devices.begin();
	      i != m_devices.end(); ++i)
		// devices are unique by definition!
		lst.push_back((*i).mm_internal);
}


void ConfigReader::get_unique_devices(list<struct hctl_ident> &idents) const
{
	idents.clear();
	for (list<struct device_info>::const_iterator i = m_devices.begin();
	      i != m_devices.end(); ++i) {
		// devices are unique by definition!
		idents.push_back((*i).hctl_identifier);
	}
}


void ConfigReader::get_devnos_by_chpid(list<__u32> &devnos, __u32 chpid) const
{
	devnos.clear();
	for (list<struct device_info>::const_iterator i = m_devices.begin();
	      i != m_devices.end(); ++i) {
		if ((*i).chpid == chpid)
			devnos.push_back((*i).devno);
	}
}


void ConfigReader::get_devnos_by_host_id(list<__u32> &devnos, __u32 host_id) const
{
	devnos.clear();
	for (list<struct device_info>::const_iterator i = m_devices.begin();
	      i != m_devices.end(); ++i) {
		if ((*i).hctl_identifier.host == host_id)
			devnos.push_back((*i).devno);
	}
}


#define get_mms_list(lst, crit, val)		lst.clear(); \
	for (list<struct device_info>::const_iterator i = m_devices.begin(); \
	      i != m_devices.end(); ++i) { \
		if ((*i).crit == val) \
			lst.push_back((*i).mm_internal); \
	} \

void ConfigReader::get_mms_by_chpid(list<__u32> &mms, __u32 chpid) const
{
	get_mms_list(mms, chpid, chpid);
}

void ConfigReader::get_mms_by_mp_mm(list<__u32> &mms, __u32 mp_mm) const
{
	get_mms_list(mms, mp_mm, mp_mm);
}

void ConfigReader::get_mms_by_wwpn(list<__u32> &mms, __u64 wwpn) const
{
	get_mms_list(mms, wwpn, wwpn);
}

void ConfigReader::get_mms_by_devno(list<__u32> &mms, __u32 d) const
{
	get_mms_list(mms, devno, d);
}

void ConfigReader::get_mms_by_lun(list<__u32> &mms, __u64 l) const
{
	get_mms_list(mms, lun, l);
}

#define verify_numeric(criterion, val)		for \
		(list<struct device_info>::const_iterator \
		i = m_devices.begin(); i != m_devices.end(); ++i) { \
		if ((*i).criterion == val) \
			return true; \
	} \
	return false;


#define verify_char(criterion, val, rc)		for \
		(list<struct device_info>::const_iterator \
		i = m_devices.begin(); i != m_devices.end(); ++i) { \
		if (val && (*i).criterion && strcmp((*i).criterion, val) == 0) \
			rc = true; \
	}


bool ConfigReader::verify_chpid(__u32 c) const
{
	verify_numeric(chpid, c);
}


bool ConfigReader::verify_device(const char *dev) const
{
	bool rc = false;
	char *tmp;

	tmp = (char*)malloc(strlen(dev) + strlen("/dev/") + 1);
	sprintf(tmp, "/dev/%s", dev);

	verify_char(device, tmp, rc);

	free(tmp);

	return rc;
}


bool ConfigReader::verify_mp_device(const char *mp) const
{
	bool rc = false;
	char *tmp;

	tmp = (char*)malloc(strlen(mp) + strlen("/dev/mapper/") + 1);
	sprintf(tmp, "/dev/mapper/%s", mp);

	verify_char(multipath_device, tmp, rc);

	free(tmp);

	return rc;
}


bool ConfigReader::verify_wwpn(__u64 w) const
{
	verify_numeric(wwpn, w);
}


bool ConfigReader::verify_devno(__u32 d) const
{
	verify_numeric(devno, d);
}


bool ConfigReader::verify_lun(__u64 l) const
{
	verify_numeric(lun, l);
}


void ConfigReader::dump(FILE *fp) const
{
	fprintf(fp, "dumping cfg....\n");
	for (list<struct device_info>::const_iterator i = m_devices.begin();
	      i != m_devices.end(); ++i) {
		fprintf(fp, "%x %u %u:%u:%u:%u %x.%x.%04x:%x.%x.%04x:%016Lx:%016Lx %s %u:%u %s %u:%u %s\n",
		       (*i).chpid, (*i).mm_internal,
		       (*i).hctl_identifier.host,
		       (*i).hctl_identifier.channel,
		       (*i).hctl_identifier.target,
		       (*i).hctl_identifier.lun,
		       ZIOREP_BUSID_UNPACKED((*i).subchannel),
		       ZIOREP_BUSID_UNPACKED((*i).devno),
		       (long long unsigned int)(*i).wwpn,
		       (long long unsigned int)(*i).lun,
		       ((*i).multipath_device ? (*i).multipath_device : "n/a"), (*i).mp_major,
		       (*i).mp_minor, (*i).device,
		       (*i).major, (*i).minor,
		       (*i).type);
	}
}




