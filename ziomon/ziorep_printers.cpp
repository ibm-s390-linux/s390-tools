/*
 * FCP report generators
 *
 * Utility classes to print framsets
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <assert.h>
#include <math.h>

extern "C" {
	#include "ziomon_tools.h"
	#include "stats.h"
}
#include "ziorep_printers.hpp"
#include "ziorep_utils.hpp"

extern const char *toolname;
extern int verbose;


#define ZIOREP_PRINTERS_MAX_QUEUE_LEN		128.



Printer::Printer(const ConfigReader *cfg, bool csv_mode)
: m_cfg(cfg), m_csv(csv_mode), m_prev_day(-1)
{
	if (m_csv)
		m_delim = ',';
	else
		m_delim = ' ';

	memset(&m_util, 0, sizeof(struct adapter_utilization));
	m_util.valid = 1;
	memset(&m_util_invalid, 0, sizeof(struct adapter_utilization));
	m_util_invalid.valid = 0;
	memset(&m_ioerr, 0, sizeof(struct ioerr_cnt));
	memset(&m_dstat, 0, sizeof(struct zfcpdd_dstat));
	memset(&m_stat, 0, sizeof(struct blkiomon_stat));
}


bool Printer::print_csv() const
{
	return m_csv;
}


void Printer::print_timestamp(FILE *fp, const Frameset &frameset)
{
	time_t t = frameset.get_end_time();
	struct tm *tm = localtime(&t);

	if (m_csv) {
		fprintf(fp, "%s", print_time_formatted(frameset.get_timestamp()));
		print_delimiter(fp);
		fprintf(fp, "%d", frameset.is_aggregated());
		print_delimiter(fp);
	}
	else {
		if (m_prev_day < 0 || m_prev_day != tm->tm_mday) {
			fprintf(fp, "%s",
				print_time_formatted(frameset.get_timestamp()));
			m_prev_day = tm->tm_mday;
		}
		else
			fprintf(fp, "%s",
				print_time_formatted_short(frameset.get_timestamp()));

		if (frameset.is_aggregated())
			fprintf(fp, " Aggregated Frame\n");
		else
			fputc('\n', fp);
	}
}


void Printer::determine_mag_factor(int leading_places, char *magnitude,
				   double *factor) const
{
	if (leading_places < 7) {
		*magnitude = 'K';
		*factor = 1000;
	}
	else if (leading_places < 10) {
		*magnitude = 'M';
		*factor = 1000000;
	}
	else if (leading_places < 13) {
		*magnitude = 'G';
		*factor = 1000000000;
	}
	else {
		// this is quite expensive, hence we avoid if possible
		*factor = pow(1000, leading_places/3);
		if (leading_places < 16)
			*magnitude = 'T';
		else if (leading_places < 19)
			*magnitude = 'P';
		else {
			assert(false);	// would be surprising if
			*magnitude = '?';
		}
	}
}


void Printer::determine_digs(int leading_places, int max_digs,
			     int *num_full_digs, int *num_places) const
{
	*num_full_digs = leading_places % 3;
	if (*num_full_digs == 0)
		*num_full_digs = 3;
	*num_places = max_digs - *num_full_digs - 2;
	if (*num_places <= 0) {
		*num_places = 0;
		*num_full_digs = max_digs - 1;
	}
}


void Printer::print_abbreviated(FILE *fp, double num, int leading_places,
			       int max_digs) const
{
	int num_full_digs;
	int num_places;
	double factor;
	int rc;
	char magnitude;

	determine_digs(leading_places, max_digs, &num_full_digs, &num_places);

	determine_mag_factor(leading_places, &magnitude, &factor);

	double tmp = num / factor;
	if (tmp + 5 * pow(10, -1 - num_places) >= pow(10, num_full_digs)) {
		if (num_places > 0)
			// just strip down one decimal place,
			// e.g. 9.96... with 1.1 format would result in
			// 10.0 otherwise
			num_places--;
		else {
			// indicate that we need one more leading place
			// e.g. 999.872 with 3.0 format digits would result
			// in 1.000K otherwise
			leading_places++;
			determine_digs(leading_places, max_digs, &num_full_digs, &num_places);
			determine_mag_factor(leading_places, &magnitude, &factor);
			tmp = num / factor;
		}
	}

	rc = fprintf(fp, "%*.*lf%c", max_digs - 1, num_places, num / factor, magnitude);

#ifdef NDEBUG
	(void)(rc);
#else
	assert(rc <= max_digs);
#endif
}


void Printer::print_abbrev_num(FILE *fp, __u64 num, int max_digs) const
{
	int rc = 0;
	char tmp[128];

	if (m_csv) {
		fprintf(fp, "%lld", (long long int)num);
		return;
	}

	/* print into a tmp buffer first - if buf is too small we might
	   write out of bounds otherwise! */
	rc = sprintf(tmp, "%Lu", (long long unsigned int)num);
	if (rc < max_digs)
		fprintf(fp, "%*Lu", max_digs, (long long unsigned int)num);
	else
		print_abbreviated(fp, num, rc, max_digs);
}


void Printer::print_abbrev_num(FILE *fp, __u32 num, int max_digs) const
{
	return print_abbrev_num(fp, (__u64)num, max_digs);
}


void Printer::print_abbrev_num(FILE *fp, double num, int max_digs,
			       bool more_places) const
{
	int  rc = 0;

	assert(max_digs > 2);

	if (m_csv) {
		fprintf(fp, "%lf", num);
		return;
	}

	/* print into a tmp buffer first - if buf is too small we might
	   write out of bounds otherwise! */
	if (num == 0)
		fprintf(fp, "%*.1lf", max_digs, 0.);
	else if (num < 1 && more_places)
		fprintf(fp, "%.*lf", max_digs - 2, num);
	else if (num < pow(10, max_digs - 2))
		fprintf(fp, "%*.1lf", max_digs, num);
	else
		print_abbreviated(fp, num, rc, max_digs);
}


/**
 * Always print doubles using 6 characters: 5 for a 3.1 format and
 * 1 for an optional character giving the magintude. */
void Printer::print_abbrev_num(FILE *fp, double num) const
{
	int  rc = 0;
	char tmp[128];

	if (m_csv) {
		fprintf(fp, "%.1lf", num);
		return;
	}

	if (num == 0) {
		fprintf(fp, "  0.0 ");
		return;
	}

	/* print into a tmp buffer first - if buf is too small we might
	   write out of bounds otherwise! */
	rc = sprintf(tmp, "%lld", (long long int)num);
	if (rc < 4)
		fprintf(fp, "%5.1lf ", num);
	else
		print_abbreviated(fp, num, rc, 6);
}


const struct adapter_utilization* Printer::get_empty_utilization(__u32 host_id)
{
	m_util.adapter_no = host_id;

	return &m_util;
}

const struct adapter_utilization* Printer::get_invalid_utilization(__u32 host_id)
{
	m_util_invalid.adapter_no = host_id;

	return &m_util_invalid;
}

const struct ioerr_cnt* Printer::get_empty_ioerr(struct hctl_ident *identifier)
{
	if (identifier)
		m_ioerr.identifier = *identifier;
	else
		memset(&m_ioerr.identifier, 0, sizeof(struct hctl_ident));

	return &m_ioerr;
}


const struct zfcpdd_dstat* Printer::get_empty_zfcpdd_dstat(__u32 device)
{
	m_dstat.device = device;

	return &m_dstat;
}


const struct blkiomon_stat* Printer::get_empty_blkiomon_stat(__u32 device)
{
	m_stat.device = device;

	return &m_stat;
}


void Printer::print_delimiter(FILE *fp)
{
	fputc(m_delim, fp);
}

void Printer::print_invalid(FILE *fp, int width)
{
	if (m_csv)
		fputc('-', fp);
	else
		fprintf(fp, "%*c", width, '-');
}

void PhysAdapterPrinter::print_phys_adpt(FILE *fp, __u32 host_id, int *rc)
{
	__u32 chpid = m_cfg->get_chpid_by_host_id(host_id, rc);

	if (m_csv)
		fprintf(fp, "%x", chpid);
	else
		fprintf(fp, "%3x", chpid);
}


void PhysAdapterPrinter::print_utilization(FILE *fp,
					  const struct abbrev_stat *stat,
					  __u64 count, bool valid)
{
	__u64 tmp64;

	print_delimiter(fp);
	if (valid) {
		tmp64 = 0;
		if (count)
			tmp64 = stat->min;
		print_abbrev_num(fp, tmp64, 3);
	}
	else
		print_invalid(fp, 3);


	print_delimiter(fp);
	if (valid) {
		tmp64 = 0;
		if (count)
			tmp64 = stat->max;
		print_abbrev_num(fp, tmp64, 3);
	}
	else
		print_invalid(fp, 3);

	print_delimiter(fp);
	if (valid) {
		double tmp = 0;
		if (count)
			tmp = calc_avg(stat->sum, count);
		print_abbrev_num(fp, tmp, 5);
	}
	else
		print_invalid(fp, 5);
}


PhysAdapterPrinter::PhysAdapterPrinter(const ConfigReader *cfg,
				       bool csv_mode)
: Printer(cfg, csv_mode)
{
}


void PhysAdapterPrinter::print_topline(FILE *fp)
{
	if (m_csv)
		fprintf(fp, "timestamp,aggregated,CHPID,adapter min %%,"
			"adapter max %%,adapter avg %%,bus min %%,bus max %%,"
			"bus avg %%,cpu min %%,cpu max %%,cpu avg %%\n");
	else {
		fprintf(fp, "CHP|adapter in %%-|--bus in %%---|--cpu in %%---|\n");
		fprintf(fp, " ID min max   avg min max   avg min max   avg\n");
	}
}


int PhysAdapterPrinter::print_frame(FILE *fp,
				    const Frameset &frameset,
				    const DeviceFilter &dev_filt)
{
	int lrc = 0;
	bool timestamp_printed = false;
	const struct adapter_utilization *util;
	list<__u32> host_ids = dev_filt.get_host_id_list();

	assert(frameset.get_collapser()->get_criterion() == none);
	for (list<__u32>::iterator i = host_ids.begin();
	      i != host_ids.end(); ++i) {
		if (!timestamp_printed) {
			print_timestamp(fp, frameset);
			if (!m_csv)
				// print timestamp for every line in CSV mode
				timestamp_printed = true;
		}
		print_phys_adpt(fp, *i, &lrc);
		if (lrc)
			return -1;
		util = frameset.get_utilization_stat_by_host_id(*i);
		if (!util)
			util = get_empty_utilization(*i);
		print_utilization(fp, &util->stats.adapter,
				  util->stats.count,
				  util->valid);
		print_utilization(fp, &util->stats.bus,
				  util->stats.count,
				  util->valid);
		print_utilization(fp, &util->stats.cpu,
				  util->stats.count,
				  util->valid);
		fputc('\n', fp);
	}

	return 0;
}


VirtAdapterPrinter::VirtAdapterPrinter(const ConfigReader *cfg,
				       bool csv_mode)
: Printer(cfg, csv_mode)
{
}


void VirtAdapterPrinter::print_virt_adpt(FILE *fp, __u32 devno,
					int *rc)
{
	if (m_csv)
		fprintf(fp, "%x,%x.%x.%04x",
			       m_cfg->get_chpid_by_devno(devno, rc),
			       ZIOREP_BUSID_UNPACKED(devno));
	else
		fprintf(fp, "%3x/%x.%x.%04x",
			       m_cfg->get_chpid_by_devno(devno, rc),
			       ZIOREP_BUSID_UNPACKED(devno));
}

void VirtAdapterPrinter::print_queue_fill(FILE *fp,
					  const struct zfcpdd_dstat *stat,
					  const struct adapter_utilization *res)
{
	double tmp;

	tmp = 0;
	if (stat && stat->count)
		tmp = (stat->outb_max * 100)/ZIOREP_PRINTERS_MAX_QUEUE_LEN;
	print_delimiter(fp);
	print_abbrev_num(fp, tmp, 5);

	tmp = 0;
	if (res && res->valid)
		tmp = res->stats.queue_util_integral
			/ (double)res->stats.queue_util_interval;
	print_delimiter(fp);
	print_abbrev_num(fp, tmp, 5);
}


void VirtAdapterPrinter::print_queue_full(FILE *fp,
					 const struct adapter_utilization *res)
{
	__u32 val = 0;

	if (res) {
		if (res->valid)
			val = res->stats.queue_full;
		else {
			print_invalid(fp, 4);
			return;
		}
	}
	print_delimiter(fp);
	print_abbrev_num(fp, val, 4);
}


void VirtAdapterPrinter::print_failures(FILE *fp, const struct ioerr_cnt *cnt)
{
	print_delimiter(fp);
	if (cnt)
		print_abbrev_num(fp, cnt->num_ioerr, 4);
	else
		print_abbrev_num(fp, (__u32)0, 4);
}

void VirtAdapterPrinter::print_throughput(FILE *fp,
					 const struct blkiomon_stat *stat)
{
	double tmp;

	if (!stat || stat->d2c_r.num <= 0 || stat->size_r.num <= 0)
		tmp = 0;
	else
		tmp = stat->size_r.sum/(double)stat->d2c_r.sum;
	print_delimiter(fp);
	print_abbrev_num(fp, tmp);

	if (!stat || stat->d2c_w.num <= 0 || stat->size_w.num <= 0)
		tmp = 0;
	else
		tmp = stat->size_w.sum/(double)stat->d2c_w.sum;
	print_delimiter(fp);
	print_abbrev_num(fp, tmp);
}


void VirtAdapterPrinter::print_num_requests(FILE *fp, const struct blkiomon_stat *stat)
{
	print_delimiter(fp);
	if (stat)
		print_abbrev_num(fp, stat->size_r.num, 4);
	else
		print_abbrev_num(fp, (__u64)0, 4);

	print_delimiter(fp);
	if (stat)
		print_abbrev_num(fp, stat->size_w.num, 4);
	else
		print_abbrev_num(fp, (__u64)0, 4);
}


void VirtAdapterPrinter::print_topline(FILE *fp)
{
	if (m_csv)
		fprintf(fp, "timestamp,aggregated,CHPID,Bus-ID,qdio utilization max %%,qdio utilization avg %%,queue full,fail erc,throughput read / MS/s,throughput write / MS/s,I/O requests read,I/O requests write\n");
	else {
		fprintf(fp, "CHP Bus-ID  |qdio util.%%|queu|fail|-thp in MB/s-|I/O reqs-|\n");
		fprintf(fp, " ID            max   avg full  erc     rd    wrt   rd  wrt\n");
	}
}


int VirtAdapterPrinter::print_frame(FILE *fp,
				    const Frameset &frameset,
				    const DeviceFilter &dev_filt)
{
	int lrc = 0;
	bool timestamp_printed = false;
	const struct adapter_utilization 	*util;
	const struct ioerr_cnt			*ioerr;
	const struct blkiomon_stat		*blk_stat;
	const struct zfcpdd_dstat		*zfcp_stat;

	list<__u32> devnos;
	devnos = ((StagedDeviceFilter*)&dev_filt)->get_filter_devnos();

	assert(frameset.get_collapser()->get_criterion() == devno);

	for (list<__u32>::iterator i = devnos.begin(); i != devnos.end(); ++i) {
		if (!timestamp_printed) {
			print_timestamp(fp, frameset);
			if (!m_csv)
				// print timestamp for every line in CSV mode
				timestamp_printed = true;
		}

		util = frameset.get_utilization_stat_by_devno(*i);
		ioerr = frameset.get_ioerr_stat_by_devno(*i);
		blk_stat = frameset.get_blkiomon_stat_by_devno(*i);
		zfcp_stat = frameset.get_zfcpdd_stat_by_devno(*i);
		print_virt_adpt(fp, *i, &lrc);
		print_queue_fill(fp, zfcp_stat, util);
		print_queue_full(fp, util);
		print_failures(fp, ioerr);
		print_throughput(fp, blk_stat);
		print_num_requests(fp, blk_stat);
		if (lrc) {
			fprintf(stderr, "%s: Did not find matching data in"
				" .cfg file. Please check if it matches your"
				" data and try again.\n", toolname);
			return -1;
		}
		fputc('\n', fp);
	}

	return 0;
}



TrafficPrinter::TrafficPrinter(const ConfigReader *cfg, Collapser &col,
			       bool csv_mode)
: Printer(cfg, csv_mode), m_mp_whitespace(NULL), m_mp_topline_pref1(NULL),
	m_mp_topline_pref2(NULL)
{
	m_agg_crit = col.get_criterion();

	if (m_agg_crit == multipath_device) {
		if (m_csv) {
			m_mp_topline_pref1 = (char*)malloc(25);
			sprintf(m_mp_topline_pref1, "Multipath Device");
		}
		else {
			int rc = 0;
			int max_len = 32;
			int len;
			int corrector = 0;
			const list<__u32> lst =
				((AggregationCollapser*)&col)->get_reference_mp_mms();
			for (list<__u32>::const_iterator i = lst.begin();
			      i != lst.end(); ++i) {
				len = strlen(cfg->get_multipath_by_mp_mm(*i, &rc));
				assert(rc == 0);
				if (len > max_len)
					max_len = len;
			}
			m_mp_whitespace = (char*)malloc(max_len + 1);
			m_mp_topline_pref1 = (char*)malloc(max_len + 1);
			m_mp_topline_pref2 = (char*)malloc(max_len + 1);
			sprintf(m_mp_whitespace, "%*c", max_len - 1, ' ');
			corrector = (max_len - 9) % 2;
			len = (max_len - 9) / 2;
			sprintf(m_mp_topline_pref1, "%*cMultipath%*c",
				len, ' ', len + corrector, ' ');
			corrector = 1 - corrector; // invert
			len = (max_len - 6) / 2;
			sprintf(m_mp_topline_pref2, "%*cdevice%*c",
				len, ' ', len + corrector, ' ');
		}
	}
}


TrafficPrinter::~TrafficPrinter()
{
	free(m_mp_whitespace);
	free(m_mp_topline_pref1);
	free(m_mp_topline_pref2);
}


void TrafficPrinter::print_topline_prefix1(FILE *fp)
{
	const char *str = NULL;

	switch (m_agg_crit) {
	case none:
		if (m_csv)
			str = "WWPN,LUN";
		else
			str = "       WWPN                LUN       ";
		break;
	case chpid:
		if (m_csv)
			str = "CHPID";
		else
			str = "CHP";
		break;
	case devno:
		if (m_csv)
			str = "Bus-ID";
		else
			str = " Bus-ID ";
		break;
	case wwpn:
		if (m_csv)
			str = "WWPN";
		else
			str = "       WWPN       ";
		break;
	case multipath_device:
		str = m_mp_topline_pref1;
		break;
	case all:
		str = " * ";
		break;
	}

	fprintf(fp, "%s", str);
}

void TrafficPrinter::print_topline_prefix2(FILE *fp)
{
	const char *str = NULL;

	switch (m_agg_crit) {
	case none:
		str = "                                     ";
		break;
	case chpid:
		str = " ID";
		break;
	case devno:
		str = "        ";
		break;
	case wwpn:
		str = "                  ";
		break;
	case multipath_device:
		str = m_mp_topline_pref2;
		break;
	case all:
		str = "   ";
		break;
	}

	fprintf(fp, "%s", str);
}

void TrafficPrinter::print_topline_whitespace(FILE *fp)
{
	const char *str = NULL;

	switch (m_agg_crit) {
	case none:
		str = "                                     ";
		break;
	case chpid:
		str = "   ";
		break;
	case devno:
		str = "        ";
		break;
	case wwpn:
		str = "                  ";
		break;
	case multipath_device:
		str = m_mp_whitespace;
		break;
	case all:
		str = "   ";
		break;
	}

	fprintf(fp, "%s", str);
}

void TrafficPrinter::get_device_list(list<__u32> &lst,
				     const DeviceFilter &dev_filt)
{
	switch (m_agg_crit) {
	case none:
	case all:
		lst = dev_filt.get_mm_list();
		break;
	case devno:
		lst = ((StagedDeviceFilter*)&dev_filt)->get_filter_devnos();
		break;
	case multipath_device:
		lst = ((StagedDeviceFilter*)&dev_filt)->get_filter_mp_mms();
		break;
	case chpid:
		lst = ((StagedDeviceFilter*)&dev_filt)->get_filter_chpids();
		break;
	default:
		assert(false);
	}
}


void TrafficPrinter::get_device_list(list<__u64> &lst,
				     const DeviceFilter &dev_filt)
{
	assert(m_agg_crit == wwpn);
	lst = ((StagedDeviceFilter*)&dev_filt)->get_filter_wwpns();
}


void TrafficPrinter::print_device_wwpn(FILE *fp, __u64 wwpn)
{
	fprintf(fp, "0x%016Lx", (long long unsigned int)wwpn);
}

void TrafficPrinter::print_device_chpid(FILE *fp, __u32 chpid)
{
	if (m_csv)
		fprintf(fp, "%x", chpid);
	else
		fprintf(fp, "%3x", chpid);
}

void TrafficPrinter::print_device_devno(FILE *fp, __u32 devno)
{
	fprintf(fp, "%x.%x.%04x", ZIOREP_BUSID_UNPACKED(devno));
}

void TrafficPrinter::print_device_mp_mm(FILE *fp, __u32 mp_mm,
				       const ConfigReader &cfg, int *rc)
{
	if (m_csv)
		fprintf(fp, "%s", cfg.get_multipath_by_mp_mm(mp_mm, rc));
	else
		fprintf(fp, "%16s", cfg.get_multipath_by_mp_mm(mp_mm, rc));
}

void TrafficPrinter::print_device(FILE *fp, __u32 dev,
				 const ConfigReader &cfg, int *rc)
{
	if (m_csv)
		fprintf(fp, "0x%016Lx,0x%016Lx",
			       (long long unsigned int)cfg.get_wwpn_by_mm_internal(dev, rc),
			       (long long unsigned int)cfg.get_lun_by_mm_internal(dev, rc));
	else
		fprintf(fp, "0x%016Lx:0x%016Lx",
			       (long long unsigned int)cfg.get_wwpn_by_mm_internal(dev, rc),
			       (long long unsigned int)cfg.get_lun_by_mm_internal(dev, rc));
}

void TrafficPrinter::print_device_all(FILE *fp)
{
	if (m_csv)
		fprintf(fp, "*");
	else
		fprintf(fp, " * ");
}

int TrafficPrinter::print_frame(FILE *fp, const Frameset &frameset,
				       const DeviceFilter &dev_filt)
{
	int rc = 0;
	bool timestamp_printed = false;
	list<__u32> lst_32;
	list<__u64> lst_64;
	const struct blkiomon_stat	*blk_stat = NULL;
	const struct zfcpdd_dstat	*zfcp_stat = NULL;
	const AggregationCollapser *agg_col;

	switch (m_agg_crit) {
	case none:
		get_device_list(lst_32, dev_filt);
		break;
	case chpid:
		agg_col = (AggregationCollapser*)frameset.get_collapser();
		lst_32 = agg_col->get_reference_chpids();
		break;
	case devno:
		agg_col = (AggregationCollapser*)frameset.get_collapser();
		lst_32 = agg_col->get_reference_devnos();
		break;
	case wwpn:
		agg_col = (AggregationCollapser*)frameset.get_collapser();
		lst_64 = agg_col->get_reference_wwpns();
		break;
	case multipath_device:
		agg_col = (AggregationCollapser*)frameset.get_collapser();
		lst_32 = agg_col->get_reference_mp_mms();
		break;
	case all:
		break;
	}

	if (m_agg_crit == wwpn) {
		for (list<__u64>::const_iterator i = lst_64.begin();
		      i != lst_64.end(); ++i) {
			if (!timestamp_printed) {
				print_timestamp(fp, frameset);
				if (!m_csv)
					// print timestamp for every line in CSV mode
					timestamp_printed = true;
			}

			blk_stat = frameset.get_blkiomon_stat_by_wwpn(*i);
			zfcp_stat = frameset.get_zfcpdd_stat_by_wwpn(*i);
			print_device_wwpn(fp, *i);
			print_data_row(fp, blk_stat, zfcp_stat);
		}
	}
	else if (m_agg_crit == all) {
		print_timestamp(fp, frameset);

		blk_stat = frameset.get_first_blkiomon_stat();
		zfcp_stat = frameset.get_first_zfcpdd_stat();
		print_device_all(fp);
		print_data_row(fp, blk_stat, zfcp_stat);
	}
	else {
		for (list<__u32>::const_iterator i = lst_32.begin();
		      i != lst_32.end(); ++i) {
			if (!timestamp_printed) {
				print_timestamp(fp, frameset);
				if (!m_csv)
					// print timestamp for every line in CSV mode
					timestamp_printed = true;
			}

			switch (m_agg_crit) {
			case none:
				blk_stat = frameset.get_blkiomon_stat_by_mm(*i);
				zfcp_stat = frameset.get_zfcpdd_stat_by_mm(*i);
				print_device(fp, *i, *m_cfg, &rc);
				break;
			case devno:
				blk_stat = frameset.get_blkiomon_stat_by_devno(*i);
				zfcp_stat = frameset.get_zfcpdd_stat_by_devno(*i);
				print_device_devno(fp, *i);
				break;
			case multipath_device:
				blk_stat = frameset.get_blkiomon_stat_by_mp_mm(*i);
				zfcp_stat = frameset.get_zfcpdd_stat_by_mp_mm(*i);
				print_device_mp_mm(fp, *i, *m_cfg, &rc);
				break;
			case chpid:
				blk_stat = frameset.get_blkiomon_stat_by_chpid(*i);
				zfcp_stat = frameset.get_zfcpdd_stat_by_chpid(*i);
				print_device_chpid(fp, *i);
				break;
			default:
				assert(false);
			}
			if (rc )
				return -1;
			print_data_row(fp, blk_stat, zfcp_stat);
		}
	}

	return 0;
}


SummaryTrafficPrinter::SummaryTrafficPrinter(const ConfigReader *cfg,
					     Collapser &col,
					     bool csv_mode)
: TrafficPrinter(cfg, col, csv_mode)
{
}


void SummaryTrafficPrinter::print_topline(FILE *fp)
{
	if (m_csv) {
		fprintf(fp, "timestamp,aggregated,");
		print_topline_prefix1(fp);
		fprintf(fp, ",I/O rate in MB/s min,I/O rate in MB/s max,throughput in MB/s avg,throughput var,#I/O requests total,#I/O requests rd,"
			"#I/O requests wrt,#I/O requests bidi,#I/O subsystem latency in us min,#I/O subsystem latency in us max,"
			"#I/O subsystem latency in us avg,#I/O subsystem latency var,channel latency in us min,channel latency in us max,"
			"channel latency in us avg,channel latency var,fabric latency in us min,fabric latency in us max,fabric latency in us avg,"
			"fabric latency var\n");
	}
	else {
		print_topline_prefix1(fp);
		fprintf(fp, "|I/O rt MB/s|thrp in MB/s-|----I/O requests----|-I/O subs. lat. in us--|--channel lat. in us---|---fabric lat. in us---|\n");
		print_topline_prefix2(fp);
		fprintf(fp, "   min   max    avg  stdev #reqs   rd  wrt bidi  min  max    avg  stdev  min  max    avg  stdev  min  max    avg  stdev\n");
	}
}


void SummaryTrafficPrinter::print_throughput(FILE *fp, const struct blkiomon_stat *stat)
{
	struct minmax thrp_data, total_size, total_latency;
	double tmp;

	minmax_init(&thrp_data);
	minmax_init(&total_size);
	minmax_init(&total_latency);

	if (stat) {
		minmax_merge(&thrp_data, &stat->thrput_r);
		minmax_merge(&thrp_data, &stat->thrput_w);
		minmax_merge(&total_size, &stat->size_r);
		minmax_merge(&total_size, &stat->size_w);
		minmax_merge(&total_latency, &stat->d2c_r);
		minmax_merge(&total_latency, &stat->d2c_w);
	}

	tmp = 0;
	if (stat)
		tmp = thrp_data.min / 1000.;
	print_delimiter(fp);
	if (tmp < 1)
		print_abbrev_num(fp, tmp, 5, true);
	else
		print_abbrev_num(fp, tmp, 5);

	tmp = 0;
	if (stat)
		tmp = ((double)(thrp_data.max)) / 1000.;
	print_delimiter(fp);
	if (tmp < 1)
		print_abbrev_num(fp, tmp, 5, false);
	else
		print_abbrev_num(fp, tmp, 5);

	tmp = 0;
	if (stat && total_size.sum > 0)
		tmp = calc_avg(total_size.sum, total_latency.sum);
	print_delimiter(fp);
	print_abbrev_num(fp, tmp);

	tmp = 0;
	if (stat && total_size.sum > 0)
		tmp = calc_std_dev(total_size.sum, total_size.sos,
					total_latency.sum);
	print_delimiter(fp);
	print_abbrev_num(fp, tmp);
}

void SummaryTrafficPrinter::print_request_stats(FILE *fp,
					const struct blkiomon_stat *stat)
{
	__u64 val;

	val = 0;
	if (stat)
		val = stat->bidir + stat->thrput_r.num + stat->thrput_w.num;
	print_delimiter(fp);
	print_abbrev_num(fp, val, 5);

	val = 0;
	if (stat)
		val = stat->size_r.num;
	print_delimiter(fp);
	print_abbrev_num(fp, val, 4);

	val = 0;
	if (stat)
		val = stat->size_w.num;
	print_delimiter(fp);
	print_abbrev_num(fp, val, 4);

	val = 0;
	if (stat)
		val = stat->bidir;
	print_delimiter(fp);
	print_abbrev_num(fp, val, 4);
}


void SummaryTrafficPrinter::print_latency(FILE *fp,
					 const struct minmax *data)
{
	__u64 tmp64;
	double tmplf;

	tmp64 = 0;
	if (data && data->num > 0)
		tmp64 = data->min;
	print_delimiter(fp);
	print_abbrev_num(fp, tmp64, 4);

	tmp64 = 0;
	if (data && data->num > 0)
		tmp64 = data->max;
	print_delimiter(fp);
	print_abbrev_num(fp, tmp64, 4);

	tmplf = 0;
	if (data && data->num > 0)
		tmplf = minmax_avg(data);
	print_delimiter(fp);
	print_abbrev_num(fp, tmplf);

	tmplf = 0;
	if (data && data->num > 0)
		tmplf = minmax_std_dev(data);
	print_delimiter(fp);
	print_abbrev_num(fp, tmplf);
}

void SummaryTrafficPrinter::print_latency(FILE *fp,
					 const struct abbrev_stat *data,
					 __u64 count)
{
	__u64 tmp64;
	double tmplf;

	tmp64 = 0;
	if (count > 0)
		tmp64 = data->min;
	print_delimiter(fp);
	print_abbrev_num(fp, tmp64, 4);

	tmp64 = 0;
	if (count > 0)
		tmp64 = data->max;
	print_delimiter(fp);
	print_abbrev_num(fp, tmp64, 4);

	tmplf = 0;
	if (count > 0)
		tmplf = calc_avg(data->sum, count);
	print_delimiter(fp);
	print_abbrev_num(fp, tmplf);

	tmplf = 0;
	if (count > 0)
		tmplf = calc_std_dev(data->sum, data->sos, count);
	print_delimiter(fp);
	print_abbrev_num(fp, tmplf);
}

void SummaryTrafficPrinter::print_io_subsystem_latency(FILE *fp,
					const struct blkiomon_stat *stat)
{
	struct minmax data;

	minmax_init(&data);
	if (stat) {
		minmax_merge(&data, &stat->d2c_r);
		minmax_merge(&data, &stat->d2c_w);
	}

	print_latency(fp, &data);
}

void SummaryTrafficPrinter::print_channel_latency(FILE *fp,
					const struct zfcpdd_dstat *stat)
{
	print_latency(fp, &stat->chan_lat, stat->count);
}

void SummaryTrafficPrinter::print_fabric_latency(FILE *fp, const struct zfcpdd_dstat *stat)
{
	print_latency(fp, &stat->fabr_lat, stat->count);
}

void SummaryTrafficPrinter::print_data_row(FILE *fp,
					const struct blkiomon_stat *blk_stat,
					const struct zfcpdd_dstat *zfcp_stat)
{
	if (!blk_stat)
		blk_stat = get_empty_blkiomon_stat();
	if (!zfcp_stat)
		zfcp_stat = get_empty_zfcpdd_dstat();

	print_throughput(fp, blk_stat);
	print_request_stats(fp, blk_stat);
	print_io_subsystem_latency(fp, blk_stat);
	print_channel_latency(fp, zfcp_stat);
	print_fabric_latency(fp, zfcp_stat);
	fputc('\n', fp);
}


DetailedTrafficPrinter::DetailedTrafficPrinter(const ConfigReader *cfg,
					       Collapser &col,
					       bool csv_mode)
: TrafficPrinter(cfg, col, csv_mode)
{
}


void DetailedTrafficPrinter::print_topline(FILE *fp)
{
	if (m_csv) {
		fprintf(fp, "timestamp,aggregated,");
		print_topline_prefix1(fp);
		fprintf(fp, ",I/O requests 0KB,I/O requests <1KB,I/O requests <2KB,I/O requests <4KB,I/O requests <8KB,"
			"I/O requests <16KB,I/O requests <32KB,I/O requests <64KB,I/O requests <128KB,I/O requests <256KB,"
			"I/O requests <512KB,I/O requests <1MB,I/O requests <2MB,I/O requests <4MB,I/O requests <8MB,"
			"I/O requests >=8MB,I/O subsystem latency 0us,I/O subsystem latency <8us,I/O subsystem latency <16us,"
			"I/O subsystem latency <32us,I/O subsystem latency <64us,I/O subsystem latency <128us,"
			"I/O subsystem latency <256us,I/O subsystem latency <512us,I/O subsystem latency <1ms,"
			"I/O subsystem latency <2ms,I/O subsystem latency <4ms,I/O subsystem latency <8ms,"
			"I/O subsystem latency <16ms,I/O subsystem latency <32ms,I/O subsystem latency <64ms,"
			"I/O subsystem latency <128ms,I/O subsystem latency <256ms,I/O subsystem latency <512ms,"
			"I/O subsystem latency <1s,I/O subsystem latency <2s,I/O subsystem latency <4s,"
			"I/O subsystem latency <8s,I/O subsystem latency <16s,I/O subsystem latency <32s,"
			"I/O subsystem latency >=32s,channel latency 0us,"
			"channel latency <1us,channel latency <2us,channel latency <4us,channel latency <8us,"
			"channel latency <16us,channel latency <32us,channel latency <64us,channel latency <128us,"
			"channel latency <256us,channel latency <512us,channel latency <1ms,channel latency <2ms,"
			"channel latency <4us,channel latency <8ms,channel latency <16ms,channel latency <32ms,"
			"channel latency <64ms,channel latency <128ms,channel latency >=128ms,fabric latency 0us,"
			"fabric latency <8us,fabric latency <16us,fabric latency <32us,fabric latency <64us,"
			"fabric latency <128us,fabric latency <256us,fabric latency <512us,fabric latency <1ms,"
			"fabric latency <2ms,fabric latency <4ms,fabric latency <8ms,fabric latency <16ms,"
			"fabric latency <32ms,fabric latency <64ms,fabric latency <128ms,fabric latency <256ms,"
			"fabric latency <512ms,fabric latency <1s,fabric latency <2s,fabric latency <4s,"
			"fabric latency <8s,fabric latency <16s,fabric latency <32s,fabric latency >=32s\n");
	}
	else {
		print_topline_whitespace(fp);
		fprintf(fp, "|------------------------I/O request sizes in KBytes----------------------------|\n");
		print_topline_whitespace(fp);
		fprintf(fp, "    0    1    2    4    8   16   32   64  128  256  512   1K   2K   4K   8K  >8K\n");
		print_topline_whitespace(fp);
		fprintf(fp, "|------------------------I/O subsystem latency in us-------------------------------------------------------------------------|\n");
		print_topline_whitespace(fp);
		fprintf(fp, "    0    8   16   32   64  128  256  512   1K   2K   4K   8K  16K  32K  64K 128K 256K 512K   1M   2M   4M   8M  16M  32M >32M\n");
		print_topline_whitespace(fp);
		fprintf(fp, "|------------------------channel latency in us------------------------------------------------------|\n");
		print_topline_whitespace(fp);
		fprintf(fp, "    0    1    2    4    8   16   32   64  128  256  512   1K   2K   4K   8K  16K  32K  64K 128K>128K\n");
		print_topline_prefix1(fp);
		fprintf(fp, "|------------------------fabric latency in us--------------------------------------------------------------------------------|\n");
		print_topline_prefix2(fp);
		fprintf(fp, "    0    8   16   32   64  128  256  512   1K   2K   4K   8K  16K  32K  64K 128K 256K 512K   1M   2M   4M   8M  16M  32M >32M\n");
	}
}


void DetailedTrafficPrinter::print_data_row(FILE *fp,
			   const struct blkiomon_stat *blk_stat,
			   const struct zfcpdd_dstat *zfcp_stat)
{
	if (!blk_stat)
		blk_stat = get_empty_blkiomon_stat();
	if (!zfcp_stat)
		zfcp_stat = get_empty_zfcpdd_dstat();

	print_histogram_io_reqs(fp, blk_stat);
	if (!m_csv) {
		fputc('\n', fp);
		print_topline_whitespace(fp);
	}
	print_histogram_io_subs_lat(fp, blk_stat);
	if (!m_csv) {
		fputc('\n', fp);
		print_topline_whitespace(fp);
	}
	print_histogram_channel_lat(fp, zfcp_stat);
	if (!m_csv) {
		fputc('\n', fp);
		print_topline_whitespace(fp);
	}
	print_histogram_fabric_lat(fp, zfcp_stat);
	fputc('\n', fp);
}


void DetailedTrafficPrinter::print_histogram_io_reqs(FILE *fp,
			    const struct blkiomon_stat *stat)
{
	for (unsigned int i = 0; i < BLKIOMON_SIZE_BUCKETS; ++i) {
		print_delimiter(fp);
		if (stat)
			print_abbrev_num(fp, stat->size_hist[i], 4);
		else
			print_abbrev_num(fp, (__u32)0, 4);
	}
}


void DetailedTrafficPrinter::print_histogram_io_subs_lat(FILE *fp,
				const struct blkiomon_stat *stat)
{
	for (unsigned int i = 0; i < BLKIOMON_D2C_BUCKETS; ++i) {
		print_delimiter(fp);
		if (stat)
			print_abbrev_num(fp, stat->d2c_hist[i], 4);
		else
			print_abbrev_num(fp, (__u32)0, 4);
	}
}


void DetailedTrafficPrinter::print_histogram_channel_lat(FILE *fp,
				const struct zfcpdd_dstat *stat)
{
	for (unsigned int i = 0; i < BLKIOMON_CHAN_LAT_BUCKETS; ++i) {
		print_delimiter(fp);
		if (stat)
			print_abbrev_num(fp, stat->chan_lat_hist[i], 4);
		else
			print_abbrev_num(fp, (__u32)0, 4);
	}
}


void DetailedTrafficPrinter::print_histogram_fabric_lat(FILE *fp,
			       const struct zfcpdd_dstat *stat)
{
	for (unsigned int i = 0; i < BLKIOMON_FABR_LAT_BUCKETS; ++i) {
		print_delimiter(fp);
		if (stat)
			print_abbrev_num(fp, stat->fabr_lat_hist[i], 4);
		else
			print_abbrev_num(fp, (__u32)0, 4);
	}
}



