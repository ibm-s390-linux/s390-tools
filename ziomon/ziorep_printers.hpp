/*
 * FCP report generators
 *
 * Utility classes to print framsets
 *
 * Copyright IBM Corp. 2008, 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZIOREP_PRINTERS
#define ZIOREP_PRINTERS

#include "ziorep_frameset.hpp"
#include "ziorep_framer.hpp"
#include "ziorep_cfgreader.hpp"


/**
 * Base class for all printer classes
 */
class Printer {
public:
	Printer(const ConfigReader *cfg, bool csv_mode);
	virtual ~Printer() {};

	/**
	 * Print topline to fp.
	 * Returns number of characters printed or <0 in case of error */
	virtual void print_topline(FILE *fp) = 0;

	/**
	 * Print frameset to fp.
	 * Returns number of characters printed or <0 in case of error */
	virtual int print_frame(FILE *fp, const Frameset &frameset,
				const DeviceFilter &dev_filt) = 0;

	/// Whether the output should be done in CSV format or not
	bool print_csv() const;

protected:
	/**
	 * Print timestamp before the actual frame is printed.
	 * Returns number of characters printed or <0 in case of error */
	void print_timestamp(FILE *fp, const Frameset &frameset);

	const ConfigReader	*m_cfg;
	/**
	 * Print a given number 'num' in 'num_digs' characters with
	 * as many decimal places as possible.
	 * NOTE: max_digits must be 4 or 5!
	 * E.g. print_abbrev_num(13400, 5) returns '13.4K'.
	 */
	void print_abbrev_num(FILE *fp, __u64 num, int max_digs) const;
	void print_abbrev_num(FILE *fp, __u32 num, int max_digs) const;

	/**
	 * Print floats always using 6 characters */
	void print_abbrev_num(FILE *fp, double num) const;
	void print_abbrev_num(FILE *fp, double num, int max_digs,
			      bool more_places = false) const;

	const struct adapter_utilization* get_empty_utilization(__u32 host_id);
	const struct adapter_utilization* get_invalid_utilization(__u32 host_id);
	const struct ioerr_cnt* get_empty_ioerr(struct hctl_ident *identifier);
	const struct zfcpdd_dstat* get_empty_zfcpdd_dstat(__u32 device = 0);
	const struct blkiomon_stat* get_empty_blkiomon_stat(__u32 device = 0);

	/** Print the delimiter appropriate for the output. That's usually
	 * a space for regular output and ',' for CSV. */
	inline void print_delimiter(FILE *fp);

	/// Print a character indicating that the respective value is not valid
	inline void print_invalid(FILE *fp, int width);

	/// set if result should be printed is csv
	bool				m_csv;
	char				m_delim;

private:
	void print_abbreviated(FILE *fp, double num, int leading_places,
			      int max_digs) const;
	void determine_mag_factor(int leading_places, char *magnitude,
				double *factor) const;
	void determine_digs(int leading_places, int max_digs,
			     int *num_full_digs, int *num_places) const;

	struct adapter_utilization	m_util;
	struct adapter_utilization	m_util_invalid;
	struct ioerr_cnt 		m_ioerr;
	struct zfcpdd_dstat		m_dstat;
	struct blkiomon_stat		m_stat;

	/// day of month of last day that was printed
	int				m_prev_day;
};


class PhysAdapterPrinter : public Printer {
public:
	PhysAdapterPrinter(const ConfigReader *cfg, bool csv_mode);

	virtual void print_topline(FILE *fp);
	virtual int print_frame(FILE *fp, const Frameset &frameset,
				const DeviceFilter &dev_filt);

private:
	void print_phys_adpt(FILE *fp, __u32 host_id,
			     int *rc);
	void print_utilization(FILE *fp, const struct abbrev_stat *stat,
			       __u64 count, bool valid);

};


class VirtAdapterPrinter : public Printer {
public:
	VirtAdapterPrinter(const ConfigReader *cfg, bool csv_mode);

	virtual void print_topline(FILE *fp);
	virtual int print_frame(FILE *fp, const Frameset &frameset,
				const DeviceFilter &dev_filt);

private:
	void print_virt_adpt(FILE *fp, __u32 subchnl, int *rc);
	void print_queue_fill(FILE *fp, const struct zfcpdd_dstat *stat,
			      const struct adapter_utilization *res);
	void print_queue_full(FILE *fp, const struct adapter_utilization *res);
	void print_failures(FILE *fp, const struct ioerr_cnt *cnt);
	void print_throughput(FILE *fp, const struct blkiomon_stat *stat,
			      const __u64 interval);
	void print_num_requests(FILE *fp, const struct blkiomon_stat *stat);
};


class TrafficPrinter : public Printer {
public:
	virtual int print_frame(FILE *fp, const Frameset &frameset,
				const DeviceFilter &dev_filt);

protected:
	TrafficPrinter(const ConfigReader *cfg, Collapser &col,
			bool csv_mode);
	virtual ~TrafficPrinter();

	/**
	 * Print the actual row, excluding the first column */
	virtual void print_data_row(FILE *fp,
			   const struct blkiomon_stat *blk_stat,
			   const struct zfcpdd_dstat *zfcp_stat,
			   const __u64 interval) = 0;

	void print_topline_prefix1(FILE *fp);
	void print_topline_prefix2(FILE *fp);
	void print_topline_whitespace(FILE *fp);

	void get_device_list(list<__u64> &lst, const DeviceFilter &dev_filt);

	void get_device_list(list<__u32> &lst, const DeviceFilter &dev_filt);
	void print_device_wwpn(FILE *fp, __u64 wwpn);
	void print_device_chpid(FILE *fp, __u32 chpid);
	void print_device_devno(FILE *fp, __u32 devno);
	void print_device_mp_mm(FILE *fp, __u32 mp_mm,
			       const ConfigReader &cfg,
			       int *rc);
	void print_device(FILE *fp, __u32 dev,
			 const ConfigReader &cfg,
			 int *rc);
	void print_device_all(FILE *fp);

	Aggregator		m_agg_crit;
	/// Multipath devices have variable length
	char		       *m_mp_whitespace;
	char		       *m_mp_topline_pref1;
	char		       *m_mp_topline_pref2;
};


class SummaryTrafficPrinter : public TrafficPrinter {
public:
	SummaryTrafficPrinter(const ConfigReader *cfg,
			      Collapser &col, bool csv_mode);

	virtual void print_topline(FILE *fp);

private:
	virtual void print_data_row(FILE *fp,
			   const struct blkiomon_stat *blk_stat,
			   const struct zfcpdd_dstat *zfcp_stat,
			   const __u64 interval);
	void print_throughput(FILE *fp, const struct blkiomon_stat *stat,
			      const __u64 interval);
	void print_request_stats(FILE *fp, const struct blkiomon_stat *stat);
	void print_io_subsystem_latency(FILE *fp, const struct blkiomon_stat *stat);
	void print_channel_latency(FILE *fp, const struct zfcpdd_dstat *stat);
	void print_fabric_latency(FILE *fp, const struct zfcpdd_dstat *stat);
	void print_latency(FILE *fp, const struct minmax *data);
	void print_latency(FILE *fp, const struct abbrev_stat *data,
			  __u64 count);
};


class DetailedTrafficPrinter : public TrafficPrinter {
public:
	DetailedTrafficPrinter(const ConfigReader *cfg, Collapser &col,
			       bool csv_mode);

	virtual void print_topline(FILE *fp);

private:
	virtual void print_data_row(FILE *fp,
			   const struct blkiomon_stat *blk_stat,
			   const struct zfcpdd_dstat *zfcp_stat,
			   const __u64 interval);
	void print_histogram_io_reqs(FILE *fp,
				    const struct blkiomon_stat *stat);
	void print_histogram_io_subs_lat(FILE *fp,
					const struct blkiomon_stat *stat);
	void print_histogram_channel_lat(FILE *fp,
					const struct zfcpdd_dstat *stat);
	void print_histogram_fabric_lat(FILE *fp,
				       const struct zfcpdd_dstat *stat);
};

#endif

