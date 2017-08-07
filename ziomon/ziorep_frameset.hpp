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

#ifndef ZIOREP_FRAMESET
#define ZIOREP_FRAMESET

#include <list>
#include <vector>

#include "ziorep_collapser.hpp"

extern "C" {
	#include "ziomon_util.h"
	#include "blkiomon.h"
	#include "ziomon_zfcpdd.h"
	#include "ziomon_dacc.h"
}

using std::list;
using std::vector;

class Frameset {

public:
	/**
	 * If 'normalize' is set, incoming data with varying sample
	 * sizes per interval (namely utilization messages and zfcpdd data)
	 * will be normalized so that different sample sizes will not
	 * result in different weighting when aggregating.
	 */
	Frameset(const Collapser *col, bool normalize = true);
	~Frameset();

	/**
	 * Clear frame-related structures */
	void reinit();

	/// get pointer to collapser
	const Collapser* get_collapser() const;

	/**
	 * Since we don't necessarily have datasets for all messages in each
	 * frame, utilization and the qdio portion of zfcpdd messages
	 * can be inaccurate when aggregated. This method makes up for it by
	 * calculating how many datasets are expected and fixing the data so
	 * that mean values (and minima!) correctly reflect the frames with
	 * inactivity.
	 * 'interval_length' is the length of the intervals in the source data,
	 * NOT any user-specified interval!
	 */
	void replace_missing_datasets(int interval_length);

	/**
	 * Add structures to frame, automatically aggregates structures for
	 * the same device if possible.
	 */
	void add_data(struct adapter_utilization *msg);
	void add_data(struct ioerr_cnt *msg);
	void add_data(struct blkiomon_stat *msg);
	void add_data(struct zfcpdd_dstat *msg);

	/**
	 * Get start time of respective timeframe. This is the actually used
	 * start time, which means that it is slightly earlier than the
	 * expected start time so that messages that arrived slightly
	 * earlier are included in this this rather than the previous frame. */
	__u64 get_begin_time() const;

	/**
	* Get end time of respective timeframe. This is the actually used
	* end time, which means that messages that arrived slightly
	* later than the prediced end time might still have been included
	* since they belong to this rather than to the next frame. */
	__u64 get_end_time() const;

	/* Get the timestamp of the frame. The timestamp
	 * is the timestamp of the last message that was added to the frameset.
	 */
	__u64 get_timestamp() const;

	/**
	 * Get duration of respective timeframe */
	__u64 get_duration() const;

	/**
	 * Set begin and end of the interval, as well as the predicted
	 * timestamp of the last interval where all the messages should have
	 * arrived */
	void set_timeframe(__u64 begin, __u64 end, __u64 timestamp);

	/** Retrieve ioerr result.
	 * WARNING: Memory ownership remains in class - copy if necessary!
	* FURTHER WARNING: Some of the pointers can be NULL!
	 */
	const vector<struct ioerr_cnt*>& get_ioerr_stats() const;

	/** Retrieve zfcpdd result.
	*  Can be NULL.
	 */
	const struct zfcpdd_dstat* get_first_zfcpdd_stat() const;

	/** Retrieve blkiomon result.
	 *  Can be NULL.
	 */
	const struct blkiomon_stat* get_first_blkiomon_stat() const;

	const struct adapter_utilization* get_utilization_stat_by_host_id(__u32 h_id) const;

	const struct adapter_utilization* get_utilization_stat_by_chpid(__u32 chpid) const;

	const struct adapter_utilization* get_utilization_stat_by_devno(__u32 devno) const;

	const struct ioerr_cnt* get_ioerr_stat_by_chpid(__u32 chpid) const;

	const struct ioerr_cnt* get_ioerr_stat_by_devno(__u32 devno) const;

	const struct blkiomon_stat* get_blkiomon_stat_by_chpid(__u32 chpid) const;

	const struct blkiomon_stat* get_blkiomon_stat_by_devno(__u32 devno) const;

	const struct blkiomon_stat* get_blkiomon_stat_by_wwpn(__u64 wwpn) const;

	const struct blkiomon_stat* get_blkiomon_stat_by_mp_mm(__u32 mp_mm) const;

	const struct blkiomon_stat* get_blkiomon_stat_by_mm(__u32 mm) const;

	const struct zfcpdd_dstat* get_zfcpdd_stat_by_chpid(__u32 chpid) const;

	const struct zfcpdd_dstat* get_zfcpdd_stat_by_devno(__u32 devno) const;

	const struct zfcpdd_dstat* get_zfcpdd_stat_by_wwpn(__u64 wwpn) const;

	const struct zfcpdd_dstat* get_zfcpdd_stat_by_mp_mm(__u32 mp_mm) const;

	const struct zfcpdd_dstat* get_zfcpdd_stat_by_mm(__u32 mm) const;

	void set_aggregated(bool aggr);

	/** Is the frameset built from the .agg file? */
	bool is_aggregated() const;

	/** Query whether the frameset holds data or not */
	bool is_empty() const;

protected:
	struct utilization_wrapper {
		/// number aggregated datasets
		int			 	 counter;
		struct adapter_utilization	*stat;
	};

	struct zfcpdd_wrapper {
		/// number aggregated datasets
		int			 counter;
		struct zfcpdd_dstat	*stat;
	};

private:
	bool m_empty;

	void normalize_util_stat(struct utilization_stats *stats);

	void normalize_stat(struct abbrev_stat *stat, __u64 count);

	/// rescale zfcpdd_dstat->channel_latency from ns to us
	void normalize_zfcpdd_stat(struct zfcpdd_dstat *stat);

	void init_utilization_wrapper(struct utilization_wrapper *wrp);

	void init_zfcpdd_wrapper(struct zfcpdd_wrapper *wrp);

	void add_zero_frames(struct utilization_wrapper *wrp,
			     int num_expected, int interval_length);

	int get_by_chpid(__u32 chpid) const;

	int get_by_devno(__u32 devno) const;

	int get_by_mp_mm(__u32 mp_mm) const;

	int get_by_mm(__u32 mm) const;

	int get_by_wwpn(__u64 wwpn) const;

	/// returns index of 'val' as found in 'lst', <0 otherwise
	int find_index(const list<__u32> &lst, __u32 val) const;

	/// returns index of 'val' as found in 'lst', <0 otherwise
	int find_index(const list<__u64> &lst, __u64 val) const;

	/// zfcpdd statistics, ordered by host adapter no (ascending)
	vector<struct utilization_wrapper>	m_util_stats;

	/** ioerror stats, ordered by device identifiers
	 * (hierarchical & ascending) */
	vector<struct ioerr_cnt*>		m_ioerr_stats;

	/// zfcpdd statistics, ordered by device (ascending)
	vector<struct zfcpdd_wrapper>		m_zfcpdd_stats;
	/// zfcpdd statistics, ordered by device (ascending)
	vector<struct blkiomon_stat*>		m_blkiomon_stats;
	/// begin of the frame
	__u64					m_start_time;
	/// end of the frame
	__u64					m_end_time;
	/// timestamp of latest message added to the set
	__u64					m_timestamp;
	/// indicates whether the frameset is from the .agg file
	bool					m_aggregated;

	/** provides translation from data objects to (vector) index
	  * This member is kept throughout, even survives calls to reinit(). */
	const Collapser			       *m_collapser;

	/** normalize all incoming datasets so they are equally weighted
	 * when aggregating over multiple frames */
	bool					m_normalize;
};


#endif

