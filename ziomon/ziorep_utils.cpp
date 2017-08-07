/*
 * FCP report generators
 *
 * Utility functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>

#include "ziorep_utils.hpp"
#include "ziorep_cfgreader.hpp"

extern "C" {
	#include "ziomon_msg_tools.h"
}

extern const char *toolname;
extern int verbose;



/**
 * Read all essential data from the files,
 * including the headers, timestamp of first message
 * and a DeviceFilter for all available devices.
 * Note that 'agg' is NULL if not available and must
 * be free()'d otherwise. */
static int get_initial_data(const char *filename, struct file_header *f_hdr,
			    struct aggr_data **agg,
			    DeviceFilter &dev_filt, ConfigReader &cfg)
{
	FILE *fp;
	int rc = 0;
	__u64 begin;

	if (open_data_files(&fp, filename, f_hdr, agg))
		return -1;
	close_data_files(fp);

	/*
	 * Retrieve first real frame
	 */
	MsgTypeFilter msgtype_filter;
	NoopCollapser	nop_col;
	Frameset frameset(&nop_col);
	list<MsgTypes> type_flt;
	type_flt.push_back(ioerr);

	// we retrieve the first interval only, and eventually the .agg data
	// as well
	if (*agg)
		begin = (*agg)->end_time;
	else
		begin = f_hdr->begin_time;

	Framer framer(begin,
		      begin + f_hdr->interval_length,
		      f_hdr->interval_length, &type_flt,
		      (DeviceFilter*)NULL, filename, &rc);
	vector <struct ioerr_cnt*> ioerrs;
	do {
		if ( framer.get_next_frameset(frameset) != 0 ) {
			fprintf(stderr, "%s: Could not read"
				" any frames in %s%s\n", toolname, filename,
				DACC_FILE_EXT_LOG);
			return -2;
		}

		/*
		 * Construct a DeviceFilter with all devices.
		 * NOTE: The very first ioerr msg might already have been moved to the .agg
		 * file - hence we have to consider the .agg data as well!
		 */
		ioerrs = frameset.get_ioerr_stats();
		rc = 0;
		for (vector<struct ioerr_cnt*>::const_iterator i = ioerrs.begin();
		      i != ioerrs.end(); ++i) {
			vverbose_msg("    add device: hctl=[%d:%d:%d:%d], mm=%d\n",
				    (*i)->identifier.host, (*i)->identifier.channel,
				    (*i)->identifier.target, (*i)->identifier.lun,
				    cfg.get_mm_by_ident(&(*i)->identifier, &rc));
			dev_filt.add_device(cfg.get_mm_by_ident(&(*i)->identifier, &rc), &(*i)->identifier);
			if (rc)
				return -1;
		}
	} while ( frameset.is_aggregated() && !ioerrs.size());

	if (dev_filt.get_host_id_list().size() == 0 || dev_filt.get_mm_list().size() == 0) {
		fprintf(stderr, "%s: Could not retrieve initial data"
			" - data files corrupted or broken, or the .agg file is missing.\n",
			toolname);
		return -1;
	}

	verbose_msg("retrieve initial data FINISHED\n");

	return 0;
}


int add_all_devices(ConfigReader &cfg, DeviceFilter &dev_filt)
{
	int rc = 0;
	list<__u32> lst;

	cfg.get_unique_mms(lst);
	for (list<__u32>::const_iterator i = lst.begin();
	      i != lst.end(); ++i) {
		dev_filt.add_device(*i, cfg.get_ident_by_mm_internal(*i, &rc));
		assert(rc == 0);
	}

	return 0;
}


int get_all_devices(const char *filename, DeviceFilter &dev_filt,
		    ConfigReader &cfg)
{
	struct file_header f_hdr;
	struct aggr_data *agg;
	int rc = 0;

	rc = get_initial_data(filename, &f_hdr, &agg, dev_filt, cfg);
	discard_aggr_data_struct(agg);
	free(agg);

	return rc;
}


#define BUF_SZ		256

const char* print_time_formatted(__u64 timestamp)
{
	time_t t = timestamp;
	static char buf[BUF_SZ];

	strftime(buf, BUF_SZ - 1, "%Y-%m-%d %H:%M:%S", localtime(&t));

	return buf;
}


const char* print_time_formatted_short(__u64 timestamp)
{
	time_t t = timestamp;
	static char buf[BUF_SZ];

	strftime(buf, BUF_SZ - 1, "%H:%M:%S", localtime(&t));

	return buf;
}


// adjust lower timestamp to last frame boundary that was touched
static __u64 round_lower_boundary(__u64 time, __u64 begin,
			       __u32 interval_length)
{
	__u64 tmp = (time - begin)%interval_length;

	if (tmp)
		time += (interval_length - tmp);

	return time;
}


// adjust upper timestamp to last frame boundary that was touched
static __u64 round_upper_boundary(__u64 time, __u64 begin,
				     __u32 interval_length)
{
	__u64 tmp = (time - begin)%interval_length;

	if (tmp)
		time -= tmp;

	return time;
}


/**
 * The times will be adjusted to respective exakt frame boundaries.
 * The end time is only ever used to determine whether we are done - we stop
 * in case the begin of the timeframe is later than the end date.
 * Note that in case we scratch into the .agg data, we
 * (a) take all of it
 * (b) synonymously associate the .agg data with the timestamp of its
 *     final frame. This is _utterly_ important, especially in context
 *     with the interval: If it is user adjusted, and the date range touches
 *     the .agg data, we adjust the begin to the .agg data's final frame's
 *     timestamp, and make sure that when we process the agg data, the next
 *     frame is 1 unit of the original interval length away. Only after we
 *     have shifted into the 'regular' .log data can we apply any user-set
 *     interval length.
 * */
int adjust_timeframe(const char *filename, __u64 *begin, __u64 *end,
		     __u32 *interval)
{
	struct file_header f_hdr;
	struct aggr_data *agg = NULL;
	FILE *fp;
	time_t t;
	int rc = 0;

	verbose_msg("adjust timeframe:\n");

	// check begin and end time
	if (*begin > *end) {
		fprintf(stderr, "%s: Start time must be"
			" prior to end time.\n", toolname);
		rc = -1;
		goto out;
	}

	if (open_data_files(&fp, filename, &f_hdr, &agg)) {
		rc = -1;
		goto out;
	}
	close_data_files(fp);

	// check if begin scratches into .agg data
	// if so, we use the _end_ time of the .agg frame
	if (*begin == 0 && agg) {
		verbose_msg("    begin time: take from .agg data\n");
		*begin = agg->end_time;
	}
	else if (agg && *begin < agg->begin_time) {
		fprintf(stderr, "%s: Warning: Begin of timeframe is before"
			" earliest available data, which is %s.\n", toolname,
			print_time_formatted(agg->begin_time));
		*begin = agg->end_time;
		verbose_msg("    begin time: adjust to begin from .agg data\n");
	}
	else if (agg && *begin <= agg->end_time) {
		*begin = agg->end_time;
		verbose_msg("    begin time: set to end of .agg data\n");
	}
	else if (*begin < f_hdr.begin_time) {
		*begin = f_hdr.begin_time;
		verbose_msg("    begin time: adjust to begin of .log data\n");
	}
	else if (*begin > f_hdr.end_time) {
		fprintf(stderr, "%s: Begin of timeframe is past the"
			" end of available data, which is %s.\n",
			toolname, print_time_formatted(f_hdr.end_time));
		rc = -1;
		goto out;
	}
	else {
		verbose_msg("    begin time: round to nearest boundary\n");
		*begin = round_lower_boundary(*begin, f_hdr.begin_time, f_hdr.interval_length);
	}
	t = *begin;
	verbose_msg("    begin time set to: %s", ctime(&t));

	if (*end == UINT64_MAX) {
		*end = f_hdr.end_time;
		verbose_msg("    end time  : take from .log data\n");
	}
	else if (agg && *end < agg->begin_time) {
		fprintf(stderr, "%s: End of timeframe is prior to earliest"
			" available data, which is %s.\n", toolname,
			print_time_formatted(agg->begin_time));
		rc = -1;
		goto out;
	}
	else if (agg && *end < agg->end_time) {
		*end = agg->end_time;
		verbose_msg("    end time  : take from .agg data\n");
	}
	else if (!agg && *end < f_hdr.begin_time) {
		fprintf(stderr, "%s: End of timeframe is prior to earliest"
			" available data, which is %s.\n", toolname,
			print_time_formatted(f_hdr.begin_time));
		rc = -1;
		goto out;
	}
	else if (*end > f_hdr.end_time) {
		fprintf(stderr, "%s: Warning: End of timeframe is after"
			" latest available data, which is %s.\n", toolname,
			print_time_formatted(f_hdr.end_time));
		*end = f_hdr.end_time;
		verbose_msg("    end time  : adjust to end of .log data\n");
	}
	else {
		*end = round_upper_boundary(*end, f_hdr.begin_time,
					       f_hdr.interval_length);
		verbose_msg("    end time  : round to nearest boundary\n");
	}
	t = *end;
	verbose_msg("    end time set to  : %s", ctime(&t));
	assert((*end - *begin) % f_hdr.interval_length == 0);

	if (*interval == UINT32_MAX) {
		*interval = f_hdr.interval_length;
		verbose_msg("using original interval length: %lus\n",
			    (long unsigned int)*interval);
	}
	/* the exact frame boundaries don't include the length of the very
	   first interval, so we have to add one more to our calculations */
	if (*interval && (*end - *begin + f_hdr.interval_length) % *interval != 0) {
		// cut off rest in case of user-set interval
		*end -= (*end - *begin) % *interval + f_hdr.interval_length;
		t = *end;
		verbose_msg("    cut off at : %s", ctime(&t));
	}

	// check if the interval is correct
	if (*interval % f_hdr.interval_length) {
		fprintf(stderr, "%s: Data aggregation interval %lu"
			" is incompatible with source data. Please use"
			" a multiple of %lu and try again.\n", toolname,
			(long unsigned int)*interval,
			(long unsigned int)(f_hdr.interval_length));
		rc = -1;
		goto out;
	}

out:
	if (agg) {
		discard_aggr_data_struct(agg);
		free(agg);
	}

	return rc;
}


int print_report(FILE *fp, __u64 begin, __u64 end, __u32 interval,
				char *filename, __u64 topline,
				list<MsgTypes> *filter_types,
				DeviceFilter &dev_filter, Collapser &col,
				Printer &printer)
{
	int frames_printed = 0;
	bool first_time = true;
	time_t t;
	int rc = 0;
	Frameset frameset(&col);
	Framer framer(begin, end, interval,
		      filter_types, &dev_filter,
		      filename, &rc);

	if (rc)
		return -1;

	if (topline && printer.print_csv()) {
		fprintf(stderr, "%s: Warning: Cannot use '-t' with CSV mode,"
			" ignoring\n", toolname);
		topline = 0;
	}

	verbose_msg("print report for:\n");
	t = (time_t)begin;
	verbose_msg("    begin    : %s", ctime(&t));
	t = (time_t)end;
	verbose_msg("    end      : %s", (end == UINT64_MAX ? "-\n" : ctime(&t)));
	verbose_msg("    interval : %lu\n", (long unsigned int)interval);
	verbose_msg("    topline  : %llu\n", (long long unsigned int)topline);
	verbose_msg("    csv mode : %d\n", printer.print_csv());

	while ( (rc = framer.get_next_frameset(frameset, true)) == 0 ) {
		vverbose_msg("printing frameset %d\n", frames_printed);
		if (first_time || (topline && frames_printed % topline == 0)) {
			first_time = false;
			printer.print_topline(fp);
		}
		if (printer.print_frame(fp, frameset, dev_filter) < 0)
			return -1;
		++frames_printed;
	}

	if (rc > 0)
		return frames_printed;

	return rc;
}


int print_summary_report(FILE *fp, char *filename, ConfigReader &cfg)
{
	int rc = 0;
	int lrc=0;
	struct file_header f_hdr;
	struct aggr_data *a_hdr;
	DeviceFilter dev_filt;

	if (get_initial_data(filename, &f_hdr, &a_hdr, dev_filt, cfg))
		return -1;

	rc += fprintf(fp, "Data Summary\n");
	rc += fprintf(fp, "------------\n");

	rc += fprintf(fp, "Aggregated range: ");
	if (a_hdr) {
		rc += fprintf(fp, "%s to ",
			      print_time_formatted(a_hdr->begin_time - f_hdr.interval_length));
		rc += fprintf(fp, "%s\n",
			      print_time_formatted(a_hdr->end_time));
	}
	else
		rc += fprintf(fp, "none\n");

	discard_aggr_data_struct(a_hdr);
	free(a_hdr);
	a_hdr = NULL;

	rc += fprintf(fp, "Detailed range:   %s to ",
		      print_time_formatted(f_hdr.begin_time - f_hdr.interval_length));
	rc += fprintf(fp, "%s\n", print_time_formatted(f_hdr.end_time));
	rc += fprintf(fp, "Interval length:  %d seconds\n",
		      f_hdr.interval_length);

	list<__u32> disks = dev_filt.get_mm_list();
	list<__u32> host_ids  = dev_filt.get_host_id_list();
	int first = 1;
	const char *frmt;
	for (list<__u32>::const_iterator i = host_ids.begin();
	      i != host_ids.end(); ++i) {
		if (first) {
			frmt = "HBA/CHPID:        %x.%x.%04x/%x\n";
			first = 0;
		}
		else
			frmt = "                  %x.%x.%04x/%x\n";
		rc += fprintf(fp, frmt, ZIOREP_BUSID_UNPACKED(cfg.get_devno_by_host_id(*i, &lrc)),
			      cfg.get_chpid_by_host_id(*i, &lrc));
		if (lrc)
			return -1;
	}

	first = 1;
	for (list<__u32>::const_iterator i = disks.begin();
	      i != disks.end(); ++i) {
		if (first) {
			frmt = "WWPN/LUN (dev):   0x%016Lx/0x%016Lx (%s)\n";
			first = 0;
		}
		else
			frmt = "                  0x%016Lx/0x%016Lx (%s)\n";
		rc += fprintf(fp, frmt, cfg.get_wwpn_by_mm_internal(*i, &lrc),
			      cfg.get_lun_by_mm_internal(*i, &lrc),
			      cfg.get_dev_by_mm_internal(*i, &lrc));
		if (lrc)
			return -1;
	}

	return rc;
}

/* Calculates seconds since 1970 _without_ caring for daylight
   savings time (comtrary to mktime() et al).
   It does not care for leap years and the like, which is OK,
   since we use it in a very narrow scenario: To calculate any
   daylight savings time related shifts.
   Hence: Dont't use if you're not sure what you are doing... */
static __u64 secs_since_1970(const struct tm *t) {
	__u64 res = 0;
	res += t->tm_sec;
	res += 60 * t->tm_min;
	res += 3600 * t->tm_hour;
	res += 86400 * t->tm_yday;
	res += 86400 * 365 * t->tm_year;

	return res;
}


int get_datetime_val(const char *str, __u64 *tgt)
{
	struct tm t, t_old;
	char *ret;

	// strptime only sets
	memset(&t, 0, sizeof(struct tm));
	ret = strptime(str, "%Y-%m-%d %H:%M", &t);
	if (ret == NULL || *ret != '\0') {
		ret = strptime(str, "%Y-%m-%d %H:%M:%S", &t);
		if (ret == NULL || *ret != '\0') {
			fprintf(stderr, "%s: Could not parse date %s."
				" Please use format as specified in"
				" man-page\n", toolname, str);
			return -1;
		}
	}
	t_old = t;
	*tgt = mktime(&t);
	// if daylight savings time applies, 't' has been adjusted,
	// so we have to correct
	if (t_old.tm_hour != t.tm_hour)
		*tgt -= secs_since_1970(&t) - secs_since_1970(&t_old);
	verbose_msg("datetime value from user after translation: %s", ctime((const time_t *)tgt));

	return 0;
}


int parse_topline_arg(char *str, __u64 *arg)
{
	char *p;

	*arg = strtoull(str, &p, 0);
	if (*arg == ULLONG_MAX) {
		fprintf(stderr, "%s: Cannot convert"
			" %s, over/underflow occurred. Try a smaller/larger"
			" value.\n", toolname, str);
		return -1;
	}
	if (*p != '\0') {
		fprintf(stderr, "%s: Non-numeric"
			" characters in argument '%s' to option '-t'. Make"
			" sure to use only numeric characters.\n", toolname,
			str);
		return -1;
	}

	return 0;
}

FILE* open_csv_output_file(const char *filename, const char *extension,
			   int *rc)
{
	char *tmp;
	FILE *fp = NULL;

	*rc = 0;

	tmp = (char*)malloc(strlen(filename) + strlen(extension) + 1);

	sprintf(tmp, "%s%s", filename, extension);
	fp = fopen(tmp, "w");

	if (!fp) {
		fprintf(stdout, "%s: Could not open file %s. Make sure that you"
			" have sufficient permissions and try again.\n", toolname, tmp);
		*rc = -1;
	}
	else
		fprintf(stdout, "Exporting data in CSV format to %s\n", tmp);

	free(tmp);

	return fp;
}




