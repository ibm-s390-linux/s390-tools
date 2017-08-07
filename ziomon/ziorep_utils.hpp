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

#ifndef ZIOREP_UTILS_HPP
#define ZIOREP_UTILS_HPP

#include "ziorep_framer.hpp"
#include "ziorep_cfgreader.hpp"
#include "ziorep_printers.hpp"
#include "ziorep_collapser.hpp"

extern "C" {
#include "ziomon_dacc.h"
}


#include <linux/types.h>

/**
 * Parse date provided in 'str' and store as seconds since 1970 in 'tgt'. */
int get_datetime_val(const char *str, __u64 *tgt);


/**
 * Print the provided value (seconds since 1970) in our common style. */
const char* print_time_formatted(__u64 timestamp);

/**
 * Print the provided value (seconds since 1970) in our common style. */
const char* print_time_formatted_short(__u64 timestamp);

/**
 * Adjust the timeframe to appropriate interval boundaries */
int adjust_timeframe(const char* filename, __u64 *begin, __u64 *end,
		     __u32 *interval);


/**
 * Add all present devices to the device filter */
int add_all_devices(ConfigReader &cfg, DeviceFilter &dev_filt);


/**
 * Utility function to retrieve a list of all devices that we have data for.
 * Result is put into 'dev_filt'.
 */
int get_all_devices(const char *filename, DeviceFilter &dev_filt,
		    ConfigReader &cfg);

/**
 * Run over frames and print each one.
 * Returns <0 in case of error and number of frames printed otherwise.
 */
int print_report(FILE *fp, __u64 begin, __u64 end,
				__u32 interval,
				char *filename, __u64 topline,
				list<MsgTypes> *filter_types,
				DeviceFilter &dev_filter, Collapser &col,
				Printer &printer);

/**
 * Print summary of available data.
 * 'fp' is the file to write all output to, 'filename' the standard
 * basename.
 * Returns number of characters printed.
 */
int print_summary_report(FILE *fp, char *filename, ConfigReader &cfg);


/**
 * Minor help function to parse a string into a __u64 and check
 * that it is >= 0 */
int parse_topline_arg(char *str, __u64 *arg);

FILE* open_csv_output_file(const char *filename, const char *extension,
			   int *rc);

/**
 * accessors for internal representation of device and subchannel bus-IDs
 * packed:   takes channel subsystem, subchannel set, device number/subchannel
 *           returns 32 bit integer
 * unpacked: takes 32 bit integer
 *           returns channel subsystem, subchannel set, device number/subchannel
 *           as a comma separated list
 */
#define ZIOREP_BUSID_PACKED(busid_part1, busid_part2, busid_part3) \
	(((busid_part1) << 24) | ((busid_part2) << 16) | (busid_part3))
#define ZIOREP_BUSID_UNPACKED(busid) \
	((busid) >> 24) & 0xFF, ((busid) >> 16) & 0xFF, (busid) & 0xFFFF

#endif

