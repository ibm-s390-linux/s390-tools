/* Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIBCPUMF_H
#define LIBCPUMF_H

#include <sched.h>
#include <stdbool.h>

#define	S390_CPUMF_CF		"/sys/devices/cpum_cf/"
#define	S390_CPUMF_CFDIAG	"/sys/devices/cpum_cf_diag/"
#define	S390_CPUMF_SF		"/sys/devices/cpum_sf/"
#define S390_CPUS_POSSIBLE	"/sys/devices/system/cpu/possible"
#define S390_CPUS_ONLINE	"/sys/devices/system/cpu/online"
#define S390_CPUMSF_BUFFERSZ	"/sys/module/kernel/parameters/cpum_sfb_size"
#define S390_SYSFS_PAI_CRYPTO	"/sys/devices/pai_crypto/"

/**
 * Read out the PMU type from a given file.
 *
 * Return the PMU type number assigned to this PMU by the kernel. This is
 * a non zero number.
 *
 * @param[in]    dirname   Name of the event directory in sysfs
 * @retval       >=0       Number of PMU assigned by the kernel
 * @retval       -1        PMU unknown to kernel
 */
int libcpumf_pmutype(const char *dirname);

/**
 * Read out the CPU list from a given file name, for example from files
 * /sys/devices/system/cpu/online or /sys/devices/system/cpu/possible.
 *
 * Return the cpu_set_t created from parsing the CPU list in the second
 * parameter.
 *
 * @param[in]    buffer   Comma separated string of a CPU list
 * @param[in]    filename Name of a sysfs CPU list file name
 * @param[out]   mask     Converted buffer into cpu_set_t mask structure
 * @retval       0        Successful conversion of cpulist
 * @retval       -1       Unsuccessful conversion of cpulist
 */
int libcpumf_cpuset(const char *buffer, cpu_set_t *mask);
int libcpumf_cpuset_fn(const char *filename, cpu_set_t *mask);

/**
 * Read CPU Measurement Counting Facility hardware information
 *
 * Return true if CPU Measurement Counter facility information has been
 * retrieved and is valid.
 *
 * Return false if the information could not be extracted from the file.
 *
 * @param[out]   cfvn     Contains CPUMF counter first version number
 * @param[out]   csvn     Contains CPUMF counter second version number
 * @param[out]   auth     Contains CPUMF counter set authorization level
 * @retval       true     Information returned in parameters is valid
 * @retval       false    Information could not be retrieved
 */
bool libcpumf_cpumcf_info(int *cfvn, int *csvn, int *auth);

/**
 * Return true if CPU Measurement Counter Facility is available.
 *
 * @retval       true     CPU Measurement Counter Facility is available
 * @retval       false    CPU Measurement Counter Facility is not available
 */
bool libcpumf_have_cpumcf(void);

/**
 * Read CPU Measurement Sampling Facility hardware information
 *
 * Read all necessary information from /sysfs file /proc/service_levels
 * to return CPU Measurement Counter Sampling facility information
 * characteristics.
 * Return true on success and false when the data can not be retrieved.
 *
 * @param[out]   min       Minimum supported sampling interval
 * @param[out]   max       Maximum supported sampling interval
 * @param[out]   speed     Current CPU speed, number of CPU cylces per
 *                         microsecond
 * @param[out]   basic_sz  Basic sample size in bytes
 * @param[out]   diag_sz   Diagnostic sample size in bytes
 * @retval       true      Information returned in parameters is valid
 * @retval       false     Information could not be retrieved
 */
bool libcpumf_cpumsf_info(unsigned long *min, unsigned long *max,
			  unsigned long *speed, int *basic_sz, int *diag_sz);

/**
 * Return true if CPU Measurement Sampling Facility is available.
 *
 * @retval       true     CPU Measurement Sampling Facility is available
 * @retval       false    CPU Measurement Sampling Facility is not available
 */
bool libcpumf_have_cpumsf(void);

/**
 * Return true if CPU Measurement Sampling Facility buffer sizes are
 * available.
 *
 * @retval       true     CPU Measurement Sampling Facility buffer sizes are
 *                        available
 * @retval       false    CPU Measurement Sampling Facility buffer sizes are
 *                        not available
 */
bool libcpumf_have_sfb(void);

/**
 * Read CPU Measurement Sampling Facility supported sampling buffer sizes.
 *
 * Return the minimum and maximum CPU Measurement sampling facitity buffer
 * sizes supported.
 * Return true on success and false otherwise.
 *
 * @param[out]   min       Minimum supported sampling buffer size
 * @param[out]   max       Maximum supported sampling buffer size
 * @retval       true      Information returned in parameters is valid
 * @retval       false     Information could not be retrieved
 */
bool libcpumf_sfb_info(unsigned long *min, unsigned long *max);

/**
 * Return true if PAI_CRYPTO counter Facility is supported.
 *
 * @retval       true     PAI_CRYPTO counter Facility is available
 * @retval       false    PAI_CRYPTO counter Facility is not available
 */
bool libcpumf_have_pai_crypto(void);
#endif
