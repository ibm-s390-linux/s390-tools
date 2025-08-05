/* Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIBCPUMF_H
#define LIBCPUMF_H

#include <sched.h>
#include <stdbool.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>

#define	S390_CPUMF_CF		"devices/cpum_cf/"
#define	S390_CPUMF_CFDIAG	"devices/cpum_cf_diag/"
#define	S390_CPUMF_SF		"devices/cpum_sf/"
#define S390_CPUS_ONLINE	"devices/system/cpu/online"
#define S390_CPUMSF_BUFFERSZ	"module/kernel/parameters/cpum_sfb_size"
#define S390_SYSFS_PAI_CRYPTO	"devices/pai_crypto/"
#define S390_SYSFS_PAI_EXT	"devices/pai_ext/"
#define S390_SYSFS_PAI_NNPA	S390_SYSFS_PAI_EXT "events/NNPA_ALL"

#define CPUMF_CTRSET_NONE		0
#define CPUMF_CTRSET_EXTENDED		1
#define CPUMF_CTRSET_BASIC		2
#define CPUMF_CTRSET_PROBLEM_STATE	4
#define CPUMF_CTRSET_CRYPTO		8
#define CPUMF_CTRSET_MT_DIAG		32

/**
 * Return counter set a counter belongs to.
 *
 * Return the counter set a given counter belongs to, given the
 * CPU Measurement facility counter version first and second number.
 *
 * @param[in]    ctr   Counter number
 * @param[in]    cfvn  CPUM Counter facility first version number
 * @param[in]    csvn  CPUM Counter facility second version number
 * @retval       >=0   Counter set number to counter belongs to
 */
int libcpumf_ctrset(int ctr, int cfvn, int csvn);

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
 * Read out the PMU name from a given type.
 *
 * Return the PMU name this PMU was registered in kernel. If the PMU was
 * registered without a name, it is not listed in the directory.
 * The caller must free the memory returned by name.
 *
 * @param[in]    wanted_type Type number of the PMU
 * @param[out]   name        Name of the PMU (when retval is 0)
 * @retval       0           PMU wanted_type detected and PMU name valid
 * @retval       -1          No PMU with wanted_type
 */
int libcpumf_pmuname(unsigned int wanted_type, char **name);

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
 * @param[out]   speed     Current CPU speed, number of CPU cycles per
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

/**
 * Return true if PAI_EXTENSION Facility is supported.
 *
 * @retval       true     PAI_EXTENSION counter Facility is available
 * @retval       false    PAI_EXTENSION counter Facility is not available
 */
bool libcpumf_have_pai_ext(void);

/**
 * Return true if PAI_NNPA counter Facility is supported. This PMU facility
 * supports the Neural Network Processing Assist (NNPA) counter set.
 *
 * @retval       true     PAI_NNPA counter Facility is available
 * @retval       false    PAI_NNPA counter Facility is not available
 */
bool libcpumf_have_pai_nnpa(void);

/**
 * Wrapper for the perf_event_open syscall used to configure performance events.
 * This function simplifies usage of perf_event_open and provides a consistent
 * interface for libcpumf internals.
 *
 * @param hw_event   Pointer to perf_event_attr structure describing the event
 * @param pid        Target process ID (0 for current process)
 * @param cpu        Target CPU (-1 for all CPUs)
 * @param group_fd   File descriptor of event group leader, or -1 if none
 * @param flags      Additional flags (usually 0)
 *
 * @return           File descriptor for the opened event on success
 * @return           -1 on failure, errno is set appropriately
 */

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
		     unsigned long flags);
#endif
