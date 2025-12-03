/*
 * util_time - Time related helper functions and definitions
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_TIME_H
#define LIB_UTIL_TIME_H

#define NSEC_PER_USEC	1000L
#define NSEC_PER_MSEC	1000000L
#define NSEC_PER_SEC	1000000000L

#define USEC_PER_MSEC	1000L
#define USEC_PER_SEC	1000000L

#define MSEC_PER_SEC	1000L

/**
 * Convert nanoseconds to microseconds
 *
 * Convert value from nanoseconds to microseconds by dividing the
 * value to NSEC_PER_USEC constant.
 *
 * @param[in] val Time value in nanoseconds
 *
 * @returns Time value in microseconds
 */
static inline double util_nsecs_to_usecs(double val)
{
	return val / NSEC_PER_USEC;
}

/**
 * Convert nanoseconds to milliseconds
 *
 * Convert value from nanoseconds to milliseconds by dividing the
 * value to NSEC_PER_MSEC constant.
 *
 * @param[in] val Time value in nanoseconds
 *
 * @returns Time value in milliseconds
 */
static inline double util_nsecs_to_msecs(double val)
{
	return val / NSEC_PER_MSEC;
}

/**
 * Convert nanoseconds to seconds
 *
 * Convert value from nanoseconds to seconds by dividing the
 * value to NSEC_PER_SEC constant.
 *
 * @param[in] val Time value in nanoseconds
 *
 * @returns Time value in seconds
 */
static inline double util_nsecs_to_secs(double val)
{
	return val / NSEC_PER_SEC;
}

/**
 * Convert microseconds to nanoseconds
 *
 * Convert value from microseconds to nanoseconds by multiplying the
 * value with NSEC_PER_USEC constant.
 *
 * @param[in] val Time value in microseconds
 *
 * @returns Time value in nanoseconds
 */
static inline double util_usecs_to_nsecs(double val)
{
	return val * NSEC_PER_USEC;
}

/**
 * Convert microseconds to milliseconds
 *
 * Convert value from microseconds to milliseconds by dividing the
 * value to USEC_PER_MSEC constant.
 *
 * @param[in] val Time value in microseconds
 *
 * @returns Time value in milliseconds
 */
static inline double util_usecs_to_msecs(double val)
{
	return val / USEC_PER_MSEC;
}

/**
 * Convert microseconds to seconds
 *
 * Convert value from microseconds to seconds by dividing the
 * value to USEC_PER_SEC constant.
 *
 * @param[in] val Time value in nanoseconds
 *
 * @returns Time value in seconds
 */
static inline double util_usecs_to_secs(double val)
{
	return val / USEC_PER_SEC;
}

/**
 * Convert milliseconds to nanoseconds
 *
 * Convert value from milliseconds to nanoseconds by multiplying the
 * value with NSEC_PER_MSEC constant.
 *
 * @param[in] val Time value in milliseconds
 *
 * @returns Time value in nanoseconds
 */
static inline double util_msecs_to_nsecs(double val)
{
	return val * NSEC_PER_MSEC;
}

/**
 * Convert milliseconds to microseconds
 *
 * Convert value from milliseconds to microseconds by multiplying the
 * value with USEC_PER_MSEC constant.
 *
 * @param[in] val Time value in milliseconds
 *
 * @returns Time value in microseconds
 */
static inline double util_msecs_to_usecs(double val)
{
	return val * USEC_PER_MSEC;
}

/**
 * Convert milliseconds to seconds
 *
 * Convert value from milliseconds to seconds by dividing the
 * value to MSEC_PER_SEC constant.
 *
 * @param[in] val Time value in milliseconds
 *
 * @returns Time value in seconds
 */
static inline double util_msecs_to_secs(double val)
{
	return val / MSEC_PER_SEC;
}

/**
 * Convert seconds to nanoseconds
 *
 * Convert value from seconds to nanoseconds by multiplying the
 * value with NSEC_PER_SEC constant.
 *
 * @param[in] val Time value in seconds
 *
 * @returns Time value in nanoseconds
 */
static inline double util_secs_to_nsecs(double val)
{
	return val * NSEC_PER_SEC;
}

/**
 * Convert seconds to microseconds
 *
 * Convert value from seconds to microseconds by multiplying the
 * value with USEC_PER_SEC constant.
 *
 * @param[in] val Time value in seconds
 *
 * @returns Time value in microseconds
 */
static inline double util_secs_to_usecs(double val)
{
	return val * USEC_PER_SEC;
}

/**
 * Convert seconds to milliseconds
 *
 * Convert value from seconds to milliseconds by multiplying the
 * value with MSEC_PER_SEC constant.
 *
 * @param[in] val Time value in seconds
 *
 * @returns Time value in milliseconds
 */
static inline double util_secs_to_msecs(double val)
{
	return val * MSEC_PER_SEC;
}

#endif /* LIB_UTIL_TIME_H */
