/*
 * UV device (uvio) related functions and definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef PVATTEST_UVIO_H
#define PVATTEST_UVIO_H
#include "config.h"

#ifdef PVATTEST_COMPILE_PERFORM

#include <sys/ioctl.h>
#include <asm/uvdevice.h>

#include "libpv/glib-helper.h"

#include "arcb.h"
#include "common.h"

#define UVC_EXECUTED 0x0001

typedef struct uvio_attest uvio_attest_t;
G_STATIC_ASSERT(sizeof(uvio_attest_t) == 0x138);
G_STATIC_ASSERT(sizeof(struct uvio_ioctl_cb) == 0x40);

/**
 * build_attestation_v1_ioctl:
 * @serialized_arcb: A ARCB in binary format
 * @user_data (optional): up to 256 bytes of user data to be added to the measurement
 * @measurement_size: Size of the measurement result to be allocated
 * @add_data_size: Size of the additional data to be allocated
 * @error: return location for a #GError
 *
 * Builds the structure to be passed to `/dev/uv` for attestation IOCTLs and
 * allocates any required memory.
 *
 * Returns: (nullable) (transfer full): Pointer to a uvio_attest_t to be passed to `/dev/uv`
 */
uvio_attest_t *build_attestation_v1_ioctl(GBytes *serialized_arcb, GBytes *user_data,
					  const uint32_t measurement_size,
					  const uint32_t add_data_size, GError **error)
	PV_NONNULL(1);
GBytes *uvio_get_measurement(const uvio_attest_t *attest) PV_NONNULL(1);
GBytes *uvio_get_additional_data(const uvio_attest_t *attest) PV_NONNULL(1);
GBytes *uvio_get_config_uid(const uvio_attest_t *attest) PV_NONNULL(1);
void uvio_attest_free(uvio_attest_t *attest);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(uvio_attest_t, uvio_attest_free)

/**
 * uvio_ioctl:
 * @uv_fd: file descriptor to the UV-device
 * @cmd: IOCTL cmd
 * @flags: flags for the uv IOCTL
 * @argument: pointer to the payload
 * @argument_size: size of #argument
 * @error: return location for a #GError
 *
 * Builds the IOCTL structure using, flags and argument, performs the IOCTL, and returns the UV rc in big endian.
 * If the device driver emits an error code, a corresponding #GError will be created.
 * Use the specialized calls (uvio_ioctl_*).
 *
 * Returns: UV rc if no device error occurred (>0)
 * 	    0 on #GError
 */
uint16_t uvio_ioctl(const int uv_fd, const unsigned int cmd, const uint32_t flags,
		    const void *argument, const uint32_t argument_size, GError **error)
	PV_NONNULL(4);
/**
 * uvio_ioctl_attest:
 * @uv_fd: file descriptor to the UV-device
 * @attest: pointer to the attestation request
 * @error: return location for a #GError
 *
 * Wraps 'uvio_ioctl' for attestation.
 *
 * Returns: UV rc if no device error occurred (>0)
 * 	    0 on #GError
 */
uint16_t uvio_ioctl_attest(const int uv_fd, uvio_attest_t *attest, GError **error) PV_NONNULL(2);

/**
 * uvio_open:
 * @uv_path: path of the UV-device usually at /dev/uv
 * @error: return location for a #GError
 *
 * Returns: File descriptor for the UV-device
 *	    0 on #GError
 */
int uvio_open(const char *uv_path, GError **error) PV_NONNULL(1);

/**
 * uvio_uv_rc_to_str:
 * @rc: UV return code
 *
 * Returns: Pointer to an error string corresponding to the given UV-rc.
 */
const char *uvio_uv_rc_to_str(const int rc);

#define UVIO_ERROR g_quark_from_static_string("pv-uvio_error-quark")
typedef enum {
	UVIO_ERR_UV_IOCTL,
	UVIO_ERR_UV_OPEN,
	UVIO_ERR_UV_NOT_OK,
} uvio_error_e;

#endif /* PVATTEST_COMPILE_PERFORM */
#endif /* PVATTEST_UVIO_H */
