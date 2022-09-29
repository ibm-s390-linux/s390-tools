/*
 * UV device (uvio) related functions and definitions.
 * uses s390 only (kernel) features.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#ifdef PVATTEST_COMPILE_PERFORM
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "attestation.h"
#include "uvio.h"
#include "common.h"
#include "log.h"

/* some helper macros */
#define U64_TO_PTR(v) ((void *)(v))
#define PTR_TO_U64(ptr) ((uint64_t)(ptr))

uvio_attest_t *build_attestation_v1_ioctl(GBytes *serialized_arcb, GBytes *user_data,
					  const uint32_t measurement_size,
					  const uint32_t add_data_size, GError **error)
{
	g_autoptr(uvio_attest_t) uvio_attest = NULL;
	size_t arcb_size;
	void *arcb;

	pv_wrapped_g_assert(serialized_arcb);

	g_bytes_ref(serialized_arcb);
	arcb = g_bytes_unref_to_data(serialized_arcb, &arcb_size);

	uvio_attest = g_malloc0(sizeof(*uvio_attest));
	uvio_attest->arcb_addr = PTR_TO_U64(g_steal_pointer(&arcb));
	g_assert_cmpuint(arcb_size, <, UINT32_MAX);
	uvio_attest->arcb_len = (uint32_t)arcb_size;
	/* transferred the local ownership of the arcb from this function to uvio_attest; nullify pointer */
	g_steal_pointer(&serialized_arcb);

	if (user_data) {
		if (g_bytes_get_size(user_data) > sizeof(uvio_attest->user_data)) {
			g_set_error(error, ATT_ERROR, ATT_ERR_INVALID_USER_DATA,
				    _("User data larger than %li bytes"),
				    sizeof(uvio_attest->user_data));
			return NULL;
		}
		uvio_attest->user_data_len = (uint16_t)g_bytes_get_size(user_data);
		pv_gbytes_memcpy(uvio_attest->user_data, uvio_attest->user_data_len, user_data);
	}

	uvio_attest->meas_addr = PTR_TO_U64(g_malloc0(measurement_size));
	uvio_attest->meas_len = measurement_size;

	uvio_attest->add_data_addr = PTR_TO_U64(g_malloc0(add_data_size));
	uvio_attest->add_data_len = add_data_size;

	return g_steal_pointer(&uvio_attest);
}

void uvio_attest_free(uvio_attest_t *attest)
{
	if (!attest)
		return;

	g_free(U64_TO_PTR(attest->arcb_addr));
	g_free(U64_TO_PTR(attest->meas_addr));
	g_free(U64_TO_PTR(attest->add_data_addr));
	g_free(attest);
}

GBytes *uvio_get_measurement(const uvio_attest_t *attest)
{
	pv_wrapped_g_assert(attest);

	if (attest->meas_addr == (__u64)0)
		return NULL;
	return g_bytes_new(U64_TO_PTR(attest->meas_addr), attest->meas_len);
}

GBytes *uvio_get_additional_data(const uvio_attest_t *attest)
{
	pv_wrapped_g_assert(attest);

	if (attest->add_data_addr == (__u64)0)
		return NULL;
	return g_bytes_new(U64_TO_PTR(attest->add_data_addr), attest->add_data_len);
}

GBytes *uvio_get_config_uid(const uvio_attest_t *attest)
{
	pv_wrapped_g_assert(attest);

	return g_bytes_new(attest->config_uid, sizeof(attest->config_uid));
}

uint16_t uvio_ioctl(const int uv_fd, const unsigned int cmd, const uint32_t flags,
		    const void *argument, const uint32_t argument_size, GError **error)
{
	g_autofree struct uvio_ioctl_cb *uv_ioctl = g_malloc0(sizeof(*uv_ioctl));
	int rc, cached_errno;

	pv_wrapped_g_assert(argument);

	uv_ioctl->flags = flags;
	uv_ioctl->argument_addr = PTR_TO_U64(argument);
	uv_ioctl->argument_len = argument_size;
	rc = ioctl(uv_fd, cmd, uv_ioctl);
	cached_errno = errno;

	if (rc < 0) {
		g_set_error(error, UVIO_ERROR, UVIO_ERR_UV_IOCTL, _("ioctl failed: %s "),
			    g_strerror(cached_errno));
		return 0;
	}

	if (uv_ioctl->uv_rc != UVC_EXECUTED)
		g_set_error(error, UVIO_ERROR, UVIO_ERR_UV_NOT_OK,
			    _("Ultravisor call returned '%#x' (%s)"), uv_ioctl->uv_rc,
			    uvio_uv_rc_to_str(uv_ioctl->uv_rc));
	return uv_ioctl->uv_rc;
}

uint16_t uvio_ioctl_attest(const int uv_fd, uvio_attest_t *attest, GError **error)
{
	pv_wrapped_g_assert(attest);

	return uvio_ioctl(uv_fd, UVIO_IOCTL_ATT, 0, attest, sizeof(*attest), error);
}

int uvio_open(const char *uv_path, GError **error)
{
	pv_wrapped_g_assert(uv_path);

	int uv_fd;
	int cached_errno;

	uv_fd = open(uv_path, O_RDWR);
	cached_errno = errno;
	if (uv_fd < 0)
		g_set_error(error, UVIO_ERROR, UVIO_ERR_UV_OPEN,
			    _("Cannot open uv driver at %s: %s"), uv_path,
			    g_strerror(cached_errno));
	return uv_fd;
}

const char *uvio_uv_rc_to_str(const int rc)
{
	switch (rc) {
	case 0x02:
		return _("Invalid UV command");
	case 0x106:
		return _("Unsupported attestation request version");
	case 0x108:
		return _("Number of key slots is greater than the maximum number supported");
	case 0x10a:
		return _("Unsupported plaintext attestation flags");
	case 0x10c:
		return _(
			"Unable to decrypt attestation request control block. No valid host-key was provided");
	case 0x10d:
		return _("Measurement data length is too small to store measurement");
	case 0x10e:
		return _("Additional data length is too small to store measurement");
	default:
		return _("Unknown code");
	}
}

#endif /* PVATTEST_COMPILE_PERFORM */
