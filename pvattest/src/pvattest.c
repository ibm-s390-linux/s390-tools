/*
 * Entry point for the pvattest tool.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <stdio.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "libpv/crypto.h"
#include "libpv/cert.h"

#include "uvio.h"
#include "common.h"
#include "attestation.h"
#include "arcb.h"
#include "argparse.h"
#include "exchange_format.h"
#include "log.h"

#define PVATTEST_NID NID_secp521r1
#define PVATTEST_UV_PATH "/dev/uv"
#define PVATTEST_EXIT_MEASURE_NOT_VERIFIED 2

enum pvattest_error {
	PVATTEST_ERROR_INVAL_ATT_RESULT,
};

static arcb_v1_t *create_arcb(char **host_key_paths, const gboolean use_nonce,
			      const gboolean phkh_img, const gboolean phkh_att,
			      const uint64_t user_paf, GError **error)
{
	g_autoptr(GBytes) arpk = NULL, meas_key = NULL, nonce = NULL, iv = NULL;
	g_autoslist(PvX509WithPath) host_keys_with_path = NULL;
	g_autoslist(EVP_PKEY) evp_host_keys = NULL;
	const uint32_t mai = MAI_HMAC_SHA512;
	g_autoptr(EVP_PKEY) evp_cpk = NULL;
	g_autoptr(arcb_v1_t) arcb = NULL;
	uint64_t paf = user_paf;

	g_assert(host_key_paths);

	arpk = pv_generate_key(EVP_aes_256_gcm(), error);
	if (!arpk)
		return NULL;
	iv = pv_generate_iv(EVP_aes_256_gcm(), error);
	if (!iv)
		return NULL;
	evp_cpk = pv_generate_ec_key(PVATTEST_NID, error);
	if (!evp_cpk)
		return NULL;
	meas_key = pv_generate_rand_data(HMAC_SHA512_KEY_SIZE, error);
	if (!meas_key)
		return NULL;

	if (phkh_img)
		paf |= ARCB_V1_PAF_AAD_PHKH_HEADER;
	if (phkh_att)
		paf |= ARCB_V1_PAF_AAD_PHKH_ATTEST;

	arcb = arcb_v1_new(arpk, iv, mai, evp_cpk, meas_key, paf, error);
	if (!arcb)
		return NULL;
	if (use_nonce) {
		nonce = pv_generate_rand_data(ARCB_V1_NONCE_SIZE, error);
		if (!nonce)
			return NULL;
		arcb_v1_set_nonce(arcb, nonce);
	}

	host_keys_with_path = pv_load_certificates(host_key_paths, error);
	if (!host_keys_with_path)
		return NULL;

	/* Extract EVP_PKEY structures and verify that the correct elliptic
	 * curve is used.
	 */
	evp_host_keys = pv_get_ec_pubkeys(host_keys_with_path, PVATTEST_NID, error);
	if (!evp_host_keys)
		return NULL;
	for (GSList *iter = evp_host_keys; iter; iter = iter->next) {
		EVP_PKEY *host_key = iter->data;

		if (arcb_v1_add_key_slot(arcb, host_key, error) < 0)
			return NULL;
	}
	return g_steal_pointer(&arcb);
}

#define __PVATTEST_CREATE_ERROR_MSG _("Creating the attestation request failed")
static int do_create(const pvattest_create_config_t *create_config)
{
	g_autoptr(exchange_format_ctx_t) output_ctx = NULL;
	uint32_t measurement_size, additional_data_size;
	g_autoptr(GBytes) serialized_arcb = NULL;
	g_autoptr(arcb_v1_t) arcb = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GBytes) arpk = NULL;

	if (!create_config->use_nonce)
		pvattest_log_warning(_("No nonce used. (Experimental setting)"));

	if (create_config->no_verify) {
		pvattest_log_warning(_("Host-key document verification is disabled.\n"
				       "The attestation result could be compromised!"));
		pvattest_log_debug(_("Verification skipped."));
	} else {
		if (pv_verify_host_key_docs_by_path(
			    create_config->host_key_document_paths, create_config->root_ca_path,
			    create_config->crl_paths, create_config->certificate_paths,
			    create_config->online, &error) < 0)
			goto err_exit;
		pvattest_log_debug(_("Verification passed."));
	}

	/* build attestation request */
	arcb = create_arcb(create_config->host_key_document_paths, create_config->use_nonce,
			   create_config->phkh_img, create_config->phkh_att, create_config->paf,
			   &error);
	if (!arcb)
		goto err_exit;

	additional_data_size = arcb_v1_get_required_additional_size(arcb);
	if (create_config->x_aad_size >= 0) {
		g_assert_cmpint(create_config->x_aad_size, <=, UINT32_MAX);
		additional_data_size = (uint32_t)create_config->x_aad_size;
	}
	measurement_size = arcb_v1_get_required_measurement_size(arcb, &error);
	if (error)
		goto err_exit;

	serialized_arcb = arcb_v1_serialize(arcb, &error);
	if (!serialized_arcb)
		goto err_exit;

	/* write attestation request data to file */
	output_ctx = exchange_ctx_new(PVATTEST_EXCHANGE_VERSION_1_00, serialized_arcb,
				      measurement_size, additional_data_size, &error);
	if (!output_ctx)
		goto err_exit;
	if (exchange_write_to_file(output_ctx, create_config->output_path, &error) < 0)
		goto err_exit;
	pvattest_log_debug(_("ARCB written to file."));

	/* write attestation request protection key to file */
	arpk = arcb_v1_get_arp_key(arcb);
	wrapped_g_file_set_content(create_config->arp_key_out_path, arpk, 0600, &error);
	if (error)
		goto err_exit;
	pvattest_log_debug(_("ARPK written to file."));

	return EXIT_SUCCESS;

err_exit:
	pvattest_log_GError(__PVATTEST_CREATE_ERROR_MSG, error);
	return EXIT_FAILURE;
}

#ifdef PVATTEST_COMPILE_PERFORM
#define __PVATTEST_MEASURE_ERROR_MSG _("Performing the attestation measurement failed")
static int do_perform(pvattest_perform_config_t *perform_config)
{
	g_autoptr(GBytes) serialized_arcb = NULL, user_data = NULL, measurement = NULL,
			  additional_data = NULL, config_uid = NULL;
	size_t uv_measurement_data_size, uv_addidtional_data_size;
	g_autoptr(exchange_format_ctx_t) exchange_ctx = NULL;
	uint32_t measurement_size, additional_data_size;
	g_autoptr(uvio_attest_t) uvio_attest = NULL;
	g_autoptr(GError) error = NULL;
	be16_t uv_rc;
	int uv_fd;

	exchange_ctx = exchange_ctx_from_file(perform_config->input_path, &error);
	if (!exchange_ctx)
		goto err_exit;

	serialized_arcb = exchange_get_serialized_arcb(exchange_ctx);
	if (!serialized_arcb) {
		g_set_error(&error, PVATTEST_ERROR, ARCB_ERR_INVALID_ARCB,
			    _("The input does not provide an attestation request."));

		goto err_exit;
	}

	measurement_size = exchange_get_requested_measurement_size(exchange_ctx);
	additional_data_size = exchange_get_requested_additional_data_size(exchange_ctx);

	pvattest_log_debug(_("Input data loaded."));

	if (perform_config->user_data_path) {
		user_data = pv_file_get_content_as_g_bytes(perform_config->user_data_path, &error);
		if (!user_data)
			goto err_exit;
		pvattest_log_debug(_("Added user data from '%s'"), perform_config->user_data_path);
	}
	uvio_attest = build_attestation_v1_ioctl(serialized_arcb, user_data, measurement_size,
						 additional_data_size, &error);
	if (!uvio_attest)
		goto err_exit;

	pvattest_log_debug(_("attestation context generated."));

	/* execute attestation */
	uv_fd = uvio_open(PVATTEST_UV_PATH, &error);
	if (uv_fd < 0)
		goto err_exit;

	uv_rc = uvio_ioctl_attest(uv_fd, uvio_attest, &error);
	close(uv_fd);
	if (uv_rc != UVC_EXECUTED)
		goto err_exit;
	pvattest_log_debug(_("attestation measurement successful. rc = %#x"), uv_rc);

	/* write to file */
	measurement = uvio_get_measurement(uvio_attest);
	additional_data = uvio_get_additional_data(uvio_attest);
	config_uid = uvio_get_config_uid(uvio_attest);

	uv_measurement_data_size = measurement == NULL ? 0 : g_bytes_get_size(measurement);
	if (uv_measurement_data_size != measurement_size) {
		g_set_error(&error, PVATTEST_ERROR, PVATTEST_ERROR_INVAL_ATT_RESULT,
			    "The measurement size returned by Ultravisor is not as expected.");
		goto err_exit;
	}

	uv_addidtional_data_size = additional_data == NULL ? 0 : g_bytes_get_size(additional_data);
	if (uv_addidtional_data_size != additional_data_size) {
		g_set_error(&error, PVATTEST_ERROR, PVATTEST_ERROR_INVAL_ATT_RESULT,
			    "The additional data size returned by Ultravisor is not as expected.");
		goto err_exit;
	}

	exchange_set_measurement(exchange_ctx, measurement);
	if (additional_data)
		exchange_set_additional_data(exchange_ctx, additional_data);
	exchange_set_config_uid(exchange_ctx, config_uid);
	if (user_data)
		exchange_set_user_data(exchange_ctx, user_data);

	if (exchange_write_to_file(exchange_ctx, perform_config->output_path, &error) < 0)
		goto err_exit;

	pvattest_log_debug(_("Output written to file."));

	return EXIT_SUCCESS;

err_exit:
	pvattest_log_GError(__PVATTEST_MEASURE_ERROR_MSG, error);
	return EXIT_FAILURE;
}
#endif /* PVATTEST_COMPILE_PERFORM */

static int fprint_verify_result(FILE *stream, const enum verify_output_format fmt,
				GBytes *config_uid, GBytes *additional_data)
{
	switch (fmt) {
	case VERIFY_FMT_HUMAN:
		if (fprintf(stream, _("Attestation measurement verified\n")) < 0)
			return -1;
		if (fprintf(stream, _("Config UID:\n")) < 0)
			return -1;
		if (pvattest_hexdump(stream, config_uid, 0x10L, "0x", FALSE) < 0)
			return -1;
		if (fprintf(stream, _("\n")) < 0)
			return -1;

		if (additional_data) {
			if (fprintf(stream, _("Additional Data:\n")) < 0)
				return -1;
			if (pvattest_hexdump(stream, additional_data, 0x60L, "0x", FALSE) < 0)
				return -1;
			if (fprintf(stream, _("\n")) < 0)
				return -1;
		}
		break;
	case VERIFY_FMT_YAML:
		if (fprintf(stream, "cuid: ") < 0)
			return -1;
		if (pvattest_hexdump(stream, config_uid, 0L, "'0x", FALSE) < 0)
			return -1;
		if (fprintf(stream, _("'\n")) < 0)
			return -1;

		if (additional_data) {
			if (fprintf(stream, "add: ") < 0)
				return -1;

			if (pvattest_hexdump(stream, additional_data, 0x0L, "'0x", FALSE) < 0)
				return -1;
			if (fprintf(stream, _("'\n")) < 0)
				return -1;
		}
		break;
	default:
		g_assert_not_reached();
		break;
	}
	return 0;
}

#define __PVATTEST_VERIFY_ERROR_MSG _("Attestation measurement verification failed")
static int do_verify(const pvattest_verify_config_t *verify_config, const int appl_log_lvl)
{
	g_autoptr(GBytes) user_data = NULL, uv_measurement = NULL, additional_data = NULL,
			  image_hdr = NULL, calc_measurement = NULL, config_uid = NULL,
			  meas_key = NULL, arp_key = NULL, nonce = NULL, serialized_arcb = NULL;
	g_autofree att_meas_ctx_t *measurement_hdr = NULL;
	g_autoptr(exchange_format_ctx_t) input_ctx = NULL;
	const char *err_prefix = __PVATTEST_VERIFY_ERROR_MSG;
	g_autoptr(GError) error = NULL;
	gboolean rc;

	image_hdr = pv_file_get_content_as_g_bytes(verify_config->hdr_path, &error);
	if (!image_hdr)
		goto err_exit;

	measurement_hdr = att_extract_from_hdr(image_hdr, &error);
	if (!measurement_hdr)
		goto err_exit;

	pvattest_log_debug(_("Image header loaded."));

	input_ctx = exchange_ctx_from_file(verify_config->input_path, &error);
	if (!input_ctx)
		goto err_exit;

	config_uid = exchange_get_config_uid(input_ctx);
	uv_measurement = exchange_get_measurement(input_ctx);
	user_data = exchange_get_user_data(input_ctx);
	additional_data = exchange_get_additional_data(input_ctx);
	serialized_arcb = exchange_get_serialized_arcb(input_ctx);

	if (!uv_measurement || !serialized_arcb) {
		g_set_error(&error, PVATTEST_ERROR, PVATTEST_SUBC_INVALID,
			    _("Input data has no measurement"));
		goto err_exit;
	}
	pvattest_log_debug(_("Input data loaded."));

	att_add_uid(measurement_hdr, config_uid);

	arp_key = pv_file_get_content_as_g_bytes(verify_config->arp_key_in_path, &error);
	if (!arp_key)
		goto err_exit;
	pvattest_log_debug(_("ARPK loaded."));

	rc = arcb_v1_verify_serialized_arcb(serialized_arcb, arp_key, &meas_key, &nonce, &error);
	if (!rc)
		goto err_exit;

	pvattest_log_debug(_("Input ARCB verified."));

	calc_measurement = att_gen_measurement_hmac_sha512(measurement_hdr, meas_key, user_data,
							   nonce, additional_data, &error);
	if (!calc_measurement)
		goto err_exit;
	pvattest_log_debug(_("Measurement calculated."));

	if (!att_verify_measurement(calc_measurement, uv_measurement, &error)) {
		pvattest_log_GError(__PVATTEST_VERIFY_ERROR_MSG, error);
		pvattest_log_debug(_("Measurement values:"));
		gbhexdump(uv_measurement);
		gbhexdump(calc_measurement);
		return PVATTEST_EXIT_MEASURE_NOT_VERIFIED;
	}

	/* Write human-readable output to stdout */
	if (appl_log_lvl >= PVATTEST_LOG_LVL_INFO) {
		if (fprint_verify_result(stdout, VERIFY_FMT_HUMAN, config_uid, additional_data) <
		    0) {
			g_set_error(&error, PV_GLIB_HELPER_ERROR, PV_GLIB_HELPER_FILE_ERROR,
				    "stdout: %s", g_strerror(errno));
			err_prefix = "Failed to write output";
			goto err_exit;
		}
	}

	/* Write to file */
	if (verify_config->output_path) {
		g_autoptr(FILE) output = pv_file_open(verify_config->output_path, "wx", &error);

		if (!output) {
			err_prefix = "Failed to write output";
			goto err_exit;
		}
		if (fprint_verify_result(output, verify_config->output_fmt, config_uid,
					 additional_data) < 0) {
			g_set_error(&error, PV_GLIB_HELPER_ERROR, PV_GLIB_HELPER_FILE_ERROR,
				    "'%s': %s", verify_config->output_path, g_strerror(errno));
			err_prefix = "Failed to write output";
			goto err_exit;
		}
	}
	return EXIT_SUCCESS;

err_exit:
	pvattest_log_GError(err_prefix, error);
	return EXIT_FAILURE;
}

/*
 * Will not free the config structs, but the nested char* etc.
 * that's what we need to do as we will receive a statically allocated config_t
 * Not defined in the parse header as someone might incorrectly assume
 * that the config pointers will be freed.
 */
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(pvattest_config_t, pvattest_parse_clear_config)
int main(int argc, char *argv[])
{
	int appl_log_lvl = PVATTEST_LOG_LVL_DEFAULT;
	g_autoptr(pvattest_config_t) config = NULL;
	g_autoptr(GError) error = NULL;
	enum pvattest_command command;
	int rc;

	/* setting up the default log handler to filter messages based on the
	 * log level specified by the user.
	 */
	g_log_set_handler(NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
			  &pvattest_log_default_logger, &appl_log_lvl);
	/* setting up the log handler for hexdumps (no prefix and '\n' at end of
	 * message)to filter messages based on the log level specified by the
	 * user.
	 */
	g_log_set_handler(PVATTEST_BYTES_LOG_DOMAIN,
			  G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
			  &pvattest_log_plain_logger, &appl_log_lvl);

	command = pvattest_parse(&argc, &argv, &config, &error);
	if (command == PVATTEST_SUBC_INVALID) {
		pvattest_log_error(_("%s\nTry '%s --help' for more information"), error->message,
				   GETTEXT_PACKAGE);
		exit(EXIT_FAILURE);
	}
	g_assert(config);
	appl_log_lvl = config->general.log_level;

	pv_init();

	switch (command) {
	case PVATTEST_SUBC_CREATE:
		rc = do_create(&config->create);
		break;
#ifdef PVATTEST_COMPILE_PERFORM
	case PVATTEST_SUBC_PERFORM:
		rc = do_perform(&config->perform);
		break;
#endif /* PVATTEST_COMPILE_PERFORM */
	case PVATTEST_SUBC_VERIFY:
		rc = do_verify(&config->verify, appl_log_lvl);
		break;
	default:
		g_return_val_if_reached(EXIT_FAILURE);
	}

	pv_cleanup();

	return rc;
}
