/*
 * PV error related functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <glib.h>

#include "pv_error.h"

GQuark pv_error_quark(void)
{
	return g_quark_from_static_string("pv-error-quark");
}

GQuark pv_crypto_error_quark(void)
{
	return g_quark_from_static_string("pv-crypto-error-quark");
}

GQuark pv_component_error_quark(void)
{
	return g_quark_from_static_string("pv-component-error-quark");
}

GQuark pv_image_error_quark(void)
{
	return g_quark_from_static_string("pv-image-error-quark");
}

GQuark pv_parse_error_quark(void)
{
	return g_quark_from_static_string("pv-parse-error-quark");
}
