// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025

//! Constants used throughout the PV Info Tool

// Base directories
#[cfg(test)]
pub const BASE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets");

#[cfg(not(test))]
pub const BASE_DIR: &str = "/sys/firmware/uv";

pub const QUERY_DIR: &str = "query";

// File names
pub const FACILITIES: &str = "facilities";
pub const FEATURE_INDICATIONS: &str = "feature_indications";
pub const PROT_VIRT_GUEST: &str = "prot_virt_guest";
pub const PROT_VIRT_HOST: &str = "prot_virt_host";
pub const MAX_ADDRESS: &str = "max_address";
pub const MAX_ASSOC_SECRETS: &str = "max_assoc_secrets";
pub const MAX_CPUS: &str = "max_cpus";
pub const MAX_GUESTS: &str = "max_guests";
pub const MAX_RETR_SECRETS: &str = "max_retr_secrets";
pub const MAX_SECRETS: &str = "max_secrets";
pub const SUPP_ADD_SECRET_PCF: &str = "supp_add_secret_pcf";
pub const SUPP_ADD_SECRET_REQ_VER: &str = "supp_add_secret_req_ver";
pub const SUPP_ATT_PFLAGS: &str = "supp_att_pflags";
pub const SUPP_ATT_REQ_HDR_VER: &str = "supp_att_req_hdr_ver";
pub const SUPP_SE_HDR_PCF: &str = "supp_se_hdr_pcf";
pub const SUPP_SE_HDR_VER: &str = "supp_se_hdr_ver";
pub const SUPP_SECRET_TYPES: &str = "supp_secret_types";

// Limits
pub const LIMITS: [(&str, &str); 6] = [
    (MAX_ADDRESS, "Maximal Address for a SE-Guest"),
    (MAX_ASSOC_SECRETS, "Maximal number of associated secrets"),
    (MAX_CPUS, "Maximal number of CPUs in one SE-Guest"),
    (MAX_GUESTS, "Maximal number of SE-Guests"),
    (MAX_RETR_SECRETS, "Maximal number of retrievable secrets"),
    (MAX_SECRETS, "Maximal number of secrets in the system"),
];
