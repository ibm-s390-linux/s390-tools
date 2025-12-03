// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025

//! PV Info method implementation for the PV Info Tool

use crate::cli::CliOptions;
use crate::constants::*;
use crate::io_utils::{
    collect_bit_messages, collect_limits, collect_version_flags, read_bool_from_file,
    read_hex_from_file,
};
use crate::se_status::*;
use crate::strings::*;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

#[derive(Serialize)]
pub struct PvInfo {
    pub se_status: Option<SeStatus>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub facilities: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_indications: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<HashMap<String, u64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_plaintext_control_flags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_se_header_versions: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_plaintext_attestation_flags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_attestation_request_versions: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_secret_types: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_add_secret_request_versions: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_plaintext_add_secret_flags: Option<Vec<String>>,
}

impl PvInfo {
    pub fn read(cli: &CliOptions, base_dir: &Path, query_dir: &Path) -> Self {
        // helper function
        fn process_flag_file<F>(
            enabled: bool,
            query_dir: &Path,
            file: &str,
            collector: F,
        ) -> Option<Vec<String>>
        where
            F: Fn(u64) -> Vec<String>,
        {
            if !enabled {
                return None;
            }

            read_hex_from_file(query_dir.join(file), file)
                .map(collector)
                .filter(|v| !v.is_empty())
        }

        // Read Secure Execution guest or host state
        let virt_guest = read_bool_from_file(base_dir.join(PROT_VIRT_GUEST), PROT_VIRT_GUEST);
        let virt_host = read_bool_from_file(base_dir.join(PROT_VIRT_HOST), PROT_VIRT_HOST);
        let se_status = if cli.se_status {
            Some(SeStatus::from_flags(virt_guest, virt_host))
        } else {
            None
        };

        // Collect all optional subsections depending on CLI flags
        let facilities = process_flag_file(cli.facilities, query_dir, FACILITIES, |hex| {
            collect_bit_messages(hex, FACILITIES_DESC)
        });

        let feature_indications = process_flag_file(
            cli.feature_indications,
            query_dir,
            FEATURE_INDICATIONS,
            |hex| collect_bit_messages(hex, FEATURE_INDICATIONS_DESC),
        );

        let limits = if cli.limits {
            let map = collect_limits(query_dir);
            if map.is_empty() {
                None
            } else {
                Some(map)
            }
        } else {
            None
        };

        let supported_plaintext_attestation_flags = process_flag_file(
            cli.supported_plaintext_attestation_flags,
            query_dir,
            SUPP_ATT_PFLAGS,
            |hex| collect_bit_messages(hex, SUPP_ATT_PFLAGS_DESC),
        );

        let supported_se_header_versions = process_flag_file(
            cli.supported_se_header_versions,
            query_dir,
            SUPP_SE_HDR_VER,
            collect_version_flags,
        );

        let supported_secret_types = process_flag_file(
            cli.supported_secret_types,
            query_dir,
            SUPP_SECRET_TYPES,
            |hex| collect_bit_messages(hex, SUPP_SECRET_TYPES_DESC),
        );

        let supported_plaintext_control_flags = process_flag_file(
            cli.supported_plaintext_control_flags,
            query_dir,
            SUPP_SE_HDR_PCF,
            |hex| collect_bit_messages(hex, SUPP_SE_HDR_PCF_DESC),
        );

        let supported_attestation_request_versions = process_flag_file(
            cli.supported_attestation_request_versions,
            query_dir,
            SUPP_ATT_REQ_HDR_VER,
            collect_version_flags,
        );

        let supported_add_secret_request_versions = process_flag_file(
            cli.supported_add_secret_request_versions,
            query_dir,
            SUPP_ADD_SECRET_REQ_VER,
            collect_version_flags,
        );

        let supported_plaintext_add_secret_flags = process_flag_file(
            cli.supported_plaintext_add_secret_flags,
            query_dir,
            SUPP_ADD_SECRET_PCF,
            |hex| collect_bit_messages(hex, SUPP_ADD_SECRET_PCF_DESC),
        );

        Self {
            se_status,
            facilities,
            feature_indications,
            limits,
            supported_plaintext_control_flags,
            supported_se_header_versions,
            supported_plaintext_attestation_flags,
            supported_attestation_request_versions,
            supported_secret_types,
            supported_add_secret_request_versions,
            supported_plaintext_add_secret_flags,
        }
    }

    //// Print the PvInfo data to the provided writer.
    /// Prints SE status first (if present)
    /// and then the rest of the sections.
    pub fn write(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
        if let Some(status) = &self.se_status {
            writeln!(writer, "{status}")?;
        }
        write!(writer, "{self}")?;
        Ok(())
    }
}

// Implements human-readable output for PvInfo
impl fmt::Display for PvInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(fac) = &self.facilities {
            writeln!(f, "\nFacilities: Installed Ultravisor Calls")?;
            for entry in fac {
                writeln!(f, "{entry}")?;
            }
        }

        if let Some(fi) = &self.feature_indications {
            writeln!(f, "\nFeature Indications: Ultravisor Features")?;
            for entry in fi {
                writeln!(f, "{entry}")?;
            }
        }

        if let Some(lims) = &self.limits {
            writeln!(f, "\nLimits:")?;
            for (k, v) in lims {
                writeln!(f, "{k} {v}")?;
            }
        }

        if let Some(flags) = &self.supported_plaintext_attestation_flags {
            writeln!(f, "\nSupported Plaintext Attestation Flags:")?;
            for flag in flags {
                writeln!(f, "{flag}")?;
            }
        }

        if let Some(vers) = &self.supported_se_header_versions {
            writeln!(f, "\nSupported SE Header Versions:")?;
            for ver in vers {
                writeln!(f, "{ver}")?;
            }
        }

        if let Some(types) = &self.supported_secret_types {
            writeln!(f, "\nSupported secret types:")?;
            for ty in types {
                writeln!(f, "{ty}")?;
            }
        }

        if let Some(flags) = &self.supported_plaintext_control_flags {
            writeln!(f, "\nSupported plaintext control flags:")?;
            for flag in flags {
                writeln!(f, "{flag}")?;
            }
        }

        if let Some(vers) = &self.supported_attestation_request_versions {
            writeln!(f, "\nSupported Attestation Request Versions:")?;
            for ver in vers {
                writeln!(f, "{ver}")?;
            }
        }

        if let Some(vers) = &self.supported_add_secret_request_versions {
            writeln!(f, "\nSupported Add Secret Request Versions:")?;
            for ver in vers {
                writeln!(f, "{ver}")?;
            }
        }

        if let Some(flags) = &self.supported_plaintext_add_secret_flags {
            writeln!(f, "\nSupported plaintext add secret flags:")?;
            for flag in flags {
                writeln!(f, "{flag}")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    //! Unit Tests for pvinfo_method

    use super::*;
    use crate::se_status::SeStatus;
    use std::collections::HashMap;

    // Test that Display for PvInfo produces a truly empty string
    // when all optional fields are None/

    #[test]
    fn display_with_no_optional_fields_is_empty() {
        // Create a PvInfo instance with only se_status set, everything else is None
        let pv = PvInfo {
            se_status: Some(SeStatus::from_flags(false, false)),
            facilities: None,
            feature_indications: None,
            limits: None,
            supported_plaintext_control_flags: None,
            supported_se_header_versions: None,
            supported_plaintext_attestation_flags: None,
            supported_attestation_request_versions: None,
            supported_secret_types: None,
            supported_add_secret_request_versions: None,
            supported_plaintext_add_secret_flags: None,
        };

        // Format PvInfo into a string
        let out = format!("{pv}");

        // Assert that when all optional fields are None, Display implementation outputs nothing
        assert!(
            out.trim().is_empty(),
            "expected empty display, got: {out:?}"
        );
    }

    // Test that Display for PvInfo containing all fields
    // produces the correct headers and entries for each section.
    // This verifies both section titles and specific values appear in the output

    #[test]
    fn display_with_all_fields_contains_expected_sections_and_entries() {
        // Create a limits map with multiple entries
        let mut limits = HashMap::new();
        limits.insert("max_secrets".to_string(), 42_u64);
        limits.insert("max_payload".to_string(), 1024_u64);

        // Create a PvInfo instance with all fields populated
        let pv = PvInfo {
            se_status: Some(SeStatus::from_flags(true, false)),
            facilities: Some(vec!["fac-a".into(), "fac-b".into()]),
            feature_indications: Some(vec!["feat-x".into(), "feat-y".into()]),
            limits: Some(limits),
            supported_plaintext_control_flags: Some(vec!["pcf-1".into()]),
            supported_se_header_versions: Some(vec!["v1".into(), "v2".into()]),
            supported_plaintext_attestation_flags: Some(vec!["paf-1".into()]),
            supported_attestation_request_versions: Some(vec!["arv-1".into()]),
            supported_secret_types: Some(vec!["secret-type-foo".into()]),
            supported_add_secret_request_versions: Some(vec!["asrv-1".into()]),
            supported_plaintext_add_secret_flags: Some(vec!["pasf-1".into()]),
        };

        // Format PvInfo into a string
        let out = format!("{pv}");

        // Verify that all expected section headers appear in the formatted output
        assert!(
            out.contains("Facilities: Installed Ultravisor Calls"),
            "missing facilities header: {out}"
        );
        assert!(
            out.contains("Feature Indications: Ultravisor Features"),
            "missing feature indications header: {out}"
        );
        assert!(out.contains("Limits:"), "missing Limits header: {out}");
        assert!(
            out.contains("Supported Plaintext Attestation Flags:"),
            "missing attestation flags header: {out}"
        );
        assert!(
            out.contains("Supported SE Header Versions:"),
            "missing se header versions header: {out}"
        );
        assert!(
            out.contains("Supported secret types:"),
            "missing secret types header: {out}"
        );
        assert!(
            out.contains("Supported plaintext control flags:"),
            "missing plaintext control flags header: {out}"
        );
        assert!(
            out.contains("Supported Attestation Request Versions:"),
            "missing attestation request versions header: {out}"
        );
        assert!(
            out.contains("Supported Add Secret Request Versions:"),
            "missing add secret request versions header: {out}"
        );
        assert!(
            out.contains("Supported plaintext add secret flags:"),
            "missing plaintext add secret flags header: {out}"
        );

        // Verify that specific entries inside sections are correctly displayed
        assert!(out.contains("fac-a"), "missing facility entry: {out}");
        assert!(
            out.contains("feat-x"),
            "missing feature indication entry: {out}"
        );
        assert!(
            out.contains("max_secrets 42"),
            "missing limits key/value: {out}"
        );
        assert!(
            out.contains("max_payload 1024"),
            "missing limits key/value: {out}"
        );
        assert!(
            out.contains("pcf-1"),
            "missing plaintext control flag entry: {out}"
        );
        assert!(out.contains("v1"), "missing se header version entry: {out}");
        assert!(
            out.contains("secret-type-foo"),
            "missing secret type entry: {out}"
        );
        assert!(
            out.contains("pasf-1"),
            "missing add secret flag entry: {out}"
        );
    }

    // Test that serde serialization of `PvInfo` skips fields set to None
    // Ensures optional values are omitted in the YAML output, but mandatory fields remain
    #[test]
    fn serde_serialization_skips_none_fields() {
        // Create a PvInfo instance with some fields set, most left as None
        let pv = PvInfo {
            se_status: Some(SeStatus::from_flags(false, true)),
            facilities: Some(vec!["one".into()]),
            feature_indications: None,
            limits: None,
            supported_plaintext_control_flags: None,
            supported_se_header_versions: None,
            supported_plaintext_attestation_flags: None,
            supported_attestation_request_versions: None,
            supported_secret_types: None,
            supported_add_secret_request_versions: None,
            supported_plaintext_add_secret_flags: None,
        };

        // Serialize PvInfo into YAML
        let v = serde_yaml::to_value(pv).expect("serialize to value");

        // Verify YAML is a mapping (equivalent to an object in JSON)
        let map = v.as_mapping().expect("expected YAML mapping");

        // "facilities" should appear because it's Some(...)
        assert!(
            map.contains_key(serde_yaml::Value::from("facilities")),
            "facilities should be serialized when Some"
        );

        // Optional fields that were None should not be serialized
        assert!(
            !map.contains_key(serde_yaml::Value::from("feature_indications")),
            "feature_indications should be skipped when None"
        );
        assert!(
            !map.contains_key(serde_yaml::Value::from("limits")),
            "limits should be skipped when None"
        );
        assert!(
            !map.contains_key(serde_yaml::Value::from("supported_plaintext_control_flags")),
            "supported_plaintext_control_flags should be skipped when None"
        );

        // "se_status" should always be present
        assert!(
            map.contains_key(serde_yaml::Value::from("se_status")),
            "se_status should be serialized"
        );
    }
}
