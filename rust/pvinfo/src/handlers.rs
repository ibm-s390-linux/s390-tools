// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025

//! Handlers for processing CLI flags and subcommands

use crate::constants::*;
use crate::io_utils::{collect_bit_messages, collect_version_flags, read_hex_from_file};
use crate::strings::*;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// Represents metadata for a supported content file.
struct Content {
    file: &'static str,
    label: &'static str,
    desc_content: Option<&'static str>,
}

impl Content {
    //Reads a hex file, then prints either:
    // bit messages or version flags
    fn handle_flag(&self, writer: &mut dyn Write, query_dir: &Path) -> io::Result<String> {
        let hex = match read_hex_from_file(query_dir.join(self.file), self.label) {
            Some(h) => h,
            None => {
                return Ok(String::new());
            }
        };

        let mut output = String::new();
        let header = format!("\n{}:", self.label);
        writeln!(writer, "{header}")?;
        output.push_str(&header);

        match self.desc_content {
            Some(desc) => {
                for msg in collect_bit_messages(hex, desc) {
                    writeln!(writer, "{msg}")?;
                    output.push_str(&format!("\n{msg}"));
                }
            }
            None => {
                for v in collect_version_flags(hex) {
                    writeln!(writer, "{v}")?;
                    output.push_str(&format!("\n{v}"));
                }
            }
        }

        Ok(output)
    }
}

// Define constants for each supported flag group
const SUPP_SECRET_C: Content = Content {
    file: SUPP_SECRET_TYPES,
    label: "Supported Secret types",
    desc_content: Some(SUPP_SECRET_TYPES_DESC),
};

const SUPP_ADD_SECRET_REQ_C: Content = Content {
    file: SUPP_ADD_SECRET_REQ_VER,
    label: "Supported Add Secret Request Versions",
    desc_content: None,
};

const SUPP_ADD_SECRET_PCF_C: Content = Content {
    file: SUPP_ADD_SECRET_PCF,
    label: "Supported Plaintext Add Secret Flags",
    desc_content: Some(SUPP_ADD_SECRET_PCF_DESC),
};

const SUPP_ATT_PFLAGS_C: Content = Content {
    file: SUPP_ATT_PFLAGS,
    label: "Supported Plaintext Attestation Flags",
    desc_content: Some(SUPP_ATT_PFLAGS_DESC),
};

const SUPP_ATT_REQ_HDR_VER_C: Content = Content {
    file: SUPP_ATT_REQ_HDR_VER,
    label: "Supported Attestation Request Versions",
    desc_content: None,
};

const SUPP_SE_HDR_VER_C: Content = Content {
    file: SUPP_SE_HDR_VER,
    label: "Supported SE Header Versions",
    desc_content: None,
};

const SUPP_SE_HDR_PCF_C: Content = Content {
    file: SUPP_SE_HDR_PCF,
    label: "Supported Plaintext Control Flags",
    desc_content: Some(SUPP_SE_HDR_PCF_DESC),
};

// Main entry point for handling the supported-flags subcommand.
pub fn handle_supported_flags(
    writer: &mut dyn Write,
    secret: bool,
    attestation: bool,
    header: bool,
    query_dir: PathBuf,
) -> io::Result<Vec<String>> {
    let mut results = Vec::new();

    if secret {
        results.push(SUPP_SECRET_C.handle_flag(writer, &query_dir)?);
        results.push(SUPP_ADD_SECRET_REQ_C.handle_flag(writer, &query_dir)?);
        results.push(SUPP_ADD_SECRET_PCF_C.handle_flag(writer, &query_dir)?);
    }

    if attestation {
        results.push(SUPP_ATT_PFLAGS_C.handle_flag(writer, &query_dir)?);
        results.push(SUPP_ATT_REQ_HDR_VER_C.handle_flag(writer, &query_dir)?);
    }

    if header {
        results.push(SUPP_SE_HDR_VER_C.handle_flag(writer, &query_dir)?);
        results.push(SUPP_SE_HDR_PCF_C.handle_flag(writer, &query_dir)?);
    }

    if results.is_empty() {
        let mut all_results = handle_supported_flags(writer, true, true, true, query_dir)?;
        results.append(&mut all_results);
    }

    Ok(results)
}

// Unit Tests for handlers
#[cfg(test)]
mod test {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // Verifies that handle_supported_flags correctly processes all
    #[test]
    fn test_handle_supported_flags_with_buffer() {
        let dir = tempdir().unwrap();

        // Creating files
        fs::write(dir.path().join(SUPP_SECRET_TYPES), "1").unwrap();
        fs::write(dir.path().join(SUPP_ADD_SECRET_REQ_VER), "1").unwrap();
        fs::write(dir.path().join(SUPP_ADD_SECRET_PCF), "1").unwrap();
        fs::write(dir.path().join(SUPP_ATT_PFLAGS), "1").unwrap();
        fs::write(dir.path().join(SUPP_ATT_REQ_HDR_VER), "1").unwrap();
        fs::write(dir.path().join(SUPP_SE_HDR_VER), "1").unwrap();
        fs::write(dir.path().join(SUPP_SE_HDR_PCF), "1").unwrap();

        // Capture output into buffer
        let mut buffer = Vec::new();
        let results =
            handle_supported_flags(&mut buffer, true, true, true, dir.path().to_path_buf())
                .unwrap();

        // Convert buffer to string
        let printed = String::from_utf8(buffer).unwrap();

        let normalized: String = printed
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");

        let expected = [
            "Supported Secret types:",
            "Supported Add Secret Request Versions:",
            "Supported Plaintext Add Secret Flags:",
            "Supported Plaintext Attestation Flags:",
            "Supported Attestation Request Versions:",
            "Supported SE Header Versions:",
            "Supported Plaintext Control Flags:",
        ];

        for label in &expected {
            assert!(
                normalized.contains(label),
                "{label} missing in printed output!\nNormalized buffer:\n{normalized}"
            );
            assert!(
                results.iter().any(|r| r.contains(label)),
                "{label} missing in results Vec!"
            );
        }
    }
}
