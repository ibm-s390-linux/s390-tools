// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025

//! I/O utilities for the PV Info Tool

use crate::constants::*;
use anyhow::{Context, Result};
use pv_core::misc::{read_file, read_file_string, try_parse_u64};
use pv_core::misc::{Flags, Msb0Flags64};
use std::collections::HashMap;
use std::path::Path;
use std::str;

// Verify that the Ultravisor directory exists
pub fn check_uv_exists() -> Result<()> {
    let uv_path = Path::new(BASE_DIR);
    if !uv_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Ultravisor directory missing",
        ))
        .context("This system is neither a SE-host or SE-guest");
    }
    Ok(())
}

// File readers
pub fn read_hex_from_file<P: AsRef<Path>>(path: P, context: &str) -> Option<u64> {
    // Add precise context for which file failed
    let content_str = read_file_string(path.as_ref(), context).ok()?;
    let first_line = content_str.lines().next()?.trim();
    if first_line.is_empty() {
        return None;
    }

    match try_parse_u64(first_line, context) {
        Ok(val) if val != 0 => Some(val),
        Ok(_) => None, // treat "0x0" as absent
        Err(e) => panic!(
            "Failed to parse hex value in {} ({}): {}",
            path.as_ref().display(),
            context,
            e
        ),
    }
}

pub fn read_integer_from_file<P: AsRef<Path>>(path: P, context: &str) -> Option<u64> {
    let content_str = read_file_string(path.as_ref(), context).ok()?;
    let first_line = content_str.lines().next()?.trim();
    if first_line.is_empty() {
        return None;
    }
    match first_line.parse::<u64>() {
        Ok(val) => Some(val),
        Err(e) => panic!(
            "Failed to parse integer in {} ({}): {}",
            path.as_ref().display(),
            context,
            e
        ),
    }
}

pub fn read_bool_from_file<P: AsRef<Path>>(path: P, context: &str) -> bool {
    let content = read_file(path.as_ref(), context).unwrap_or_else(|e| {
        panic!(
            "Failed to read {} ({}): {}",
            path.as_ref().display(),
            context,
            e
        )
    });

    let content_str = str::from_utf8(&content)
        .unwrap_or_else(|_| panic!("Invalid UTF-8 in {} ({})", path.as_ref().display(), context));

    match content_str.lines().next().unwrap_or("").trim() {
        "1" => true,
        "0" => false,
        other => panic!(
            "Invalid boolean value in {} ({}): {}",
            path.as_ref().display(),
            context,
            other
        ),
    }
}

// Collectors
pub fn collect_bit_messages(hex_value: u64, desc_content: &str) -> Vec<String> {
    let flags = Msb0Flags64::from(hex_value);
    let mut messages = Vec::new();

    for (line_index, line) in desc_content.lines().enumerate() {
        if flags.is_set(line_index as u8) {
            if line.to_lowercase().contains("reserved") {
                messages.push(format!("{line} Bit-{line_index}"));
            } else {
                messages.push(line.to_string());
            }
        }
    }

    if messages.is_empty() {
        messages.push("No matching messages. But these bits are ON:".into());
        for bit in 0..64 {
            if flags.is_set(bit) {
                messages.push(format!("- Bit {bit} is ON"));
            }
        }
    }

    messages
}

pub fn collect_version_flags(hex_value: u64) -> Vec<String> {
    let flags = Msb0Flags64::from(hex_value);
    let mut versions = Vec::new();

    for bit in 0..64 {
        if flags.is_set(bit as u8) {
            let version = (bit + 1) * 0x100;
            versions.push(format!("version {version:x} hex is supported"));
        }
    }

    versions
}

pub fn collect_limits(query_dir: &Path) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    for (file, desc) in LIMITS {
        if let Some(val) = read_integer_from_file(query_dir.join(file), file) {
            map.insert(desc.to_string(), val);
        }
    }
    map
}

#[cfg(test)]
mod test {
    //! Unit Tests for io_utils

    use super::*;
    use std::io::{self, Write};
    use std::path::Path;
    use tempfile::{tempdir, NamedTempFile};

    // Tests check_uv_exists() by observing the real BASE_DIR at test runtime
    // if BASE_DIR exists on the machine running the tests, check_uv_exists() must return Ok
    // otherwise, it must return Err(anyhow::Error) whose cause is an io::ErrorKind::NotFound,
    // and whose message also contains the added context string

    #[test]
    fn test_check_uv_exists_behaviour_matches_base_dir() {
        let base_dir = BASE_DIR;
        let uv_path = Path::new(base_dir);
        let res = check_uv_exists();

        if uv_path.exists() {
            assert!(
                res.is_ok(),
                "BASE_DIR exists but check_uv_exists returned Err: {res:?}"
            );
        } else {
            assert!(
                res.is_err(),
                "BASE_DIR missing but check_uv_exists returned Ok"
            );
            if let Err(e) = res {
                // downcast anyhow::Error into std::io::Error
                if let Some(io_err) = e.downcast_ref::<io::Error>() {
                    assert_eq!(io_err.kind(), io::ErrorKind::NotFound);
                } else {
                    panic!("Expected std::io::Error inside anyhow::Error, got: {e:?}");
                }

                // ensure both the base error and context message appear
                let msg = format!("{e}");
                assert!(msg.contains("Ultravisor directory missing"));
                assert!(msg.contains("This system is neither a SE-host or SE-guest"));
            }
        }
    }

    // read_hex_from_file tests

    #[test]
    fn test_read_hex_from_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0x1a2b").unwrap();
        let got = read_hex_from_file(file.path(), "test");
        assert_eq!(got, Some(0x1a2b));
    }

    #[test]
    fn test_read_hex_from_file_zero_is_none() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0x0").unwrap();
        assert_eq!(read_hex_from_file(file.path(), "test"), None);
    }

    #[test]
    #[should_panic(expected = "Failed to parse hex value")]
    fn test_read_hex_from_file_invalid_panics() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not_hex").unwrap();
        // should panic now
        let _ = read_hex_from_file(file.path(), "test");
    }

    #[test]
    fn test_read_hex_from_file_missing_returns_none() {
        // missing file -> None
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no_such_file");
        assert_eq!(read_hex_from_file(missing, "test"), None);
    }

    // read_integer_from_file tests

    #[test]
    fn test_read_integer_from_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "12345").unwrap();
        assert_eq!(read_integer_from_file(file.path(), "test"), Some(12345));
    }

    #[test]
    fn test_read_integer_from_file_empty_returns_none() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file).unwrap();
        assert_eq!(read_integer_from_file(file.path(), "test"), None);
    }

    #[test]
    #[should_panic(expected = "Failed to parse integer")]
    fn test_read_integer_from_file_invalid_panics() {
        let mut file2 = NamedTempFile::new().unwrap();
        writeln!(file2, "abc").unwrap();
        // should panic now
        let _ = read_integer_from_file(file2.path(), "test");
    }

    // read_bool_from_file tests

    #[test]
    fn test_read_bool_from_file_true() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "1").unwrap();
        assert!(read_bool_from_file(file.path(), "test"));
    }

    #[test]
    fn test_read_bool_from_file_false() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0").unwrap();
        assert!(!read_bool_from_file(file.path(), "test"));
    }

    #[test]
    #[should_panic(expected = "Invalid boolean value")]
    fn test_read_bool_from_file_invalid_value_panics() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "yes").unwrap();
        // should panic with clear error
        let _ = read_bool_from_file(file.path(), "test");
    }

    // collect_bit_messages tests

    #[test]
    fn test_collect_bit_messages_matches_and_reserved() {
        // lines: index 0 -> bit 63, index 1 -> bit 62, index 2 -> bit 61
        let desc = "First Feature\nreserved for future use\nThird Feature";

        // set bit for line 0 and line 2
        let hex = (1u64 << 63) | (1u64 << 61);
        let messages = collect_bit_messages(hex, desc);

        // Expect "First Feature" and "Third Feature" (and the reserved line should get the " Bit-<index>" if matched)
        assert!(messages.iter().any(|m| m == "First Feature"));
        assert!(messages.iter().any(|m| m == "Third Feature"));
        // reserved wasn't set here; now test reserved specifically below
    }

    #[test]
    fn test_collect_bit_messages_reserved_line() {
        let desc = "one\nReserved entry\nthree";
        // set the bit corresponding to line index 1 -> bit 62
        let hex = 1u64 << (63 - 1);
        let messages = collect_bit_messages(hex, desc);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], "Reserved entry Bit-1");
    }

    #[test]
    fn test_collect_bit_messages_fallback_lists_bits() {
        let desc = "only one line";
        // pick a bit that does not map to line 0 (63) so fallback triggers; e.g. bit 5
        let hex = 1u64 << 5;
        let messages = collect_bit_messages(hex, desc);
        assert!(!messages.is_empty());
        assert!(messages[0].starts_with("No matching messages"));
        assert!(messages.iter().any(|m| m.contains("Bit 5")));
    }

    // collect_version_flags tests

    #[test]
    fn test_collect_version_flags_two_bits() {
        // top two bits set => versions 0x100 and 0x200 should be present
        let hex = (1u64 << 63) | (1u64 << 62);
        let versions = collect_version_flags(hex);
        assert!(versions.contains(&"version 100 hex is supported".to_string()));
        assert!(versions.contains(&"version 200 hex is supported".to_string()));
    }
}
