// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
//
//! UV related functions for pvapconfig
//

use pv::uv::{ListCmd, SecretList, UvDevice, UvcSuccess};
use regex::Regex;
use std::path::Path;

/// The byte size of association secret of type 2 in struct SecretEntry
pub const AP_ASSOC_SECRET_ID_SIZE: usize = 32;

const PATH_SYS_FW_UV_FACILITIES: &str = "/sys/firmware/uv/query/facilities";

const RE_UV_FACILITIES: &str = r"^(0x)?([[:xdigit:]]+)";
const RE_UV_FAC_BIT_LIST_SECRETS: u32 = 30;

/// Check UV facilities to offer the 'list secrets' call.
/// Returns a Result with Ok(()) if the 'list secrets' feature
/// is available, otherwise an Err(reasonstring) is returned where
/// the string denotes a hint which can be displayed.
/// # Panics
/// Panics if the compilation of a static regular expression fails.
/// Panics if RE_UV_FACILITIES does not match.
pub fn has_list_secrets_facility() -> Result<(), String> {
    if !Path::new(PATH_SYS_FW_UV_FACILITIES).is_file() {
        return Err(format!(
            "UV facilities sysfs attribute not found (file {} does not exist).",
            PATH_SYS_FW_UV_FACILITIES
        ));
    }
    let facstr = match crate::helper::sysfs_read_string(PATH_SYS_FW_UV_FACILITIES) {
        Ok(s) => s,
        Err(err) => {
            return Err(format!(
                "Failure reading UV facilities from {PATH_SYS_FW_UV_FACILITIES} ({:?}).",
                err
            ))
        }
    };
    let re_uv_facilities = Regex::new(RE_UV_FACILITIES).unwrap();
    if !re_uv_facilities.is_match(&facstr) {
        Err(format!("Failure parsing UV facilities entry '{facstr}'."))
    } else {
        let caps = re_uv_facilities.captures(&facstr).unwrap();
        let fachex = caps.get(2).unwrap().as_str();
        let i: usize = RE_UV_FAC_BIT_LIST_SECRETS as usize / 4;
        if i >= fachex.len() {
            return Err(format!("Failure parsing UV facilities entry '{fachex}'."));
        }
        let nibble = u32::from_str_radix(&fachex[i..i + 1], 16).unwrap();
        const THEBIT: u32 = 1 << (3 - (RE_UV_FAC_BIT_LIST_SECRETS % 4));
        if nibble & THEBIT == 0 {
            return Err("The 'list secret' feature is missing on this UV.".to_string());
        }
        Ok(())
    }
}

/// Fetch the list of secrets from the UV.
/// Returns Err(errorstring) on error or
/// Ok(SecretList) on success.
/// The list may be empty if the UV doesn't have any secrets stored.
pub fn gather_secrets() -> Result<SecretList, String> {
    let uv = match UvDevice::open() {
        Err(e) => return Err(format!("Failed to open UV device: {:?}.", e)),
        Ok(u) => u,
    };
    let mut cmd = ListCmd::default();
    match uv.send_cmd(&mut cmd).map_err(|e| format!("{e:?}"))? {
        UvcSuccess::RC_SUCCESS => (),
        UvcSuccess::RC_MORE_DATA => println!("Warning: There is more data available than expected"),
    };
    cmd.try_into().map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {

    use super::*;

    // As the name says: check for list secrets feature bit in UV facilities.
    #[test]
    fn test_has_list_secrets_facility() {
        let r = has_list_secrets_facility();
        if pv::misc::pv_guest_bit_set() {
            assert!(r.is_ok());
        } else {
            assert!(r.is_err());
        }
    }

    // Simple invocation of the list_secrets function. Should not fail
    #[test]
    fn test_list_secrets() {
        let r = gather_secrets();
        if pv::misc::pv_guest_bit_set() {
            assert!(r.is_ok());
        } else {
            assert!(r.is_err());
        }
    }
}
