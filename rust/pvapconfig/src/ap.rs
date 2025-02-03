// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
//
//! AP support functions for pvapconfig
//

use crate::helper::*;
use pv_core::ap::*;
use pv_core::misc::read_file_string;
use std::path::Path;
use std::slice::Iter;
use std::thread;
use std::time;

const RE_CARD_DIR: &str = r"^card([[:xdigit:]]{2})$";

const PATH_SYS_BUS_AP: &str = "/sys/bus/ap";
const PATH_SYS_BUS_AP_FEATURES: &str = "/sys/bus/ap/features";
const PATH_SYS_BUS_AP_BINDINGS: &str = "/sys/bus/ap/bindings";
const PATH_SYS_DEVICES_AP: &str = "/sys/devices/ap";

const SYS_BUS_AP_BINDINGS_POLL_MS: u64 = 500;

/// Check if AP bus support is available.
/// Returns Result with Ok(()) or Err(failurestring).
pub fn check_ap_bus_support() -> Result<(), String> {
    if !Path::new(PATH_SYS_BUS_AP).is_dir() {
        return Err(format!(
            "AP bus support missing (path {PATH_SYS_BUS_AP} is invalid)."
        ));
    }
    Ok(())
}

/// Check if AP bus supports APSB.
///
/// When APSB support is available returns Result
/// with Ok(()) or otherwise Err(failurestring).
pub fn ap_bus_has_apsb_support() -> Result<(), String> {
    let features =
        read_file_string(PATH_SYS_BUS_AP_FEATURES, "AP bus features").map_err(|e| e.to_string())?;
    match features.find("APSB") {
        Some(_) => Ok(()),
        None => Err("Missing AP bus feature APSB (SE AP pass-through not enabled ?).".to_string()),
    }
}

/// Wait for AP bus set up all it's devices.
///
/// This function loops until the AP bus reports that
/// - all AP queue devices have been constructed
/// - and all AP device have been bound to a device driver.
///
/// This may take some time and even loop forever if there
/// is something wrong with the kernel modules setup.
/// Returns true when AP bus bindings are complete,
/// otherwise false and a message is printed.
/// When AP bus binding complete is not immediately reached
/// and this function needs to loop, about every 5 seconds
/// a message is printed "Waiting for ...".
pub fn wait_for_ap_bus_bindings_complete() -> bool {
    let mut counter = 0;
    loop {
        match read_file_string(PATH_SYS_BUS_AP_BINDINGS, "AP bus bindings") {
            Ok(s) => {
                if s.contains("complete") {
                    return true;
                }
            }
            Err(err) => {
                eprintln!("{err}");
                return false;
            }
        }
        thread::sleep(time::Duration::from_millis(SYS_BUS_AP_BINDINGS_POLL_MS));
        counter += 1;
        if counter % 10 == 0 {
            println!("Waiting for AP bus bindings complete.");
        }
    }
}

/// Wrapper object around Vector of Apqns
#[derive(Debug)]
pub struct ApqnList(Vec<Apqn>);

impl ApqnList {
    /// Create from APQN vector.
    #[cfg(test)] // only used in test code
    pub fn from_apqn_vec(apqns: Vec<Apqn>) -> Self {
        Self(apqns)
    }

    /// Converts to an APQN vector.
    #[cfg(test)] // only used in test code
    pub fn to_apqn_vec(&self) -> Vec<Apqn> {
        self.0.clone()
    }

    /// Iter over APQN list
    pub fn iter(&self) -> Iter<'_, Apqn> {
        self.0.iter()
    }

    /// Length of the APQN list
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if APQN list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Scan AP bus devices in sysfs and construct the Apqnlist.
    ///
    /// The list is a vector of struct Apqn for each APQN found in sysfs
    /// that this struct can be created from.
    /// On success a vector of struct Apqn is returned. This list may be
    /// empty if there are no APQNs available or do not match to the conditions.
    /// On failure None is returned.
    pub fn gather_apqns() -> Option<Self> {
        let mut apqns: Vec<Apqn> = Vec::new();
        let card_dirs =
            match sysfs_get_list_of_subdirs_matching_regex(PATH_SYS_DEVICES_AP, RE_CARD_DIR) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!(
                        "Failure reading AP devices {} ({:?}).",
                        PATH_SYS_DEVICES_AP, err
                    );
                    return None;
                }
            };
        for dir in card_dirs {
            let path = format!("{PATH_SYS_DEVICES_AP}/{dir}");
            let queue_dirs = match sysfs_get_list_of_subdirs_matching_regex(&path, RE_QUEUE_DIR) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!(
                        "Failure reading AP queue directories in {} ({:?}).",
                        path, err
                    );
                    return None;
                }
            };
            for queue_dir in queue_dirs {
                let apqn: Apqn = match (&queue_dir as &str).try_into() {
                    Ok(apqn) => apqn,
                    Err(e) => {
                        eprintln!("{e}");
                        continue;
                    }
                };
                // Warn about non-fatal errors
                if apqn.info.is_none() {
                    eprintln!("Warning: Failure gathering info for APQN {queue_dir}");
                }
                if let Some(apqn_info::Cca(ref cca_info)) = apqn.info {
                    if cca_info.mkvp_aes.is_empty() {
                        eprintln!("Warning: APQN {queue_dir} has no valid AES master key set.");
                    }
                    if cca_info.mkvp_apka.is_empty() {
                        eprintln!("Warning: APQN {queue_dir} has no valid APKA master key set.");
                    }
                }
                if let Some(apqn_info::Ep11(ref ep11_info)) = apqn.info {
                    if ep11_info.mkvp.is_empty() {
                        eprintln!("Warning: APQN {queue_dir} has no valid wrapping key set.");
                    }
                }
                apqns.push(apqn);
            }
        }
        Some(Self(apqns))
    }

    /// Sort this Apqnlist by card generation:
    /// newest generation first, older generations last.
    pub fn sort_by_gen(&mut self) {
        self.0.sort_unstable_by(|a, b| b.gen.cmp(&a.gen));
    }

    /// Check MK restriction
    ///
    /// Within one card there must not exist 2 APQNs with same
    /// MK setup. This rule only applies to EP11 cards.
    /// Returns true if this check passed,
    /// otherwise false and a message is printed.
    pub fn check_mk_restriction(&self) -> bool {
        for a1 in self.0.iter() {
            for a2 in self.0.iter() {
                if a1.card == a2.card
                    && a1.domain < a2.domain
                    && a1.mode == apqn_mode::Ep11
                    && a1.info.is_some()
                    && a2.info.is_some()
                {
                    let i1 = match a1.info.as_ref().unwrap() {
                        apqn_info::Ep11(i) => i,
                        _ => continue,
                    };
                    let i2 = match a2.info.as_ref().unwrap() {
                        apqn_info::Ep11(i) => i,
                        _ => continue,
                    };
                    if i1.mkvp.is_empty() || i2.mkvp.is_empty() {
                        continue;
                    }
                    if i1.mkvp == i2.mkvp {
                        eprintln!("APQN {} and APQN {} have same MPVK", a1, a2);
                        return false;
                    }
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // These tests assume, there is an AP bus available
    // Also for each APQN which is online, it is assumed
    // to have a valid master key set up (for Ep11 and CCA).

    #[test]
    fn test_check_ap_bus_support() {
        if Path::new(PATH_SYS_BUS_AP).is_dir() {
            assert!(check_ap_bus_support().is_ok());
        } else {
            assert!(check_ap_bus_support().is_err());
        }
    }
    #[test]
    fn test_check_ap_bus_apsb_support() {
        if Path::new(PATH_SYS_BUS_AP).is_dir() {
            // if we are inside a secure execution guest the
            // apsb check should succeed. Outside an SE guest
            // the check should fail.
            if pv_core::misc::pv_guest_bit_set() {
                assert!(ap_bus_has_apsb_support().is_ok());
            } else {
                assert!(ap_bus_has_apsb_support().is_err());
            }
        } else {
            assert!(ap_bus_has_apsb_support().is_err());
        }
    }
    #[test]
    fn test_wait_for_ap_bus_bindings_complete() {
        let r = wait_for_ap_bus_bindings_complete();
        if Path::new(PATH_SYS_BUS_AP).is_dir() {
            assert!(r);
        } else {
            assert!(!r);
        }
    }
    #[test]
    fn test_gather_apqns() {
        let r = ApqnList::gather_apqns();
        if Path::new(PATH_SYS_BUS_AP).is_dir() {
            assert!(r.is_some());
            // fail if no entries found
            let l = r.unwrap();
            let v = l.to_apqn_vec();
            for a in v {
                match a.mode {
                    apqn_mode::Accel => {
                        // fail if no ApqnInfo is attached
                        assert!(a.info.is_some());
                    }
                    apqn_mode::Ep11 => {
                        // fail if no ApqnInfo is attached
                        assert!(a.info.is_some());
                        let info = a.info.unwrap();
                        let i = match &info {
                            apqn_info::Ep11(i) => i,
                            _ => panic!("ApqnInfo attached onto Ep11 APQN is NOT ApqnInfoEp11 ?!?"),
                        };
                        // fail if no serialnr
                        assert!(!i.serialnr.is_empty());
                        // mkvp is either empty (no WK set) or has exact 32 characters
                        assert!(i.mkvp.is_empty() || i.mkvp.len() == 32);
                    }
                    apqn_mode::Cca => {
                        // fail if no ApqnInfo is attached
                        assert!(a.info.is_some());
                        let info = a.info.unwrap();
                        let i = match &info {
                            apqn_info::Cca(i) => i,
                            _ => panic!("ApqnInfo attached onto Cca APQN is NOT ApqnInfoCca ?!?"),
                        };
                        // fail if no serialnr
                        assert!(!i.serialnr.is_empty());
                        // aes mkvp is either empty (no MK set) or exact 16 characters
                        assert!(i.mkvp_aes.is_empty() || i.mkvp_aes.len() == 16);
                        // apka mkvp is either empty (no MK set) or exact 16 characters
                        assert!(i.mkvp_apka.is_empty() || i.mkvp_apka.len() == 16);
                    }
                }
            }
        } else {
            assert!(r.is_none());
        }
    }
}
