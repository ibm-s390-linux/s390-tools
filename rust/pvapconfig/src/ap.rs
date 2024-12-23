// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
//
//! AP support functions for pvapconfig
//

use crate::helper::*;
use regex::Regex;
use std::fmt;
use std::path::Path;
use std::slice::Iter;
use std::thread;
use std::time;

const PATH_SYS_BUS_AP: &str = "/sys/bus/ap";
const PATH_SYS_BUS_AP_FEATURES: &str = "/sys/bus/ap/features";
const PATH_SYS_BUS_AP_BINDINGS: &str = "/sys/bus/ap/bindings";
const PATH_SYS_DEVICES_AP: &str = "/sys/devices/ap";

const RE_CARD_DIR: &str = r"^card([[:xdigit:]]{2})$";
const RE_QUEUE_DIR: &str = r"^([[:xdigit:]]{2})\.([[:xdigit:]]{4})$";
const RE_CARD_TYPE: &str = r"^CEX([3-8])([ACP])$";
const RE_EP11_MKVP: &str = r"WK\s+CUR:\s+(\S+)\s+(\S+)";
const RE_CCA_AES_MKVP: &str = r"AES\s+CUR:\s+(\S+)\s+(\S+)";
const RE_CCA_APKA_MKVP: &str = r"APKA\s+CUR:\s+(\S+)\s+(\S+)";

const SYS_BUS_AP_BINDINGS_POLL_MS: u64 = 500;

const SYS_BUS_AP_BIND_POLL_MS: u64 = 500;
const SYS_BUS_AP_BIND_TIMEOUT_MS: u64 = 10000;

const SYS_BUS_AP_ASSOC_POLL_MS: u64 = 500;
const SYS_BUS_AP_ASSOC_TIMEOUT_MS: u64 = 10000;

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
    if !Path::new(PATH_SYS_BUS_AP_FEATURES).is_file() {
        return Err(format!(
            "AP bus features support missing (file {PATH_SYS_BUS_AP_FEATURES} does not exist)."
        ));
    }
    let features = sysfs_read_string(PATH_SYS_BUS_AP_FEATURES).map_err(|err| {
        format!("Failure reading AP bus features from {PATH_SYS_BUS_AP_FEATURES} ({err:?}).")
    })?;
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
        match sysfs_read_string(PATH_SYS_BUS_AP_BINDINGS) {
            Ok(s) => {
                if s.contains("complete") {
                    return true;
                }
            }
            Err(err) => {
                eprintln!(
                    "Failure reading AP bus bindings from {} ({:?}).",
                    PATH_SYS_BUS_AP_BINDINGS, err
                );
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApqnMode {
    Accel,
    Ep11,
    Cca,
}

#[derive(Debug, Clone)]
pub struct ApqnInfoAccel {
    // empty
}

#[derive(Debug, Clone)]
pub struct ApqnInfoEp11 {
    pub serialnr: String,
    pub mkvp: String, // may be an empty string if no WK set
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ApqnInfoCca {
    pub serialnr: String,
    pub mkvp_aes: String,  // may be an empty string if no MK set
    pub mkvp_apka: String, // may be an empty string if no MK set
}

#[derive(Debug, Clone)]
pub enum ApqnInfo {
    Accel(ApqnInfoAccel),
    Ep11(ApqnInfoEp11),
    #[allow(dead_code)]
    Cca(ApqnInfoCca),
}

impl ApqnInfo {
    fn accel_info(_carddir: &str, _queuedir: &str) -> Result<Self, String> {
        Ok(Self::Accel(ApqnInfoAccel {}))
    }

    fn cca_info(carddir: &str, queuedir: &str) -> Result<Self, String> {
        let serialnr = match sysfs_read_string(&format!("{carddir}/serialnr")) {
            Ok(r) => r,
            Err(err) => {
                return Err(format!(
                    "Failure reading serialnr from {carddir}/serialnr: {:?}.",
                    err
                ))
            }
        };
        let mkvps = match sysfs_read_string(&format!("{carddir}/{queuedir}/mkvps")) {
            Ok(r) => r,
            Err(err) => {
                return Err(format!(
                    "Failure reading mkvps from {carddir}/{queuedir}/mkvps: {:?}.",
                    err
                ))
            }
        };
        let mut aes_mkvp = String::new();
        let re_cca_aes_mkvp = Regex::new(RE_CCA_AES_MKVP).unwrap();
        if !re_cca_aes_mkvp.is_match(&mkvps) {
            return Err(format!(
                "APQN {} failure parsing mkvps string '{}'.",
                queuedir, mkvps
            ));
        } else {
            let caps = re_cca_aes_mkvp.captures(&mkvps).unwrap();
            let valid = caps.get(1).unwrap().as_str().to_lowercase();
            if valid != "valid" {
                eprintln!(
                    "Warning: APQN {} has no valid AES master key set.",
                    queuedir
                );
            } else {
                aes_mkvp = caps.get(2).unwrap().as_str().to_lowercase();
                if aes_mkvp.starts_with("0x") {
                    aes_mkvp = String::from(&aes_mkvp[2..]);
                }
            }
        }
        let mut apka_mkvp = String::new();
        let re_cca_apka_mkvp = Regex::new(RE_CCA_APKA_MKVP).unwrap();
        if !re_cca_apka_mkvp.is_match(&mkvps) {
            return Err(format!(
                "APQN {} failure parsing mkvps string '{}'.",
                queuedir, mkvps
            ));
        } else {
            let caps = re_cca_apka_mkvp.captures(&mkvps).unwrap();
            let valid = caps.get(1).unwrap().as_str().to_lowercase();
            if valid != "valid" {
                eprintln!(
                    "Warning: APQN {} has no valid APKA master key set.",
                    queuedir
                );
            } else {
                apka_mkvp = caps.get(2).unwrap().as_str().to_lowercase();
                if apka_mkvp.starts_with("0x") {
                    apka_mkvp = String::from(&apka_mkvp[2..]);
                }
            }
        }
        Ok(Self::Cca(ApqnInfoCca {
            serialnr,
            mkvp_aes: aes_mkvp,
            mkvp_apka: apka_mkvp,
        }))
    }

    fn ep11_info(carddir: &str, queuedir: &str) -> Result<Self, String> {
        let serialnr = match sysfs_read_string(&format!("{carddir}/serialnr")) {
            Ok(r) => r,
            Err(err) => {
                return Err(format!(
                    "Failure reading serialnr from {carddir}/serialnr: {:?}.",
                    err
                ))
            }
        };
        let mkvps = match sysfs_read_string(&format!("{carddir}/{queuedir}/mkvps")) {
            Ok(r) => r,
            Err(err) => {
                return Err(format!(
                    "Failure reading mkvps from {carddir}/{queuedir}/mkvps: {:?}.",
                    err
                ))
            }
        };
        let mut mkvp = String::new();
        let re_ep11_mkvp = Regex::new(RE_EP11_MKVP).unwrap();
        if !re_ep11_mkvp.is_match(&mkvps) {
            return Err(format!(
                "APQN {} failure parsing mkvps string '{}'.",
                queuedir, mkvps
            ));
        } else {
            let caps = re_ep11_mkvp.captures(&mkvps).unwrap();
            let valid = caps.get(1).unwrap().as_str().to_lowercase();
            if valid != "valid" {
                eprintln!("Warning: APQN {} has no valid wrapping key set.", queuedir);
            } else {
                mkvp = caps.get(2).unwrap().as_str().to_lowercase();
                if mkvp.starts_with("0x") {
                    mkvp = String::from(&mkvp[2..]);
                }
                if mkvp.len() > 32 {
                    mkvp = String::from(&mkvp[..32])
                }
            }
        }
        Ok(Self::Ep11(ApqnInfoEp11 { serialnr, mkvp }))
    }

    fn info(mode: &ApqnMode, carddir: &str, queuedir: &str) -> Result<Self, String> {
        match mode {
            ApqnMode::Accel => Self::accel_info(carddir, queuedir),
            ApqnMode::Cca => Self::cca_info(carddir, queuedir),
            ApqnMode::Ep11 => Self::ep11_info(carddir, queuedir),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Apqn {
    #[allow(dead_code)]
    pub name: String,
    pub card: u32,
    pub domain: u32,
    pub gen: u32,
    pub mode: ApqnMode,
    pub info: Option<ApqnInfo>,
}

impl fmt::Display for Apqn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})", self.card, self.domain)
    }
}

impl Apqn {
    pub fn bind_state(&self) -> Result<BindState, String> {
        get_apqn_bind_state(self.card, self.domain)
    }

    pub fn set_bind_state(&self, state: BindState) -> Result<(), String> {
        set_apqn_bind_state(self.card, self.domain, state)
    }

    pub fn associate_state(&self) -> Result<AssocState, String> {
        get_apqn_associate_state(self.card, self.domain)
    }

    pub fn set_associate_state(&self, state: AssocState) -> Result<(), String> {
        set_apqn_associate_state(self.card, self.domain, state)
    }
}

/// Wrapper object around Vector of Apqns
pub struct ApqnList(Vec<Apqn>);

impl ApqnList {
    #[cfg(test)] // only used in test code
    pub fn from_apqn_vec(apqns: Vec<Apqn>) -> Self {
        Self(apqns)
    }

    #[cfg(test)] // only used in test code
    pub fn to_apqn_vec(&self) -> Vec<Apqn> {
        self.0.clone()
    }

    pub fn iter(&self) -> Iter<'_, Apqn> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Scan AP bus devices in sysfs and construct the Apqnlist.
    ///
    /// The list is a vector of struct Apqn for each APQN found in sysfs
    /// which is online and the card type matches to the regular expression
    /// RE_CARD_TYPE.
    /// On success a vector of struct Apqn is returned. This list may be
    /// empty if there are no APQNs available or do not match to the conditions.
    /// On failure None is returned.
    /// Fatal errors which should never happened like unable to compile a
    /// static regular expression will result in calling panic.
    /// # Panics
    /// Panics if the compilation of a static regular expression fails.
    pub fn gather_apqns() -> Option<Self> {
        let mut apqns: Vec<Apqn> = Vec::new();
        let re_card_type = Regex::new(RE_CARD_TYPE).unwrap();
        let re_queue_dir = Regex::new(RE_QUEUE_DIR).unwrap();
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
            let card_type = match sysfs_read_string(&format!("{path}/type")) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("Failure reading card type from {} ({:?}).", path, err);
                    return None;
                }
            };
            if !re_card_type.is_match(&card_type) {
                eprintln!("Failure parsing card type string '{}'.", card_type);
                return None;
            }
            let caps = re_card_type.captures(&card_type).unwrap();
            let gen = caps.get(1).unwrap().as_str().parse::<u32>().unwrap();
            let mode = match caps.get(2).unwrap().as_str().parse::<char>().unwrap() {
                'A' => ApqnMode::Accel,
                'C' => ApqnMode::Cca,
                'P' => ApqnMode::Ep11,
                _ => panic!("Code inconsistence between regex RE_CARD_TYPE and evaluation code."),
            };
            if pv_core::misc::pv_guest_bit_set() {
                // the UV blocks requests to CCA cards within SE guest with
                // AP pass-through support. However, filter out CCA cards as these
                // cards cause hangs during information gathering.
                if mode == ApqnMode::Cca {
                    continue;
                }
            }
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
                let _online = match sysfs_read_i32(&format!("{path}/{queue_dir}/online")) {
                    Ok(1) => true,
                    _ => continue,
                };
                let caps = re_queue_dir.captures(&queue_dir).unwrap();
                let cardstr = caps.get(1).unwrap().as_str();
                let card = u32::from_str_radix(cardstr, 16).unwrap();
                let domstr = caps.get(2).unwrap().as_str();
                let dom = u32::from_str_radix(domstr, 16).unwrap();
                // For the mpvk and serialnr to fetch from the APQN within a SE
                // guest the APQN needs to be bound to the guest. So if the APQN
                // is not bound, temporarily bind it here until the info has
                // been retrieved.
                let mut tempbound = false;
                if pv_core::misc::pv_guest_bit_set() {
                    let cbs = match get_apqn_bind_state(card, dom) {
                        Ok(bs) => bs,
                        Err(err) => {
                            eprintln!(
                                "Error: Failure reading APQN ({},{}) bind state: {}",
                                card, dom, err
                            );
                            BindState::NotSupported
                        }
                    };
                    if cbs == BindState::Unbound {
                        let r = set_apqn_bind_state(card, dom, BindState::Bound);
                        if r.is_err() {
                            eprintln!(
                                "Warning: Failure to temp. bind APQN ({},{}): {}",
                                card,
                                dom,
                                r.unwrap_err()
                            );
                            continue;
                        } else {
                            tempbound = true;
                        }
                    };
                };
                let info = match ApqnInfo::info(&mode, &path, &queue_dir) {
                    Err(err) => {
                        // print the error but continue with info set to None
                        eprintln!(
                            "Warning: Failure to gather info for APQN ({},{}): {}",
                            card, dom, err
                        );
                        None
                    }
                    Ok(i) => Some(i),
                };
                if tempbound {
                    let r = set_apqn_bind_state(card, dom, BindState::Unbound);
                    if r.is_err() {
                        eprintln!(
                            "Warning: Failure to unbind temp. bound APQN ({},{}): {}",
                            card,
                            dom,
                            r.unwrap_err()
                        );
                    }
                };
                apqns.push(Apqn {
                    name: queue_dir.clone(),
                    card,
                    domain: dom,
                    gen,
                    mode: mode.clone(),
                    info,
                });
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
                    && a1.mode == ApqnMode::Ep11
                    && a1.info.is_some()
                    && a2.info.is_some()
                {
                    let i1 = match a1.info.as_ref().unwrap() {
                        ApqnInfo::Ep11(i) => i,
                        _ => continue,
                    };
                    let i2 = match a2.info.as_ref().unwrap() {
                        ApqnInfo::Ep11(i) => i,
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

#[derive(PartialEq, Eq)]
pub enum BindState {
    Bound,
    Unbound,
    NotSupported,
}

/// Query bind state for this APQN.
///
/// Returns a BindState enum as defined above or on failure
/// an error string. Does NOT print any error messages.
pub fn get_apqn_bind_state(card: u32, dom: u32) -> Result<BindState, String> {
    let path = format!(
        "{}/card{:02x}/{:02x}.{:04x}/se_bind",
        PATH_SYS_DEVICES_AP, card, card, dom
    );
    match sysfs_read_string(&path) {
        Err(err) => Err(format!(
            "Failure reading se_bind attribute for APQN({},{}): {:?}.",
            card, dom, err
        )),
        Ok(str) => match str.as_str() {
            "bound" => Ok(BindState::Bound),
            "unbound" => Ok(BindState::Unbound),
            "-" => Ok(BindState::NotSupported),
            _ => Err(format!("Unknown bind state '{str}'.")),
        },
    }
}

/// Bind or unbind an APQN.
///
/// The action is determined by the BindState given in.
/// But of course only Bound and Unbound is supported - otherwise
/// this function panics!
/// The function actively loops over the bind state until
/// the requested bind state is reached or a timeout has
/// occurred (SYS_BUS_AP_BIND_TIMEOUT_MS).
/// On success () is returned, on failure an error string
/// is returned. Does NOT print any error messages.
/// # Panics
/// Panics if a desired bind state other than Bound or Unbound is given.
pub fn set_apqn_bind_state(card: u32, dom: u32, state: BindState) -> Result<(), String> {
    let path = format!(
        "{}/card{:02x}/{:02x}.{:04x}/se_bind",
        PATH_SYS_DEVICES_AP, card, card, dom
    );
    let r = match state {
        BindState::Bound => sysfs_write_i32(&path, 1),
        BindState::Unbound => sysfs_write_i32(&path, 0),
        _ => panic!("set_apqn_bind_state called with invalid BindState."),
    };
    if r.is_err() {
        return Err(format!(
            "Failure writing se_bind attribute for APQN({},{}): {:?}.",
            card,
            dom,
            r.unwrap_err()
        ));
    }
    let mut ms: u64 = 0;
    loop {
        thread::sleep(time::Duration::from_millis(SYS_BUS_AP_BIND_POLL_MS));
        ms += SYS_BUS_AP_BIND_POLL_MS;
        if ms >= SYS_BUS_AP_BIND_TIMEOUT_MS {
            break Err(format!(
                "Timeout setting APQN({},{}) bind state.",
                card, dom
            ));
        }
        let newstate = get_apqn_bind_state(card, dom)?;
        if newstate == state {
            return Ok(());
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum AssocState {
    Associated(u16),
    AssociationPending,
    Unassociated,
    NotSupported,
}

/// Query association state for this APQN.
///
/// Returns an AssocState enum as defined above or on failure
/// an error string. Does NOT print any error messages.
pub fn get_apqn_associate_state(card: u32, dom: u32) -> Result<AssocState, String> {
    let path = format!(
        "{}/card{:02x}/{:02x}.{:04x}/se_associate",
        PATH_SYS_DEVICES_AP, card, card, dom
    );
    match sysfs_read_string(&path) {
        Err(err) => Err(format!(
            "Failure reading se_associate attribute for APQN({},{}: {:?}",
            card, dom, err
        )),
        Ok(str) => {
            if let Some(prefix) = str.strip_prefix("associated ") {
                let value = &prefix.parse::<u16>();
                match value {
                    Ok(v) => Ok(AssocState::Associated(*v)),
                    Err(_) => Err(format!("Invalid association index in '{str}'.")),
                }
            } else {
                match str.as_str() {
                    "association pending" => Ok(AssocState::AssociationPending),
                    "unassociated" => Ok(AssocState::Unassociated),
                    "-" => Ok(AssocState::NotSupported),
                    _ => Err(format!("Unknown association state '{str}'.")),
                }
            }
        }
    }
}

fn set_apqn_associate_state_associate(card: u32, dom: u32, idx: u16) -> Result<(), String> {
    let path = format!(
        "{}/card{:02x}/{:02x}.{:04x}/se_associate",
        PATH_SYS_DEVICES_AP, card, card, dom
    );
    let r = sysfs_write_i32(&path, idx as i32);
    if r.is_err() {
        return Err(format!(
            "Failure writing se_associate attribute for APQN({},{}): {:?}.",
            card,
            dom,
            r.unwrap_err()
        ));
    }
    let mut ms: u64 = 0;
    loop {
        thread::sleep(time::Duration::from_millis(SYS_BUS_AP_ASSOC_POLL_MS));
        ms += SYS_BUS_AP_ASSOC_POLL_MS;
        if ms >= SYS_BUS_AP_ASSOC_TIMEOUT_MS {
            break Err(format!(
                "Timeout setting APQN({},{}) association idx {} state.",
                card, dom, idx
            ));
        }
        let newstate = get_apqn_associate_state(card, dom)?;
        if let AssocState::Associated(i) = newstate {
            if idx == i {
                return Ok(());
            } else {
                return Err(format!(
                    "Failure: APQN({},{}) is associated with {} but it should be {}.",
                    card, dom, i, idx
                ));
            }
        }
    }
}

fn set_apqn_associate_state_unbind(card: u32, dom: u32) -> Result<(), String> {
    let bindpath = format!(
        "{}/card{:02x}/{:02x}.{:04x}/se_bind",
        PATH_SYS_DEVICES_AP, card, card, dom
    );
    let r = sysfs_write_i32(&bindpath, 0);
    if r.is_err() {
        return Err(format!(
            "Failure writing se_bind attribute for APQN({},{}): {:?}.",
            card,
            dom,
            r.unwrap_err()
        ));
    }
    let mut ms: u64 = 0;
    loop {
        thread::sleep(time::Duration::from_millis(SYS_BUS_AP_ASSOC_POLL_MS));
        ms += SYS_BUS_AP_ASSOC_POLL_MS;
        if ms >= SYS_BUS_AP_ASSOC_TIMEOUT_MS {
            break Err(format!(
                "Timeout setting APQN({},{}) association unbind state.",
                card, dom
            ));
        }
        let newstate = get_apqn_associate_state(card, dom)?;
        if newstate == AssocState::Unassociated {
            return Ok(());
        }
    }
}

/// Associate or Unassociate an APQN.
///
/// The action is determined by the AssocState given in.
/// But of course only Associated and Unassociated is supported
/// otherwise this function panics!
/// The function actively loops over the association state until
/// the requested state is reached or a timeout has
/// occurred (SYS_BUS_AP_ASSOC_TIMEOUT_MS).
/// The unassociate is in fact a unbind. So the code triggers
/// an unbind and then loops over the sysfs se_associate until
/// "unassociated" is reached.
/// On success () is returned, on failure an error string
/// is returned. Does NOT print any error messages.
/// # Panics
/// Panics if a desired bind state other than Associated or
/// Unassociated is given.
pub fn set_apqn_associate_state(card: u32, dom: u32, state: AssocState) -> Result<(), String> {
    match state {
        AssocState::Associated(idx) => set_apqn_associate_state_associate(card, dom, idx),
        AssocState::Unassociated => set_apqn_associate_state_unbind(card, dom),
        _ => panic!("set_apqn_associate_state called with invalid AssocState."),
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
                    ApqnMode::Accel => {
                        // fail if no ApqnInfo is attached
                        assert!(a.info.is_some());
                    }
                    ApqnMode::Ep11 => {
                        // fail if no ApqnInfo is attached
                        assert!(a.info.is_some());
                        let info = a.info.unwrap();
                        let i = match &info {
                            ApqnInfo::Ep11(i) => i,
                            _ => panic!("ApqnInfo attached onto Ep11 APQN is NOT ApqnInfoEp11 ?!?"),
                        };
                        // fail if no serialnr
                        assert!(!i.serialnr.is_empty());
                        // mkvp is either empty (no WK set) or has exact 32 characters
                        assert!(i.mkvp.is_empty() || i.mkvp.len() == 32);
                    }
                    ApqnMode::Cca => {
                        // fail if no ApqnInfo is attached
                        assert!(a.info.is_some());
                        let info = a.info.unwrap();
                        let i = match &info {
                            ApqnInfo::Cca(i) => i,
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
