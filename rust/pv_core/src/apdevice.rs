// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
//
//! AP support functions
//

use crate::{
    utils::{pv_guest_bit_set, read_file_string, write_file},
    Error, Result,
};
use regex::Regex;
use std::fmt;
use std::thread;
use std::time;

const PATH_SYS_DEVICES_AP: &str = "/sys/devices/ap";

/// Regular expression for AP queue directories
pub const RE_QUEUE_DIR: &str = r"^([[:xdigit:]]{2})\.([[:xdigit:]]{4})$";
const RE_CARD_TYPE: &str = r"^CEX([3-8])([ACP])$";
const RE_EP11_MKVP: &str = r"WK\s+CUR:\s+(\S+)\s+(\S+)";
const RE_CCA_AES_MKVP: &str = r"AES\s+CUR:\s+(\S+)\s+(\S+)";
const RE_CCA_APKA_MKVP: &str = r"APKA\s+CUR:\s+(\S+)\s+(\S+)";

const SYS_BUS_AP_BIND_POLL_MS: u64 = 500;
const SYS_BUS_AP_BIND_TIMEOUT_MS: u64 = 10000;

const SYS_BUS_AP_ASSOC_POLL_MS: u64 = 500;
const SYS_BUS_AP_ASSOC_TIMEOUT_MS: u64 = 10000;

/// APQN mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApqnMode {
    /// Accelerator mode
    Accel,
    /// EP11 (Enterprise PKCS #11) coprocessor mode
    Ep11,
    /// Common Cryptographic Architecture (CCA) coprocessor mode
    Cca,
}

/// Info on an APQN configured for accelerator
#[derive(Debug, Clone)]
pub struct ApqnInfoAccel {
    // empty
}

/// Info on an APQN configured for EP11 coprocessor
#[derive(Debug, Clone)]
pub struct ApqnInfoEp11 {
    /// Serial number of the Crypto Express adapter as a case-sensitive ASCII string
    pub serialnr: String,
    /// Master key verification pattern as hex string
    pub mkvp: String, // may be an empty string if no WK set
}

/// Info on an APQN configured for CCA coprocessor
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ApqnInfoCca {
    /// Serial number of the Crypto Express adapter as a case-sensitive ASCII string
    pub serialnr: String,
    /// Master key verification pattern as hex string for AES
    pub mkvp_aes: String, // may be an empty string if no MK set
    /// Master key verification pattern as hex string for asymmetric public key algorithms
    pub mkvp_apka: String, // may be an empty string if no MK set
}

/// Info for an APQN's mode
#[derive(Debug, Clone)]
pub enum ApqnInfo {
    /// Info on an APQN configured for accelerator
    Accel(ApqnInfoAccel),
    /// Info on an APQN configured for EP11 coprocessor
    Ep11(ApqnInfoEp11),
    /// Info on an APQN configured for CCA coprocessor
    #[allow(dead_code)]
    Cca(ApqnInfoCca),
}

macro_rules! parse_error {
    ($subject:expr, $content:expr) => {
        Error::ParseError {
            subject: $subject,
            content: $content,
        }
    };
}

impl ApqnInfo {
    fn accel_info(_carddir: &str, _queuedir: &str) -> Result<Self> {
        Ok(Self::Accel(ApqnInfoAccel {}))
    }

    fn cca_info(carddir: &str, queuedir: &str) -> Result<Self> {
        let serialnr_str = read_file_string(format!("{carddir}/serialnr"), "serialnr")?;
        let serialnr = serialnr_str.trim().to_string();
        let mkvps = read_file_string(format!("{carddir}/{queuedir}/mkvps"), "mkvps")?;
        let mut aes_mkvp = String::new();
        let re_cca_aes_mkvp = Regex::new(RE_CCA_AES_MKVP).unwrap();
        if !re_cca_aes_mkvp.is_match(&mkvps) {
            return Err(parse_error!(format!("APQN {queuedir} MKVPs"), mkvps));
        } else {
            let caps = re_cca_aes_mkvp.captures(&mkvps).unwrap();
            if caps.get(1).unwrap().as_str().to_lowercase() == "valid" {
                aes_mkvp = caps.get(2).unwrap().as_str().to_lowercase();
                if aes_mkvp.starts_with("0x") {
                    aes_mkvp = String::from(&aes_mkvp[2..]);
                }
            }
        }
        let mut apka_mkvp = String::new();
        let re_cca_apka_mkvp = Regex::new(RE_CCA_APKA_MKVP).unwrap();
        if !re_cca_apka_mkvp.is_match(&mkvps) {
            return Err(parse_error!(format!("APQN {queuedir} MKVPs"), mkvps));
        } else {
            let caps = re_cca_apka_mkvp.captures(&mkvps).unwrap();
            if caps.get(1).unwrap().as_str().to_lowercase() == "valid" {
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

    fn ep11_info(carddir: &str, queuedir: &str) -> Result<Self> {
        let serialnr_str = read_file_string(format!("{carddir}/serialnr"), "serialnr")?;
        let serialnr = serialnr_str.trim().to_string();
        let mkvps = read_file_string(format!("{carddir}/{queuedir}/mkvps"), "mkvps")?;
        let mut mkvp = String::new();
        let re_ep11_mkvp = Regex::new(RE_EP11_MKVP).unwrap();
        if !re_ep11_mkvp.is_match(&mkvps) {
            return Err(parse_error!(format!("APQN {queuedir} MKVPs"), mkvps));
        } else {
            let caps = re_ep11_mkvp.captures(&mkvps).unwrap();
            if caps.get(1).unwrap().as_str().to_lowercase() == "valid" {
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

    /// Get mode-specific info
    pub fn info(mode: &ApqnMode, carddir: &str, queuedir: &str) -> Result<Self> {
        match mode {
            ApqnMode::Accel => Self::accel_info(carddir, queuedir),
            ApqnMode::Cca => Self::cca_info(carddir, queuedir),
            ApqnMode::Ep11 => Self::ep11_info(carddir, queuedir),
        }
    }
}

/// `Apqn` encodes an adjunct processor queue number.
#[derive(Debug, Clone)]
pub struct Apqn {
    /// Name of the APQN
    #[allow(dead_code)]
    pub name: String,
    /// Card number
    pub card: u32,
    /// Domain number
    pub domain: u32,
    /// CryptoExpress generation
    pub gen: u32,
    /// Mode that adapter is configured to use
    pub mode: ApqnMode,
    /// Mode-specific info
    pub info: Option<ApqnInfo>,
}

impl TryFrom<&str> for Apqn {
    type Error = Error;

    /// Create an `Apqn` struct from a CARD.DOMAIN-formatted APQN
    /// string, such as `28.0014`. Will not populate `info` upon
    /// failure to read it. Other failures to read required information
    /// are treated as an Error.
    /// # Panics
    /// Panics if the compilation of a static regular expression fails
    /// or a regex capture that is already format-checked does not
    /// parse, e.g. when the capture `([[:xdigit:]]{2})` does not
    /// parse as hex string.
    fn try_from(name: &str) -> Result<Self> {
        let re_card_type = Regex::new(RE_CARD_TYPE).unwrap();
        let re_queue_dir = Regex::new(RE_QUEUE_DIR).unwrap();

        let caps = re_queue_dir
            .captures(name)
            .ok_or_else(|| parse_error!("queue".to_string(), name.to_string()))?;
        let cardstr = caps.get(1).unwrap().as_str();
        let card = u32::from_str_radix(cardstr, 16).unwrap();
        let domstr = caps.get(2).unwrap().as_str();
        let domain = u32::from_str_radix(domstr, 16).unwrap();

        let path = format!("{PATH_SYS_DEVICES_AP}/card{cardstr}");
        let card_type =
            read_file_string(format!("{path}/type"), "card type").map(|s| s.trim().to_string())?;
        let caps = re_card_type
            .captures(&card_type)
            .ok_or_else(|| parse_error!("card type".to_string(), card_type.to_string()))?;
        let gen = caps.get(1).unwrap().as_str().parse::<u32>().unwrap();
        let mode = match caps.get(2).unwrap().as_str().parse::<char>().unwrap() {
            'A' => ApqnMode::Accel,
            'C' => ApqnMode::Cca,
            'P' => ApqnMode::Ep11,
            _ => unreachable!("Code inconsistency between regex RE_CARD_TYPE and evaluation code."),
        };
        // the UV blocks requests to CCA cards within SE guest with AP
        // pass-through support. However, filter out CCA cards as
        // these cards cause hangs during information gathering.
        if mode == ApqnMode::Cca && pv_guest_bit_set() {
            return Err(Error::CcaSeIncompatible(card));
        }

        match read_file_string(format!("{path}/{name}/online"), "AP queue online status")
            .map(|s| s.trim().parse::<i32>())
        {
            Ok(Ok(1)) => {}
            _ => return Err(Error::ApOffline { card, domain }),
        }
        // For the MKVP and serialnr to fetch from the APQN within a SE
        // guest the APQN needs to be bound to the guest. So if the APQN
        // is not bound, temporarily bind it here until the info has
        // been retrieved.
        let mut tempbound = false;
        if pv_guest_bit_set() {
            let cbs = get_apqn_bind_state(card, domain)?;
            if cbs == BindState::Unbound {
                set_apqn_bind_state(card, domain, BindState::Bound)?;
                tempbound = true;
            }
        }
        let info = ApqnInfo::info(&mode, &path, name).ok();
        if tempbound {
            set_apqn_bind_state(card, domain, BindState::Unbound)?;
        }

        Ok(Apqn {
            name: name.to_string(),
            card,
            domain,
            gen,
            mode,
            info,
        })
    }
}

impl fmt::Display for Apqn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})", self.card, self.domain)
    }
}

impl Apqn {
    /// Read bind state of the APQN.
    pub fn bind_state(&self) -> Result<BindState> {
        get_apqn_bind_state(self.card, self.domain)
    }

    /// Set bind state of the APQN.
    pub fn set_bind_state(&self, state: BindState) -> Result<()> {
        set_apqn_bind_state(self.card, self.domain, state)
    }

    /// Read associate state of the APQN.
    pub fn associate_state(&self) -> Result<AssocState> {
        get_apqn_associate_state(self.card, self.domain)
    }

    /// Set associate state of the APQN.
    pub fn set_associate_state(&self, state: AssocState) -> Result<()> {
        set_apqn_associate_state(self.card, self.domain, state)
    }
}

/// Bind state of an APQN
#[derive(Debug, PartialEq, Eq)]
pub enum BindState {
    /// APQN is bound
    Bound,
    /// APQN is unbound
    Unbound,
    /// APQN does not support bind
    NotSupported,
}

/// Query bind state for this APQN.
///
/// Returns a BindState enum as defined above or on failure
/// an error string. Does NOT print any error messages.
pub fn get_apqn_bind_state(card: u32, dom: u32) -> Result<BindState> {
    let path = format!("{PATH_SYS_DEVICES_AP}/card{card:02x}/{card:02x}.{dom:04x}/se_bind");
    let state_str = read_file_string(path, "se_bind attribute")?;
    let state = state_str.trim();
    match state {
        "bound" => Ok(BindState::Bound),
        "unbound" => Ok(BindState::Unbound),
        "-" => Ok(BindState::NotSupported),
        _ => Err(Error::UnknownBindState(state.to_string())),
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
pub fn set_apqn_bind_state(card: u32, dom: u32, state: BindState) -> Result<()> {
    let ctx = "bind APQN";
    let path = format!("{PATH_SYS_DEVICES_AP}/card{card:02x}/{card:02x}.{dom:04x}/se_bind");
    match state {
        BindState::Bound => write_file(path, 1.to_string(), ctx),
        BindState::Unbound => write_file(path, 0.to_string(), ctx),
        _ => panic!("set_apqn_bind_state called with invalid BindState."),
    }?;
    let mut ms: u64 = 0;
    loop {
        thread::sleep(time::Duration::from_millis(SYS_BUS_AP_BIND_POLL_MS));
        ms += SYS_BUS_AP_BIND_POLL_MS;
        if ms >= SYS_BUS_AP_BIND_TIMEOUT_MS {
            break Err(Error::Timeout(format!(
                "setting APQN({card},{dom}) bind state"
            )));
        }
        let newstate = get_apqn_bind_state(card, dom)?;
        if newstate == state {
            return Ok(());
        }
    }
}

/// Association state of an APQN
#[derive(Debug, PartialEq, Eq)]
pub enum AssocState {
    /// Associated with index
    Associated(u16),
    /// Association pending
    AssociationPending,
    /// Not associated
    Unassociated,
    /// APQN does not support association
    NotSupported,
}

/// Query association state for this APQN.
///
/// Returns an AssocState enum as defined above or on failure
/// an error string. Does NOT print any error messages.
pub fn get_apqn_associate_state(card: u32, dom: u32) -> Result<AssocState> {
    let path = format!("{PATH_SYS_DEVICES_AP}/card{card:02x}/{card:02x}.{dom:04x}/se_associate");
    let state_str = read_file_string(path, "se_associate attribute")?;
    let state = state_str.trim();
    match state.strip_prefix("associated ") {
        Some(prefix) => Ok(AssocState::Associated(prefix.parse()?)),
        _ => match state {
            "association pending" => Ok(AssocState::AssociationPending),
            "unassociated" => Ok(AssocState::Unassociated),
            "-" => Ok(AssocState::NotSupported),
            _ => Err(Error::UnknownAssocState(state.to_string())),
        },
    }
}

fn set_apqn_associate_state_associate(card: u32, dom: u32, idx: u16) -> Result<()> {
    let path = format!("{PATH_SYS_DEVICES_AP}/card{card:02x}/{card:02x}.{dom:04x}/se_associate");
    write_file(path, idx.to_string(), "associate APQN")?;
    let mut ms: u64 = 0;
    loop {
        thread::sleep(time::Duration::from_millis(SYS_BUS_AP_ASSOC_POLL_MS));
        ms += SYS_BUS_AP_ASSOC_POLL_MS;
        if ms >= SYS_BUS_AP_ASSOC_TIMEOUT_MS {
            break Err(Error::Timeout(format!(
                "setting APQN({card},{dom}) association index {idx} state",
            )));
        }
        match get_apqn_associate_state(card, dom)? {
            AssocState::Associated(i) if i == idx => return Ok(()),
            AssocState::Associated(i) => {
                return Err(Error::WrongAssocState {
                    card,
                    domain: dom,
                    desired: idx,
                    actual: i,
                })
            }
            _ => {}
        }
    }
}

fn set_apqn_associate_state_unbind(card: u32, dom: u32) -> Result<()> {
    let bindpath = format!("{PATH_SYS_DEVICES_AP}/card{card:02x}/{card:02x}.{dom:04x}/se_bind");
    write_file(bindpath, 0.to_string(), "unbind APQN")?;
    let mut ms: u64 = 0;
    loop {
        thread::sleep(time::Duration::from_millis(SYS_BUS_AP_ASSOC_POLL_MS));
        ms += SYS_BUS_AP_ASSOC_POLL_MS;
        if ms >= SYS_BUS_AP_ASSOC_TIMEOUT_MS {
            break Err(Error::Timeout(format!(
                "setting APQN({card},{dom}) association unbind state",
            )));
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
pub fn set_apqn_associate_state(card: u32, dom: u32, state: AssocState) -> Result<()> {
    match state {
        AssocState::Associated(idx) => set_apqn_associate_state_associate(card, dom, idx),
        AssocState::Unassociated => set_apqn_associate_state_unbind(card, dom),
        _ => panic!("set_apqn_associate_state called with invalid AssocState."),
    }
}
