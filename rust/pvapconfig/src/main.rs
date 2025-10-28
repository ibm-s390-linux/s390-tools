// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
//
//! pvapconfig - Tool to automatically set up the AP configuration
//! within an IBM Secure Execution guest.
//

mod ap;
mod cli;
mod config;
mod helper;
mod uv;

use ap::ApqnList;
use cli::ARGS;
use config::{ApConfigEntry, ApConfigList};
use helper::{LockFile, PATH_PVAPCONFIG_LOCK};
use pv_core::ap::{self as pvap, Apqn};
use pv_core::misc::encode_hex;
use pv_core::uv::{ListableSecretType, SecretList};
use std::process::ExitCode;
use utils::print_version;

/// Simple macro for
///   if Cli::verbose() {
///     print!(...);
///   }
macro_rules! info {
    ($($arg:tt)*) => {{
	if ARGS.verbose() {
	    print!($($arg)*);
	}
    }};
}

/// Simple macro for the main function only
/// Does a eprintln of the arguments and then
/// return with exit failure.
macro_rules! println_and_exit_failure {
    ($($arg:tt)*) => {{
	eprintln!($($arg)*);
	return ExitCode::FAILURE;
    }};
}

/// Simple macro for the main function only
/// Check if given object has is_err() true and
/// then eprintln the unwrapped error and
/// returns with exit failure.
macro_rules! on_error_print_and_exit {
    ($r:expr) => {
        if $r.is_err() {
            eprintln!("{}", $r.unwrap_err());
            return ExitCode::FAILURE;
        }
    };
}

fn main() -> ExitCode {
    // handle version option
    if cli::ARGS.version {
        print_version!("2023");
        return ExitCode::SUCCESS;
    }

    // make sure only one pvapconfig instance is running
    let r = LockFile::try_lock(PATH_PVAPCONFIG_LOCK);
    on_error_print_and_exit!(r);
    let _lockfile = r.unwrap();

    // AP bus check
    info!("Checking AP bus support and facilities...\n");
    let r = ap::check_ap_bus_support();
    on_error_print_and_exit!(r);
    let r = ap::ap_bus_has_apsb_support();
    on_error_print_and_exit!(r);
    info!("AP bus support and facilities are ok.\n");

    // UV check
    info!("Checking UV support and environment...\n");
    if !pv_core::misc::pv_guest_bit_set() {
        println_and_exit_failure!("Failure: this is not a SE guest.");
    }
    let r = uv::has_list_secrets_facility();
    on_error_print_and_exit!(r);
    info!("UV support and environment is ok.\n");

    let mut apconfig: ApConfigList = Default::default();
    if !cli::ARGS.unbind {
        // read configuration
        let configfile: &str = match &cli::ARGS.config {
            Some(f) => f,
            _ => cli::PATH_DEFAULT_CONFIG_FILE,
        };
        info!(
            "Reading AP configuration entries from file '{}'...\n",
            configfile
        );
        apconfig = match ApConfigList::read_and_validate_yaml_file(configfile) {
            Ok(apcfg) => apcfg,
            Err(err) => println_and_exit_failure!("{}", err),
        };
        if apconfig.is_empty() {
            println!(
                "No AP configuration entries in config file '{configfile}': Nothing to do."
            );
            return ExitCode::SUCCESS;
        }
        info!("Found {} AP configuration entries.\n", apconfig.len());
    };

    // get list of secrets from UV
    let mut secrets = SecretList::new(0, Vec::new());
    if !cli::ARGS.unbind {
        info!("Fetching list of secrets from UV...\n");
        secrets = match uv::gather_secrets() {
            Err(e) => println_and_exit_failure!("{}", e),
            Ok(los) => los,
        };
        info!("Fetched {} Secret entries from UV.\n", secrets.len());
    }

    // Warning if no UV secrets given but AP config entries require it
    let non_accel_apc = apconfig
        .iter()
        .filter(|apc| apc.mode != config::STR_MODE_ACCEL)
        .count();
    if !cli::ARGS.unbind && non_accel_apc > 0 && secrets.is_empty() {
        println!(
            "Warning: No UV Secrets given but at least one AP config entry requires a Secret."
        );
    }

    info!("Waiting for AP bus bindings complete...\n");
    if !ap::wait_for_ap_bus_bindings_complete() {
        return ExitCode::FAILURE;
    }
    info!("Fetching list of available APQNs...\n");
    let mut apqns: ApqnList = match ApqnList::gather_apqns() {
        Some(l) => l,
        None => return ExitCode::FAILURE,
    };
    if apqns.is_empty() {
        info!("List of available APQNs is empty: So there's nothing to do.\n");
        return ExitCode::SUCCESS;
    }
    info!("Found {} APQNs.\n", apqns.len());
    // check MK restriction
    if !apqns.check_mk_restriction() {
        return ExitCode::FAILURE;
    }

    // now the real work
    info!("Applying AP configuration...\n");
    let n = match do_ap_config(&mut apqns, &secrets, &apconfig, false) {
        Err(e) => println_and_exit_failure!("{}", e),
        Ok(n) => n,
    };

    if !cli::ARGS.unbind && n == 0 {
        println_and_exit_failure!(
            "None out of {} AP config entries could be applied.",
            apconfig.len()
        );
    } else if ARGS.strict() && n != apconfig.len() {
        println_and_exit_failure!(
            "Strict flag given and only {} out of {} AP config entries have been applied.",
            n,
            apconfig.len()
        );
    }

    if !cli::ARGS.unbind {
        info!(
            "Successfully applied {} out of {} AP config entries.\n",
            n,
            apconfig.len()
        );
    }

    ExitCode::SUCCESS
}

/// The real worker function
///
/// This is the real algorithm which is trying to apply the
/// AP configuration read from the config file to the existing
/// APQNs with the info from the list of secrets from the UV.
/// Returns the nr of AP config entries which are fulfilled
/// after the function ended.
/// apqns needs to be mutable as the function does a resort
/// but content stays the same.
fn do_ap_config(
    apqns: &mut ApqnList,
    secrets: &SecretList,
    apconfig: &ApConfigList,
    fntest: bool,
) -> Result<usize, String> {
    let mut resolved_entries = 0;
    let mut apconfig_done = vec![false; apconfig.len()];
    let mut apqn_done = vec![false; apqns.len()];

    // Preparation: Sort APQNs by generation.
    // All the following steps iterate through the list
    // of APQNs. So by sorting the APQNs starting with
    // highest card generation down to the older card
    // generations we prefer newer card generations over
    // older card generations.
    apqns.sort_by_gen();

    // Step 1:
    // Go through all AP config entries and try to find an APQN
    // which already matches to this entry. If such an APQN is
    // found mark the AP config entry as done, and mark the APQN
    // as used so that entry and APQN will get skipped over in
    // the next steps.

    for (ci, apc) in apconfig.iter().enumerate() {
        let cistr = if !apc.name.is_empty() {
            format!("#{} '{}'", ci + 1, apc.name)
        } else {
            format!("#{}", ci + 1)
        };
        for (ai, apqn) in apqns.iter().enumerate() {
            if apqn_done[ai] {
                continue;
            }
            if !config_and_apqn_match(apc, apqn) {
                continue;
            }
            if fntest {
                continue;
            }
            match apqn.mode {
                pvap::apqn_mode::Accel => {
                    // check bind state of this APQN
                    let bind_state_ok = match apqn.bind_state() {
                        Err(err) => {
                            eprintln!("Warning: Failure reading APQN {apqn} bind state: {err}");
                            false
                        }
                        Ok(pvap::bind_state::Bound) => true,
                        Ok(_) => false,
                    };
                    if !bind_state_ok {
                        continue;
                    }
                    // This APQN matches to the current AP config entry and is already bound.
                    // So this AP config entry is satisfied: mark this config entry as done
                    // and mark this APQN as used.
                    info!("Accelerator APQN {apqn} already satisfies AP config entry {cistr}.\n");
                    apconfig_done[ci] = true;
                    apqn_done[ai] = true;
                    resolved_entries += 1;
                    break;
                }
                pvap::apqn_mode::Ep11 => {
                    // check association state of this APQN
                    let (assoc_state_ok, assoc_idx) = match apqn.associate_state() {
                        Err(err) => {
                            eprintln!(
                                "Warning: Failure reading APQN {apqn} associate state: {err}"
                            );
                            (false, 0)
                        }
                        Ok(pvap::assoc_state::Associated(idx)) => (true, idx),
                        Ok(_) => (false, 0),
                    };
                    if !assoc_state_ok {
                        continue;
                    }
                    // check association index
                    let r = secrets.iter().find(|&se| {
                        se.stype() == ListableSecretType::Association
                            && se.id().len() == uv::AP_ASSOC_SECRET_ID_SIZE
                            && se.index() == assoc_idx
                            && encode_hex(se.id()) == apc.secretid
                    });
                    if r.is_none() {
                        continue;
                    }
                    // This APQN matches to the current AP config entry and is already
                    // associated with the right secret id. So this AP config entry is
                    // satisfied: mark this config entry as done and mark this APQN as used.
                    info!("EP11 APQN {apqn} already satisfies AP config entry {cistr}.\n");
                    apconfig_done[ci] = true;
                    apqn_done[ai] = true;
                    resolved_entries += 1;
                    break;
                }
                _ => {
                    // (currently) unknown/unsupported APQN mode
                }
            }
        }
    }

    // Step 2:
    // All APQNs NOT marked as done are now examined for their bind
    // and association state and maybe reset to "unbound".

    for (ai, apqn) in apqns.iter().enumerate() {
        if apqn_done[ai] || fntest {
            continue;
        }
        match apqn.bind_state() {
            Err(err) => eprintln!("Warning: Failure reading APQN {apqn} bind state: {err}"),
            Ok(pvap::bind_state::Bound) => {
                info!("Unbind APQN {apqn} as this bind/associate does not match to any AP config entry.\n");
                if !ARGS.dryrun() {
                    if let Err(err) = apqn.set_bind_state(pvap::bind_state::Unbound) {
                        return Err(format!("Failure unbinding APQN {apqn}: {err}"));
                    }
                }
            }
            Ok(_) => {}
        };
    }

    // Step 3:
    // Go through all remaining AP config entries and try to fulfill each
    // by searching for an APQN which would match to this config entry and
    // then prepare this APQN (bind, maybe associate).
    for (ci, apc) in apconfig.iter().enumerate() {
        let cistr = if !apc.name.is_empty() {
            format!("#{} '{}'", ci + 1, apc.name)
        } else {
            format!("#{}", ci + 1)
        };
        if apconfig_done[ci] {
            continue;
        }
        for (ai, apqn) in apqns.iter().enumerate() {
            if apqn_done[ai] {
                continue;
            }
            if !config_and_apqn_match(apc, apqn) {
                continue;
            }
            match apqn.mode {
                pvap::apqn_mode::Accel => {
                    // try to bind this accelerator APQN
                    if ARGS.verbose() || fntest {
                        println!("Bind APQN {apqn} to match to AP config entry {cistr}.");
                    }
                    if !(ARGS.dryrun() || fntest) {
                        if let Err(err) = apqn.set_bind_state(pvap::bind_state::Bound) {
                            // bind failed, unbind/reset this apqn, return with failure
                            let _ = apqn.set_bind_state(pvap::bind_state::Unbound);
                            return Err(format!("Failure binding APQN {apqn}: {err}"));
                        }
                    }
                    apconfig_done[ci] = true;
                    apqn_done[ai] = true;
                    resolved_entries += 1;
                    break;
                }
                pvap::apqn_mode::Ep11 => {
                    // EP11 needs bind and associate, but before doing this let's
                    // check out which secret index to use with the associate
                    let se = match secrets.iter().find(|&se| {
                        se.stype() == ListableSecretType::Association
                            && se.id().len() == uv::AP_ASSOC_SECRET_ID_SIZE
                            && encode_hex(se.id()) == apc.secretid
                    }) {
                        None => {
                            eprintln!("Warning: Secret id '{}' from config entry {} not found in UV secrets list.",
				      apc.secretid, cistr);
                            break;
                        }
                        Some(se) => se,
                    };
                    // try to bind
                    if ARGS.verbose() || fntest {
                        println!(
                            "Bind APQN {apqn} to match to AP config entry {cistr} (step 1/2)."
                        );
                    }
                    if !(ARGS.dryrun() || fntest) {
                        if let Err(err) = apqn.set_bind_state(pvap::bind_state::Bound) {
                            // bind failed, unbind/reset this apqn, return with failure
                            let _ = apqn.set_bind_state(pvap::bind_state::Unbound);
                            return Err(format!("Failure binding APQN {apqn}: {err}"));
                        }
                    }
                    // try to associate
                    if ARGS.verbose() || fntest {
                        println!(
			    "Associate APQN {} with uv secrets index {} to match AP config entry {} (step 2/2).",
			    apqn, se.index(), cistr
			);
                    }
                    if !(ARGS.dryrun() || fntest) {
                        let apas = pvap::assoc_state::Associated(se.index());
                        apqn.set_associate_state(apas)
                            .map_err(|err| format!("Failure associating APQN {apqn}: {err}"))?;
                    }
                    apconfig_done[ci] = true;
                    apqn_done[ai] = true;
                    resolved_entries += 1;
                    break;
                }
                _ => {
                    // (currently) unknown/unsupported APQN mode
                }
            }
        }
    }

    Ok(resolved_entries)
}

/// # Panics
/// Panics if mingen for an accelerator has not a number as the 4th character.
/// Panics if mingen for an ep11 has not a number as the 4th character.
/// Please note this can not happen, as mingen is already checked via RE
/// during storing the value into mingen.
fn config_and_apqn_match(apc: &ApConfigEntry, apqn: &Apqn) -> bool {
    if apc.mode == config::STR_MODE_ACCEL && apqn.mode == pvap::apqn_mode::Accel {
        // config and apqn are accelerators
        // maybe check mingen
        if !apc.mingen.is_empty() {
            let mingen = &apc.mingen[3..].parse::<u32>().unwrap();
            if mingen < &apqn.gen {
                return false;
            }
        }
        return true;
    } else if apc.mode == config::STR_MODE_EP11 && apqn.mode == pvap::apqn_mode::Ep11 {
        // config and apqn are ep11
        let info = match &apqn.info {
            Some(pvap::apqn_info::Ep11(i)) => i,
            _ => return false,
        };
        // maybe check mingen
        if !apc.mingen.is_empty() {
            let mingen = &apc.mingen[3..].parse::<u32>().unwrap();
            if mingen < &apqn.gen {
                return false;
            }
        }
        // maybe check serialnr
        if !apc.serialnr.is_empty() && apc.serialnr != info.serialnr {
            return false;
        }
        // check mkvp, currently an ep11 config entry must state an mkvp value
        // whereas an ep11 info from an APQN may have an empty mkvp value to
        // indicate that there is no WK set on this APQN.
        if apc.mkvp != info.mkvp {
            return false;
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {

    use super::*;
    use pv_core::{misc::decode_hex, uv::SecretEntry};

    // This is more or less only a test for the do_ap_config() function
    // However, this is THE main functionality of the whole application.

    fn make_test_apqns() -> Vec<Apqn> {
        vec![
            pvap::Apqn {
                name: String::from("10.0007"),
                card: 16,
                domain: 7,
                gen: 8,
                mode: pvap::apqn_mode::Accel,
                info: Option::Some(pvap::apqn_info::Accel(pvap::apqn_info::ApqnInfoAccel {})),
            },
            pvap::Apqn {
                name: String::from("11.0008"),
                card: 17,
                domain: 8,
                gen: 8,
                mode: pvap::apqn_mode::Ep11,
                info: Option::Some(pvap::apqn_info::Ep11(pvap::apqn_info::ApqnInfoEp11 {
                    serialnr: String::from("93AADFK719460083"),
                    mkvp: String::from("db3c3b3c3f097dd55ec7eb0e7fdbcb93"),
                })),
            },
            pvap::Apqn {
                name: String::from("12.0009"),
                card: 18,
                domain: 9,
                gen: 8,
                mode: pvap::apqn_mode::Ep11,
                info: Option::Some(pvap::apqn_info::Ep11(pvap::apqn_info::ApqnInfoEp11 {
                    serialnr: String::from("93AADHZU42082261"),
                    mkvp: String::from("4a27bb66520ac85f6073a7f678d262c0"),
                })),
            },
            pvap::Apqn {
                name: String::from("12.000a"),
                card: 18,
                domain: 10,
                gen: 8,
                mode: pvap::apqn_mode::Ep11,
                info: Option::Some(pvap::apqn_info::Ep11(pvap::apqn_info::ApqnInfoEp11 {
                    serialnr: String::from("93AADHZU42082261"),
                    mkvp: String::from("383d2a9ab781f35343554c5b3d9337cd"),
                })),
            },
            pvap::Apqn {
                name: String::from("13.000d"),
                card: 19,
                domain: 13,
                gen: 8,
                mode: pvap::apqn_mode::Ep11,
                info: Option::Some(pvap::apqn_info::Ep11(pvap::apqn_info::ApqnInfoEp11 {
                    serialnr: String::from("87HU397G150TZGR"),
                    mkvp: String::new(),
                })),
            },
            pvap::Apqn {
                name: String::from("13.000f"),
                card: 19,
                domain: 15,
                gen: 8,
                mode: pvap::apqn_mode::Ep11,
                info: Option::None,
            },
        ]
    }

    fn make_assoc_secretentry(idx: u16, hexidstr: &str) -> SecretEntry {
        let id = decode_hex(hexidstr).unwrap();
        let idlen: u32 = id.len().try_into().unwrap();
        let idarray: [u8; 32] = id.try_into().unwrap();
        SecretEntry::new(idx, ListableSecretType::Association, idarray.into(), idlen)
    }

    fn make_test_secrets() -> Vec<SecretEntry> {
        vec![
            make_assoc_secretentry(
                33,
                "3333333333333333333333333333333333333333333333333333333333333333",
            ),
            make_assoc_secretentry(
                13,
                "bc9d46c052bc3574454c5715757274629a283767ed237922cfb8651c0e77320a",
            ),
            make_assoc_secretentry(
                44,
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
            make_assoc_secretentry(
                15,
                "06cdbbac76a595b481110d108154bc05ebbf900a0f16e36a24045998934fb1e9",
            ),
            make_assoc_secretentry(
                17,
                "6831af07f8c8e7309a3ace9f3b5554d34e3eaa4a27a08fdee469e367c3fa3e9e",
            ),
        ]
    }

    fn make_test_apconfigs() -> Vec<ApConfigEntry> {
        vec![
            config::ApConfigEntry {
                name: String::from("test_1"),
                description: String::from("test_1"),
                mode: String::from("accel"),
                mkvp: String::from(""),
                serialnr: String::from(""),
                mingen: String::from("cex8"),
                secretid: String::from(""),
            },
            config::ApConfigEntry {
                name: String::from("test_2"),
                description: String::from("test_2"),
                mode: String::from("ep11"),
                mkvp: String::from("db3c3b3c3f097dd55ec7eb0e7fdbcb93"),
                serialnr: String::from("93AADFK719460083"),
                mingen: String::from("cex8"),
                secretid: String::from(
                    "bc9d46c052bc3574454c5715757274629a283767ed237922cfb8651c0e77320a",
                ),
            },
            config::ApConfigEntry {
                name: String::from("test_3"),
                description: String::from("test_3"),
                mode: String::from("ep11"),
                mkvp: String::from("4a27bb66520ac85f6073a7f678d262c0"),
                serialnr: String::from(""),
                mingen: String::from("cex8"),
                secretid: String::from(
                    "06cdbbac76a595b481110d108154bc05ebbf900a0f16e36a24045998934fb1e9",
                ),
            },
            config::ApConfigEntry {
                name: String::from("test_4"),
                description: String::from("test_4"),
                mode: String::from("ep11"),
                mkvp: String::from("8be1eaf5c44e2fa8b18804551b604b1b"),
                serialnr: String::from(""),
                mingen: String::from("cex8"),
                secretid: String::from(
                    "6831af07f8c8e7309a3ace9f3b5554d34e3eaa4a27a08fdee469e367c3fa3e9e",
                ),
            },
        ]
    }

    #[test]
    fn test_do_ap_config_invocation_1() {
        let test_apqns = make_test_apqns();
        let apqns: Vec<Apqn> = vec![test_apqns[0].clone()];
        let secrets: Vec<SecretEntry> = Vec::new();
        let secretlist = SecretList::new(secrets.len() as u16, secrets);
        let test_apconfigs = make_test_apconfigs();
        let apconfig: Vec<ApConfigEntry> = vec![test_apconfigs[0].clone()];
        let apcfglist = ApConfigList::from_apconfigentry_vec(apconfig);
        let mut apqnlist = ApqnList::from_apqn_vec(apqns);
        let r = do_ap_config(&mut apqnlist, &secretlist, &apcfglist, true);
        assert!(r.is_ok());
        let n = r.unwrap();
        assert!(n == 1);
    }

    #[test]
    fn test_do_ap_config_invocation_2() {
        let test_apqns = make_test_apqns();
        let apqns: Vec<Apqn> = vec![test_apqns[1].clone()];
        let mut secrets = make_test_secrets();
        secrets.truncate(2);
        let secretlist = SecretList::new(secrets.len() as u16, secrets);
        let test_apconfigs = make_test_apconfigs();
        let apconfig: Vec<ApConfigEntry> = vec![test_apconfigs[1].clone()];
        let apcfglist = ApConfigList::from_apconfigentry_vec(apconfig);
        let mut apqnlist = ApqnList::from_apqn_vec(apqns);
        let r = do_ap_config(&mut apqnlist, &secretlist, &apcfglist, true);
        assert!(r.is_ok());
        let n = r.unwrap();
        assert!(n == 1);
    }

    #[test]
    fn test_do_ap_config_invocation_3() {
        let test_apqns = make_test_apqns();
        let mut apqns: Vec<Apqn> = Vec::new();
        for a in test_apqns.iter() {
            apqns.push(a.clone());
        }
        apqns.reverse();
        let secrets = make_test_secrets();
        let secretlist = SecretList::new(secrets.len() as u16, secrets);
        let test_apconfigs = make_test_apconfigs();
        let mut apconfig: Vec<ApConfigEntry> = Vec::new();
        for c in test_apconfigs.iter() {
            apconfig.push(c.clone());
        }
        let apcfglist = ApConfigList::from_apconfigentry_vec(apconfig);
        let mut apqnlist = ApqnList::from_apqn_vec(apqns);
        let r = do_ap_config(&mut apqnlist, &secretlist, &apcfglist, true);
        assert!(r.is_ok());
        let n = r.unwrap();
        assert!(n == 3, "n = {n} != 3");
    }
}
