// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! # pvebc - Protected Virtualization Early Boot Customization Tool
//!
//! This tool processes AddSecretRequest files (toc.asr) that define the root of EBC
//! (Early Boot Customization) resources. It validates references to associated
//! toc.pol policies and manages their addition to the system.
//!
//! ## Features
//!
//! - Validates AddSecretRequest files and their associated policies
//! - Verifies cryptographic hashes of policy files using SHA-256
//! - Supports dry-run mode for validation without system changes
//! - MAC tag validation for AddSecretRequest files

#![allow(missing_docs)]

mod cli;
mod ebc_utils;

#[cfg(target_arch = "s390x")]
use pv_core::uv::{AddCmd, UvDevice};
#[cfg(target_arch = "s390x")]
use utils::get_reader_from_cli_file_arg;

use anyhow::{bail, Context, Error, Result};
use clap::Parser;
use pv_core::{
    misc::{decode_hex, encode_hex},
    PolicyReference,
};
use std::{
    fs::{self, File},
    io::{BufRead, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    str::from_utf8,
};
// Don't use openssl here because this tool is intended to run in the initramfs
// phase of the boot and there we don't want to dynamically link against a C lib
use sha2::{self, Digest};
use zerocopy::TryFromBytes;

use crate::cli::Cli;
use crate::ebc_utils::{get_data, get_mac_tag, get_reader};

/// Offset in bytes where user data starts in an ASRCB v1 structure
const V1_USER_DATA_OFFS: usize = 536;
/// Size in bytes of the user data field in an ASRCB
const USER_DATA_SIZE: usize = 512;

/// Validates and resolves a policy name relative to a base directory
///
/// # Errors
/// Returns an error if path traversal is detected or the resolved path
/// is outside the base directory
fn validate_and_resolve_policy_path(base: &Path, name: &str) -> Result<PathBuf> {
    // Validate path to prevent directory traversal
    if name.contains("..") || name.starts_with('/') {
        bail!("Invalid policy name: path traversal detected in '{}'", name);
    }

    let resolved = base.join(name);

    // Ensure the resulting path is within the expected directory
    if !resolved.starts_with(base) {
        bail!(
            "Policy path '{}' is outside the expected directory",
            resolved.display()
        );
    }

    Ok(resolved)
}

/// Extracts and validates the policy name from a PolicyReference
///
/// # Errors
/// Returns an error if the policy name contains invalid UTF-8 or is empty
fn extract_policy_name(policy_ref: &PolicyReference) -> Result<String> {
    let name = from_utf8(&policy_ref.name)
        .context("Policy name contains invalid UTF-8")?
        .trim_matches('\0')
        .to_string();

    if name.is_empty() {
        bail!("Policy name is empty");
    }

    Ok(name)
}

/// Computes the SHA-256 hash of data from a reader.
///
/// Reads data from the provided reader in 4096-byte chunks and computes
/// the SHA-256 hash of the entire content.
///
/// # Parameters
///
/// * `r` - A reader providing the data to hash
///
/// # Returns
///
/// Returns a `Vec<u8>` containing the 32-byte SHA-256 hash, or an error
/// if reading fails.
///
/// # Errors
///
/// Returns an error if reading from the reader fails.
pub fn sha256_hash<R: Read>(mut r: R) -> Result<Vec<u8>, Error> {
    let mut hasher = sha2::Sha256::new();
    let mut buf: [u8; 4096] = [0; 4096];

    loop {
        let read = r.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    Ok(hasher.finalize().to_vec())
}

/// Extract the user data from an ASRCB
///
/// # Errors
///
/// Returns an error if the ASRCB is too small to contain user data
fn get_user_data(asrcb: &[u8]) -> Result<Option<Vec<u8>>> {
    if asrcb.len() < V1_USER_DATA_OFFS + USER_DATA_SIZE {
        bail!(
            "ASRCB too small (expected at least {} bytes, got {})",
            V1_USER_DATA_OFFS + USER_DATA_SIZE,
            asrcb.len()
        );
    }

    let user_data = &asrcb[V1_USER_DATA_OFFS..V1_USER_DATA_OFFS + USER_DATA_SIZE];
    Ok(Some(user_data.to_vec()))
}

/// Get user data from AddSecretRequest
fn verify_user_data(filepath: &Path) -> Result<Option<Vec<u8>>> {
    let mut rd_in = get_reader(filepath)?;
    let data_in = get_data(&mut rd_in)?;

    get_user_data(&data_in).context("Could not verify the Add-secret request")
}

/// Adds the given AddSecretRequest (if dryrun == false) and parses the contained user data
///
/// # Returns
///
/// On Success returns the PolicyReference parsed from the given AddSecretRequest
///
/// # Errors
///
/// returns an error if
/// - unable to open UvDevice
/// - reader from path fails
/// - adding of ASR fails
/// - verify_user_data fails
/// - unable to convert user data to PolicyReference
fn asr_to_pol_ref(filepath: &Path, dryrun: bool) -> Result<Option<PolicyReference>> {
    print!("Add-Secret-Request: \"{}\"", filepath.display());
    if !dryrun {
        #[cfg(target_arch = "s390x")]
        {
            let uv = UvDevice::open()?;
            let mut rd_in = get_reader_from_cli_file_arg(filepath)?;
            let mut cmd = AddCmd::new(&mut rd_in)
                .context(format!("Processing input file {:?}", filepath.to_str()))?;
            uv.send_cmd(&mut cmd)?;
            println!();
        }
        #[cfg(not(target_arch = "s390x"))]
        {
            println!(" (skip adding: not running on s390x architecture)");
        }
    } else {
        println!(" (skip adding: dry-run mode)");
    }

    Ok(match verify_user_data(filepath)? {
        Some(ud) => {
            let ret = PolicyReference::try_read_from_bytes(&ud).map_err(|e| {
                anyhow::anyhow!("Failed to parse PolicyReference from user data: {:?}", e)
            })?;
            println!("    Reference: {}", ret);
            Some(ret)
        }
        None => None,
    })
}

/// Read the mac tag list of the toc policy, parse and verify every tag
fn execute_toc_pol(path: &Path, toc_pol_ref: PolicyReference) -> Result<Vec<PathBuf>> {
    let name = extract_policy_name(&toc_pol_ref)?;
    let toc_path = validate_and_resolve_policy_path(path, &name)?;
    let mut ret: Vec<PathBuf> = Vec::new();
    let mut rd_in = get_reader(&toc_path)?;
    let data_in = get_data(&mut rd_in)?;

    let macs = data_in.lines();
    let base = get_base_dir(&toc_path);

    println!("Mac tags in {:?}:", toc_path);
    for mac in macs {
        let mut mac_tag = Vec::new();
        let mac_tag_ref = match mac {
            Ok(s) => s,
            _ => continue,
        };
        print!("    {}", mac_tag_ref);

        let entries = fs::read_dir(base)?;
        for entry in entries {
            let path = entry?;
            let filepath = path.path();
            let ext = match filepath.extension() {
                Some(e) => e,
                None => continue,
            };
            if ext == "asr" {
                mac_tag = get_mac_tag(filepath.as_path())?;

                if mac_tag == decode_hex(&mac_tag_ref)? {
                    println!("    -> {}", filepath.display());
                    ret.push(filepath.clone());

                    break;
                }
            }
        }

        if mac_tag != decode_hex(&mac_tag_ref)? {
            bail!(
                "No ASR with mac tag \"{}\" found in {:?}",
                mac_tag_ref,
                base
            );
        }
    }

    println!();

    Ok(ret)
}

/// Checks whether the given hash in polref matches the actual hash of the referenced file
fn verify_policy(basename: &Path, polref: PolicyReference) -> Result<()> {
    let name = extract_policy_name(&polref)?;
    let filepath = validate_and_resolve_policy_path(basename, &name)?;
    println!("Verify \"{}\"", filepath.display());

    println!("    Referenced: {}", encode_hex(polref.hash));
    let f = File::open(filepath.as_path())?;

    let check_hash = sha256_hash(f)?;
    println!("    Calculated: {}", encode_hex(&check_hash));

    if check_hash != polref.hash {
        bail!(
            "{:?} ({}) does not match expected hash ({})",
            filepath,
            encode_hex(&check_hash),
            encode_hex(polref.hash)
        );
    }

    Ok(())
}

/// For every AddSecretRequest find the corresponding policy
fn execute_asrs(asrs: Vec<PathBuf>, dryrun: bool) -> Result<()> {
    // loop over ASRs
    for asr in asrs {
        // get the referenced policy
        let pol_ref = match asr_to_pol_ref(asr.as_path(), dryrun)? {
            Some(pr) => pr,
            None => continue,
        };

        if pol_ref.hash.iter().all(|&b| b == 0) {
            continue;
        }

        let base = get_base_dir(asr.as_path());
        let name = extract_policy_name(&pol_ref)?;
        let _pol_path = validate_and_resolve_policy_path(base, &name)?;

        // verify the integrity of the referenced policy
        verify_policy(base, pol_ref)?;
    }

    Ok(())
}

/// Get the parent directory of the given file
fn get_base_dir(filepath: &Path) -> &Path {
    match filepath.parent() {
        Some(p) => p,
        None => Path::new(""),
    }
}

/// Print a given error and return the failure exit code
fn error_to_exit_code(err: Error) -> ExitCode {
    eprintln!("Error: {}", err);

    ExitCode::FAILURE
}

/// main function
pub fn main() -> ExitCode {
    let opt: Cli = Cli::parse();

    let dryrun = opt.dry_run;

    if dryrun {
        println!("Dry-run mode detected, skipping secret addition");
        println!();
    }

    // get toc asr filepath - wrapper script has already copied files to tmpfs
    let toc_asr = &opt.toc;
    let basename = match toc_asr.parent() {
        Some(p) => p,
        None => {
            return error_to_exit_code(Error::msg("Unable to get directory from specified path"))
        }
    };

    // get the PolicyReference from toc.asr to toc.pol
    let toc_pol = match asr_to_pol_ref(toc_asr, dryrun) {
        Ok(o) => match o {
            Some(r) => r,
            None => {
                return error_to_exit_code(Error::msg(
                    "There is no linked policy in the supplied ASR",
                ))
            }
        },
        Err(e) => return error_to_exit_code(e),
    };

    // verify the integrity on the referenced toc.pol
    if let Err(e) = verify_policy(basename, toc_pol) {
        return error_to_exit_code(e);
    }

    println!();

    // get and verify ASRs from mac list of toc policy
    let asr_list = match execute_toc_pol(basename, toc_pol) {
        Ok(v) => v,
        Err(e) => return error_to_exit_code(e),
    };

    // execute ASRs
    if let Err(e) = execute_asrs(asr_list, dryrun) {
        return error_to_exit_code(e);
    }

    ExitCode::SUCCESS
}
