// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use log::{debug, warn};
use pv::attest::{AttestationFlags, AttestationMeasAlg, AttestationRequest, AttestationVersion};
use pv::misc::{create_file, write_file_private};
use pv::request::{HostKey, ReqEncrCtx, Request, SymKey, SymKeyType};

use crate::cli::{AttAddFlags, AttVersion, AttVersionSelection, CreateAttOpt};
use crate::exchange::{ExchangeFormatRequest, ExchangeFormatVersion};

fn flags(cli_flags: &[AttAddFlags]) -> AttestationFlags {
    let mut att_flags = AttestationFlags::default();
    for flag in cli_flags {
        match flag {
            AttAddFlags::PhkhImg => att_flags.set_image_phkh(),
            AttAddFlags::PhkhAtt => att_flags.set_attest_phkh(),
            AttAddFlags::SecretStoreHash => att_flags.set_secret_store_hash(),
            AttAddFlags::FirmwareState => att_flags.set_firmware_state(),
        }
    }
    att_flags
}

/// Auto-detect the attestation version based on the host keys.
///
/// Returns Two if any host key is a hybrid key, otherwise returns V1.
fn auto_detect_version(host_keys: &[HostKey]) -> AttestationVersion {
    let use_hybrid_keys = host_keys.iter().any(|k: &HostKey| k.is_hybrid());
    if use_hybrid_keys {
        AttestationVersion::Two
    } else {
        AttestationVersion::One
    }
}

impl From<AttVersion> for AttestationVersion {
    fn from(value: AttVersion) -> Self {
        match value {
            AttVersion::V1 => Self::One,
            AttVersion::V2 => Self::Two,
        }
    }
}

/// Determine the attestation  version to use.
///
/// If an explicit version is provided via CLI, use that.
/// Otherwise, auto-detect based on the host key types.
fn determine_version(
    cli_version: AttVersionSelection,
    host_keys: &[HostKey],
) -> AttestationVersion {
    match cli_version {
        AttVersionSelection::Auto => auto_detect_version(host_keys),
        AttVersionSelection::Explicit(att_version) => att_version.into(),
    }
}

pub fn create(opt: &CreateAttOpt) -> Result<ExitCode> {
    let hkds = opt.certificate_args.get_verified_hkds(
        "attestation request",
        AttVersionSelection::Explicit(opt.att_version).map(|v| v.into()),
    )?;

    let att_version = determine_version(AttVersionSelection::Explicit(opt.att_version), &hkds);
    let meas_alg = AttestationMeasAlg::HmacSha512;

    let mut arcb = AttestationRequest::new(att_version, meas_alg, flags(&opt.add_data))?;
    debug!("Generated Attestation request");

    // Add host-key documents
    for k in hkds.into_iter() {
        arcb.add_hostkey(k)?
    }
    debug!("Added all host-keys");

    let encr_ctx =
        ReqEncrCtx::random(SymKeyType::Aes256Gcm).context("Failed to generate random input")?;
    let ser_arcb = arcb.encrypt(&encr_ctx)?;
    warn!("Successfully generated the request");

    let mut output = create_file(&opt.output)?;
    let exch_ctx = ExchangeFormatRequest::new(
        ser_arcb,
        meas_alg.exp_size(),
        arcb.flags().expected_additional_size(),
    )?;
    exch_ctx.write(&mut output, ExchangeFormatVersion::One)?;

    let arpk = match encr_ctx.prot_key() {
        SymKey::Aes256(k) => k,
        _ => bail!("Unexpected key type"),
    };
    write_file_private(
        &opt.arpk,
        arpk.value(),
        "Attestation request Protection Key",
    )?;

    Ok(ExitCode::SUCCESS)
}
