// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::{
    cli::{AttAddFlags, CreateAttOpt},
    exchange::{ExchangeFormatRequest, ExchangeFormatVersion},
};
use anyhow::{bail, Context, Result};
use log::{debug, warn};
use pv::{
    attest::{AttestationFlags, AttestationMeasAlg, AttestationRequest, AttestationVersion},
    misc::{create_file, write_file},
    request::{ReqEncrCtx, Request, SymKey, SymKeyType},
};
use std::process::ExitCode;

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

pub fn create(opt: &CreateAttOpt) -> Result<ExitCode> {
    let att_version = AttestationVersion::One;
    let meas_alg = AttestationMeasAlg::HmacSha512;

    let mut arcb = AttestationRequest::new(att_version, meas_alg, flags(&opt.add_data))?;
    debug!("Generated Attestation request");

    // Add host-key documents
    opt.certificate_args
        .get_verified_hkds("attestation request")?
        .into_iter()
        .for_each(|k| arcb.add_hostkey(k));
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
    write_file(
        &opt.arpk,
        arpk.value(),
        "Attestation request Protection Key",
    )?;

    Ok(ExitCode::SUCCESS)
}
