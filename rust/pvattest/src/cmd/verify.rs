// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use anyhow::Result;
use log::{debug, warn};
use pv::{
    attest::{
        AdditionalData, AttestationFlags, AttestationItems, AttestationMeasurement,
        AttestationRequest,
    },
    misc::{create_file, open_file, read_exact_file, write_file},
    request::{openssl::pkey::PKey, BootHdrTags, Confidential, SymKey},
};
use serde::Serialize;
use std::{fmt::Display, process::ExitCode};
use utils::HexSlice;

use crate::{
    cli::{OutputType, VerifyOpt},
    exchange::ExchangeFormatResponse,
    EXIT_CODE_ATTESTATION_FAIL,
};

#[derive(Serialize)]
struct VerifyOutput<'a> {
    cuid: HexSlice<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add: Option<HexSlice<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add_fields: Option<AdditionalData<HexSlice<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data: Option<HexSlice<'a>>,
}

impl<'a> VerifyOutput<'a> {
    fn from_exchange(resp: &'a ExchangeFormatResponse, flags: &AttestationFlags) -> Result<Self> {
        let additional_data_fields = resp
            .additional()
            .map(|a| AdditionalData::from_slice(a, flags))
            .transpose()?;
        let user_data = resp.user().map(|u| u.into());

        Ok(Self {
            cuid: resp.config_uid().into(),
            add: resp.additional().map(|a| a.into()),
            add_fields: additional_data_fields.map(AdditionalData::from_other),
            user_data,
        })
    }
}

impl Display for VerifyOutput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Config UID:")?;
        writeln!(f, "{:#}", self.cuid)?;
        if let Some(data) = &self.add {
            writeln!(f, "Additional-data:")?;
            writeln!(f, "{:#}", data)?;
        }
        if let Some(data) = &self.add_fields {
            writeln!(f, "Additional-data content:")?;
            writeln!(f, "{:#}", data)?;
        }
        if let Some(data) = &self.user_data {
            writeln!(f, "user-data:")?;
            writeln!(f, "{:#}", data)?;
        }
        Ok(())
    }
}

pub fn verify(opt: &VerifyOpt) -> Result<ExitCode> {
    let mut input = open_file(&opt.input)?;
    let mut img = open_file(&opt.hdr)?;
    let output = opt.output.as_ref().map(create_file).transpose()?;
    let arpk = SymKey::Aes256(
        read_exact_file(&opt.arpk, "Attestation request protection key").map(Confidential::new)?,
    );
    let tags = BootHdrTags::from_se_image(&mut img)?;
    let exchange = ExchangeFormatResponse::read(&mut input)?;

    let (auth, conf) = AttestationRequest::decrypt_bin(exchange.arcb(), &arpk)?;
    let meas_key = PKey::hmac(conf.measurement_key())?;
    let items = AttestationItems::new(
        &tags,
        exchange.config_uid(),
        exchange.user(),
        conf.nonce().as_ref().map(|v| v.value()),
        exchange.additional(),
    );

    let measurement = AttestationMeasurement::calculate(items, auth.mai(), &meas_key)?;

    let uv_meas = exchange.measurement();
    if !measurement.eq_secure(uv_meas) {
        debug!("Measurement values:");
        debug!("Recieved: {}", HexSlice::from(uv_meas));
        debug!("Calculated: {}", HexSlice::from(measurement.as_ref()));
        warn!("Attestation measurement verification failed. Calculated and received attestation measurement are not equal.");
        return Ok(ExitCode::from(EXIT_CODE_ATTESTATION_FAIL));
    }
    warn!("Attestation measurement verified");
    // Error impossible CUID is present Attestation verified
    let pr_data = VerifyOutput::from_exchange(&exchange, auth.flags())?;

    warn!("{pr_data}");
    if let Some(mut output) = output {
        match opt.format {
            OutputType::Yaml => serde_yaml::to_writer(&mut output, &pr_data)?,
        };
    }

    if let Some(user_data) = &opt.user_data {
        match exchange.user() {
            Some(data) => write_file(user_data, data, "user-data")?,
            None => {
                warn!("Location for `user-data` specified, but respose does not contain any user-data")
            }
        }
    };

    Ok(ExitCode::SUCCESS)
}
