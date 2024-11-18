// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

mod host_key;

use self::host_key::{host_key_check, HostKeyCheck};
use crate::{additional::AttestationResult, cli::CheckOpt, exchange::ExchangeFormatResponse};
use anyhow::Result;
use log::{debug, info, warn};
use pv::{
    attest::AttestationRequest,
    misc::{create_file, open_file, read_file},
};
use serde::Serialize;
use std::process::ExitCode;
use utils::HexSlice;

#[derive(Default, Debug)]
enum CheckState<T> {
    #[default]
    None,
    Data(T),
    Err(String),
}

impl<T> CheckState<T> {
    fn check(self, issues: &mut Vec<String>) -> Option<T> {
        match self {
            Self::None => None,
            Self::Data(d) => Some(d),
            Self::Err(e) => {
                issues.push(e.to_string());
                warn!("✘ {e}");
                None
            }
        }
    }
}

impl<T> From<Option<T>> for CheckState<T> {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::None, Self::Data)
    }
}

/// Return a [`CheckState::Err`]`
#[allow(unused_macro_rules)]
macro_rules! bail_check {
    ($msg:literal) => {
        return Ok(CheckState::Err($msg.to_string()))
    };
    ($err:expr) => {
        return Ok(CheckState::Err($err.to_string()))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Ok(CheckState::Err(format!($fmt, $($arg)*)))
    };
}
use bail_check;

/// Check if the user-data matches with the user-data in the attestation response
fn user_data_check<'a>(
    opt: &CheckOpt,
    att_res: &'a AttestationResult,
) -> Result<CheckState<HexSlice<'a>>> {
    let user_data = match &opt.user_data {
        Some(file) => read_file(file, "user-data")?,
        None => return Ok(CheckState::None),
    };

    if Some(HexSlice::from(&user_data)) != att_res.user_data {
        bail_check!(
            "The Provided user data does not match the user data from the attestation response."
        );
    }
    info!("✓ Checked user-data");
    Ok(att_res.user_data.clone().into())
}

#[derive(Debug, Serialize, Default)]
pub struct CheckResult<'a> {
    successful: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    issues: Vec<String>,
    #[serde(skip_serializing_if = "HostKeyCheck::hide")]
    image_host_key: HostKeyCheck<'a>,
    #[serde(skip_serializing_if = "HostKeyCheck::hide")]
    attest_host_key: HostKeyCheck<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data: Option<HexSlice<'a>>,
}

/// Perform the policy checks
pub fn check(opt: &CheckOpt) -> Result<ExitCode> {
    let mut input = open_file(&opt.input)?;
    let inp = ExchangeFormatResponse::read(&mut input)?;
    let auth = AttestationRequest::auth_bin(inp.arcb())?;
    let att_res = AttestationResult::from_exchange(&inp, auth.flags())?;
    let mut issues = vec![];

    let image_host_key = host_key_check(opt, host_key::HkCheck::Image, &att_res)?
        .check(&mut issues)
        .unwrap();
    let attest_host_key = host_key_check(opt, host_key::HkCheck::Attest, &att_res)?
        .check(&mut issues)
        .unwrap();

    let user_data = user_data_check(opt, &att_res)?.check(&mut issues);

    let res = CheckResult {
        successful: !issues.is_empty(),
        issues,
        image_host_key,
        attest_host_key,
        user_data,
    };

    debug!("res {res:?}");
    let output = create_file(&opt.output)?;
    serde_yaml::to_writer(output, &res)?;

    match res.successful {
        true => {
            warn!("✓ The Attestation response fulfills all policies");
            Ok(ExitCode::SUCCESS)
        }
        false => {
            warn!("✘ The Attestation response does not fulfill all policies");
            Ok(ExitCode::from(crate::EXIT_CODE_ATTESTATION_FAIL))
        }
    }
}
