// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::{fmt::Display, time::Duration};

use anyhow::{bail, Result};
use base64::prelude::*;
use curl::easy::{Easy2, Handler, List, WriteError};
use log::{debug, info, log_enabled};
use serde::{Deserialize, Serialize};

use super::{bail_check, CheckState};
use crate::{additional::AttestationResult, cli::CheckOpt};

const CHECK_DEFAULT_ENDP: &str = "https://www.ibm.com/support/resourcelink/api";
const VERIFY_API: &str = "firmware-attestation/verify/v1";
const TIMEOUT_MAX: Duration = Duration::from_secs(3);
const USER_AGENT: &str = "s390-tools-pvattest";
const CONTENT_TYPE: &str = "Content-Type: application/json";
const CLIENT_ID: &str = "x-client-id: X";

#[derive(Debug, Serialize)]
struct Request {
    version: String,
    payload: String,
}

impl Request {
    const VERSION_ONE: &'static str = "1.0";

    fn new_v1(firmware_hash: &[u8]) -> Self {
        Self {
            version: Self::VERSION_ONE.to_string(),
            payload: BASE64_STANDARD.encode(firmware_hash),
        }
    }
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    version: String,
    valid: bool,
    reference_id: String,
    #[serde(default)]
    reason: Option<String>,
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The firmware is {}in a valid state",
            if self.valid { "" } else { "not " }
        )?;

        self.reason.as_ref().map_or(Ok(()), |r| {
            write!(f, "\n  Reason: {r}\n  ReferenceId: {}", self.reference_id)
        })
    }
}

#[derive(Debug)]
struct Buf(Vec<u8>);
impl Handler for Buf {
    fn write(&mut self, data: &[u8]) -> std::result::Result<usize, WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
}

fn check<U: AsRef<[u8]>>(fw_hash: &U, endp: &str) -> Result<CheckState<()>> {
    let req = serde_json::to_vec(&Request::new_v1(fw_hash.as_ref()))?;

    let url = format!("{endp}/{VERIFY_API}");
    debug!("POST {url}");

    let mut http_header = List::new();
    http_header.append(CLIENT_ID)?;
    http_header.append(CONTENT_TYPE)?;

    let mut handle = Easy2::new(Buf(Vec::with_capacity(0x1000)));
    handle.buffer_size(102400)?;
    handle.url(&url)?;
    handle.post_fields_copy(&req)?;
    handle.http_headers(http_header)?;
    handle.useragent(USER_AGENT)?;
    handle.max_redirections(50)?;
    handle.post(true)?;
    handle.timeout(TIMEOUT_MAX)?;
    handle.follow_location(true)?;
    if log_enabled!(log::Level::Trace) {
        handle.verbose(true)?;
    }
    handle.perform()?;

    if handle.response_code()? != 200 {
        bail!(
            "The firmware verification server responded with http response status code '{}'",
            handle.response_code()?
        );
    }

    let resp: Response = match serde_json::from_slice(&handle.get_ref().0) {
        Ok(res) => res,
        Err(e) => bail!(
            "Unexpected response from server: {} \n (\"{}\")",
            String::from_utf8(handle.get_ref().0.clone())
                .unwrap_or_else(|_| "No UTF-8 message".to_string()),
            e
        ),
    };

    debug!("Firmware check {resp:?}");

    match resp.valid {
        true => info!("✓ {resp}"),
        false => bail_check!(&format!("{resp}")),
    }

    Ok(CheckState::Data(()))
}

pub fn firmware_check(opt: &CheckOpt, att_res: &AttestationResult) -> Result<CheckState<()>> {
    if !opt.firmware {
        return Ok(None.into());
    }

    let endp = opt
        .firmware_verify_url
        .as_deref()
        .unwrap_or(CHECK_DEFAULT_ENDP);

    match att_res
        .add_fields
        .as_ref()
        .and_then(|add| add.firmware_state())
    {
        Some(hash) => check(hash, endp),
        None => {
            bail_check!(
                "The Attestation response contains no firmware hash, but checking was enabled"
            )
        }
    }
}
