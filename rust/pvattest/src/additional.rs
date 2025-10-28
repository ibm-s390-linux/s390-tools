// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::exchange::ExchangeFormatResponse;
use anyhow::Result;
use pv::attest::{AdditionalData, AttestationFlags};
use serde::Serialize;
use std::fmt::Display;
use utils::HexSlice;

#[derive(Serialize)]
pub struct AttestationResult<'a> {
    pub cuid: HexSlice<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add: Option<HexSlice<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_fields: Option<AdditionalData<HexSlice<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data: Option<HexSlice<'a>>,
}

impl<'a> AttestationResult<'a> {
    pub fn from_exchange(
        resp: &'a ExchangeFormatResponse,
        flags: &AttestationFlags,
    ) -> Result<Self> {
        let add_fields = resp
            .additional()
            .map(|a| AdditionalData::from_slice_sized(a, flags))
            .transpose()?;
        Ok(Self {
            cuid: resp.config_uid().into(),
            add: resp.additional().map(|a| a.into()),
            add_fields,
            user_data: resp.user().map(|u| u.into()),
        })
    }
}

impl Display for AttestationResult<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Config UID:")?;
        writeln!(f, "{:#}", self.cuid)?;
        if let Some(data) = &self.add {
            writeln!(f, "Additional-data:")?;
            writeln!(f, "{data:#}")?;
        }
        if let Some(data) = &self.add_fields {
            writeln!(f, "Additional-data content:")?;
            writeln!(f, "{data:#}")?;
        }
        if let Some(data) = &self.user_data {
            writeln!(f, "user-data:")?;
            writeln!(f, "{data:#}")?;
        }
        Ok(())
    }
}
