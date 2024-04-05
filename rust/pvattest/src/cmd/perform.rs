// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::{
    cli::PerformAttOptComb,
    exchange::{ExchangeFormatRequest, ExchangeFormatResponse, ExchangeFormatVersion},
};
use anyhow::Result;
use pv::{
    misc::{create_file, open_file, read_file},
    uv::{AttestationCmd, UvDevice},
};
use std::process::ExitCode;

pub fn perform<'a, P>(opt: P) -> Result<ExitCode>
where
    P: Into<PerformAttOptComb<'a>>,
{
    let opt = opt.into();
    let mut input = open_file(opt.input)?;
    let mut output = create_file(opt.output)?;
    let uvdevice = UvDevice::open()?;

    let ex_in = ExchangeFormatRequest::read(&mut input)?;
    let user_data = opt
        .user_data
        .map(|u| read_file(u, "user-data"))
        .transpose()?;

    let mut cmd = AttestationCmd::new_request(
        ex_in.arcb.clone().into(),
        user_data.clone(),
        ex_in.exp_measurement,
        ex_in.exp_additional,
    )?;

    uvdevice.send_cmd(&mut cmd)?;

    let measurement = cmd.measurement();
    let additional = cmd.additional_owned();
    let cuid = cmd.cuid();

    let ex_out = ExchangeFormatResponse::new(
        ex_in.arcb,
        measurement.to_owned(),
        additional,
        user_data,
        cuid.to_owned(),
    )?;
    ex_out.write(&mut output, ExchangeFormatVersion::One)?;

    Ok(ExitCode::SUCCESS)
}
