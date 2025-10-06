// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::Write;

use anyhow::Result;
use log::{info, warn};
use pv::{
    misc::{open_file, read_file},
    request::SymKey,
};
use pvimg::{
    error::OwnExitCode,
    uvdata::{KeyExchangeTrait, SeHdr, UvDataTrait},
};

use crate::cli::InfoArgs;

pub fn info(opt: &InfoArgs) -> Result<OwnExitCode> {
    info!(
        "Reading Secure Execution header {}",
        opt.input.path.display()
    );
    let mut input = open_file(&opt.input.path)?;
    let mut output = std::io::stdout();

    SeHdr::seek_sehdr(&mut input, None)?;
    let hdr = SeHdr::try_from_io(input)?;
    if let Some(key_path) = &opt.hdr_key {
        let key =
            SymKey::try_from_data(hdr.key_type(), read_file(key_path, "Reading key")?.into())?;
        serde_json::to_writer_pretty(&mut output, &hdr.decrypt(&key)?)?;
    } else {
        warn!("WARNING: The Secure Execution header integrity and authenticity was not verified. Specify '--hdr-key' to authenticate it. Do not trust the data without verification.");
        serde_json::to_writer_pretty(&mut output, &hdr)?;
    }
    writeln!(output)?;

    Ok(OwnExitCode::Success)
}
