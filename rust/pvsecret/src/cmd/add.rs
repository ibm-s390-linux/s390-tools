// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::cli::AddSecretOpt;
use anyhow::{Context, Result};
use log::warn;
use pv::uv::{AddCmd, UvDevice};
use utils::get_reader_from_cli_file_arg;

/// Do an Add Secret UVC
pub fn add(opt: &AddSecretOpt) -> Result<()> {
    let mut rd_in = get_reader_from_cli_file_arg(&opt.input)?;
    let mut cmd =
        AddCmd::new(&mut rd_in).context(format!("Processing input file {}", opt.input))?;
    UvDevice::open()?.send_cmd(&mut cmd)?;
    warn!("Successfully added the secret");
    Ok(())
}
