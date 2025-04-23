// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::{cli::AddSecretOpt, cmd::list::list_uvc};
use anyhow::{bail, Context, Result};
use log::warn;
use pv::{
    secret::AddSecretRequest,
    uv::{AddCmd, UvCmd, UvDevice},
};
use utils::get_reader_from_cli_file_arg;

/// Do an Add Secret UVC
pub fn add(opt: &AddSecretOpt) -> Result<()> {
    let uv = UvDevice::open()?;
    let mut rd_in = get_reader_from_cli_file_arg(&opt.input)?;
    let mut cmd =
        AddCmd::new(&mut rd_in).context(format!("Processing input file {}", opt.input))?;

    if let Some(id) = AddSecretRequest::bin_id(cmd.data().unwrap())? {
        if list_uvc(&uv)?.iter().any(|e| e.id() == id.as_ref()) {
            warn!("There is already a secret in the secret store with that id.");
            match opt.force {
                true => warn!("'--force' specified: Adding the secret anyways."),
                false => bail!("Unable to add the secret due to duplicated IDs"),
            }
        }
    }

    uv.send_cmd(&mut cmd)?;
    warn!("Successfully added the secret");
    Ok(())
}
